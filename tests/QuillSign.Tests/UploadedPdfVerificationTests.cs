using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Storage;
using Flow=QuillSign.Tests.CompletionDownloadTests.Flow;

namespace QuillSign.Tests;

public sealed class UploadedPdfVerificationTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_executed_and_certificate_uploads_verify_readonly_after_signing_expiry_without_private_keys_or_network_requests()
    {
        await using var f=await Flow.Create(fixture);var before=await Counts(f);var acquired=f.Run.Seal.Certificates.Calls;var tsa=f.Run.Seal.Requests;
        f.Run.Seal.Options.Pfx.Path="unavailable";f.Clock.Advance(TimeSpan.FromDays(3));
        foreach(var (bytes,kind) in new[]{(f.Published.ExecutedBytes,FinalDocumentKind.Executed),(f.Published.CertificateBytes,FinalDocumentKind.Certificate)}) {
            var result=await Verify(f,bytes);Assert.Equal(UploadedPdfVerificationStatus.Verified,result.Status);Assert.Equal(kind,result.Kind);
            Assert.True(result.SealIntegrity);Assert.True(result.TimestampIntegrity);Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)),result.Sha256);
            var json=JsonSerializer.Serialize(result);Assert.DoesNotContain(f.PublicId,json);Assert.DoesNotContain(f.Id.ToString(),json);Assert.DoesNotContain(f.Run.Signing.Envelope.SenderEmail,json);
            Assert.DoesNotContain("Blob",json);Assert.DoesNotContain("token",json,StringComparison.OrdinalIgnoreCase);Assert.DoesNotContain("download",json,StringComparison.OrdinalIgnoreCase);
        }
        Assert.Equal(before,await Counts(f));Assert.Equal(acquired,f.Run.Seal.Certificates.Calls);Assert.Equal(tsa,f.Run.Seal.Requests);Assert.Equal(2,f.Store.Writes);Assert.Empty(f.Run.Storage.Deleted);
    }
    [Fact]
    public async Task Altered_unknown_truncated_nonfinal_and_malformed_uploads_never_open_private_stored_files()
    {
        await using var f=await Flow.Create(fixture);var initial=f.Store.Reads;var before=await Counts(f);var altered=f.Published.ExecutedBytes.ToArray();altered[^1]^=1;
        foreach(var bytes in new[]{altered,f.Published.ExecutedBytes[..^1],PdfFixtures.Create(text:"Synthetic unknown NO AGREEMENT"),f.Run.Candidate.Packet.Bytes,Encoding.ASCII.GetBytes("%PDF-1.7 malformed synthetic NO AGREEMENT")}) {
            var result=await Verify(f,bytes);Assert.Equal(UploadedPdfVerificationStatus.NotRecognized,result.Status);Assert.Null(result.Kind);Assert.False(result.SealIntegrity);Assert.False(result.TimestampIntegrity);
        }
        Assert.Equal(UploadedPdfVerificationStatus.RejectedInput,(await Verify(f,Encoding.ASCII.GetBytes("not a PDF synthetic NO AGREEMENT"))).Status);
        Assert.Equal(initial,f.Store.Reads);Assert.Equal(before,await Counts(f));
    }
    [Theory]
    [InlineData("declared-large")][InlineData("actual-large")][InlineData("short")][InlineData("length-mismatch")][InlineData("unreadable")]
    public async Task Stream_limits_and_declared_lengths_are_enforced_before_database_or_blob_access(string kind)
    {
        await using var db=fixture.Open();var options=new UploadedPdfVerificationOptions {MaximumBytes=32};var clock=new SendDraftWorkflowTests.Clock();
        // A null state is deliberate: rejected input must not invoke publication reads.
        var service=new UploadedPdfVerification(db,null!,options,clock);var bytes=Encoding.ASCII.GetBytes("%PDF-1.7 synthetic NO AGREEMENT extra bytes");
        using var input=new CountingStream(kind=="short" ? bytes[..8] : kind=="length-mismatch" ? bytes[..24] : bytes);if(kind=="unreadable")input.Close();
        var result=await service.VerifyAsync(input,kind=="declared-large" ? 33 : kind=="length-mismatch" ? 20 : null);
        Assert.Equal(UploadedPdfVerificationStatus.RejectedInput,result.Status);Assert.Null(result.Kind);Assert.False(result.SealIntegrity);
        if(kind=="declared-large")Assert.Equal(0,input.Consumed);if(kind=="length-mismatch")Assert.Equal(24,input.Consumed);Assert.True(input.Consumed<=33);Assert.Equal(System.Data.ConnectionState.Closed,db.Database.GetDbConnection().State);
    }
    [Fact]
    public async Task Retention_expiry_is_unrecognized_before_storage_access_and_closed_nonfinal_hashes_grant_nothing()
    {
        await using var f=await Flow.Create(fixture);var reads=f.Store.Reads;f.Clock.Advance(TimeSpan.FromDays(8));
        Assert.Equal(UploadedPdfVerificationStatus.NotRecognized,(await Verify(f,f.Published.ExecutedBytes)).Status);Assert.Equal(reads,f.Store.Reads);
        f.Clock.Advance(TimeSpan.FromDays(-8));await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
        Assert.Equal(UploadedPdfVerificationStatus.NotRecognized,(await Verify(f,f.Published.ExecutedBytes)).Status);Assert.Equal(reads,f.Store.Reads);
    }
    [Theory]
    [InlineData("missing")][InlineData("corrupt")][InlineData("publication")][InlineData("seal")][InlineData("timestamp-root")]
    public async Task Recognized_but_missing_corrupt_or_unverifiable_evidence_never_returns_integrity_success(string kind)
    {
        await using var f=await Flow.Create(fixture);var before=await Counts(f);
        if(kind is "missing" or "corrupt")f.Store.Fault=kind;
        if(kind=="publication") {await using var db=fixture.Open();await db.CompletionPublicationResults.Where(x=>x.EnvelopeId==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FinalDocumentsJson,"{}"));}
        if(kind=="seal") {await using var db=fixture.Open();await db.CompletionSealOutputs.Where(x=>x.EnvelopeId==f.Id && x.Kind==CompletionSealKind.Executed).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.MetadataJson,"{}"));}
        if(kind=="timestamp-root")f.Run.Seal.Options.TsaTrustedRootPaths=[Path.GetFullPath("artifacts/unavailable-synthetic-tsa-root.crt")];
        var result=await Verify(f,f.Published.ExecutedBytes);Assert.Equal(kind is "missing" or "timestamp-root" ? UploadedPdfVerificationStatus.Unavailable : UploadedPdfVerificationStatus.EvidenceMismatch,result.Status);
        Assert.Null(result.Kind);Assert.False(result.SealIntegrity);Assert.False(result.TimestampIntegrity);Assert.Equal(before,await Counts(f));
    }
    [Theory]
    [InlineData("two-envelopes")][InlineData("two-kinds")]
    public async Task Ambiguous_hash_matches_never_disclose_or_inspect_another_envelope(string kind)
    {
        await using var f=await Flow.Create(fixture);var reads=f.Store.Reads;
        await using(var db=fixture.Open()) {
            if(kind=="two-envelopes") {db.Envelopes.Add(CloneMatch(f));await db.SaveChangesAsync();}
            else await db.Envelopes.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CertificateSha256,f.Published.Executed.Sha256));
        }
        var before=await Counts(f);var result=await Verify(f,f.Published.ExecutedBytes);Assert.Equal(UploadedPdfVerificationStatus.NotRecognized,result.Status);Assert.Null(result.Kind);Assert.Equal(reads,f.Store.Reads);Assert.Equal(before,await Counts(f));
    }
    [Theory]
    [InlineData("party")][InlineData("retention")][InlineData("publication")][InlineData("duplicate")][InlineData("deadline")][InlineData("cancel")][InlineData("audit-tail")]
    public async Task Current_scope_is_rechecked_after_async_storage_reads_and_allowed_audit_tails_do_not_rewrite_the_packet(string kind)
    {
        await using var f=await Flow.Create(fixture);var once=false;using var canceled=new CancellationTokenSource();
        f.Store.AfterRead=async ()=> {
            if(once)return;once=true;await using var db=fixture.Open();
            if(kind=="party")await db.Signers.Where(x=>x.EnvelopeId==f.Id && x.Order==2).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FullName,"Changed synthetic party"));
            if(kind=="retention")await db.Envelopes.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PurgeAfter,(DateTimeOffset?)f.Clock.GetUtcNow()));
            if(kind=="publication")await db.CompletionPublicationResults.Where(x=>x.EnvelopeId==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FinalDocumentsJson,"{}"));
            if(kind=="duplicate") {db.Envelopes.Add(CloneMatch(f));await db.SaveChangesAsync();}
            if(kind=="deadline")f.Clock.Advance(TimeSpan.FromMinutes(3));if(kind=="cancel")canceled.Cancel();
            if(kind=="audit-tail") {await using var tx=await db.Database.BeginTransactionAsync();await new AuditWriter(db,f.Clock).AppendAsync(f.Id,"synthetic_readonly_tail",null,null,null,default,"{}",PartyType.System);await tx.CommitAsync();}
        };
        if(kind=="cancel")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Verify(f,f.Published.ExecutedBytes,ct:canceled.Token));
        else {
            var result=await Verify(f,f.Published.ExecutedBytes);
            Assert.Equal(kind=="audit-tail" ? UploadedPdfVerificationStatus.Verified : kind=="duplicate" ? UploadedPdfVerificationStatus.NotRecognized : kind=="deadline" ? UploadedPdfVerificationStatus.Unavailable : UploadedPdfVerificationStatus.EvidenceMismatch,result.Status);
        }
        Assert.True(once);Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);Assert.Empty(f.Run.Storage.Deleted);
    }
    [Fact]
    public async Task Cancelled_upload_and_dirty_callers_do_not_read_or_clear_the_callers_changes()
    {
        await using var db=fixture.Open();var service=new UploadedPdfVerification(db,null!,new(),TimeProvider.System);using var input=new MemoryStream(Encoding.ASCII.GetBytes("%PDF-1.7 synthetic NO AGREEMENT"));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>service.VerifyAsync(input,ct:new CancellationToken(true)));
        var e=new Envelope {SenderEmail="synthetic@example.invalid"};db.Envelopes.Add(e);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>service.VerifyAsync(input));Assert.True(db.ChangeTracker.HasChanges());Assert.Equal(0,input.Position);
    }
    [Fact]
    public void Registration_validates_bounds_and_remains_lazy_for_minimal_hosts_without_database_or_signing_services()
    {
        foreach(var values in new[]{new Dictionary<string,string?> {{"PdfVerification:MaximumBytes","15"}},new() {{"PdfVerification:MaximumBytes","67108865"}},new() {{"PdfVerification:TimeoutSeconds","0"}},new() {{"PdfVerification:TimeoutSeconds","121"}}})
            Assert.Throws<InvalidOperationException>(()=>new ServiceCollection().AddUploadedPdfVerification(new ConfigurationBuilder().AddInMemoryCollection(values).Build()));
        var services=new ServiceCollection();services.AddUploadedPdfVerification(new ConfigurationBuilder().Build());using var provider=services.BuildServiceProvider(new ServiceProviderOptions {ValidateOnBuild=true,ValidateScopes=true});
    }
    private static Envelope CloneMatch(Flow f)=>new() {SenderEmail="synthetic-other@example.invalid",Title="Synthetic other NO AGREEMENT",Status=EnvelopeStatus.Completed,FinalSha256=f.Published.Executed.Sha256.ToArray(),CompletedAt=f.Clock.GetUtcNow(),PurgeAfter=f.Clock.GetUtcNow().AddDays(1)};
    private async Task<UploadedPdfVerificationResult> Verify(Flow f,byte[] bytes,long? length=null,CancellationToken ct=default) {
        await using var db=fixture.Open();var state=new CompletionAccessState(db,f.Run.Collector(db),()=>f.Publication(db),f.Clock);
        using var input=new MemoryStream(bytes,false);var result=await new UploadedPdfVerification(db,state,new(),f.Clock).VerifyAsync(input,length,ct);Assert.False(db.ChangeTracker.HasChanges());return result;
    }
    private async Task<string> Counts(Flow f) {await using var db=fixture.Open();return string.Join(',',await db.AuditEvents.CountAsync(),await db.WorkItems.CountAsync(),await db.EmailOutbox.CountAsync(),await db.AuthTokens.CountAsync(),f.Store.Writes,f.Run.Storage.Created.Count,f.Run.Storage.Deleted.Count,f.Run.Seal.Requests,f.Run.Seal.Certificates.Calls);}
    private sealed class CountingStream(byte[] bytes) : MemoryStream(bytes,false) {
        public int Consumed;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default) {var read=await base.ReadAsync(buffer,ct);Consumed+=read;return read;}
    }
}
