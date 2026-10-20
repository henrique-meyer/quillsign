using System.Data.Common;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Sealing;
using QuillSign.Storage;
using SigningRun=QuillSign.Tests.CompletionEvidenceCollectorTests.Run;

namespace QuillSign.Tests;

public sealed class CompletionSealOutputTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_candidate_produces_both_verified_seals_and_reuses_exact_bytes_without_private_keys_after_restart_or_expiry()
    {
        await using var run=await Run.Create(fixture); var before=await run.Counts();
        var pair=(await run.Prepare())!; Assert.NotNull(pair); Assert.Equal(run.Candidate.Id,pair.CandidateId); Assert.Equal(2,run.Seal.Requests);
        Assert.Equal(run.Candidate.Packet.Sha256,pair.Executed.Pdf.SourceSha256);
        Assert.Equal(run.Candidate.Packet.DocumentPages+run.Candidate.Packet.CertificatePages,pair.Executed.Pdf.PageCount);
        Assert.Equal(run.Seal.Seal.RawData,pair.Executed.Pdf.CertificateDer); Assert.Equal(pair.Executed.Pdf.CertificateSha256,pair.Certificate.Pdf.CertificateSha256);
        Assert.Equal(123,pair.Executed.Pdf.SealedAt.Millisecond); Assert.Equal(123,pair.Certificate.Pdf.SealedAt.Millisecond);
        Assert.Equal(SHA256.HashData(pair.Executed.Pdf.Bytes),pair.Executed.Pdf.Sha256); Assert.Equal(SHA256.HashData(pair.Certificate.Pdf.Bytes),pair.Certificate.Pdf.Sha256);
        var after=await run.Counts(); Assert.Equal(before with {Audit=before.Audit+2},after); Assert.Equal(4,run.Storage.Created.Count); Assert.Empty(run.Storage.Deleted);
        var repeated=(await run.Prepare())!; Assert.Equal(pair.Executed.Id,repeated.Executed.Id); Assert.Equal(pair.Certificate.Pdf.Bytes,repeated.Certificate.Pdf.Bytes);
        var calls=run.Seal.Certificates.Calls; run.Seal.Options.Pfx.Path="unavailable"; run.Signing.H.Clock.Advance(TimeSpan.FromDays(31));
        var recovered=(await run.Read())!; Assert.Equal(pair.Executed.Pdf.Bytes,recovered.Executed.Pdf.Bytes); Assert.Equal(pair.Certificate.Pdf.Bytes,recovered.Certificate.Pdf.Bytes);
        Assert.Equal(calls,run.Seal.Certificates.Calls); Assert.Equal(2,run.Seal.Requests);
        Assert.Equal(EnvelopeStatus.Sent,(await run.Signing.Refresh()).Status); Assert.Null(run.Signing.Envelope.FinalBlob); Assert.Null(run.Signing.Envelope.CompletedAt);
        await using(var db=fixture.Open()) {
            var row=await db.CompletionSealOutputs.FirstAsync(x=>x.EnvelopeId==pair.EnvelopeId); row.RecipeVersion="changed";
            await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync()); db.ChangeTracker.Clear();
            row=await db.CompletionSealOutputs.FirstAsync(x=>x.EnvelopeId==pair.EnvelopeId); db.Remove(row); await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());
        }
        using var scope=run.Signing.H.App.Services.CreateScope(); Assert.NotNull(scope.ServiceProvider.GetRequiredService<CompletionSealOutputs>());
        if(Environment.GetEnvironmentVariable("QUILLSIGN_COMPLETION_SEAL_ARTIFACTS") is {Length:>0} path) {
            Directory.CreateDirectory(path); await File.WriteAllBytesAsync(Path.Combine(path,"source.pdf"),(await run.Signing.Collect())!.Source);
            await File.WriteAllBytesAsync(Path.Combine(path,"candidate.pdf"),run.Candidate.Packet.Bytes);
            await File.WriteAllBytesAsync(Path.Combine(path,"executed.pdf"),pair.Executed.Pdf.Bytes); await File.WriteAllBytesAsync(Path.Combine(path,"certificate.pdf"),pair.Certificate.Pdf.Bytes);
            using var authority=new TimestampAuthority(run.Seal.Options,run.Seal.App.Environment,run.Signing.H.Clock);
            foreach(var (name,output) in new[]{("executed",pair.Executed.Pdf),("certificate",pair.Certificate.Pdf)}) {
                using var leaf=X509CertificateLoader.LoadCertificate(output.CertificateDer);
                var inspected=await new SealCms(run.Seal.Options,authority).VerifyAsync(output.Bytes,leaf,output.SealedAt,default);
                var cms=new System.Security.Cryptography.Pkcs.SignedCms(new System.Security.Cryptography.Pkcs.ContentInfo(inspected.SignedBytes),true); cms.Decode(inspected.Cms);
                await File.WriteAllBytesAsync(Path.Combine(path,name+"-signature.der"),inspected.Cms); await File.WriteAllBytesAsync(Path.Combine(path,name+"-signed-bytes.bin"),inspected.SignedBytes);
                await File.WriteAllBytesAsync(Path.Combine(path,name+"-timestamp.der"),inspected.Timestamp.Encoded); await File.WriteAllBytesAsync(Path.Combine(path,name+"-signature-value.bin"),cms.SignerInfos[0].GetSignature());
            }
            await File.WriteAllTextAsync(Path.Combine(path,"tsa-root.crt"),run.Seal.Root.ExportCertificatePem());
        }
    }

    [Fact]
    public async Task A_second_stage_TSA_failure_preserves_the_first_exact_seal_for_retry()
    {
        await using var run=await Run.Create(fixture);
        run.Storage.AfterWrite=b=> {if(b.Kind==DocumentBlobKind.CompletionExecutedSeal)run.Seal.Mode="http"; return Task.CompletedTask;};
        await Assert.ThrowsAsync<SealUnavailableException>(()=>run.Prepare());
        await using var db=fixture.Open(); var first=await db.CompletionSealOutputs.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id);
        Assert.Equal(CompletionSealKind.Executed,first.Kind); Assert.Equal(2,run.Seal.Requests); Assert.Null(await run.Read());
        run.Storage.AfterWrite=null; run.Seal.Mode="valid"; var result=(await run.Prepare())!;
        Assert.Equal(first.Id,result.Executed.Id); Assert.Equal(first.PdfSha256,result.Executed.Pdf.Sha256); Assert.Equal(3,run.Seal.Requests); Assert.Empty(run.Storage.Deleted);
    }

    [Theory]
    [InlineData("lost-write",CompletionSealKind.Executed)][InlineData("lost-commit",CompletionSealKind.Executed)][InlineData("lost-commit",CompletionSealKind.Certificate)]
    public async Task Lost_storage_or_SQL_acknowledgements_reuse_the_exact_saved_outputs(string fault,CompletionSealKind kind)
    {
        await using var run=await Run.Create(fixture); var faults=new Faults {Event=kind==CompletionSealKind.Executed ? "completion_executed_sealed" : "completion_certificate_sealed",LoseCommit=fault=="lost-commit"};
        if(fault=="lost-write")run.Storage.LoseWrite=DocumentBlobKind.CompletionExecutedSeal;
        var result=(await run.Prepare(faults))!; Assert.NotNull(result); Assert.Equal(2,run.Seal.Requests); Assert.Empty(run.Storage.Deleted);
        var replay=(await run.Prepare())!; Assert.Equal(result.Executed.Pdf.Bytes,replay.Executed.Pdf.Bytes); Assert.Equal(result.Certificate.Pdf.Bytes,replay.Certificate.Pdf.Bytes);
        Assert.Equal(2,run.Seal.Requests);
    }

    [Theory]
    [InlineData(CompletionSealKind.Executed)][InlineData(CompletionSealKind.Certificate)]
    public async Task Audit_rollback_deletes_only_new_proven_objects_and_retains_any_prior_stage(CompletionSealKind kind)
    {
        await using var run=await Run.Create(fixture); var faults=new Faults {Event=kind==CompletionSealKind.Executed ? "completion_executed_sealed" : "completion_certificate_sealed",RejectAudit=true};
        await Assert.ThrowsAsync<DbUpdateException>(()=>run.Prepare(faults));
        await using var db=fixture.Open(); var rows=await db.CompletionSealOutputs.AsNoTracking().Where(x=>x.EnvelopeId==run.Signing.Envelope.Id).ToArrayAsync();
        Assert.Equal(kind==CompletionSealKind.Executed ? 0 : 1,rows.Length); Assert.Equal(kind==CompletionSealKind.Executed ? 1 : 2,run.Storage.Deleted.Count);
        var result=(await run.Prepare())!; if(rows.Length==1)Assert.Equal(rows[0].Id,result.Executed.Id); Assert.Equal(3,run.Seal.Requests);
    }

    [Fact]
    public async Task Rotation_between_outputs_cannot_silently_change_the_platform_identity()
    {
        await using var run=await Run.Create(fixture); await using var other=await SealFixtures.Create();
        var path=run.Seal.Options.Pfx.Path; var password=run.Seal.Options.Pfx.Password;
        run.Storage.AfterWrite=b=> {if(b.Kind==DocumentBlobKind.CompletionExecutedSeal) {run.Seal.Options.Pfx.Path=other.Options.Pfx.Path; run.Seal.Options.Pfx.Password=other.Options.Pfx.Password;} return Task.CompletedTask;};
        await Assert.ThrowsAsync<SealUnavailableException>(()=>run.Prepare()); Assert.Equal(1,run.Seal.Requests);
        await using var db=fixture.Open(); var first=await db.CompletionSealOutputs.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id);
        run.Storage.AfterWrite=null; run.Seal.Options.Pfx.Path=path; run.Seal.Options.Pfx.Password=password;
        var result=(await run.Prepare())!; Assert.Equal(first.Id,result.Executed.Id); Assert.Equal(2,run.Seal.Requests);
    }

    [Fact]
    public async Task Concurrent_attempts_publish_one_winner_per_stage_without_deleting_referenced_files()
    {
        await using var run=await Run.Create(fixture); var arrived=0; var gate=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        run.Storage.AfterWrite=async b=> {if(b.Kind!=DocumentBlobKind.CompletionExecutedSeal)return; if(Interlocked.Increment(ref arrived)==2)gate.TrySetResult(); await gate.Task.WaitAsync(TimeSpan.FromSeconds(60));};
        var pairs=await Task.WhenAll(run.Prepare(),run.Prepare()); Assert.All(pairs,x=>Assert.NotNull(x));
        Assert.Equal(pairs[0]!.Executed.Id,pairs[1]!.Executed.Id); Assert.Equal(pairs[0]!.Certificate.Id,pairs[1]!.Certificate.Id);
        Assert.Equal(pairs[0]!.Certificate.Pdf.Bytes,pairs[1]!.Certificate.Pdf.Bytes); Assert.InRange(run.Seal.Requests,3,4);
        await using var db=fixture.Open(); var rows=await db.CompletionSealOutputs.Where(x=>x.EnvelopeId==run.Signing.Envelope.Id).ToArrayAsync(); Assert.Equal(2,rows.Length);
        Assert.Equal(2,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id && (x.Event=="completion_executed_sealed" || x.Event=="completion_certificate_sealed")));
        Assert.DoesNotContain(run.Storage.Deleted,b=>rows.Any(x=>x.PdfObjectId==b.ObjectId || x.SourceObjectId==b.ObjectId)); Assert.NotEmpty(run.Storage.Deleted);
    }

    [Fact]
    public async Task Missing_corrupt_size_mismatched_or_oversized_saved_objects_never_trigger_resealing()
    {
        await using var run=await Run.Create(fixture); var original=(await run.Prepare())!; var before=await run.Counts(); var written=run.Storage.Created.Count;
        foreach(var kind in new[]{DocumentBlobKind.CompletionExecutedSeal,DocumentBlobKind.CompletionCertificateSource,DocumentBlobKind.CompletionCertificateSeal})
        foreach(var failure in new[]{"missing","corrupt","length","oversize"}) {
            run.Storage.ReadKind=kind; run.Storage.ReadFault=failure;
            if(failure=="missing")await Assert.ThrowsAsync<IOException>(()=>run.Prepare()); else await Assert.ThrowsAsync<InvalidDataException>(()=>run.Prepare());
            Assert.Equal(2,run.Seal.Requests); Assert.Equal(written,run.Storage.Created.Count); Assert.Empty(run.Storage.Deleted); Assert.Equal(before,await run.Counts());
        }
        run.Storage.ReadKind=null; run.Storage.ReadFault=null; Assert.Equal(original.Certificate.Pdf.Bytes,(await run.Read())!.Certificate.Pdf.Bytes);
    }

    [Fact]
    public async Task Coherently_rehashed_storage_metadata_and_audit_cannot_substitute_a_broken_CMS_signature()
    {
        await using var run=await Run.Create(fixture); var pair=(await run.Prepare())!;
        var verified=await new SealCms(run.Seal.Options,run.Seal.Timestamps).VerifyAsync(pair.Executed.Pdf.Bytes,run.Seal.Seal,pair.Executed.Pdf.SealedAt,default);
        var cms=new System.Security.Cryptography.Pkcs.SignedCms(new System.Security.Cryptography.Pkcs.ContentInfo(verified.SignedBytes),true); cms.Decode(verified.Cms);
        var changed=pair.Executed.Pdf.Bytes.ToArray(); var needle=Convert.ToHexString(cms.SignerInfos[0].GetSignature());
        var position=Encoding.ASCII.GetString(changed).IndexOf(needle,StringComparison.OrdinalIgnoreCase); Assert.True(position>0); changed[position]=changed[position]=='0' ? (byte)'1' : (byte)'0';
        await using(var db=fixture.Open()) {
            var row=await db.CompletionSealOutputs.AsNoTracking().SingleAsync(x=>x.Id==pair.Executed.Id); row.PdfSha256=SHA256.HashData(changed);
            row.RecipeSha256=(byte[])typeof(CompletionSealOutputs).GetMethod("Recipe",BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,[row])!;
            var data=(string)typeof(CompletionSealOutputs).GetMethod("Evidence",BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,[row])!;
            await db.CompletionSealOutputs.Where(x=>x.Id==row.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PdfSha256,row.PdfSha256).SetProperty(x=>x.RecipeSha256,row.RecipeSha256));
            var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==row.EnvelopeId).OrderBy(x=>x.Sequence).ToArrayAsync();
            for(var i=0;i<events.Length;i++) {
                var entry=events[i]; if(entry.Event=="completion_executed_sealed")entry.DataJson=data;
                entry.PrevHash=i==0 ? null : events[i-1].Hash; entry.Hash=AuditHash.Compute(entry); byte[]? previous=entry.PrevHash;
                await db.AuditEvents.Where(x=>x.Id==entry.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,entry.DataJson).SetProperty(x=>x.PrevHash,previous).SetProperty(x=>x.Hash,entry.Hash));
            }
        }
        run.Storage.Override=async (p,b,s,ct)=> {EnvelopeStorageAuthorization.DemandRead(p,b); if(b.Kind!=DocumentBlobKind.CompletionExecutedSeal)return await run.Signing.H.Blobs.Inner.CopyToAsync(p,b,s,ct); await s.WriteAsync(changed,ct); return changed.Length;};
        await Assert.ThrowsAsync<SealUnavailableException>(()=>run.Read()); Assert.Equal(2,run.Seal.Requests); Assert.Empty(run.Storage.Deleted);
    }

    [Theory]
    [InlineData("void")][InlineData("predecessor")][InlineData("audit")]
    public async Task Rechecks_detect_state_and_predecessor_changes_but_allow_verified_audit_tails(string change)
    {
        await using var run=await Run.Create(fixture); var original=(await run.Prepare())!; var once=false;
        run.Storage.AfterRead=async b=> {
            if(once || b.Kind!=(change=="predecessor" ? DocumentBlobKind.CompletionCertificateSource : DocumentBlobKind.CompletionExecutedSeal))return; once=true;
            await using var db=fixture.Open();
            if(change=="void")await db.Envelopes.Where(x=>x.Id==run.Signing.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            else if(change=="predecessor")await db.CompletionSealOutputs.Where(x=>x.Id==original.Executed.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.RecipeVersion,"changed"));
            else {await using var transaction=await db.Database.BeginTransactionAsync(); await new AuditWriter(db,run.Signing.H.Clock).AppendAsync(run.Signing.Envelope.Id,"synthetic_tail_during_seal_read",null,null,null,default,"{}",PartyType.System); await transaction.CommitAsync();}
        };
        if(change=="audit")Assert.Equal(original.Certificate.Pdf.Bytes,(await run.Read())!.Certificate.Pdf.Bytes);
        else await Assert.ThrowsAsync<QuillSign.Documents.DocumentConflictException>(()=>run.Read());
        Assert.True(once); Assert.Equal(2,run.Seal.Requests); Assert.Empty(run.Storage.Deleted);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Cancellation_before_commit_cleans_owned_bytes_and_after_commit_preserves_the_saved_pair(bool afterCommit)
    {
        await using var run=await Run.Create(fixture); using var cancellation=new CancellationTokenSource(); var faults=new Faults {Event="completion_certificate_sealed",CancelAfterCommit=afterCommit ? cancellation : null};
        if(!afterCommit)run.Storage.AfterWrite=b=> {if(b.Kind==DocumentBlobKind.CompletionExecutedSeal)cancellation.Cancel(); return Task.CompletedTask;};
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>run.Prepare(faults,cancellation.Token));
        Assert.Equal(afterCommit ? 0 : 1,run.Storage.Deleted.Count); run.Storage.AfterWrite=null;
        await using(var db=fixture.Open())Assert.Equal(afterCommit ? 2 : 0,await db.CompletionSealOutputs.CountAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id));
        Assert.NotNull(await run.Prepare()); Assert.Equal(afterCommit ? 2 : 3,run.Seal.Requests);
    }

    [Fact]
    public async Task An_unresolved_commit_never_deletes_possible_references_and_retries_from_authoritative_state()
    {
        await using var run=await Run.Create(fixture);
        await Assert.ThrowsAsync<IOException>(()=>run.Prepare(new() {Event="completion_executed_sealed",RejectCommit=true})); Assert.Empty(run.Storage.Deleted);
        await using(var db=fixture.Open())Assert.False(await db.CompletionSealOutputs.AnyAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id));
        Assert.NotNull(await run.Prepare()); Assert.Equal(3,run.Seal.Requests); Assert.Empty(run.Storage.Deleted); Assert.Equal(5,run.Storage.Created.Count);
    }

    [Fact]
    public async Task Restricted_runtime_can_create_and_verify_seals_but_cannot_mutate_rows_or_use_public_storage_authority()
    {
        await using var run=await Run.Create(fixture); await using var db=fixture.Open(); await db.Database.OpenConnectionAsync();
        var connection=(SqlConnection)db.Database.GetDbConnection(); await using var command=connection.CreateCommand();
        command.CommandText="IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN"; await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection); command.CommandText="EXECUTE AS USER = 'app_runtime'"; await command.ExecuteNonQueryAsync();
        CompletionSealPair pair;
        try {
            pair=(await run.Service(db).PrepareAsync(run.Signing.Envelope.Id))!; Assert.NotNull(pair);
            command.CommandText="UPDATE [CompletionSealOutputs] SET [RecipeVersion]='forbidden'";
            Assert.Equal(229,(await Assert.ThrowsAsync<SqlException>(async ()=>await command.ExecuteNonQueryAsync())).Number);
            command.CommandText="DELETE FROM [CompletionSealOutputs]";
            Assert.Equal(229,(await Assert.ThrowsAsync<SqlException>(async ()=>await command.ExecuteNonQueryAsync())).Number);
            await DatabaseCommands.VerifyRuntimeAsync(db);
        } finally {command.CommandText="REVERT"; await command.ExecuteNonQueryAsync();}
        foreach(var blob in run.Storage.Created.Where(x=>x.Kind!=DocumentBlobKind.CompletionCandidate)) {
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(run.Signing.Sender,blob));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.Demand(run.Signing.Sender,blob));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandDelete(run.Signing.Sender,blob));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(run.Signing.LastSigner,blob));
            using var output=new MemoryStream(); await Assert.ThrowsAsync<Azure.RequestFailedException>(()=>run.Signing.H.Blobs.Inner.CopyToAsync(run.Signing.Sender,blob with {Kind=DocumentBlobKind.Normalized},output));
            foreach(var op in Enum.GetValues<Operation>()) {
                var p=Capability(blob,op,run.Signing.H.Clock);
                void Demand(DocumentBlob target,Operation requested) {if(requested==Operation.Read)EnvelopeStorageAuthorization.DemandRead(p,target);else if(requested==Operation.Write)EnvelopeStorageAuthorization.Demand(p,target);else EnvelopeStorageAuthorization.DemandDelete(p,target);}
                Demand(blob,op); foreach(var other in Enum.GetValues<Operation>().Where(x=>x!=op))Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob,other));
                Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob with {EnvelopeId=Guid.NewGuid()},op)); Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob with {ObjectId=Guid.NewGuid()},op));
                Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob with {Kind=DocumentBlobKind.Normalized},op));
                p.AddIdentity(new ClaimsIdentity([new Claim(EnvelopeStorageAuthorization.EnvelopeClaim,blob.EnvelopeId.ToString())],EnvelopeStorageAuthorization.SenderScheme));
                Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob,op));
            }
        }
        var target=run.Storage.Created.First(x=>x.Kind==DocumentBlobKind.CompletionExecutedSeal); var expired=Capability(target,Operation.Read,run.Signing.H.Clock);
        run.Signing.H.Clock.Advance(TimeSpan.FromMinutes(3)); Assert.Throws<IOException>(()=>EnvelopeStorageAuthorization.DemandRead(expired,target));
        Assert.Equal(pair.Certificate.Pdf.Bytes,(await run.Read())!.Certificate.Pdf.Bytes); Assert.Equal(2,run.Seal.Requests);
    }

    [Fact]
    public async Task Late_processing_of_the_last_on_time_Finish_can_seal_and_publish_the_exact_completed_pair()
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false,publishLast:false);
        run.Signing.H.Clock.Advance(TimeSpan.FromHours(2));run.Seal.Time.Advance(TimeSpan.FromHours(2));Assert.True(await run.Signing.H.Once());
        await using(var prepare=fixture.Open())Assert.NotNull(await run.Candidates(prepare).PrepareAsync(run.Signing.Envelope.Id));
        Assert.NotNull(await run.Prepare());await using var db=fixture.Open();var final=new CompletionDownloadTests.FinalStore(run.Signing.H.Clock);
        var publication=new CompletionPublication(db,run.Candidates(db),run.Service(db),run.Collector(db),final,new(db,run.Signing.H.Clock),run.Signing.H.Clock,
            new() {DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},run.Seal.App.Environment);
        var saved=await publication.PublishAsync(run.Signing.Envelope.Id);Assert.NotNull(saved);Assert.Equal(saved.ExecutedBytes,(await publication.ReadAsync(run.Signing.Envelope.Id))!.ExecutedBytes);
        Assert.True(saved.CompletedAt>run.Signing.Envelope.ExpiresAt);Assert.Equal(2,run.Seal.Requests);Assert.Equal(2,final.Writes);
    }

    internal sealed class Run : IAsyncDisposable
    {
        public SigningRun Signing=null!; public SealFixtures Seal=null!; public Probe Storage=null!; public CompletionCandidateData Candidate=null!;
        private SqlDatabaseFixture fixture=null!; private TimestampAuthority timestamps=null!; private PlatformPdfSeal engine=null!; private SealCms verifier=null!;
        public static async Task<Run> Create(SqlDatabaseFixture fixture,bool prepareCandidate=true,bool publishLast=true,bool senderAlsoSigns=false,int? uploadRetentionDays=null,TimeSpan? afterUploadDelay=null,DateTimeOffset? initialTime=null,string? mailbox=null,Func<SigningRun,int,Task<bool>>? signerOverride=null,Func<SendDraftWorkflowTests.Harness,string,Task>? requestSender=null,Func<int,string>? signerMailbox=null,string? recipientMailbox=null,bool demo=true)
        {
            var r=new Run {fixture=fixture,Signing=await SigningRun.Create(fixture,demo:demo,publishLast:publishLast,senderAlsoSigns:senderAlsoSigns,uploadRetentionDays:uploadRetentionDays,afterUploadDelay:afterUploadDelay,initialTime:initialTime,mailbox:mailbox,signerOverride:signerOverride,requestSender:requestSender,signerMailbox:signerMailbox,recipientMailbox:recipientMailbox),Seal=await SealFixtures.Create(initialTime:initialTime)};
            var latest=new[]{r.Signing.H.Clock.GetUtcNow(),r.Seal.Time.GetUtcNow()}.Max();
            r.Signing.H.Clock.Advance(latest-r.Signing.H.Clock.GetUtcNow()+TimeSpan.FromMilliseconds(123)); r.Seal.Time.Advance(latest-r.Seal.Time.GetUtcNow()+TimeSpan.FromMilliseconds(123));
            r.timestamps=new(r.Seal.Options,r.Seal.App.Environment,r.Signing.H.Clock); r.engine=new(r.Seal.Options,r.Seal.Certificates,r.timestamps,r.Seal.App.Environment,r.Signing.H.Clock);
            r.verifier=new(r.Seal.Options,r.timestamps); r.Storage=new(r.Signing.H.Blobs.Inner,r.Signing.H.Clock);
            await using var db=fixture.Open(); if(prepareCandidate) {r.Candidate=(await r.Candidates(db).PrepareAsync(r.Signing.Envelope.Id))!; Assert.NotNull(r.Candidate);} return r;
        }
        public CompletionEvidenceCollector Collector(QuillSignDbContext db)=>new(db,new(db,Signing.H.Clock),new(Storage,Signing.H.Clock),Storage,Signing.H.Clock);
        public CompletionCandidates Candidates(QuillSignDbContext db,CompletionCommitScope? scope=null)=>new(db,Collector(db),new(),Storage,new(db,Signing.H.Clock),Signing.H.Clock,scope);
        public CompletionSealOutputs Service(QuillSignDbContext db,CompletionCommitScope? scope=null)=>new(db,Candidates(db,scope),Collector(db),new(),engine,verifier,Storage,new(db,Signing.H.Clock),Signing.H.Clock,scope);
        public async Task<CompletionSealPair?> Prepare(Faults? faults=null,CancellationToken ct=default)
        {
            await using var baseline=fixture.Open(); var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString());
            if(faults is not null)options.AddInterceptors(faults); await using var db=new QuillSignDbContext(options.Options); return await Service(db).PrepareAsync(Signing.Envelope.Id,ct);
        }
        public async Task<CompletionSealPair?> Read() {await using var db=fixture.Open(); return await Service(db).ReadAsync(Signing.Envelope.Id);}
        public sealed record CountsData(int Audit,int Work,int Mail,int Sent);
        public async Task<CountsData> Counts() {await using var db=fixture.Open(); var id=Signing.Envelope.Id; return new(await db.AuditEvents.CountAsync(x=>x.EnvelopeId==id),await db.WorkItems.CountAsync(x=>x.EnvelopeId==id),await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==id),Signing.H.Sender.Calls);}
        public async ValueTask DisposeAsync() {timestamps.Dispose(); await Storage.DisposeAsync(); await Seal.DisposeAsync(); await Signing.DisposeAsync();}
    }
    internal sealed class Faults : DbTransactionInterceptor,ISaveChangesInterceptor
    {
        public string Event=""; public bool LoseCommit,RejectAudit,RejectCommit; public CancellationTokenSource? CancelAfterCommit; public Action? BeforeAudit; private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> result,CancellationToken ct=default)
        {if(e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && x.Entity.Event==Event)) {BeforeAudit?.Invoke();if(RejectAudit)throw new DbUpdateException("Synthetic seal audit rollback"); armed=true;} return ValueTask.FromResult(result);}
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default)
        {
            if(armed && CancelAfterCommit is not null) {CancelAfterCommit.Cancel(); CancelAfterCommit=null; ct.ThrowIfCancellationRequested();}
            if(armed && LoseCommit) {LoseCommit=false; throw new IOException("Synthetic lost seal commit acknowledgement");} return Task.CompletedTask;
        }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,TransactionEventData e,InterceptionResult result,CancellationToken ct=default)
        {if(armed && RejectCommit) {RejectCommit=false; throw new IOException("Synthetic unresolved seal commit");} return ValueTask.FromResult(result);}
    }
    private enum Operation { Read,Write,Delete }
    private static ClaimsPrincipal Capability(DocumentBlob blob,Operation op,TimeProvider time)
    {
        var assembly=typeof(IBlobStore).Assembly; var name=blob.Kind==DocumentBlobKind.CompletionCandidate ? "CompletionCandidateCapability" : "CompletionSealCapability";
        var type=assembly.GetType("QuillSign.Storage."+name,true)!; var operation=Enum.Parse(assembly.GetType("QuillSign.Storage.AssetOperation",true)!,op.ToString());
        return (ClaimsPrincipal)type.GetMethod("Create",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[blob,operation,time])!;
    }
    internal sealed class Probe(IBlobStore inner,TimeProvider time) : IBlobStore,IAsyncDisposable
    {
        public List<DocumentBlob> Created=[],Deleted=[]; public DocumentBlobKind? LoseWrite,ReadKind; public string? ReadFault; public Func<DocumentBlob,Task>? AfterWrite,AfterRead;
        public Func<ClaimsPrincipal,DocumentBlob,Stream,CancellationToken,Task<long>>? Override;
        public async Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,long n,CancellationToken ct)
        {
            EnvelopeStorageAuthorization.Demand(p,b); lock(Created)Created.Add(b); await inner.WriteAsync(p,b,s,n,ct); if(AfterWrite is not null)await AfterWrite(b);
            if(LoseWrite==b.Kind) {LoseWrite=null; throw new IOException("Synthetic lost seal upload acknowledgement");}
        }
        public async Task<long> CopyToAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,CancellationToken ct)
        {
            EnvelopeStorageAuthorization.DemandRead(p,b); if(Override is not null)return await Override(p,b,s,ct);
            if(ReadKind==b.Kind) {
                if(ReadFault=="missing")throw new Azure.RequestFailedException(404,"Synthetic missing seal object");
                if(ReadFault=="corrupt") {var bytes=PdfFixtures.Create(text:"Wrong synthetic seal source"); await s.WriteAsync(bytes,ct); return bytes.Length;}
                if(ReadFault=="oversize") {var block=new byte[1024*1024]; for(var i=0;i<65;i++)await s.WriteAsync(block,ct); return 65L*block.Length;}
            }
            var n=await inner.CopyToAsync(p,b,s,ct); if(AfterRead is not null)await AfterRead(b); return ReadKind==b.Kind && ReadFault=="length" ? n-1 : n;
        }
        public async Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct) {EnvelopeStorageAuthorization.DemandDelete(p,b); lock(Deleted)Deleted.Add(b); await inner.DeleteAsync(p,b,ct);}
        public async ValueTask DisposeAsync() {foreach(var b in Created.Distinct())await inner.DeleteAsync(Capability(b,Operation.Delete,time),b);}
    }
}
