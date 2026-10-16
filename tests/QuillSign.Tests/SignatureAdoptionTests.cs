using System.Buffers.Binary;
using System.Data.Common;
using System.IO.Compression;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Legal;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class SignatureAdoptionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Exact_preview_bytes_statement_and_reported_descriptors_are_adopted_once_without_signing_or_filling()
    {
        await using var run = await Harness.Create(fixture);
        var request = new SignaturePreviewRequest(Mark(),Mark(60),SignatureMethod.Typed,"  Cafe\u0301 synthetic  ","CS");
        var preview = (await run.Prepare(request))!;
        Assert.Equal("Café synthetic",preview.TypedName); Assert.Equal(SignaturePng.Normalize(request.Signature).Bytes,preview.Signature);
        Assert.Equal(SignaturePng.Normalize(request.Initials).Bytes,preview.Initials); Assert.Equal(SignatureAdoptionStatement.Text,preview.Statement);
        run.Clock.Advance(TimeSpan.FromMinutes(1)); var again = (await run.Read(preview.Receipt))!;
        Assert.Equal(preview.Signature,again.Signature); Assert.Equal(preview.ExpiresAt,again.ExpiresAt);
        var results = await Task.WhenAll(Enumerable.Range(0,4).Select(_ => run.Adopt(preview.Receipt)));
        Assert.Single(results,x => x == SignatureAdoptionResult.Adopted); Assert.Equal(3,results.Count(x => x == SignatureAdoptionResult.AlreadyAdopted));
        await using var db = fixture.Open(); var signer = await db.Signers.SingleAsync(x => x.Id == run.Signer.Id);
        Assert.Equal(preview.Id,signer.SignatureAdoptionId); Assert.Equal(SignerStatus.Viewed,signer.Status); Assert.Null(signer.SignedAt);
        Assert.Equal("Synthetic signer",signer.FullName); Assert.Equal("Café synthetic",signer.SignatureTypedName);
        Assert.Equal(SHA256.HashData(preview.Signature),signer.SignatureImageSha256); Assert.Equal(SHA256.HashData(preview.Initials),signer.InitialsImageSha256);
        Assert.Equal(run.Clock.GetUtcNow(),signer.SignatureAdoptedAt); Assert.Equal(SignaturePng.Version,signer.SignatureNormalizationVersion);
        var evidence = Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == run.Envelope.Id).ToArrayAsync());
        Assert.Equal("signature_adopted",evidence.Event); Assert.Equal(PartyType.Signer,evidence.ActorType); Assert.Equal(signer.Id,evidence.ActorId); Assert.Equal(signer.Email,evidence.ActorEmail);
        Assert.Equal(AuditHash.Compute(evidence),evidence.Hash); using var data = JsonDocument.Parse(evidence.DataJson);
        Assert.Equal(SignatureAdoptionStatement.Text,data.RootElement.GetProperty("statement").GetString());
        Assert.Equal(Convert.ToHexStringLower(SignatureAdoptionStatement.Sha256),data.RootElement.GetProperty("statementSha256").GetString());
        Assert.Contains(run.Identity.DocumentHash,evidence.DataJson); Assert.Contains(run.Identity.DisclosureHash,evidence.DataJson); Assert.DoesNotContain(preview.Receipt,evidence.DataJson);
        Assert.Equal(run.Envelope.RowVersion,(await db.Envelopes.SingleAsync(x => x.Id == run.Envelope.Id)).RowVersion);
        Assert.Equal("unchanged",(await db.Fields.SingleAsync(x => x.EnvelopeId == run.Envelope.Id)).Value);
        Assert.Equal(preview.Signature,(await run.Read(preview.Receipt))!.Signature);
    }

    [Fact]
    public async Task Replacement_requires_fresh_revision_preserves_old_assets_and_invalidates_old_or_parallel_preview()
    {
        await using var run = await Harness.Create(fixture); var first = (await run.Prepare())!; var stale = (await run.Prepare())!;
        Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(first.Receipt));
        Assert.Equal(SignatureAdoptionResult.InvalidPreview,await run.Adopt(stale.Receipt)); Assert.Null(await run.Read(stale.Receipt));
        var replacement = (await run.Prepare(new(Mark(80),Mark(100),SignatureMethod.Uploaded)))!;
        Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(replacement.Receipt));
        Assert.Equal(SignatureAdoptionResult.InvalidPreview,await run.Adopt(first.Receipt));
        await using var db = fixture.Open(); Assert.Equal(replacement.Id,(await db.Signers.SingleAsync(x => x.Id == run.Signer.Id)).SignatureAdoptionId);
        var evidence = await db.AuditEvents.Where(x => x.EnvelopeId == run.Envelope.Id).OrderBy(x => x.Sequence).ToArrayAsync(); Assert.Equal(2,evidence.Length);
        Assert.Equal(evidence[0].Hash,evidence[1].PrevHash); Assert.Contains(first.Id.ToString(),evidence[1].DataJson);
        foreach (var blob in run.Blobs.Created) Assert.True((await run.Raw(blob).ExistsAsync()).Value);
    }

    [Theory]
    [InlineData("receipt")][InlineData("tampered")][InlineData("foreign-session")][InlineData("foreign-nonce")][InlineData("foreign-envelope")][InlineData("expired-preview")]
    [InlineData("expired-session")][InlineData("consent")][InlineData("document")][InlineData("disclosure")][InlineData("state")]
    [InlineData("signer-version")][InlineData("order")][InlineData("ack")][InlineData("statement")]
    public async Task Invalid_context_evidence_or_acknowledgment_cannot_read_or_adopt(string kind)
    {
        await using var run = await Harness.Create(fixture); var preview = (await run.Prepare())!; string? receipt = preview.Receipt;
        if (kind == "receipt") receipt = null; if (kind == "tampered") receipt += "broken";
        if (kind == "foreign-session") run.Identity = run.Identity with { SessionExpiresAt = run.Identity.SessionExpiresAt.AddSeconds(-1) };
        if (kind == "foreign-nonce") run.Identity = run.Identity with { SessionId = Guid.NewGuid() };
        if (kind == "foreign-envelope") run.Identity = run.Identity with { EnvelopeId = Guid.NewGuid() };
        if (kind == "expired-preview") run.Clock.Advance(TimeSpan.FromMinutes(10)); if (kind == "expired-session") run.Clock.Advance(TimeSpan.FromHours(2));
        await using (var db = fixture.Open())
        {
            if (kind == "consent") await db.Signers.Where(x => x.Id == run.Signer.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsentAt,(DateTimeOffset?)null));
            if (kind == "signer-version") await db.Signers.Where(x => x.Id == run.Signer.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Role,"changed"));
            if (kind == "document") await db.Envelopes.Where(x => x.Id == run.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SentPdfSha256,SHA256.HashData(new byte[]{99})));
            if (kind == "disclosure") await db.Envelopes.Where(x => x.Id == run.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.ErsdText,"changed"));
            if (kind == "state") await db.Envelopes.Where(x => x.Id == run.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status,EnvelopeStatus.Voided));
            if (kind == "order") { await db.Signers.Where(x => x.Id == run.Signer.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Order,2)); db.Signers.Add(new Signer { EnvelopeId=run.Envelope.Id,Email="prior@example.invalid",FullName="Prior synthetic",Order=1 }); await db.SaveChangesAsync(); }
        }
        Assert.NotEqual(SignatureAdoptionResult.Adopted,await run.Adopt(receipt,kind != "ack",kind == "statement" ? "old" : SignatureAdoptionStatement.Version));
        if (kind is not ("ack" or "statement")) Assert.Null(await run.Read(receipt));
        await using var inspect = fixture.Open(); Assert.Null((await inspect.Signers.SingleAsync(x => x.Id == run.Signer.Id)).SignatureAdoptionId);
        Assert.False(await inspect.AuditEvents.AnyAsync(x => x.EnvelopeId == run.Envelope.Id));
    }

    [Theory]
    [InlineData("missing")][InlineData("tampered")][InlineData("oversize")][InlineData("truncated")]
    public async Task Storage_must_match_saved_exact_hash_before_exposure_or_adoption(string kind)
    {
        await using var run = await Harness.Create(fixture); var preview = (await run.Prepare())!; var blob = run.Blobs.Created[0];
        if (kind == "missing") await run.Raw(blob).DeleteAsync();
        if (kind == "tampered") await run.Raw(blob).UploadAsync(BinaryData.FromBytes(Mark(120)),true);
        if (kind == "oversize") await run.Raw(blob).UploadAsync(BinaryData.FromBytes(new byte[512*1024+1]),true);
        if (kind == "truncated") run.Blobs.WrongLength = true;
        await Assert.ThrowsAnyAsync<Exception>(() => run.Read(preview.Receipt)); await Assert.ThrowsAnyAsync<Exception>(() => run.Adopt(preview.Receipt));
        await using var db = fixture.Open(); Assert.Null((await db.Signers.SingleAsync(x => x.Id == run.Signer.Id)).SignatureAdoptionId);
    }

    [Theory]
    [InlineData("method")][InlineData("name")][InlineData("initials")][InlineData("long")][InlineData("format")][InlineData("unicode")][InlineData("drawn-descriptor")][InlineData("blank-image")]
    public async Task Invalid_input_is_rejected_without_creating_assets(string kind)
    {
        await using var run = await Harness.Create(fixture);
        var request = new SignaturePreviewRequest(Mark(),Mark(60),SignatureMethod.Typed,"Synthetic name","SN");
        request = kind switch { "method" => request with { Method=(SignatureMethod)100 },"name" => request with { TypedName=null },"initials" => request with { TypedInitials=" " },
            "long" => request with { TypedInitials=new string('s',21) },"format" => request with { TypedName="Synthetic\u202ename" },"unicode" => request with { TypedName="bad\ud800" },
            "drawn-descriptor" => request with { Method=SignatureMethod.Drawn },_ => request with { Signature=new byte[]{1,2,3} } };
        if (kind == "blank-image") await Assert.ThrowsAsync<SignatureImageRejectedException>(() => run.Prepare(request));
        else await Assert.ThrowsAnyAsync<ArgumentException>(() => run.Prepare(request));
        Assert.Empty(run.Blobs.Created);
    }

    [Fact]
    public async Task Consent_is_required_before_normalization_storage_or_preview_and_expiry_is_clamped_to_session()
    {
        await using var run = await Harness.Create(fixture);
        await using (var db = fixture.Open()) await db.Signers.Where(x => x.Id == run.Signer.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsentAt,(DateTimeOffset?)null));
        Assert.Null(await run.Prepare(new([],[],SignatureMethod.Drawn))); Assert.Empty(run.Blobs.Created);
        await using (var db = fixture.Open()) await db.Signers.Where(x => x.Id == run.Signer.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsentAt,run.Clock.GetUtcNow()));
        run.Identity = run.Identity with { SessionExpiresAt = run.Clock.GetUtcNow().AddMinutes(3) };
        var preview = (await run.Prepare())!; Assert.Equal(run.Identity.SessionExpiresAt,preview.ExpiresAt);
        run.Clock.Advance(TimeSpan.FromMinutes(2)); Assert.Equal(preview.ExpiresAt,(await run.Read(preview.Receipt))!.ExpiresAt);
        run.Clock.Advance(TimeSpan.FromMinutes(1)); Assert.Null(await run.Read(preview.Receipt));
    }

    [Fact]
    public async Task Envelope_lock_serializes_preview_count_and_bounds_expired_history()
    {
        await using var run = await Harness.Create(fixture);
        var previews = await Task.WhenAll(Enumerable.Range(0,8).Select(async _ => { try { return await run.Prepare(); } catch(InvalidOperationException) { return null; } }));
        Assert.Equal(SignatureAdoption.MaximumActivePreviews,previews.Count(x => x is not null));
        for (var i = SignatureAdoption.MaximumActivePreviews; i < SignatureAdoption.MaximumPreviewsPerSigner; i++)
        { run.Clock.Advance(TimeSpan.FromMinutes(10)); run.Identity = run.Identity with { SessionExpiresAt=run.Clock.GetUtcNow().AddHours(2) }; Assert.NotNull(await run.Prepare()); }
        run.Clock.Advance(TimeSpan.FromMinutes(10)); await Assert.ThrowsAsync<InvalidOperationException>(() => run.Prepare());
    }

    [Theory]
    [InlineData("write")][InlineData("save")][InlineData("expired")][InlineData("commit")]
    public async Task Known_preview_failures_clean_new_objects_but_uncertain_commit_preserves_referenced_assets(string kind)
    {
        await using var run = await Harness.Create(fixture);
        run.Blobs.FailWrite = kind == "write"; run.Faults.FailPreviewSave = kind == "save"; run.Faults.FailCommitNumber = kind == "commit" ? 2 : 0;
        if (kind == "expired") run.Blobs.AfterWrite = () => run.Clock.Advance(TimeSpan.FromMinutes(11));
        if (kind == "expired") Assert.Null(await run.Prepare()); else await Assert.ThrowsAnyAsync<Exception>(() => run.Prepare());
        await using var db = fixture.Open(); Assert.Equal(kind == "commit" ? 1 : 0,await db.SignaturePreviews.CountAsync(x => x.EnvelopeId == run.Envelope.Id));
        Assert.NotEmpty(run.Blobs.Created);
        foreach (var blob in run.Blobs.Created) Assert.Equal(kind == "commit",(await run.Raw(blob).ExistsAsync()).Value);
    }

    [Fact]
    public async Task Audit_failure_rolls_back_adoption_and_preview_use_then_retry_succeeds()
    {
        await using var run = await Harness.Create(fixture); var preview = (await run.Prepare())!; run.Faults.FailAudit = true;
        await Assert.ThrowsAsync<DbUpdateException>(() => run.Adopt(preview.Receipt));
        await using (var db = fixture.Open()) { Assert.Null((await db.Signers.SingleAsync(x => x.Id == run.Signer.Id)).SignatureAdoptionId); Assert.Null((await db.SignaturePreviews.SingleAsync(x => x.Id == preview.Id)).UsedAt); }
        run.Faults.FailAudit = false; Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(preview.Receipt));
    }

    [Fact]
    public async Task Lost_adoption_commit_acknowledgment_replays_without_a_second_event()
    {
        await using var run = await Harness.Create(fixture); var preview = (await run.Prepare())!;
        run.Faults.FailCommitNumber = run.Faults.Commits + 1;
        await Assert.ThrowsAsync<IOException>(() => run.Adopt(preview.Receipt));
        Assert.Equal(SignatureAdoptionResult.AlreadyAdopted,await run.Adopt(preview.Receipt));
        await using var db = fixture.Open(); Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == run.Envelope.Id).ToArrayAsync());
    }

    [Fact]
    public async Task Preview_verifies_written_storage_and_cleans_both_assets_if_readback_fails()
    {
        await using var run = await Harness.Create(fixture); run.Blobs.WrongLength = true;
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Prepare());
        Assert.Equal(2,run.Blobs.Created.Count); foreach(var blob in run.Blobs.Created) Assert.False((await run.Raw(blob).ExistsAsync()).Value);
        await using var db = fixture.Open(); Assert.False(await db.SignaturePreviews.AnyAsync(x => x.EnvelopeId == run.Envelope.Id));
    }

    [Theory]
    [InlineData("normalization")][InlineData("adoption")][InlineData("session")][InlineData("hash")][InlineData("document")]
    public async Task Stored_preview_scope_version_or_hash_corruption_cannot_be_adopted(string kind)
    {
        await using var run = await Harness.Create(fixture); var preview = (await run.Prepare())!;
        await using(var db = fixture.Open())
        {
            var row = db.SignaturePreviews.Where(x => x.Id == preview.Id);
            if(kind == "normalization") await row.ExecuteUpdateAsync(s => s.SetProperty(x => x.NormalizationVersion,"old"));
            if(kind == "adoption") await row.ExecuteUpdateAsync(s => s.SetProperty(x => x.AdoptionVersion,"old"));
            if(kind == "session") await row.ExecuteUpdateAsync(s => s.SetProperty(x => x.SessionSha256,SHA256.HashData(new byte[]{99})));
            if(kind == "hash") await row.ExecuteUpdateAsync(s => s.SetProperty(x => x.SignatureSha256,SHA256.HashData(new byte[]{99})));
            if(kind == "document") await row.ExecuteUpdateAsync(s => s.SetProperty(x => x.DocumentId,Guid.NewGuid()));
        }
        Assert.Null(await run.Read(preview.Receipt)); Assert.Equal(SignatureAdoptionResult.InvalidPreview,await run.Adopt(preview.Receipt));
    }

    [Fact]
    public async Task Saved_preview_contents_cannot_be_changed_by_tracked_entity_updates()
    {
        await using var run = await Harness.Create(fixture); var preview = (await run.Prepare())!;
        await using var db = fixture.Open(); var row = await db.SignaturePreviews.SingleAsync(x => x.Id == preview.Id); row.TypedName="changed";
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task Captured_internal_capabilities_are_exact_object_operation_and_expiry_scoped_and_not_copyable_to_cookies()
    {
        await using var run = await Harness.Create(fixture); _ = await run.Prepare();
        var (cap,blob) = run.Blobs.Writes[0]; using var bytes = new MemoryStream(Mark());
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Blobs.Inner.CopyToAsync(cap,blob,bytes));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Blobs.Inner.DeleteAsync(cap,blob));
        foreach (var wrong in new[] { blob with { ObjectId=Guid.NewGuid() },blob with { EnvelopeId=Guid.NewGuid() },blob with { Kind=DocumentBlobKind.Initials },new DocumentBlob(blob.EnvelopeId,DocumentBlobKind.Normalized,run.Identity.DocumentId),blob with { Kind=DocumentBlobKind.Original } })
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Blobs.Inner.WriteAsync(cap,wrong,bytes,bytes.Length));
        foreach (var wrong in new[] { run.Principal,new ClaimsPrincipal(cap),new ClaimsPrincipal(cap.Identities) })
        { await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Blobs.Inner.WriteAsync(wrong,blob,bytes,bytes.Length)); await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Blobs.Inner.CopyToAsync(wrong,blob,bytes)); await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Blobs.Inner.DeleteAsync(wrong,blob)); }
        cap.AddIdentity(new ClaimsIdentity([],"Other")); await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Blobs.Inner.WriteAsync(cap,blob,bytes,bytes.Length));
        var second = run.Blobs.Writes[1]; run.Clock.Advance(TimeSpan.FromMinutes(2)); await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Blobs.Inner.WriteAsync(second.Principal,second.Blob,bytes,bytes.Length));
    }

    private sealed class Harness : IAsyncDisposable
    {
        private SqlDatabaseFixture fixture = null!;
        public Envelope Envelope = null!; public Signer Signer = null!; public VerifiedSigner Identity = null!;
        public Clock Clock = new(); public Faults Faults = new(); public Blobs Blobs = null!; private readonly EphemeralDataProtectionProvider protection = new();
        public ClaimsPrincipal Principal => SignerAccessConfiguration.Principal(Identity);
        public static async Task<Harness> Create(SqlDatabaseFixture fixture)
        {
            var run = new Harness { fixture=fixture }; var now = run.Clock.GetUtcNow();
            run.Envelope = new Envelope { SenderEmail="sender@example.invalid",Title="Synthetic adoption - NO AGREEMENT",Status=EnvelopeStatus.Sent,SenderVerifiedAt=now,SentAt=now,SentPdfBlob=Guid.NewGuid().ToString("N"),SentPdfSha256=SHA256.HashData(new byte[]{1,2,3}),ExpiresAt=now.AddDays(30) };
            var disclosure = new ElectronicRecordDisclosure(ElectronicRecordDisclosureTests.Policy()).Build(run.Envelope.PublicId,run.Envelope.Title,run.Envelope.SenderEmail);
            run.Envelope.ErsdVersion=disclosure.Version; run.Envelope.ErsdText=disclosure.Text; run.Envelope.ErsdSha256=disclosure.Sha256;
            run.Signer = new Signer { EnvelopeId=run.Envelope.Id,Email="signer@example.invalid",FullName="Synthetic signer",ConsentAt=now,Status=SignerStatus.Viewed };
            await using var db = fixture.Open(); db.AddRange(run.Envelope,run.Signer,new DocumentField { EnvelopeId=run.Envelope.Id,Type=FieldType.Text,X=.1m,Y=.1m,Width=.2m,Height=.1m,Value="unchanged" }); await db.SaveChangesAsync();
            run.Identity=new(run.Envelope.Id,run.Envelope.PublicId,run.Signer.Id,run.Signer.Email,Guid.Parse(run.Envelope.SentPdfBlob),Convert.ToHexStringLower(run.Envelope.SentPdfSha256),Convert.ToHexStringLower(disclosure.Sha256),now.AddHours(2));
            run.Blobs = new(new AzureBlobStore(new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)),1024*1024,true)); return run;
        }
        private QuillSignDbContext Open() { using var db=fixture.Open(); return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(db.Database.GetConnectionString()).AddInterceptors(Faults).Options); }
        private SignatureAdoption Service(QuillSignDbContext db) => new(db,new(db,new(db,Clock),new(),Clock),Blobs,new(protection,Clock),new(db,Clock),Clock);
        public async Task<SignaturePreviewData?> Prepare(SignaturePreviewRequest? request = null) { await using var db=Open(); return await Service(db).PrepareAsync(Principal,Envelope.PublicId,request ?? new(Mark(),Mark(60),SignatureMethod.Drawn)); }
        public async Task<SignaturePreviewData?> Read(string? receipt) { await using var db=Open(); return await Service(db).ReadAsync(Principal,Envelope.PublicId,receipt); }
        public async Task<SignatureAdoptionResult> Adopt(string? receipt,bool ack=true,string? version=SignatureAdoptionStatement.Version) { await using var db=Open(); return await Service(db).AdoptAsync(Principal,Envelope.PublicId,receipt,ack,version,"127.0.0.1","Synthetic test"); }
        public BlobClient Raw(DocumentBlob blob) => new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)).GetBlobContainerClient("normalized").GetBlobClient($"{blob.EnvelopeId:N}/{blob.ObjectId:N}");
        public async ValueTask DisposeAsync() { foreach(var blob in Blobs.Created.Distinct()) await Raw(blob).DeleteIfExistsAsync(); }
    }
    private sealed class Clock : TimeProvider { private DateTimeOffset now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()); public override DateTimeOffset GetUtcNow()=>now; public void Advance(TimeSpan value)=>now+=value; }
    private sealed class Blobs(IBlobStore inner) : IBlobStore
    {
        public IBlobStore Inner => inner; public List<DocumentBlob> Created=[]; public List<(ClaimsPrincipal Principal,DocumentBlob Blob)> Writes=[]; public bool FailWrite,WrongLength; public Action? AfterWrite;
        public async Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,long length,CancellationToken ct=default) { lock(Created) { Created.Add(b); Writes.Add((p,b)); } await inner.WriteAsync(p,b,s,length,ct); AfterWrite?.Invoke(); if(FailWrite)throw new IOException("Synthetic lost write response"); }
        public async Task<long> CopyToAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,CancellationToken ct=default) { var length=await inner.CopyToAsync(p,b,s,ct); return WrongLength ? length+1 : length; }
        public Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct=default)=>inner.DeleteAsync(p,b,ct);
    }
    private sealed class Faults : DbTransactionInterceptor,ISaveChangesInterceptor
    {
        public bool FailPreviewSave,FailAudit; public int FailCommitNumber,Commits;
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default) { if(Interlocked.Increment(ref Commits)==FailCommitNumber)throw new IOException("Synthetic lost commit acknowledgement"); return Task.CompletedTask; }
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> r,CancellationToken ct=default) { if(FailPreviewSave && e.Context!.ChangeTracker.Entries<SignaturePreview>().Any(x=>x.State==EntityState.Added) || FailAudit && e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added))throw new DbUpdateException("Synthetic save failure"); return ValueTask.FromResult(r); }
    }
    private static byte[] Mark(byte shade=20)
    {
        var header=new byte[13]; BinaryPrimitives.WriteInt32BigEndian(header,32); BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(4),16); header[8]=8; header[9]=6;
        using var raw=new MemoryStream(); for(var y=0;y<16;y++) { raw.WriteByte(0); for(var x=0;x<32;x++) raw.Write(x>=8 && x<24 && y>=5 && y<11 ? new byte[]{shade,40,80,255} : new byte[]{255,255,255,0}); }
        using var compressed=new MemoryStream(); using(var z=new ZLibStream(compressed,CompressionLevel.Optimal,true))z.Write(raw.ToArray());
        using var png=new MemoryStream(); png.Write(new byte[]{137,80,78,71,13,10,26,10});
        foreach(var part in new[]{("IHDR",header),("IDAT",compressed.ToArray()),("IEND",Array.Empty<byte>())}) { var type=Encoding.ASCII.GetBytes(part.Item1); var n=new byte[4]; BinaryPrimitives.WriteInt32BigEndian(n,part.Item2.Length); png.Write(n); png.Write(type); png.Write(part.Item2); uint crc=uint.MaxValue; foreach(var value in type.Concat(part.Item2)) { crc^=value; for(var i=0;i<8;i++)crc=(crc&1)!=0 ? crc>>1^0xedb88320 : crc>>1; } BinaryPrimitives.WriteUInt32BigEndian(n,~crc); png.Write(n); }
        return png.ToArray();
    }
}
