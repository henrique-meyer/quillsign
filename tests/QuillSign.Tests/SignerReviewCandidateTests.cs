using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using PigDocument=UglyToad.PdfPig.PdfDocument;

namespace QuillSign.Tests;

public sealed class SignerReviewCandidateTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Explicit_preparation_is_atomic_reusable_exact_and_does_not_sign_or_fill_fields()
    {
        await using var r=await Run.Create(fixture); var before=await r.FieldVersions();
        var prepared=await Task.WhenAll(Enumerable.Range(0,3).Select(_=>r.Prepare())); Assert.All(prepared,p=>Assert.NotNull(p)); Assert.Single(prepared.Select(p=>p!.Id).Distinct());
        var first=prepared[0]!; var data=(await r.Read(first.Receipt))!; Assert.Equal(first.Id,data.Candidate.Id); Assert.Equal(first.PdfSha256,Convert.ToHexStringLower(SHA256.HashData(data.Pdf)));
        Assert.Equal(data.Pdf,(await r.Read(first.Receipt))!.Pdf); Assert.Equal(before,await r.FieldVersions());
        using var pdf=PigDocument.Open(data.Pdf); Assert.Equal(2,pdf.NumberOfPages);
        foreach(var value in new[]{"Sender fixed synthetic","Synthetic signer","Saved review text","2028-02-29",first.ProspectiveDate.ToString("yyyy-MM-dd")})Assert.Contains(value,pdf.GetPage(1).Text);
        Assert.DoesNotContain("Other synthetic",pdf.GetPage(1).Text); Assert.Single(pdf.GetPage(2).GetImages());
        await using var db=fixture.Open(); var row=Assert.Single(await db.SignerReviewCandidates.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ToArrayAsync());
        Assert.Equal(r.H.Identity.DocumentId,row.SourceObjectId); Assert.NotEqual(row.SourceObjectId,row.PdfObjectId); Assert.Equal(data.Pdf.LongLength,row.PdfLength);
        var evidence=Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_review_prepared").ToArrayAsync()); Assert.Equal(AuditHash.Compute(evidence),evidence.Hash); Assert.Equal(r.H.Signer.Id,evidence.ActorId); Assert.Contains("not_user_review_or_finish",evidence.DataJson);
        var signer=await db.Signers.SingleAsync(x=>x.Id==r.H.Signer.Id); Assert.Equal(SignerStatus.Viewed,signer.Status); Assert.Null(signer.SignedAt); Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.SingleAsync(x=>x.Id==r.H.Envelope.Id)).Status);
        Assert.Null((await db.Fields.SingleAsync(x=>x.Id==r.H.Field(FieldType.DateSigned).Id)).Value); Assert.Null(row.UsedAt);
    }
    [Theory]
    [InlineData("sender")][InlineData("mixed")][InlineData("nonce")][InlineData("request")][InlineData("consent")][InlineData("session")]
    [InlineData("document")][InlineData("disclosure")][InlineData("state")][InlineData("signed")][InlineData("prior-signer")]
    public async Task Current_scope_and_session_nonce_gate_candidate_preparation_and_reads(string kind)
    {
        await using var r=await Run.Create(fixture); var first=(await r.Prepare())!; var principal=r.H.Principal; var publicId=r.H.Envelope.PublicId;
        if(kind=="sender")principal=BlobStorageTests.Sender(r.H.Envelope.Id);
        if(kind=="mixed")principal.AddIdentity(new ClaimsIdentity([new(EnvelopeStorageAuthorization.EnvelopeClaim,r.H.Envelope.Id.ToString())],EnvelopeStorageAuthorization.SenderScheme));
        if(kind=="nonce") { r.H.Identity=r.H.Identity with { SessionId=Guid.NewGuid() }; principal=r.H.Principal; }
        if(kind=="request")publicId=Guid.NewGuid().ToString("N");
        if(kind=="session")r.H.Clock.Advance(TimeSpan.FromHours(2));
        await using(var db=fixture.Open()) {
            if(kind=="consent")await db.Signers.Where(x=>x.Id==r.H.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ConsentAt,(DateTimeOffset?)null));
            if(kind=="document")await db.Envelopes.Where(x=>x.Id==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,new byte[32]));
            if(kind=="disclosure")await db.Envelopes.Where(x=>x.Id==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ErsdSha256,new byte[32]));
            if(kind=="state")await db.Envelopes.Where(x=>x.Id==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            if(kind=="signed")await db.Signers.Where(x=>x.Id==r.H.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Signed));
            if(kind=="prior-signer") { await db.Signers.Where(x=>x.Id==r.H.Other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,3)); await db.Signers.Where(x=>x.Id==r.H.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,2)); await db.Signers.Where(x=>x.Id==r.H.Other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,1)); }
        }
        Assert.Null(await r.Read(first.Receipt,principal,publicId));
        if(kind=="nonce") { var second=(await r.Prepare())!; Assert.NotEqual(first.Id,second.Id); }
        else Assert.Null(await r.Prepare(principal,publicId));
    }
    [Theory]
    [InlineData(FieldType.Signature)][InlineData(FieldType.Initials)][InlineData(FieldType.FullName)][InlineData(FieldType.Text)][InlineData(FieldType.Checkbox)][InlineData(FieldType.Date)]
    public async Task Every_required_entry_must_be_saved_before_a_candidate_can_be_prepared(FieldType type)
    {
        await using var r=await Run.Create(fixture); await r.Clear(r.H.Field(type).Id); Assert.Null(await r.Prepare());
        await using var db=fixture.Open(); Assert.False(await db.SignerReviewCandidates.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id));
    }
    [Theory]
    [InlineData("missing")][InlineData("malformed")][InlineData("oversized")][InlineData("expired")][InlineData("used")][InlineData("superseded")]
    public async Task Invalid_expired_or_consumed_receipts_never_return_PDF_bytes(string kind)
    {
        await using var r=await Run.Create(fixture); var first=(await r.Prepare())!; var receipt=kind switch { "missing"=>null,"malformed"=>"bad", "oversized"=>new string('x',8193),_=>first.Receipt };
        if(kind=="expired")r.H.Clock.Advance(TimeSpan.FromMinutes(10));
        await using(var db=fixture.Open()) {
            if(kind=="used")await db.SignerReviewCandidates.Where(x=>x.Id==first.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.UsedAt,r.H.Clock.GetUtcNow()));
            if(kind=="superseded")await db.SignerReviewCandidates.Where(x=>x.Id==first.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SupersededAt,r.H.Clock.GetUtcNow()));
        }
        Assert.Null(await r.Read(receipt));
    }
    [Theory]
    [InlineData("value")][InlineData("revision-only")][InlineData("label")][InlineData("name")][InlineData("geometry")]
    public async Task Any_reviewed_snapshot_change_invalidates_the_old_receipt(string kind)
    {
        await using var r=await Run.Create(fixture); var first=(await r.Prepare())!; var field=r.H.Field(FieldType.Text);
        await using(var db=fixture.Open()) {
            var query=db.Fields.Where(x=>x.Id==field.Id);
            if(kind=="value")await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Value,"Changed review text"));
            if(kind=="revision-only")await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Value,"Saved review text"));
            if(kind=="label")await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Label,"Changed label"));
            if(kind=="geometry")await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.X,.12m));
            if(kind=="name")await db.Signers.Where(x=>x.Id==r.H.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FullName,"Changed signer name"));
        }
        Assert.Null(await r.Read(first.Receipt));
        if(kind!="name") { var second=(await r.Prepare())!; Assert.NotEqual(first.Id,second.Id); Assert.NotEqual(first.SnapshotSha256,second.SnapshotSha256); await using var db=fixture.Open(); Assert.NotNull((await db.SignerReviewCandidates.SingleAsync(x=>x.Id==first.Id)).SupersededAt); }
    }
    [Fact]
    public async Task Replaced_marks_require_each_signature_and_initials_to_be_deliberately_reapplied()
    {
        await using var r=await Run.Create(fixture); var first=(await r.Prepare())!; var replacement=await r.H.Adopt(100);
        Assert.Null(await r.Read(first.Receipt)); Assert.Null(await r.Prepare());
        foreach(var id in r.H.Fields.Where(x=>x.Type is FieldType.Signature or FieldType.Initials).Select(x=>x.Id).Append(r.H.ExtraSignature.Id))await r.ApplyMark(id,replacement.Id);
        var second=(await r.Prepare())!; Assert.NotEqual(first.Id,second.Id); Assert.NotNull(await r.Read(second.Receipt));
    }
    [Fact]
    public async Task Prospective_server_date_expires_at_UTC_midnight_and_never_fills_Date_Signed()
    {
        await using var r=await Run.Create(fixture,midnight:true); var date=DateOnly.FromDateTime(r.H.Clock.GetUtcNow().UtcDateTime);var first=(await r.Prepare())!;
        Assert.Equal(new DateTimeOffset(date.AddDays(1).ToDateTime(TimeOnly.MinValue),TimeSpan.Zero),first.ExpiresAt); Assert.Equal(date,first.ProspectiveDate);
        r.H.Clock.Advance(TimeSpan.FromSeconds(11)); Assert.Null(await r.Read(first.Receipt)); var second=(await r.Prepare())!; Assert.Equal(date.AddDays(1),second.ProspectiveDate);
        using var pdf=PigDocument.Open((await r.Read(second.Receipt))!.Pdf); Assert.Contains(date.AddDays(1).ToString("yyyy-MM-dd",System.Globalization.CultureInfo.InvariantCulture),pdf.GetPage(1).Text);
        await using var db=fixture.Open(); Assert.Null((await db.Fields.SingleAsync(x=>x.Id==r.H.Field(FieldType.DateSigned).Id)).FilledAt); Assert.Null((await db.Signers.SingleAsync(x=>x.Id==r.H.Signer.Id)).SignedAt);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Candidate_expiry_is_bounded_by_current_session_and_envelope(bool envelope)
    {
        await using var r=await Run.Create(fixture); var expiry=DateTimeOffset.FromUnixTimeSeconds(r.H.Clock.GetUtcNow().AddSeconds(20).ToUnixTimeSeconds());
        if(envelope) { await using var db=fixture.Open(); await db.Envelopes.Where(x=>x.Id==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,expiry)); }
        else r.H.Identity=r.H.Identity with { SessionExpiresAt=expiry };
        var first=(await r.Prepare())!; Assert.Equal(expiry,first.ExpiresAt); r.H.Clock.Advance(TimeSpan.FromSeconds(21)); Assert.Null(await r.Read(first.Receipt));
    }
    [Theory]
    [InlineData("write")][InlineData("verify")][InlineData("length")][InlineData("audit")][InlineData("session-during-read")]
    public async Task Known_preparation_failures_leave_no_candidate_evidence_or_readable_orphan(string kind)
    {
        await using var r=await Run.Create(fixture); var before=r.H.Blobs.Created.Count;
        r.H.Blobs.FailReviewWrite=kind=="write"; r.H.Blobs.TamperReviewRead=kind=="verify"; r.H.Blobs.WrongReviewLength=kind=="length"; r.H.Faults.FailAudit=kind=="audit";
        if(kind=="session-during-read")r.H.Blobs.ReadCompleted=b=> { if(b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=r.H.Identity.DocumentId)r.H.Clock.Advance(TimeSpan.FromHours(2)); };
        if(kind=="session-during-read")Assert.Null(await r.Prepare());
        else { var failure=await Record.ExceptionAsync(()=>r.Prepare()); Assert.NotNull(failure); Assert.True(failure is IOException or InvalidDataException or DbUpdateException); }
        await using var db=fixture.Open(); Assert.False(await db.SignerReviewCandidates.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id)); Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_review_prepared"));
        foreach(var blob in r.H.Blobs.Created.Skip(before))Assert.False((await r.H.Raw(blob).ExistsAsync()).Value);
    }
    [Fact]
    public async Task Read_rechecks_expiry_after_storage_and_cannot_extend_the_receipt()
    {
        await using var r=await Run.Create(fixture); var first=(await r.Prepare())!; var before=await r.FieldVersions();
        r.H.Blobs.ReadCompleted=b=> { if(b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=r.H.Identity.DocumentId)r.H.Clock.Advance(TimeSpan.FromMinutes(11)); };
        Assert.Null(await r.Read(first.Receipt)); Assert.Equal(before,await r.FieldVersions());
        await using var db=fixture.Open(); Assert.Equal(first.ExpiresAt,(await db.SignerReviewCandidates.SingleAsync(x=>x.Id==first.Id)).ExpiresAt);
    }
    [Fact]
    public async Task Cleanup_failure_keeps_only_unreachable_bytes_and_preserves_a_fresh_retry()
    {
        await using var r=await Run.Create(fixture); var before=r.H.Blobs.Created.Count; r.H.Blobs.FailReviewDelete=true; r.H.Faults.FailAudit=true;
        await Assert.ThrowsAsync<DbUpdateException>(()=>r.Prepare()); var orphan=Assert.Single(r.H.Blobs.Created.Skip(before));
        Assert.True((await r.H.Raw(orphan).ExistsAsync()).Value); Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(r.H.Principal,orphan));
        await using var db=fixture.Open(); Assert.False(await db.SignerReviewCandidates.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id));
        r.H.Faults.FailAudit=false; r.H.Blobs.FailReviewDelete=false; var retry=(await r.Prepare())!; var row=await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==retry.Id); Assert.NotEqual(orphan.ObjectId,row.PdfObjectId); Assert.NotNull(await r.Read(retry.Receipt));
    }
    [Fact]
    public async Task Lost_commit_acknowledgment_keeps_referenced_bytes_and_recovers_the_same_candidate_once()
    {
        await using var r=await Run.Create(fixture); r.H.Faults.Commits=0; r.H.Faults.FailCommitNumber=1;
        await Assert.ThrowsAsync<IOException>(()=>r.Prepare()); r.H.Faults.FailCommitNumber=0;
        await using var db=fixture.Open(); var row=Assert.Single(await db.SignerReviewCandidates.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ToArrayAsync()); Assert.True((await r.H.Raw(new(row.EnvelopeId,DocumentBlobKind.Normalized,row.PdfObjectId)).ExistsAsync()).Value);
        var retry=(await r.Prepare())!; Assert.Equal(row.Id,retry.Id); Assert.NotNull(await r.Read(retry.Receipt)); Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_review_prepared").ToArrayAsync());
    }
    [Theory]
    [InlineData("missing-pdf")][InlineData("changed-pdf")][InlineData("changed-asset")][InlineData("evidence-missing")][InlineData("evidence-hash")][InlineData("evidence-content")]
    public async Task Missing_or_changed_saved_bytes_or_preparation_evidence_fail_closed(string kind)
    {
        await using var r=await Run.Create(fixture); var first=(await r.Prepare())!;
        await using var db=fixture.Open(); var row=await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==first.Id);
        var raw=r.H.Raw(new(row.EnvelopeId,DocumentBlobKind.Normalized,row.PdfObjectId));
        if(kind=="missing-pdf")await raw.DeleteAsync(); if(kind=="changed-pdf")await raw.UploadAsync(BinaryData.FromBytes(PdfFixtures.Create()),true);
        if(kind=="changed-asset")await r.H.Raw(new(row.EnvelopeId,DocumentBlobKind.Signature,Guid.Parse((await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==r.H.Signer.Id)).SignatureImageBlob!))).UploadAsync(BinaryData.FromBytes(SignatureAdoptionTests.Mark(100)),true);
        if(kind.StartsWith("evidence")) {
            if(kind=="evidence-missing")await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_review_prepared").ExecuteDeleteAsync();
            else if(kind=="evidence-hash")await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_review_prepared").ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Hash,new byte[32]));
            else { var e=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="signer_review_prepared"); e.DataJson="{}"; var hash=AuditHash.Compute(e); await db.AuditEvents.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}").SetProperty(x=>x.Hash,hash)); }
            Assert.Null(await r.Read(first.Receipt));
        } else if(kind=="missing-pdf")await Assert.ThrowsAsync<Azure.RequestFailedException>(()=>r.Read(first.Receipt));
        else await Assert.ThrowsAsync<InvalidDataException>(()=>r.Read(first.Receipt));
    }
    [Fact]
    public async Task Active_session_and_lifetime_caps_preserve_idempotent_reuse()
    {
        await using var r=await Run.Create(fixture); var original=r.H.Identity; var first=(await r.Prepare())!;
        r.H.Identity=original with { SessionId=Guid.NewGuid() }; Assert.NotNull(await r.Prepare()); r.H.Identity=original with { SessionId=Guid.NewGuid() }; await Assert.ThrowsAsync<InvalidOperationException>(()=>r.Prepare());
        r.H.Identity=original; Assert.Equal(first.Id,(await r.Prepare())!.Id);
        await using var db=fixture.Open(); var row=await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==first.Id);
        for(var i=2;i<SignerReviewCandidates.MaximumCandidatesPerSigner;i++) { var p=JsonSerializer.Deserialize<SignerReviewCandidate>(JsonSerializer.Serialize(row))!; p.Id=Guid.NewGuid(); p.PdfObjectId=Guid.NewGuid(); p.RowVersion=[]; p.PreparedAt=p.PreparedAt.AddDays(-1); p.ExpiresAt=p.PreparedAt.AddMinutes(1); p.ProspectiveDate=DateOnly.FromDateTime(p.PreparedAt.UtcDateTime); db.Add(p); }
        await db.SaveChangesAsync(); Assert.Equal(first.Id,(await r.Prepare())!.Id); r.H.Clock.Advance(TimeSpan.FromMinutes(11)); await Assert.ThrowsAsync<InvalidOperationException>(()=>r.Prepare());
    }
    [Fact]
    public async Task Database_constraints_and_immutability_keep_candidate_ownership_and_retention_order_explicit()
    {
        await using var r=await Run.Create(fixture); var first=(await r.Prepare())!; await using var db=fixture.Open(); var row=await db.SignerReviewCandidates.SingleAsync(x=>x.Id==first.Id);
        row.PdfSha256=new byte[32]; await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync()); db.ChangeTracker.Clear();
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.SignerReviewCandidates.Where(x=>x.Id==first.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SignerId,r.H.Other.Id)));
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.SignerReviewCandidates.Where(x=>x.Id==first.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SourceObjectId,row.PdfObjectId)));
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.SignerReviewCandidates.Where(x=>x.Id==first.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,row.PreparedAt.AddMinutes(11))));
        await db.Fields.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ExecuteDeleteAsync();
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.SignaturePreviews.Where(x=>x.Id==row.AdoptionId).ExecuteDeleteAsync());
        await db.SignerReviewCandidates.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ExecuteDeleteAsync(); await db.SignaturePreviews.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ExecuteDeleteAsync(); await db.Signers.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ExecuteDeleteAsync();
    }
    [Fact]
    public async Task Review_capabilities_do_not_broaden_cookie_claim_copy_or_cross_object_operation_authority()
    {
        await using var r=await Run.Create(fixture); var first=(await r.Prepare())!; await using var db=fixture.Open(); var row=await db.SignerReviewCandidates.SingleAsync(x=>x.Id==first.Id); var blob=new DocumentBlob(row.EnvelopeId,DocumentBlobKind.Normalized,row.PdfObjectId);
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(r.H.Principal,blob));
        var cap=Assert.IsAssignableFrom<ClaimsPrincipal>(r.H.Blobs.LastReviewRead); EnvelopeStorageAuthorization.DemandRead(cap,blob);
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.Demand(cap,blob)); Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandDelete(cap,blob));
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(cap,blob with { ObjectId=Guid.NewGuid() }));
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(new ClaimsPrincipal(cap.Identities),blob));
        r.H.Clock.Advance(TimeSpan.FromMinutes(2)); Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(cap,blob));
    }

    internal sealed class Run : IAsyncDisposable
    {
        public SignerFieldTests.Harness H=null!; private SqlDatabaseFixture fixture=null!;
        public IWorkSignals Signals=new CheckpointSignals(); public WorkOptions Work=new() { Enabled=true };
        public static async Task<Run> Create(SqlDatabaseFixture fixture,bool midnight=false)
        {
            // Seed consent and all earlier evidence on the same clock; never rewind a live-date fixture.
            // Storage also checks wall-clock session expiry. Keep the synthetic midnight ahead of it.
            var r=new Run { H=await SignerFieldTests.Harness.Create(fixture,midnight ? new DateTimeOffset(DateTime.UtcNow.Date.AddDays(1),TimeSpan.Zero).AddSeconds(-10) : null),fixture=fixture }; var h=r.H;
            using var input=new MemoryStream(PdfFixtures.Create(text:"Sender fixed synthetic - NO AGREEMENT")); using var normalized=new MemoryStream(); var pages=new PdfValidation(new()).Rewrite(input,normalized); var bytes=normalized.ToArray(); h.Blobs.SourceId=h.Identity.DocumentId;
            await h.Blobs.WriteAsync(BlobStorageTests.Sender(h.Envelope.Id),new(h.Envelope.Id,DocumentBlobKind.Normalized,h.Identity.DocumentId),new MemoryStream(bytes),bytes.Length);
            await using(var db=fixture.Open()) {
                await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,SHA256.HashData(bytes)).SetProperty(x=>x.PageCount,2).SetProperty(x=>x.PageSizesJson,JsonSerializer.Serialize(pages)));
                foreach(var f in h.Fields)await db.Fields.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.X,.1m).SetProperty(x=>x.Y,.2m+(int)f.Type*.1m).SetProperty(x=>x.Width,.7m).SetProperty(x=>x.Height,.08m));
                await db.Fields.Where(x=>x.Id==h.ExtraSignature.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Page,2));
                h.Fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==h.Envelope.Id && x.SignerId==h.Signer.Id && x.Id!=h.ExtraSignature.Id).ToListAsync(); h.ExtraSignature=await db.Fields.AsNoTracking().SingleAsync(x=>x.Id==h.ExtraSignature.Id);
            }
            h.Identity=h.Identity with { DocumentHash=Convert.ToHexStringLower(SHA256.HashData(bytes)) }; var adopted=await h.Adopt();
            foreach(var f in h.Fields.Where(f=>f.Type!=FieldType.DateSigned).Append(h.ExtraSignature)) {
                var mark=f.Type is FieldType.Signature or FieldType.Initials;
                var value=f.Type switch { FieldType.Text=>"Saved review text",FieldType.Checkbox=>"false",FieldType.Date=>"2028-02-29",_=>null };
                Assert.Equal(SignerFieldOutcome.Applied,(await h.Apply(f,value,mark ? adopted.Id : null)).Outcome);
            }
            return r;
        }
        private SignerReviewCandidates Service(QuillSignDbContext db)=>new(db,H.Access(db),H.Adoption(db),new(H.Blobs,new()),new(25*1024*1024,20,200),H.Blobs,new(H.Protection,H.Clock),new(db,H.Clock),H.Clock);
        public async Task<SignerFinishResult> Finish(string? receipt,bool affirm=true,string? version=SignerFinishStatement.Version,ClaimsPrincipal? p=null,string? id=null)
        { await using var db=H.Open(); return await new SignerFinish(db,H.Access(db),Service(db),new(H.Protection,H.Clock),new(db,H.Clock),H.Clock,new(db,()=>Signals,Work,H.Clock)).AcceptAsync(p??H.Principal,id??H.Envelope.PublicId,receipt,affirm,version,"127.0.0.1","Synthetic Finish test"); }
        public async Task<SignerReviewPrepared?> Prepare(ClaimsPrincipal? p=null,string? id=null) { await using var db=H.Open(); return await Service(db).PrepareAsync(p??H.Principal,id??H.Envelope.PublicId,"127.0.0.1","Synthetic review test"); }
        public async Task<SignerReviewData?> Read(string? receipt,ClaimsPrincipal? p=null,string? id=null) { await using var db=H.Open(); return await Service(db).ReadAsync(p??H.Principal,id??H.Envelope.PublicId,receipt); }
        public async Task Clear(Guid id) { await using var db=fixture.Open(); var f=await db.Fields.AsNoTracking().SingleAsync(x=>x.Id==id); Assert.Equal(SignerFieldOutcome.Applied,(await H.Change(new(id,Convert.ToBase64String(f.RowVersion),SignerFieldAction.Clear))).Outcome); }
        public async Task ApplyMark(Guid id,Guid adoption) { await using var db=fixture.Open(); var f=await db.Fields.AsNoTracking().SingleAsync(x=>x.Id==id); Assert.Equal(SignerFieldOutcome.Applied,(await H.Change(new(id,Convert.ToBase64String(f.RowVersion),SignerFieldAction.Apply,AdoptionId:adoption))).Outcome); }
        public async Task<string> FieldVersions() { await using var db=fixture.Open(); return JsonSerializer.Serialize(await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==H.Envelope.Id).OrderBy(x=>x.Id).ToArrayAsync()); }
        public ValueTask DisposeAsync()=>H.DisposeAsync();
    }
    internal sealed class CheckpointSignals : IWorkSignals
    {
        public bool FailHint { get; set; } public bool FailPublish { get; set; } public List<Guid> Hints=[],Published=[];
        public Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct) { if(FailHint)throw new IOException("Synthetic hint failure"); Hints.Add(id); return Task.CompletedTask; }
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct) { if(FailPublish)throw new IOException("Synthetic publish failure"); Published.Add(id); return Task.CompletedTask; }
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>Task.CompletedTask;
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>Task.FromResult<WorkDelivery?>(null);
        public Task DeferAsync(WorkDelivery delivery,TimeSpan delay,CancellationToken ct)=>Task.CompletedTask;
        public Task AcknowledgeAsync(WorkDelivery delivery,CancellationToken ct)=>Task.CompletedTask;
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>Task.FromResult(0);
        public Task VerifyAsync(CancellationToken ct)=>Task.CompletedTask;
    }
}
