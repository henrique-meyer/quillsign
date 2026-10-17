using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
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

public sealed class SignerFieldTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Snapshot_is_owned_read_only_and_each_mark_application_is_explicit_atomic_and_idempotent()
    {
        await using var run=await Harness.Create(fixture); var adoption=await run.Adopt(); var initial=(await run.Snapshot())!;
        Assert.Equal(8,initial.Fields.Count); Assert.All(initial.Fields,x=>Assert.False(x.Filled)); Assert.Equal(adoption.Id,initial.AdoptionId);
        var field=initial.Fields.Single(x=>x.Id==run.Field(FieldType.Signature).Id);
        var results=await Task.WhenAll(Enumerable.Range(0,4).Select(_=>run.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:adoption.Id))));
        Assert.Single(results,x=>x.Outcome==SignerFieldOutcome.Applied); Assert.Equal(3,results.Count(x=>x.Outcome==SignerFieldOutcome.AlreadyApplied));
        var after=(await run.Snapshot())!; Assert.Single(after.Fields,x=>x.Filled); Assert.Null(after.Fields.Single(x=>x.Id==field.Id).Value);
        await using var db=fixture.Open(); var saved=await db.Fields.SingleAsync(x=>x.Id==field.Id); var signer=await db.Signers.SingleAsync(x=>x.Id==run.Signer.Id);
        Assert.Equal(signer.SignatureAdoptionId,saved.SignatureAdoptionId); Assert.Equal(signer.SignatureImageBlob,saved.Value); Assert.Equal(signer.SignatureImageSha256,saved.ImageSha256);
        Assert.Equal(PartyType.Signer,saved.FilledBy); Assert.NotNull(saved.FilledAt); Assert.Null(signer.SignedAt); Assert.Equal(SignerStatus.Viewed,signer.Status);
        Assert.Equal(run.Envelope.RowVersion,(await db.Envelopes.SingleAsync(x=>x.Id==run.Envelope.Id)).RowVersion);
        var evidence=Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="field_filled").ToArrayAsync());
        Assert.Equal(PartyType.Signer,evidence.ActorType); Assert.Equal(run.Signer.Id,evidence.ActorId); Assert.Equal(AuditHash.Compute(evidence),evidence.Hash);
        Assert.Contains(run.Identity.DocumentHash,evidence.DataJson); Assert.Contains(run.Identity.DisclosureHash,evidence.DataJson); Assert.Contains(adoption.Id.ToString(),evidence.DataJson);
        Assert.Contains(Convert.ToHexStringLower(saved.ImageSha256!),evidence.DataJson);
        Assert.Null((await db.Fields.SingleAsync(x=>x.Id==run.ExtraSignature.Id)).Value); Assert.Equal("sender fixed",(await db.Fields.SingleAsync(x=>x.Id==run.Unassigned.Id)).Value);
    }

    [Fact]
    public async Task Current_assets_survive_preview_expiry_and_new_session_without_refreshing_preview_or_mutating_fields()
    {
        await using var run=await Harness.Create(fixture); var preview=await run.Adopt(); run.Clock.Advance(TimeSpan.FromMinutes(11));
        run.Identity=run.Identity with { SessionId=Guid.NewGuid() }; var assets=(await run.Current())!;
        Assert.Equal(preview.Id,assets.Id); Assert.Equal(preview.Signature,assets.Signature); Assert.Equal(preview.Initials,assets.Initials);
        await using var db=fixture.Open(); Assert.Equal(preview.ExpiresAt,(await db.SignaturePreviews.SingleAsync(x=>x.Id==preview.Id)).ExpiresAt);
        Assert.All((await run.Snapshot())!.Fields,x=>Assert.False(x.Filled));
        var field=run.Field(FieldType.Initials); Assert.Equal(SignerFieldOutcome.Applied,(await run.Apply(field,adoption:preview.Id)).Outcome);
        var saved=await db.Fields.AsNoTracking().SingleAsync(x=>x.Id==field.Id); Assert.Equal(SHA256.HashData(preview.Initials),saved.ImageSha256);
    }

    [Fact]
    public async Task Current_asset_evidence_matches_adoption_ID_when_a_real_clock_advances_between_adoption_and_audit()
    {
        await using var run=await Harness.Create(fixture); run.Clock.TickOnRead=true; var preview=await run.Adopt();
        await using var db=fixture.Open(); var signer=await db.Signers.SingleAsync(x=>x.Id==run.Signer.Id); var evidence=await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==run.Envelope.Id);
        Assert.NotEqual(signer.SignatureAdoptedAt,evidence.At); Assert.Equal(preview.Id,(await run.Current())!.Id);
    }

    [Fact]
    public async Task Replacement_makes_applied_marks_stale_until_each_field_is_deliberately_reapplied_or_cleared()
    {
        await using var run=await Harness.Create(fixture); var first=await run.Adopt(); var field=run.Field(FieldType.Signature);
        var applied=await run.Apply(field,adoption:first.Id); Assert.Equal(SignerFieldOutcome.Applied,applied.Outcome);
        var second=await run.Adopt(80); var snapshot=(await run.Snapshot())!; var stale=snapshot.Fields.Single(x=>x.Id==field.Id);
        Assert.True(stale.Stale); Assert.False(stale.Filled); Assert.Equal(first.Id,stale.AdoptionId);
        Assert.Equal(SignerFieldOutcome.InvalidAdoption,(await run.Change(new(field.Id,stale.Version,SignerFieldAction.Apply,AdoptionId:first.Id))).Outcome);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(field.Id,stale.Version,SignerFieldAction.Apply,AdoptionId:second.Id))).Outcome);
        var current=(await run.Snapshot())!.Fields.Single(x=>x.Id==field.Id); Assert.False(current.Stale); Assert.True(current.Filled); Assert.Equal(second.Id,current.AdoptionId);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(field.Id,current.Version,SignerFieldAction.Clear))).Outcome);
        Assert.Equal(SignerFieldOutcome.AlreadyApplied,(await run.Change(new(field.Id,current.Version,SignerFieldAction.Clear))).Outcome);
        await using var db=fixture.Open(); var cleared=await db.Fields.SingleAsync(x=>x.Id==field.Id); Assert.Null(cleared.Value); Assert.Null(cleared.ImageSha256); Assert.Null(cleared.SignatureAdoptionId); Assert.Null(cleared.FilledAt);
        Assert.Equal(2,await db.SignaturePreviews.CountAsync(x=>x.EnvelopeId==run.Envelope.Id && x.UsedAt!=null));
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="field_cleared").ToArrayAsync());
    }

    [Theory]
    [InlineData("consent")][InlineData("session")][InlineData("sender")][InlineData("mixed")][InlineData("document")][InlineData("disclosure")]
    [InlineData("state")][InlineData("signed")][InlineData("prior-signer")][InlineData("foreign-field")][InlineData("unassigned-field")]
    public async Task Invalid_scope_or_ownership_cannot_apply_fields_or_expose_another_signers_data(string kind)
    {
        await using var run=await Harness.Create(fixture); var preview=await run.Adopt(); var field=run.Field(FieldType.Signature); var principal=run.Principal;
        await using(var db=fixture.Open())
        {
            if(kind=="consent")await db.Signers.Where(x=>x.Id==run.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ConsentAt,(DateTimeOffset?)null));
            if(kind=="session")run.Clock.Advance(TimeSpan.FromHours(2));
            if(kind=="sender")principal=BlobStorageTests.Sender(run.Envelope.Id);
            if(kind=="mixed")principal.AddIdentity(new ClaimsIdentity([],"Other"));
            if(kind=="document")await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,SHA256.HashData(new byte[]{99})));
            if(kind=="disclosure")await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ErsdText,"changed"));
            if(kind=="state")await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            if(kind=="signed")await db.Signers.Where(x=>x.Id==run.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Signed));
            if(kind=="prior-signer") { await db.Signers.Where(x=>x.Id==run.Other.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,3)); await db.Signers.Where(x=>x.Id==run.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,2)); db.Signers.Add(new Signer { EnvelopeId=run.Envelope.Id,FullName="Prior synthetic",Email="prior@example.invalid",Order=1 }); await db.SaveChangesAsync(); }
            if(kind=="foreign-field")field=run.Foreign;
            if(kind=="unassigned-field")field=run.Unassigned;
        }
        Assert.Equal(SignerFieldOutcome.NotFound,(await run.Change(new(field.Id,Convert.ToBase64String(field.RowVersion),SignerFieldAction.Apply,AdoptionId:preview.Id),principal)).Outcome);
        if(kind is not ("foreign-field" or "unassigned-field")) { Assert.Null(await run.Snapshot(principal)); Assert.Null(await run.Current(principal)); }
        await using var inspect=fixture.Open(); Assert.False(await inspect.AuditEvents.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="field_filled"));
    }

    [Theory]
    [InlineData("no-adoption")][InlineData("wrong-adoption")][InlineData("blob-value")][InlineData("bad-version")][InlineData("old-version")][InlineData("bad-action")]
    public async Task Forged_input_or_different_stale_revision_cannot_apply_a_mark(string kind)
    {
        await using var run=await Harness.Create(fixture); var preview=await run.Adopt(); var field=run.Field(FieldType.Signature);
        var change=new SignerFieldChange(field.Id,Convert.ToBase64String(field.RowVersion),SignerFieldAction.Apply,AdoptionId:preview.Id);
        if(kind=="no-adoption")change=change with { AdoptionId=null }; if(kind=="wrong-adoption")change=change with { AdoptionId=Guid.NewGuid() };
        if(kind=="blob-value")change=change with { Value=Guid.NewGuid().ToString("N") }; if(kind=="bad-version")change=change with { Version="broken" };
        if(kind=="old-version")change=change with { Version=Convert.ToBase64String(new byte[8]) }; if(kind=="bad-action")change=change with { Action=(SignerFieldAction)100 };
        Assert.Contains((await run.Change(change)).Outcome,new[]{SignerFieldOutcome.InvalidAdoption,SignerFieldOutcome.InvalidValue,SignerFieldOutcome.Conflict});
        Assert.False((await run.Snapshot())!.Fields.Single(x=>x.Id==field.Id).Filled);
    }

    [Theory]
    [InlineData("missing")][InlineData("tamper")][InlineData("oversize")][InlineData("expire-during-read")][InlineData("missing-evidence")][InlineData("tampered-evidence")]
    public async Task Missing_or_changed_assets_evidence_or_expired_scope_cannot_apply_a_mark(string kind)
    {
        await using var run=await Harness.Create(fixture); var preview=await run.Adopt(); var blob=run.Blobs.Created[0];
        if(kind=="missing")await run.Raw(blob).DeleteAsync();
        if(kind=="tamper")await run.Raw(blob).UploadAsync(BinaryData.FromBytes(SignatureAdoptionTests.Mark(100)),true);
        if(kind=="oversize")await run.Raw(blob).UploadAsync(BinaryData.FromBytes(new byte[512*1024+1]),true);
        if(kind=="expire-during-read")run.Blobs.AfterRead=()=>run.Clock.Advance(TimeSpan.FromHours(2));
        if(kind is "missing-evidence" or "tampered-evidence")
        {
            await using var db=fixture.Open();
            if(kind=="missing-evidence")await db.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id).ExecuteDeleteAsync();
            else await db.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{\"adoptionId\":\""+preview.Id+"\"}"));
        }
        Task<SignerFieldResult> Apply()=>run.Apply(run.Field(FieldType.Signature),adoption:preview.Id);
        if(kind=="missing")await Assert.ThrowsAsync<Azure.RequestFailedException>(Apply);
        else if(kind=="tamper")await Assert.ThrowsAsync<InvalidDataException>(Apply);
        else if(kind=="oversize")await Assert.ThrowsAsync<QuillSign.Documents.DocumentRejectedException>(Apply);
        else Assert.Contains((await Apply()).Outcome,new[]{SignerFieldOutcome.InvalidAdoption,SignerFieldOutcome.NotFound});
        await using var inspect=fixture.Open(); Assert.Null((await inspect.Fields.SingleAsync(x=>x.Id==run.Field(FieldType.Signature).Id)).Value);
        Assert.False(await inspect.AuditEvents.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="field_filled"));
    }

    [Fact]
    public async Task Manual_values_are_canonical_Full_Name_is_server_derived_and_Date_Signed_is_reserved_for_Finish()
    {
        await using var run=await Harness.Create(fixture);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Apply(run.Field(FieldType.Text),"Cafe\u0301\r\nline 2")).Outcome);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Apply(run.Field(FieldType.Checkbox),"false")).Outcome);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Apply(run.Field(FieldType.Date),"2026-10-16")).Outcome);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Apply(run.Field(FieldType.FullName))).Outcome);
        Assert.Equal(SignerFieldOutcome.InvalidValue,(await run.Apply(run.Field(FieldType.FullName),"Client override")).Outcome);
        Assert.Equal(SignerFieldOutcome.ReadOnly,(await run.Apply(run.Field(FieldType.DateSigned),"1900-01-01")).Outcome);
        var snapshot=(await run.Snapshot())!; Assert.Equal("Café\nline 2",snapshot.Fields.Single(x=>x.Type==FieldType.Text).Value);
        Assert.Equal("Synthetic signer",snapshot.Fields.Single(x=>x.Type==FieldType.FullName).Value); Assert.True(snapshot.Fields.Single(x=>x.Type==FieldType.Checkbox).Filled);
        Assert.False(snapshot.Fields.Single(x=>x.Type==FieldType.DateSigned).Filled);
        var text=snapshot.Fields.Single(x=>x.Type==FieldType.Text);
        Assert.Equal(SignerFieldOutcome.Conflict,(await run.Change(new(text.Id,Convert.ToBase64String(run.Field(FieldType.Text).RowVersion),SignerFieldAction.Apply,"changed"))).Outcome);
        Assert.Equal(SignerFieldOutcome.AlreadyApplied,(await run.Change(new(text.Id,Convert.ToBase64String(run.Field(FieldType.Text).RowVersion),SignerFieldAction.Apply,"Café\nline 2"))).Outcome);
    }

    [Theory]
    [InlineData("long")][InlineData("control")][InlineData("format")][InlineData("unicode")][InlineData("checkbox")][InlineData("date")][InlineData("manual-adoption")][InlineData("clear-payload")]
    public async Task Invalid_manual_or_clear_payloads_leave_values_unchanged(string kind)
    {
        await using var run=await Harness.Create(fixture); var field=run.Field(kind=="checkbox" ? FieldType.Checkbox : kind=="date" ? FieldType.Date : FieldType.Text);
        var value=kind switch { "long"=>new string('x',4001),"control"=>"bad\0text","format"=>"bad\u202etext","unicode"=>"bad\ud800","checkbox"=>"yes","date"=>"2026-02-30",_=>"valid" };
        var change=new SignerFieldChange(field.Id,Convert.ToBase64String(field.RowVersion),kind=="clear-payload" ? SignerFieldAction.Clear : SignerFieldAction.Apply,value,kind=="manual-adoption" ? Guid.NewGuid() : null);
        Assert.Equal(SignerFieldOutcome.InvalidValue,(await run.Change(change)).Outcome);
        await using var db=fixture.Open(); Assert.Null((await db.Fields.SingleAsync(x=>x.Id==field.Id)).Value);
    }

    [Fact]
    public async Task Audit_failure_rolls_back_field_application_and_clear_and_lost_commit_acknowledgment_replays_once()
    {
        await using var run=await Harness.Create(fixture); var preview=await run.Adopt(); var field=run.Field(FieldType.Signature); run.Faults.FailAudit=true;
        await Assert.ThrowsAsync<DbUpdateException>(()=>run.Apply(field,adoption:preview.Id));
        await using(var db=fixture.Open())Assert.Null((await db.Fields.SingleAsync(x=>x.Id==field.Id)).Value);
        run.Faults.FailAudit=false; run.Faults.FailCommitNumber=run.Faults.Commits+1;
        await Assert.ThrowsAsync<IOException>(()=>run.Apply(field,adoption:preview.Id));
        Assert.Equal(SignerFieldOutcome.AlreadyApplied,(await run.Apply(field,adoption:preview.Id)).Outcome);
        var current=(await run.Snapshot())!.Fields.Single(x=>x.Id==field.Id); run.Faults.FailAudit=true;
        await Assert.ThrowsAsync<DbUpdateException>(()=>run.Change(new(field.Id,current.Version,SignerFieldAction.Clear)));
        run.Faults.FailAudit=false; Assert.True((await run.Snapshot())!.Fields.Single(x=>x.Id==field.Id).Filled);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(field.Id,current.Version,SignerFieldAction.Clear))).Outcome);
        await using var inspect=fixture.Open(); Assert.Single(await inspect.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="field_filled").ToArrayAsync());
    }

    [Fact]
    public async Task Database_binding_constraints_reject_other_signers_previews_and_incomplete_mark_bindings()
    {
        await using var run=await Harness.Create(fixture); var preview=await run.Adopt(); await using var db=fixture.Open();
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.Fields.Where(x=>x.Id==run.Foreign.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SignatureAdoptionId,preview.Id)
            .SetProperty(x=>x.ImageSha256,SHA256.HashData(preview.Signature)).SetProperty(x=>x.Value,Guid.NewGuid().ToString("N")).SetProperty(x=>x.FilledAt,run.Clock.GetUtcNow()).SetProperty(x=>x.FilledBy,PartyType.Signer)));
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.Fields.Where(x=>x.Id==run.Field(FieldType.Signature).Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SignatureAdoptionId,preview.Id)));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Invalid_page_metadata_or_field_page_fails_closed(bool fieldPage)
    {
        await using var run=await Harness.Create(fixture); await using var db=fixture.Open();
        if(fieldPage)await db.Fields.Where(x=>x.Id==run.Field(FieldType.Text).Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Page,2));
        else await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PageCount,(int?)null));
        Assert.Null(await run.Snapshot()); Assert.Equal(SignerFieldOutcome.NotFound,(await run.Apply(run.Field(FieldType.Text),"value")).Outcome);
    }

    internal sealed class Harness : IAsyncDisposable
    {
        private SqlDatabaseFixture fixture=null!; private readonly EphemeralDataProtectionProvider protection=new();
        internal EphemeralDataProtectionProvider Protection=>protection;
        public Envelope Envelope=null!; public Signer Signer=null!,Other=null!; public DocumentField Unassigned=null!,Foreign=null!,ExtraSignature=null!; public List<DocumentField> Fields=[];
        public VerifiedSigner Identity=null!; public Clock Clock=new(); public Faults Faults=new(); public Blobs Blobs=null!;
        public ClaimsPrincipal Principal=>SignerAccessConfiguration.Principal(Identity);
        public DocumentField Field(FieldType type)=>Fields.Single(x=>x.Type==type);
        public static async Task<Harness> Create(SqlDatabaseFixture fixture,DateTimeOffset? initialTime=null)
        {
            var run=new Harness { fixture=fixture }; if(initialTime is { } start)run.Clock.Set(start);
            var now=run.Clock.GetUtcNow(); run.Envelope=new Envelope { SenderEmail="sender@example.invalid",Title="Synthetic fields - NO AGREEMENT",Status=EnvelopeStatus.Sent,SentAt=now,SenderVerifiedAt=now,SentPdfBlob=Guid.NewGuid().ToString("N"),SentPdfSha256=SHA256.HashData(new byte[]{1,2,3}),PageCount=1,ExpiresAt=now.AddDays(2) };
            var disclosure=new ElectronicRecordDisclosure(ElectronicRecordDisclosureTests.Policy()).Build(run.Envelope.PublicId,run.Envelope.Title,run.Envelope.SenderEmail); run.Envelope.ErsdVersion=disclosure.Version; run.Envelope.ErsdText=disclosure.Text; run.Envelope.ErsdSha256=disclosure.Sha256;
            run.Signer=new Signer { EnvelopeId=run.Envelope.Id,FullName="Synthetic signer",Email="signer@example.invalid",ConsentAt=now,Status=SignerStatus.Viewed };
            run.Other=new Signer { EnvelopeId=run.Envelope.Id,FullName="Other synthetic",Email="other@example.invalid",Order=2 };
            DocumentField Make(FieldType type,Guid? owner)=>new() { EnvelopeId=run.Envelope.Id,SignerId=owner,Type=type,Page=1,X=.1m,Y=.1m,Width=.3m,Height=.1m,Required=true,Label=type.ToString() };
            run.Fields=Enum.GetValues<FieldType>().Select(t=>Make(t,run.Signer.Id)).ToList(); run.ExtraSignature=Make(FieldType.Signature,run.Signer.Id); run.Unassigned=Make(FieldType.Text,null); run.Unassigned.Value="sender fixed"; run.Unassigned.FilledBy=PartyType.Sender; run.Unassigned.FilledAt=now; run.Foreign=Make(FieldType.Signature,run.Other.Id);
            await using(var db=fixture.Open()) { db.AddRange(run.Envelope,run.Signer,run.Other,run.ExtraSignature,run.Unassigned,run.Foreign); db.AddRange(run.Fields); await db.SaveChangesAsync(); }
            run.Identity=new(run.Envelope.Id,run.Envelope.PublicId,run.Signer.Id,run.Signer.Email,Guid.Parse(run.Envelope.SentPdfBlob),Convert.ToHexStringLower(run.Envelope.SentPdfSha256),Convert.ToHexStringLower(disclosure.Sha256),now.AddHours(2));
            run.Blobs=new(new AzureBlobStore(new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)),1024*1024,true)); return run;
        }
        internal QuillSignDbContext Open() { using var original=fixture.Open(); return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(original.Database.GetConnectionString()).AddInterceptors(Faults).Options); }
        internal SignerAccess Access(QuillSignDbContext db)=>new(db,new(db,Clock),new(),Clock);
        internal SignatureAdoption Adoption(QuillSignDbContext db)=>new(db,Access(db),Blobs,new(protection,Clock),new(db,Clock),Clock);
        public async Task<SignaturePreviewData> Adopt(byte shade=20) { await using var db=Open(); var service=Adoption(db); var preview=(await service.PrepareAsync(Principal,Envelope.PublicId,new(SignatureAdoptionTests.Mark(shade),SignatureAdoptionTests.Mark((byte)(shade+10)),SignatureMethod.Drawn)))!; Clock.Advance(TimeSpan.FromMilliseconds(1)); Assert.Equal(SignatureAdoptionResult.Adopted,await service.AdoptAsync(Principal,Envelope.PublicId,preview.Receipt,true,SignatureAdoptionStatement.Version,null,null)); return preview; }
        public async Task<SignerFieldSnapshot?> Snapshot(ClaimsPrincipal? principal=null) { await using var db=Open(); return await new SignerFields(db,Access(db),Adoption(db),new(db,Clock),Clock).GetAsync(principal??Principal,Envelope.PublicId); }
        public async Task<AdoptedSignatureData?> Current(ClaimsPrincipal? principal=null) { await using var db=Open(); return await Adoption(db).ReadCurrentAsync(principal??Principal,Envelope.PublicId); }
        public Task<SignerFieldResult> Apply(DocumentField field,string? value=null,Guid? adoption=null)=>Change(new(field.Id,Convert.ToBase64String(field.RowVersion),SignerFieldAction.Apply,value,adoption));
        public async Task<SignerFieldResult> Change(SignerFieldChange change,ClaimsPrincipal? principal=null) { await using var db=Open(); return await new SignerFields(db,Access(db),Adoption(db),new(db,Clock),Clock).ChangeAsync(principal??Principal,Envelope.PublicId,change,"127.0.0.1","Synthetic field test"); }
        public BlobClient Raw(DocumentBlob blob)=>new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)).GetBlobContainerClient("normalized").GetBlobClient($"{blob.EnvelopeId:N}/{blob.ObjectId:N}");
        public async ValueTask DisposeAsync() { foreach(var blob in Blobs.Created.Distinct())await Raw(blob).DeleteIfExistsAsync(); }
    }
    internal sealed class Clock : TimeProvider { private DateTimeOffset now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()); public bool TickOnRead; public override DateTimeOffset GetUtcNow() { var result=now; if(TickOnRead)now=now.AddMilliseconds(1); return result; } public void Advance(TimeSpan span)=>now+=span; public void Set(DateTimeOffset value)=>now=value; }
    internal sealed class Blobs(IBlobStore inner) : IBlobStore
    { public List<DocumentBlob> Created=[]; public Action? AfterRead; public Action<DocumentBlob>? ReadCompleted;
        public Guid SourceId; public bool FailReviewWrite,TamperReviewRead,WrongReviewLength,FailReviewDelete,OversizeReviewRead; public ClaimsPrincipal? LastReviewRead; public IBlobStore Inner=>inner;
        public Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,long length,CancellationToken ct=default) { Created.Add(b); if(FailReviewWrite && b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=SourceId)throw new IOException("Synthetic review write failure"); return inner.WriteAsync(p,b,s,length,ct); }
        public async Task<long> CopyToAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,CancellationToken ct=default) { long length;
            if(b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=SourceId)LastReviewRead=p;
            if(OversizeReviewRead && b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=SourceId)s.SetLength(64*1024*1024+1);
            if(TamperReviewRead && b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=SourceId) { using var m=new MemoryStream(); length=await inner.CopyToAsync(p,b,m,ct); var bytes=m.ToArray(); bytes[0]^=1; await s.WriteAsync(bytes,ct); }
            else length=await inner.CopyToAsync(p,b,s,ct); AfterRead?.Invoke(); ReadCompleted?.Invoke(b); return WrongReviewLength && b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=SourceId ? long.MaxValue : length; }
        public Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct=default) { if(FailReviewDelete && b.Kind==DocumentBlobKind.Normalized && b.ObjectId!=SourceId)throw new IOException("Synthetic review cleanup failure"); return inner.DeleteAsync(p,b,ct); } }
    internal sealed class Faults : DbTransactionInterceptor,ISaveChangesInterceptor
    { public bool FailAudit; public int FailCommitNumber,Commits;
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default) { if(Interlocked.Increment(ref Commits)==FailCommitNumber)throw new IOException("Synthetic lost commit acknowledgement"); return Task.CompletedTask; }
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> r,CancellationToken ct=default) { if(FailAudit && e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added))throw new DbUpdateException("Synthetic audit failure"); return ValueTask.FromResult(r); }
    }
}
