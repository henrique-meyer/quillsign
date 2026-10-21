using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionSignerAdoptionFieldAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Preexisting_exact_preview_is_adopted_and_owned_mark_applied_cleared_with_sealed_SQL_outcomes()
    {
        await using var run=await Connected.Create(fixture);Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt());
        Assert.Equal(SignatureAdoptionResult.AlreadyAdopted,await run.Adopt());
        var signature=await run.Field(FieldType.Signature);var applied=await run.Change(new(signature.Id,Convert.ToBase64String(signature.RowVersion),SignerFieldAction.Apply,AdoptionId:run.Preview.Id));
        Assert.Equal(SignerFieldOutcome.Applied,applied.Outcome);Assert.True(applied.Field!.Filled);
        Assert.Equal(SignerFieldOutcome.AlreadyApplied,(await run.Change(new(signature.Id,applied.Field.Version,SignerFieldAction.Apply,AdoptionId:run.Preview.Id))).Outcome);
        Assert.Equal(SignerFieldOutcome.Conflict,(await run.Change(new(signature.Id,Convert.ToBase64String(signature.RowVersion),SignerFieldAction.Clear))).Outcome);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(signature.Id,applied.Field.Version,SignerFieldAction.Clear))).Outcome);
        await using var db=fixture.Open();Assert.Null((await db.Fields.AsNoTracking().SingleAsync(x=>x.Id==signature.Id)).Value);
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="signature_adopted"));
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="field_filled"));
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="field_cleared"));
        var state=await run.Record.Journal.ReadAsync(run.Record.Id);Assert.Null(state.OutstandingOperation);
        Assert.Contains(state.Operations!.Values,x=>x.Kind=="signer/adopt");Assert.Contains(state.Operations.Values,x=>x.Kind=="signer/field"&&x.Reference.EndsWith("/Clear",StringComparison.Ordinal));
    }

    [Fact]
    public async Task Pending_hold_blocks_adoption_fields_and_fresh_preview_without_changing_rows_or_images()
    {
        await using var run=await Connected.Create(fixture);var hold=Place(run.Record.Id);
        await run.Record.Journal.IntentAsync(Authority(run.Record.Time,hold.Permission),Operators,hold,Guid.NewGuid());
        var copies=run.Blobs.Copies;await using(var db=fixture.Open())await Assert.ThrowsAsync<QuillSign.Documents.DocumentRejectedException>(()=>run.Adoption(db).ReadAsync(run.Principal,run.PublicId,run.Receipt));
        Assert.Equal(copies,run.Blobs.Copies);Assert.Equal(SignatureAdoptionResult.InvalidContext,await run.Adopt());
        var text=await run.Field(FieldType.Text);Assert.Equal(SignerFieldOutcome.NotFound,(await run.Change(new(text.Id,Convert.ToBase64String(text.RowVersion),SignerFieldAction.Apply,"synthetic value"))).Outcome);
        await using var check=fixture.Open();Assert.Null((await check.SignaturePreviews.AsNoTracking().SingleAsync(x=>x.Id==run.Preview.Id)).UsedAt);
        Assert.Null((await check.Fields.AsNoTracking().SingleAsync(x=>x.Id==text.Id)).Value);Assert.Null((await check.Signers.AsNoTracking().SingleAsync(x=>x.Id==run.Identity.SignerId)).SignatureAdoptionId);
        Assert.False(await check.AuditEvents.AnyAsync(x=>x.EnvelopeId==run.Record.Id&&(x.Event=="signature_adopted"||x.Event=="field_filled")));
        Assert.Equal(hold,(await run.Record.Journal.ReadAsync(run.Record.Id)).Unacknowledged);
    }

    [Theory]
    [InlineData("adopt")][InlineData("field")]
    public async Task Unknown_SQL_ack_keeps_original_outcome_pending_and_idempotent_readback_does_not_replay(string action)
    {
        await using var run=await Connected.Create(fixture);var text=await run.Field(FieldType.Text);string connection;
        await using(var source=fixture.Open())connection=source.Database.GetConnectionString()!;
        await using(var lost=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
        {
            if(action=="adopt")await Assert.ThrowsAsync<IOException>(()=>run.Adopt(lost));
            else await Assert.ThrowsAsync<IOException>(()=>run.Change(new(text.Id,Convert.ToBase64String(text.RowVersion),SignerFieldAction.Apply,"exact original value"),lost));
        }
        var state=await run.Record.Journal.ReadAsync(run.Record.Id);Assert.NotNull(state.OutstandingOperation);Assert.True(state.Outcomes!.ContainsKey(state.OutstandingOperation!.Value));
        if(action=="adopt")Assert.Equal(SignatureAdoptionResult.AlreadyAdopted,await run.Adopt());
        else Assert.Equal(SignerFieldOutcome.AlreadyApplied,(await run.Change(new(text.Id,Convert.ToBase64String(text.RowVersion),SignerFieldAction.Apply,"exact original value"))).Outcome);
        Assert.Equal(state.HeadHash,(await run.Record.Journal.ReadAsync(run.Record.Id)).HeadHash);
        await using var check=fixture.Open();Assert.Equal(1,await check.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event==(action=="adopt"?"signature_adopted":"field_filled")));
    }

    [Fact]
    public async Task Invalid_acknowledgment_receipt_version_readonly_and_dirty_caller_never_reserve_or_flush()
    {
        await using var run=await Connected.Create(fixture);var state=await run.Record.Journal.ReadAsync(run.Record.Id);
        await using(var db=fixture.Open())
        {
            Assert.Equal(SignatureAdoptionResult.InvalidAcknowledgment,await run.Adoption(db).AdoptAsync(run.Principal,run.PublicId,run.Receipt,false,SignatureAdoptionStatement.Version,null,null));
            Assert.Equal(SignatureAdoptionResult.InvalidPreview,await run.Adoption(db).AdoptAsync(run.Principal,run.PublicId,"invalid",true,SignatureAdoptionStatement.Version,null,null));
        }
        var text=await run.Field(FieldType.Text);Assert.Equal(SignerFieldOutcome.InvalidValue,(await run.Change(new(text.Id,"invalid",SignerFieldAction.Apply,"text"))).Outcome);
        var date=await run.Field(FieldType.DateSigned);Assert.Equal(SignerFieldOutcome.ReadOnly,(await run.Change(new(date.Id,Convert.ToBase64String(date.RowVersion),SignerFieldAction.Apply,"2030-01-01"))).Outcome);
        await using(var dirty=fixture.Open())
        {
            var foreign=new Envelope{SenderEmail="synthetic-unadmitted@example.invalid"};dirty.Add(foreign);
            await Assert.ThrowsAsync<InvalidDataException>(()=>run.Adopt(dirty));
            await Assert.ThrowsAsync<InvalidDataException>(()=>run.Change(new(text.Id,Convert.ToBase64String(text.RowVersion),SignerFieldAction.Apply,"text"),dirty));
            await using var check=fixture.Open();Assert.False(await check.Envelopes.AnyAsync(x=>x.Id==foreign.Id));
            dirty.ChangeTracker.Clear();await using var tx=await dirty.Database.BeginTransactionAsync();await Assert.ThrowsAsync<InvalidDataException>(()=>run.Adopt(dirty));
        }
        Assert.Equal(state.HeadHash,(await run.Record.Journal.ReadAsync(run.Record.Id)).HeadHash);
    }

    [Fact]
    public async Task Ordinary_field_canonicalization_and_FullName_are_unchanged_in_opt_in_SQL_path()
    {
        await using var run=await Connected.Create(fixture);var text=await run.Field(FieldType.Text);var uuid=Guid.NewGuid().ToString("N");
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(text.Id,Convert.ToBase64String(text.RowVersion),SignerFieldAction.Apply,uuid))).Outcome);
        var name=await run.Field(FieldType.FullName);var applied=await run.Change(new(name.Id,Convert.ToBase64String(name.RowVersion),SignerFieldAction.Apply));
        Assert.Equal(SignerFieldOutcome.Applied,applied.Outcome);Assert.Equal("Synthetic First",applied.Field!.Value);
        await using var db=fixture.Open();Assert.Equal(uuid,(await db.Fields.AsNoTracking().SingleAsync(x=>x.Id==text.Id)).Value);
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
    }

    private sealed class LostCommit:DbTransactionInterceptor
    {public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData data,CancellationToken ct=default)=>throw new IOException("Synthetic unknown SQL acknowledgement");}
    private sealed class Marks:IReadOnlyDictionary<DocumentBlob,byte[]>,IBlobStore
    {
        private readonly Dictionary<DocumentBlob,byte[]> items=[];internal int Copies;
        internal void Add(DocumentBlob blob,byte[] bytes)=>items.Add(blob,bytes);
        public Task<long> CopyToAsync(ClaimsPrincipal principal,DocumentBlob blob,Stream destination,CancellationToken ct=default)
        {EnvelopeStorageAuthorization.DemandRead(principal,blob);Copies++;destination.Write(items[blob]);return Task.FromResult(items[blob].LongLength);}
        public Task WriteAsync(ClaimsPrincipal principal,DocumentBlob blob,Stream source,long length,CancellationToken ct=default)=>throw new InvalidOperationException("No runtime preview writes in this SQL-only fixture.");
        public Task DeleteAsync(ClaimsPrincipal principal,DocumentBlob blob,CancellationToken ct=default)=>throw new InvalidOperationException("No preview deletion authority.");
        public byte[] this[DocumentBlob key]=>items[key];public IEnumerable<DocumentBlob> Keys=>items.Keys;public IEnumerable<byte[]> Values=>items.Values;public int Count=>items.Count;
        public bool ContainsKey(DocumentBlob key)=>items.ContainsKey(key);public bool TryGetValue(DocumentBlob key,out byte[] value)=>items.TryGetValue(key,out value!);
        public IEnumerator<KeyValuePair<DocumentBlob,byte[]>> GetEnumerator()=>items.GetEnumerator();System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()=>GetEnumerator();
    }
    private sealed class Connected(SqlDatabaseFixture fixture,ProductionInvitationWorkerAdmissionTests.Delivered delivered):IAsyncDisposable
    {
        private readonly ProductionInvitationWorkerAdmissionTests.Delivered delivery=delivered;
        internal ProductionRuntimeAdmissionTests.Run Record=>delivery.Record;internal string PublicId=>delivery.Ready.Original.PublicId;
        internal VerifiedSigner Identity=null!;internal ClaimsPrincipal Principal=null!;internal SignaturePreview Preview=null!;internal string Receipt="";internal readonly Marks Blobs=new();
        private ProductionSignerMutationAdmission Hook=>new(Record.Admission);
        private SignerAccess Access(QuillSignDbContext db)=>new(db,new(db,Record.Time),new(),Record.Time){HoldAdmission=Hook};
        internal SignatureAdoption Adoption(QuillSignDbContext db)=>new(db,Access(db),Blobs,new(Record.Keys,Record.Time),new(db,Record.Time),Record.Time){HoldAdmission=Hook};
        internal SignerFields Fields(QuillSignDbContext db)=>new(db,Access(db),Adoption(db),new(db,Record.Time),Record.Time){HoldAdmission=Hook};
        internal async Task<SignatureAdoptionResult> Adopt(QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;return await Adoption(supplied??owned!).AdoptAsync(Principal,PublicId,Receipt,true,SignatureAdoptionStatement.Version,null,null);}
        internal async Task<SignerFieldResult> Change(SignerFieldChange change,QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;return await Fields(supplied??owned!).ChangeAsync(Principal,PublicId,change,null,null);}
        internal async Task<DocumentField> Field(FieldType type)
        {await using var db=fixture.Open();return await db.Fields.AsNoTracking().SingleAsync(x=>x.EnvelopeId==Record.Id&&x.SignerId==Identity.SignerId&&x.Type==type);}
        internal static async Task<Connected> Create(SqlDatabaseFixture fixture)
        {
            var run=new Connected(fixture,await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture));await using var db=fixture.Open();
            run.Identity=(await run.Access(db).RedeemAsync(run.delivery.Token,null,null))!;Assert.NotNull(run.Identity);run.Principal=SignerAccessConfiguration.Principal(run.Identity);
            var context=(await run.Access(db).GetContextAsync(run.Principal,run.PublicId))!;
            var pdf=await new SignerPdfAccess(run.delivery.Ready.Prepared.Blobs,new()){HoldAdmission=run.Hook}.PrepareAsync(run.Principal,context);
            Assert.Equal(context.DocumentSha256,SHA256.HashData(pdf));
            var consent=new SignerConsent(db,run.Access(db),new(run.Record.Keys,run.Record.Time),new(db,run.Record.Time),new DeclineNotificationWriter(db,()=>run.delivery.Ready.Signals,new(){Enabled=true},new(run.Record.Keys),run.Record.Time),run.Record.Time){HoldAdmission=run.Hook};
            Assert.Equal(ConsentResult.Accepted,await consent.AcceptAsync(run.Principal,run.PublicId,new SignerReceiptProtection(run.Record.Keys,run.Record.Time).Create(context),true,true,"preview",null,null));
            // Explicit TEST staging of existing preview metadata and bytes. This does
            // not exercise or authorize runtime provider preview creation.
            var scope=await run.Record.Admission.BeginAsync(run.Record.Id,Guid.NewGuid(),"test/existing-preview","explicit-saved-preview-and-field-fixture");
            await using(var tx=await db.Database.BeginTransactionAsync())
            {
                var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==run.Identity.SignerId);
                var mark=SignaturePng.Normalize(SignatureAdoptionTests.Mark());var initials=SignaturePng.Normalize(SignatureAdoptionTests.Mark(60));
                run.Preview=new(){EnvelopeId=run.Record.Id,SignerId=signer.Id,DocumentId=run.Identity.DocumentId,SignatureObjectId=Guid.NewGuid(),InitialsObjectId=Guid.NewGuid(),
                    SignatureSha256=mark.Sha256,InitialsSha256=initials.Sha256,DocumentSha256=Convert.FromHexString(run.Identity.DocumentHash),DisclosureSha256=Convert.FromHexString(run.Identity.DisclosureHash),
                    SessionSha256=SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(run.Identity)),BaselineSignerVersion=signer.RowVersion,SignatureWidth=mark.Width,SignatureHeight=mark.Height,InitialsWidth=initials.Width,InitialsHeight=initials.Height,
                    Method=SignatureMethod.Drawn,NormalizationVersion=SignaturePng.Version,AdoptionVersion=SignatureAdoptionStatement.Version,CreatedAt=run.Record.Time.Now,ExpiresAt=run.Record.Time.Now.AddMinutes(10)};
                run.Blobs.Add(new(run.Record.Id,DocumentBlobKind.Signature,run.Preview.SignatureObjectId),mark.Bytes);run.Blobs.Add(new(run.Record.Id,DocumentBlobKind.Initials,run.Preview.InitialsObjectId),initials.Bytes);
                db.SignaturePreviews.Add(run.Preview);
                foreach(var type in new[]{FieldType.Signature,FieldType.Text,FieldType.FullName,FieldType.DateSigned})
                {
                    if(!await db.Fields.AnyAsync(x=>x.EnvelopeId==run.Record.Id&&x.SignerId==signer.Id&&x.Type==type))db.Fields.Add(new(){EnvelopeId=run.Record.Id,SignerId=signer.Id,Type=type,Page=1,X=.1m,Y=.1m,Width=.2m,Height=.1m});
                }
                await db.SaveChangesAsync();await run.Record.Admission.PrepareOutcomeLockedAsync(db,scope);await tx.CommitAsync();
            }
            await run.Record.Admission.CompleteAsync(scope,Hash);run.Receipt=new SignaturePreviewProtection(run.Record.Keys,run.Record.Time).Create(run.Preview,run.Identity);return run;
        }
        public ValueTask DisposeAsync()=>delivery.DisposeAsync();
    }
}
