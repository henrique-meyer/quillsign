using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionSignaturePreviewAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_unenrolled_demo_keeps_preview_adoption_and_field_behavior_with_both_helpers_configured()
    {
        await using var run=await Flow.Create(fixture,demo:true);var oldWrites=run.Blobs.UnwitnessedWrites;
        var preview=(await run.Prepare())!;Assert.NotNull(preview);Assert.NotNull(await run.Read(preview.Receipt));
        Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(preview));
        var field=(await run.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:preview.Id))).Outcome);
        Assert.Equal(oldWrites+2,run.Blobs.UnwitnessedWrites);Assert.Equal(0,run.Blobs.MarkWrites);
        Assert.Equal(0,(await run.Record.Journal.ReadAsync(run.Id)).Sequence);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Partial_production_helper_composition_cannot_fall_back_to_unwitnessed_preview_writes()
    {
        await using var run=await Flow.Create(fixture);
        foreach(var missingPreview in new[]{true,false})
        {
            await using var db=fixture.Open();
            var service=new SignatureAdoption(db,ProductionSignerMutationAdmissionTests.Access(run.Delivered,db),run.Blobs,new(run.Record.Keys,run.Record.Time),new(db,run.Record.Time),run.Record.Time)
                {HoldAdmission=missingPreview?new(run.Record.Admission):null,HoldPreviews=missingPreview?null:new(run.Record.Admission,run.Blobs,run.Record.Time)};
            Assert.Null(await service.PrepareAsync(run.Principal,run.Delivered.Ready.Original.PublicId,
                new(SignatureAdoptionTests.Mark(),SignatureAdoptionTests.Mark(60),SignatureMethod.Drawn)));
        }
        Assert.Equal(0,run.Blobs.MarkWrites);Assert.Equal(0,run.Blobs.UnwitnessedWrites);Assert.Equal(0,run.Blobs.Deletes);
        Assert.Null((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
        await using var check=fixture.Open();Assert.False(await check.SignaturePreviews.AnyAsync(x=>x.EnvelopeId==run.Id));
    }

    [Theory]
    [InlineData(SignatureMethod.Typed)][InlineData(SignatureMethod.Drawn)][InlineData(SignatureMethod.Uploaded)]
    public async Task Genuine_consent_preview_adoption_and_owned_fields_preserve_the_complete_bundle_under_independent_holds(SignatureMethod method)
    {
        await using var run=await Flow.Create(fixture);var original=run.Identity;
        var preview=(await run.Prepare(method))!;Assert.NotNull(preview);
        Assert.Equal(2,run.Blobs.MarkWrites);Assert.Equal(0,run.Blobs.UnwitnessedWrites);Assert.Equal(0,run.Blobs.Deletes);
        var exact=(await run.Read(preview.Receipt))!;Assert.Equal(preview.Signature,exact.Signature);Assert.Equal(preview.Initials,exact.Initials);
        Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(preview));
        var fields=(await run.Fields())!;
        foreach(var field in fields.Fields)
        {
            var change=field.Type switch {
                FieldType.Signature or FieldType.Initials=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:preview.Id),
                FieldType.FullName=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply),
                _=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply,Guid.NewGuid().ToString("N"))};
            Assert.Equal(field.Type==FieldType.DateSigned?SignerFieldOutcome.ReadOnly:SignerFieldOutcome.Applied,(await run.Change(change)).Outcome);
        }
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        var a=await holds.Place(0);Assert.Equal(7,holds.Provider.Files.Count);
        var b=await holds.Place(1);Assert.Equal(14,holds.Provider.Files.Count);
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Read(preview.Receipt));
        Assert.True(await holds.Release(a,2));Assert.False(await holds.Release(b,3));
        Assert.Equal(preview.ExpiresAt,(await run.Read(preview.Receipt))!.ExpiresAt);
        Assert.Equal(original,run.Identity);Assert.All(holds.Provider.Files.Values,x=>Assert.False(x.Held));
        await using var db=fixture.Open();Assert.Equal(1,await db.SignaturePreviews.CountAsync(x=>x.EnvelopeId==run.Id));
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Id&&x.Event=="signature_adopted"));
        Assert.Equal(4,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Id&&x.Event=="field_filled"));
        Assert.Equal(run.Delivered.TokenRecord.ExpiresAt,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.Delivered.TokenRecord.Id)).ExpiresAt);
        Assert.Equal(0,run.Blobs.Deletes);Assert.Null((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task Effective_hold_refuses_preview_before_any_mark_write_and_release_preserves_original_session()
    {
        await using var run=await Flow.Create(fixture);using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        var hold=await holds.Place(0);Assert.Null(await run.Prepare());Assert.Equal(0,run.Blobs.MarkWrites);
        await using(var db=fixture.Open())Assert.False(await db.SignaturePreviews.AnyAsync(x=>x.EnvelopeId==run.Id));
        Assert.False(await holds.Release(hold,1));Assert.NotNull(await run.Prepare());
        Assert.Equal(2,run.Blobs.MarkWrites);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task A_prepared_unused_preview_has_complete_preservation_proof_without_implying_adoption()
    {
        await using var run=await Flow.Create(fixture);var preview=(await run.Prepare())!;
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);var hold=await holds.Place(0);
        Assert.Equal(7,holds.Provider.Files.Count);Assert.False(await holds.Release(hold,1));
        await using var db=fixture.Open();Assert.Null((await db.SignaturePreviews.AsNoTracking().SingleAsync(x=>x.Id==preview.Id)).UsedAt);
        Assert.Null((await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==run.Identity.SignerId)).SignatureAdoptionId);
    }

    [Fact]
    public async Task Hold_arriving_during_readonly_preview_commit_prevents_issuing_a_fresh_receipt()
    {
        await using var run=await Flow.Create(fixture);var preview=(await run.Prepare())!;var hold=Place(run.Id);
        string connection;await using(var source=fixture.Open())connection=source.Database.GetConnectionString()!;
        var interceptor=new CommitHold(async()=>{await run.Record.Journal.IntentAsync(Authority(run.Record.Time,hold.Permission),Operators,hold,Guid.NewGuid());});
        await using var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(interceptor).Options);
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Read(preview.Receipt,db));Assert.True(interceptor.Published);
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.Equal(hold,state.Unacknowledged);Assert.Null(state.OutstandingOperation);
        Assert.Null((await db.SignaturePreviews.AsNoTracking().SingleAsync(x=>x.Id==preview.Id)).UsedAt);
        Assert.Equal(2,run.Blobs.MarkWrites);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Equal_mark_bytes_under_a_different_provider_version_do_not_satisfy_the_retained_write_receipt()
    {
        await using var run=await Flow.Create(fixture);Assert.NotNull(await run.Prepare());run.Blobs.MarkVersionSuffix="-unexpected-version";
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);var hold=Place(run.Id);
        await holds.Coordinator().SubmitAsync(Authority(run.Record.Time,hold.Permission),Operators,hold);
        await Assert.ThrowsAsync<InvalidDataException>(()=>holds.Coordinator().PreserveAsync(run.Id,hold.HoldId,Guid.NewGuid()));
        Assert.Empty(holds.Provider.Files);Assert.False((await run.Record.Journal.ReadAsync(run.Id)).Holds[hold.HoldId].Effective);
        Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Correctly_sealed_SQL_and_exact_normalized_preview_bytes_without_a_runtime_write_plan_are_not_complete_preservation()
    {
        await using var run=await Flow.Create(fixture);
        var steps=new ProductionSignerMutationAdmissionTests(fixture);var context=(await steps.Preview(run.Delivered,run.Principal)).Context;
        var mark=SignaturePng.Normalize(SignatureAdoptionTests.Mark());var initials=SignaturePng.Normalize(SignatureAdoptionTests.Mark(60));
        var scope=await run.Record.Admission.BeginAsync(run.Id,Guid.NewGuid(),"test/preview-sql-only","synthetic-no-provider-plan");
        await using(var db=fixture.Open())
        {
            await using var tx=await db.Database.BeginTransactionAsync();var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==run.Identity.SignerId);
            // Deliberately TEST-staged business evidence, not a provider operation.
            // The production coordinator must refuse to turn this into a hold.
            var row=new SignaturePreview {EnvelopeId=run.Id,SignerId=signer.Id,DocumentId=run.Identity.DocumentId,
                SignatureObjectId=Guid.NewGuid(),InitialsObjectId=Guid.NewGuid(),SignatureSha256=mark.Sha256,InitialsSha256=initials.Sha256,
                SignatureWidth=mark.Width,SignatureHeight=mark.Height,InitialsWidth=initials.Width,InitialsHeight=initials.Height,
                DocumentSha256=Convert.FromHexString(run.Identity.DocumentHash),DisclosureSha256=Convert.FromHexString(run.Identity.DisclosureHash),
                SessionSha256=SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(run.Identity)),BaselineSignerVersion=signer.RowVersion,
                Method=SignatureMethod.Drawn,NormalizationVersion=SignaturePng.Version,AdoptionVersion=SignatureAdoptionStatement.Version,
                CreatedAt=run.Record.Time.Now,ExpiresAt=new[]{run.Record.Time.Now.AddMinutes(SignatureAdoption.PreviewMinutes),context.AccessExpiresAt}.Min()};
            run.Blobs.Objects.Add(new(run.Id,DocumentBlobKind.Signature,row.SignatureObjectId),mark.Bytes);
            run.Blobs.Objects.Add(new(run.Id,DocumentBlobKind.Initials,row.InitialsObjectId),initials.Bytes);
            db.SignaturePreviews.Add(row);await db.SaveChangesAsync();await run.Record.Admission.PrepareOutcomeLockedAsync(db,scope);await tx.CommitAsync();
        }
        await run.Record.Admission.CompleteAsync(scope,Hash);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);var hold=Place(run.Id);
        var state=await holds.Coordinator().SubmitAsync(Authority(run.Record.Time,hold.Permission),Operators,hold);
        await using(var db=fixture.Open())
        {
            await using var tx=await db.Database.BeginTransactionAsync();
            var snapshot=await new ProductionHoldObjectInventory(db,run.Record.Keys,run.Record.Time,run.Blobs).CaptureLockedAsync(run.Id,state.RequestRevision,state.RequestFenceHash!);
            using var sql=ProductionHoldSqlInventory.OpenVerified(snapshot.Sql,run.Record.Keys);
            Assert.Single(ProductionHoldSentAuditReferences.ReadVerified(sql.RootElement,ProductionHoldObjectInventory.OpenVerified(snapshot,run.Record.Keys,run.Record.Time),run.Record.Keys));
            await tx.RollbackAsync();
        }
        await Assert.ThrowsAsync<InvalidDataException>(()=>holds.Coordinator().PreserveAsync(run.Id,hold.HoldId,Guid.NewGuid()));
        Assert.Empty(holds.Provider.Files);Assert.False((await run.Record.Journal.ReadAsync(run.Id)).Holds[hold.HoldId].Effective);
    }

    [Theory]
    [InlineData(1)][InlineData(2)]
    public async Task Unknown_first_or_second_mark_acknowledgement_preserves_exact_intents_bytes_and_no_automatic_cleanup_or_replay(int lostAt)
    {
        await using var run=await Flow.Create(fixture);run.Blobs.LoseMarkAcknowledgementAt=lostAt;
        await Assert.ThrowsAsync<IOException>(()=>run.Prepare());Assert.Equal(lostAt,run.Blobs.MarkWrites);Assert.Equal(0,run.Blobs.Deletes);
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.NotNull(state.OutstandingOperation);
        await using(var db=fixture.Open())Assert.False(await db.SignaturePreviews.AnyAsync(x=>x.EnvelopeId==run.Id));
        Assert.Null(await run.Prepare());Assert.Equal(lostAt,run.Blobs.MarkWrites);
        Assert.Equal(state.HeadHash,(await run.Record.Journal.ReadAsync(run.Id)).HeadHash);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Original_preview_or_session_expiry_stops_remaining_writes_without_cleanup_or_new_proof(bool firstWritten)
    {
        await using var run=await Flow.Create(fixture);
        if(firstWritten)run.Blobs.AfterMarkWrite=count=>{if(count==1)run.Record.Time.Now=run.Record.Time.Now.AddMinutes(SignatureAdoption.PreviewMinutes);return Task.CompletedTask;};
        else run.Blobs.BeforeMarkWrite=()=>{run.Record.Time.Now=run.Identity.SessionExpiresAt;return Task.CompletedTask;};
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Prepare());Assert.Equal(firstWritten?1:0,run.Blobs.MarkWrites);
        Assert.Equal(0,run.Blobs.Deletes);Assert.NotNull((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
        await using var db=fixture.Open();Assert.False(await db.SignaturePreviews.AnyAsync(x=>x.EnvelopeId==run.Id));
        Assert.Equal(run.Delivered.TokenRecord.ExpiresAt,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.Delivered.TokenRecord.Id)).ExpiresAt);
    }

    [Fact]
    public async Task Original_preview_operation_drains_mid_write_hold_intent_but_cannot_expose_a_fresh_receipt_while_held()
    {
        await using var run=await Flow.Create(fixture);var hold=Place(run.Id);
        run.Blobs.AfterMarkWrite=async count=>{
            if(count!=1)return;
            var pending=await run.Record.Coordinator.SubmitAsync(Authority(run.Record.Time,hold.Permission),Operators,hold);
            Assert.NotNull(pending.OutstandingOperation);Assert.Equal(hold,pending.Unacknowledged);
        };
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.Prepare());Assert.Equal(2,run.Blobs.MarkWrites);
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.Null(state.OutstandingOperation);Assert.Equal(hold,state.Unacknowledged);
        await using(var db=fixture.Open())Assert.Equal(1,await db.SignaturePreviews.CountAsync(x=>x.EnvelopeId==run.Id));
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);await holds.Preserve(hold);
        Assert.Equal(7,holds.Provider.Files.Count);Assert.False(await holds.Release(hold,1));
        run.Blobs.AfterMarkWrite=null;Assert.NotNull(await run.Prepare());Assert.Equal(4,run.Blobs.MarkWrites);Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Lost_preview_SQL_acknowledgement_exposes_no_receipt_and_retains_a_single_exact_unreplayed_pair()
    {
        await using var run=await Flow.Create(fixture);string connection;await using(var db=fixture.Open())connection=db.Database.GetConnectionString()!;
        await using(var lost=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
            await Assert.ThrowsAsync<IOException>(()=>run.Prepare(supplied:lost));
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.NotNull(state.OutstandingOperation);
        Assert.True(state.Outcomes!.ContainsKey(state.OutstandingOperation!.Value));Assert.Equal(2,run.Blobs.MarkWrites);
        Assert.Null(await run.Prepare());Assert.Equal(state.HeadHash,(await run.Record.Journal.ReadAsync(run.Id)).HeadHash);
        await using var check=fixture.Open();Assert.Equal(1,await check.SignaturePreviews.CountAsync(x=>x.EnvelopeId==run.Id));Assert.Equal(0,run.Blobs.Deletes);
    }

    [Fact]
    public async Task Old_applied_marks_remain_preserved_after_new_adoption_until_explicit_clear_and_reapply()
    {
        await using var run=await Flow.Create(fixture);var a=(await run.Prepare())!;Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(a));
        var field=(await run.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:a.Id))).Outcome);
        var b=(await run.Prepare(SignatureMethod.Uploaded))!;Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(b));
        field=(await run.Fields())!.Fields.Single(x=>x.Id==field.Id);Assert.True(field.Stale);
        using(var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered))
        {var hold=await holds.Place(0);Assert.Equal(9,holds.Provider.Files.Count);Assert.False(await holds.Release(hold,1));}
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(field.Id,field.Version,SignerFieldAction.Clear))).Outcome);
        field=(await run.Fields())!.Fields.Single(x=>x.Id==field.Id);
        Assert.Equal(SignerFieldOutcome.Applied,(await run.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:b.Id))).Outcome);
        Assert.False((await run.Fields())!.Fields.Single(x=>x.Id==field.Id).Stale);Assert.Equal(0,run.Blobs.Deletes);Assert.Equal(4,run.Blobs.MarkWrites);
    }

    private sealed class LostCommit:DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)
        {
            // The ordinary initial context lookup also commits a read-only
            // transaction. Lose only the actual inserted-preview commit.
            if(eventData.Context?.ChangeTracker.Entries<SignaturePreview>().Any()==true)
                throw new IOException("Synthetic lost preview SQL acknowledgement.");
            return Task.CompletedTask;
        }
    }
    private sealed class CommitHold(Func<Task> publish):DbTransactionInterceptor
    {
        internal bool Published;
        public override async Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)
        {if(!Published){Published=true;await publish();}}
    }
    private sealed class Flow(SqlDatabaseFixture fixture,ProductionInvitationWorkerAdmissionTests.Delivered delivered,VerifiedSigner identity):IAsyncDisposable
    {
        internal readonly ProductionInvitationWorkerAdmissionTests.Delivered Delivered=delivered;internal readonly VerifiedSigner Identity=identity;
        internal ProductionRuntimeAdmissionTests.Run Record=>Delivered.Record;internal Guid Id=>Record.Id;
        internal ProductionRecordUploadAdmissionTests.Blobs Blobs=>Delivered.Ready.Prepared.Blobs;
        internal ClaimsPrincipal Principal=>SignerAccessConfiguration.Principal(Identity);
        internal static async Task<Flow> Create(SqlDatabaseFixture fixture,bool demo=false)
        {
            var delivered=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture,demo:demo,withFields:true);
            var steps=new ProductionSignerMutationAdmissionTests(fixture);var identity=(await steps.Redeem(delivered))!;Assert.NotNull(identity);
            var principal=SignerAccessConfiguration.Principal(identity);var receipt=(await steps.Preview(delivered,principal)).Receipt;
            Assert.Equal(ConsentResult.Accepted,await steps.Accept(delivered,principal,receipt));return new(fixture,delivered,identity);
        }
        private SignatureAdoption Adoption(QuillSignDbContext db)=>new(db,ProductionSignerMutationAdmissionTests.Access(Delivered,db),Blobs,
            new(Record.Keys,Record.Time),new(db,Record.Time),Record.Time){HoldAdmission=new(Record.Admission),HoldPreviews=new(Record.Admission,Blobs,Record.Time)};
        private SignerFields Fields(QuillSignDbContext db)=>new(db,ProductionSignerMutationAdmissionTests.Access(Delivered,db),Adoption(db),new(db,Record.Time),Record.Time)
            {HoldAdmission=new(Record.Admission)};
        internal async Task<SignaturePreviewData?> Prepare(SignatureMethod method=SignatureMethod.Drawn,QuillSignDbContext? supplied=null)
        {
            await using var owned=supplied is null?fixture.Open():null;var db=supplied??owned!;
            return await Adoption(db).PrepareAsync(Principal,Delivered.Ready.Original.PublicId,new(SignatureAdoptionTests.Mark(),SignatureAdoptionTests.Mark(60),method,
                method==SignatureMethod.Typed?"Synthetic First":null,method==SignatureMethod.Typed?"SF":null));
        }
        internal async Task<SignaturePreviewData?> Read(string receipt,QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;var db=supplied??owned!;return await Adoption(db).ReadAsync(Principal,Delivered.Ready.Original.PublicId,receipt);}
        internal async Task<SignatureAdoptionResult> Adopt(SignaturePreviewData preview)
        {await using var db=fixture.Open();return await Adoption(db).AdoptAsync(Principal,Delivered.Ready.Original.PublicId,preview.Receipt,true,SignatureAdoptionStatement.Version,null,null);}
        internal async Task<SignerFieldSnapshot?> Fields()
        {await using var db=fixture.Open();return await Fields(db).GetAsync(Principal,Delivered.Ready.Original.PublicId);}
        internal async Task<SignerFieldResult> Change(SignerFieldChange change)
        {await using var db=fixture.Open();return await Fields(db).ChangeAsync(Principal,Delivered.Ready.Original.PublicId,change,null,null);}
        public ValueTask DisposeAsync()=>Delivered.DisposeAsync();
    }
}
