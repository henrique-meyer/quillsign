using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionSignerMutationAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Same_parent_proof_gate_preserves_the_callers_transaction_and_denies_a_later_external_hold_intent()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);
        var identity=(await Redeem(run))!;var user=SignerAccessConfiguration.Principal(identity);
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();
        var context=(await Access(run,db).GetLockedContextAsync(user,run.Ready.Original.PublicId,default))!;Assert.NotNull(context);
        using var bounded=new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await Hook(run).DemandNewProofLockedAsync(db,context,bounded.Token);
        Assert.Same(tx,db.Database.CurrentTransaction);Assert.False(db.ChangeTracker.HasChanges());
        var hold=Place(run.Record.Id);
        await run.Record.Journal.IntentAsync(Authority(run.Record.Time,hold.Permission),Operators,hold,Guid.NewGuid());
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>Hook(run).DemandNewProofLockedAsync(db,context,bounded.Token));
        Assert.Same(tx,db.Database.CurrentTransaction);Assert.False(db.ChangeTracker.HasChanges());
        Assert.False(await db.ProductionHoldRequests.AnyAsync(x=>x.EnvelopeId==run.Record.Id));
        await tx.RollbackAsync();
        Assert.Equal(identity.SessionExpiresAt,context.Identity.SessionExpiresAt);
    }

    [Fact]
    public async Task Actual_invitation_Finish_redemption_exact_PDF_and_consent_form_a_complete_bundle_with_independent_holds_and_releases()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);
        var session=await Redeem(run);Assert.NotNull(session);var principal=SignerAccessConfiguration.Principal(session);
        var (context,receipt)=await Preview(run,principal);Assert.Equal(session,context.Identity);
        Assert.Equal(ConsentResult.Accepted,await Accept(run,principal,receipt));
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
        using var holds=new Holds(fixture,run);var a=await holds.Place(0);Assert.Equal(5,holds.Provider.Files.Count);
        var b=await holds.Place(1);Assert.Equal(10,holds.Provider.Files.Count);
        Assert.True(await holds.Release(a,2));Assert.False(await holds.Release(b,3));
        Assert.All(holds.Provider.Files.Values,x=>Assert.False(x.Held));
        await using var db=fixture.Open();Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="link_opened"));
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="consent_given"));
        Assert.Equal(run.TokenRecord.ExpiresAt,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.TokenRecord.Id)).ExpiresAt);
        Assert.Equal(0,run.Ready.Prepared.Blobs.Deletes);
    }

    [Fact]
    public async Task Effective_hold_denies_original_unused_link_without_consuming_it_then_exact_release_allows_that_same_link()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);using var holds=new Holds(fixture,run);
        var hold=await holds.Place(0);Assert.Null(await Redeem(run));
        await using(var db=fixture.Open())Assert.Null((await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.TokenRecord.Id)).UsedAt);
        Assert.False(await holds.Release(hold,1));Assert.NotNull(await Redeem(run));
        await using var check=fixture.Open();Assert.Equal(run.TokenRecord.ExpiresAt,(await check.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.TokenRecord.Id)).ExpiresAt);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Hold_after_real_preview_blocks_new_proof_and_consent_and_release_never_renews_the_saved_receipt(bool expireReceipt)
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);var identity=(await Redeem(run))!;
        var user=SignerAccessConfiguration.Principal(identity);var (context,receipt)=await Preview(run,user);
        var receipts=new SignerReceiptProtection(run.Record.Keys,run.Record.Time);var saved=receipts.Read(receipt,identity)!;
        using var holds=new Holds(fixture,run);var hold=await holds.Place(0);
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>Pdf(run).PrepareAsync(user,context));
        Assert.Equal(ConsentResult.InvalidContext,await Accept(run,user,receipt));
        await using(var db=fixture.Open())Assert.Null((await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==identity.SignerId)).ConsentAt);
        if(expireReceipt)run.Record.Time.Now=saved.ExpiresAt;
        Assert.False(await holds.Release(hold,1));
        Assert.Equal(expireReceipt?ConsentResult.InvalidEvidence:ConsentResult.Accepted,await Accept(run,user,receipt));
        Assert.Equal(identity.SessionExpiresAt,context.Identity.SessionExpiresAt);
        if(!expireReceipt)Assert.Equal(saved,receipts.Read(receipt,identity));
    }

    [Theory]
    [InlineData("redeem")][InlineData("consent")]
    public async Task Unknown_SQL_acknowledgement_exposes_no_new_session_or_replays_the_original_mutation(string action)
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);ClaimsPrincipal? principal=null;string? receipt=null;
        if(action=="consent"){principal=SignerAccessConfiguration.Principal((await Redeem(run))!);receipt=(await Preview(run,principal)).Receipt;}
        string connection;await using(var source=fixture.Open())connection=source.Database.GetConnectionString()!;
        await using(var lost=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
        {
            if(action=="redeem")await Assert.ThrowsAsync<IOException>(()=>Access(run,lost).RedeemAsync(run.Token,null,null));
            else await Assert.ThrowsAsync<IOException>(()=>Consent(run,lost).AcceptAsync(principal!,run.Ready.Original.PublicId,receipt,true,true,"preview",null,null));
        }
        var before=await run.Record.Journal.ReadAsync(run.Record.Id);Assert.NotNull(before.OutstandingOperation);Assert.True(before.Outcomes!.ContainsKey(before.OutstandingOperation!.Value));
        if(action=="redeem")Assert.Null(await Redeem(run));else Assert.Equal(ConsentResult.AlreadyAccepted,await Accept(run,principal!,receipt!));
        Assert.Equal(before.HeadHash,(await run.Record.Journal.ReadAsync(run.Record.Id)).HeadHash);
        await using var check=fixture.Open();Assert.Equal(1,await check.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event==(action=="redeem"?"link_opened":"consent_given")));
        Assert.Equal(run.TokenRecord.ExpiresAt,(await check.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.TokenRecord.Id)).ExpiresAt);
    }

    [Fact]
    public async Task Session_expiring_during_exact_PDF_copy_cannot_produce_fresh_access_evidence()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);var identity=(await Redeem(run))!;
        var principal=SignerAccessConfiguration.Principal(identity);SignerReadContext context;
        await using(var db=fixture.Open())context=(await Access(run,db).GetContextAsync(principal,run.Ready.Original.PublicId))!;
        run.Ready.Prepared.Blobs.AfterCopy=()=>{run.Record.Time.Now=identity.SessionExpiresAt;return Task.CompletedTask;};
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>Pdf(run).PrepareAsync(principal,context));
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task Hold_arriving_during_PDF_copy_prevents_new_proof_but_exact_release_keeps_the_original_session_usable()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);var identity=(await Redeem(run))!;
        var principal=SignerAccessConfiguration.Principal(identity);SignerReadContext context;
        await using(var db=fixture.Open())context=(await Access(run,db).GetContextAsync(principal,run.Ready.Original.PublicId))!;
        using var holds=new Holds(fixture,run);ProductionHoldCommand? hold=null;
        run.Ready.Prepared.Blobs.AfterCopy=async()=>{hold=await holds.Place(0);};
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>Pdf(run).PrepareAsync(principal,context));Assert.NotNull(hold);
        run.Ready.Prepared.Blobs.AfterCopy=null;Assert.False(await holds.Release(hold!,1));
        Assert.Equal(context.DocumentSha256,SHA256.HashData(await Pdf(run).PrepareAsync(principal,context)));
        Assert.Equal(identity.SessionExpiresAt,context.Identity.SessionExpiresAt);
    }

    [Fact]
    public async Task Changed_or_restored_business_SQL_cannot_authorize_new_PDF_evidence_from_an_older_valid_session()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);var identity=(await Redeem(run))!;
        var principal=SignerAccessConfiguration.Principal(identity);SignerReadContext context;
        await using(var db=fixture.Open())context=(await Access(run,db).GetContextAsync(principal,run.Ready.Original.PublicId))!;
        var state=await run.Record.Journal.ReadAsync(run.Record.Id);var copies=run.Ready.Prepared.Blobs.Copies;
        await using(var db=fixture.Open())await db.Signers.Where(x=>x.Id==identity.SignerId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FullName,"Synthetic unacknowledged restored business row"));
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>Pdf(run).PrepareAsync(principal,context));
        Assert.Equal(copies,run.Ready.Prepared.Blobs.Copies);Assert.Equal(state.HeadHash,(await run.Record.Journal.ReadAsync(run.Record.Id)).HeadHash);
    }

    [Fact]
    public async Task Genuine_unenrolled_demo_keeps_its_actual_decline_path_with_the_opt_in_helpers_configured()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture,demo:true);
        var session=(await Redeem(run))!;Assert.NotNull(session);var user=SignerAccessConfiguration.Principal(session);
        await using var db=fixture.Open();Assert.NotNull(await Consent(run,db).DeclineAsync(user,run.Ready.Original.PublicId,"Synthetic demo refusal",null,null));
        Assert.Equal(EnvelopeStatus.Declined,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id)).Status);
        Assert.Equal(0,(await run.Record.Journal.ReadAsync(run.Record.Id)).Sequence);
        Assert.Equal(1,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Template=="signer-declined"));
        Assert.Equal(run.TokenRecord.ExpiresAt,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.TokenRecord.Id)).ExpiresAt);
    }
    [Fact]
    public async Task Production_decline_waits_for_exact_release_then_commits_one_terminal_and_notification_without_renewal()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);var user=SignerAccessConfiguration.Principal((await Redeem(run))!);
        using var holds=new Holds(fixture,run);var hold=await holds.Place(0);
        await using var db=fixture.Open();var before=await run.Record.Journal.ReadAsync(run.Record.Id);
        Assert.Null(await Consent(run,db).DeclineAsync(user,run.Ready.Original.PublicId,"Synthetic refusal",null,null));
        Assert.Equal(before.HeadHash,(await run.Record.Journal.ReadAsync(run.Record.Id)).HeadHash);
        Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id)).Status);
        Assert.False(await holds.Release(hold,1));
        Assert.NotNull(await Consent(run,db).DeclineAsync(user,run.Ready.Original.PublicId,"Synthetic refusal",null,null));
        Assert.Equal(EnvelopeStatus.Declined,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id)).Status);
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="declined"));
        Assert.Equal(1,await db.ProductionRetentionTerminals.CountAsync(x=>x.EnvelopeId==run.Record.Id));
        Assert.Equal(1,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Template=="signer-declined"));
        Assert.Equal(run.TokenRecord.ExpiresAt,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.TokenRecord.Id)).ExpiresAt);
        Assert.Null(await Consent(run,db).DeclineAsync(user,run.Ready.Original.PublicId,"Synthetic refusal",null,null));
    }

    internal static ProductionSignerMutationAdmission Hook(ProductionInvitationWorkerAdmissionTests.Delivered run)=>new(run.Record.Admission);
    internal static SignerAccess Access(ProductionInvitationWorkerAdmissionTests.Delivered run,QuillSignDbContext db)
        =>new(db,new(db,run.Record.Time),new(),run.Record.Time){HoldAdmission=Hook(run)};
    internal static SignerConsent Consent(ProductionInvitationWorkerAdmissionTests.Delivered run,QuillSignDbContext db)
        =>new(db,Access(run,db),new(run.Record.Keys,run.Record.Time),new(db,run.Record.Time),
            new DeclineNotificationWriter(db,()=>run.Ready.Signals,new(){Enabled=true},new(run.Record.Keys),run.Record.Time),run.Record.Time){HoldAdmission=Hook(run)};
    internal static SignerPdfAccess Pdf(ProductionInvitationWorkerAdmissionTests.Delivered run)
        =>new(run.Ready.Prepared.Blobs,new()){HoldAdmission=Hook(run)};
    internal async Task<VerifiedSigner?> Redeem(ProductionInvitationWorkerAdmissionTests.Delivered run)
    {await using var db=fixture.Open();return await Access(run,db).RedeemAsync(run.Token,null,null);}
    internal async Task<ConsentResult> Accept(ProductionInvitationWorkerAdmissionTests.Delivered run,ClaimsPrincipal principal,string receipt)
    {await using var db=fixture.Open();return await Consent(run,db).AcceptAsync(principal,run.Ready.Original.PublicId,receipt,true,true,"preview",null,null);}
    internal async Task<(SignerReadContext Context,string Receipt)> Preview(ProductionInvitationWorkerAdmissionTests.Delivered run,ClaimsPrincipal user)
    {
        await using var db=fixture.Open();var context=(await Access(run,db).GetContextAsync(user,run.Ready.Original.PublicId))!;Assert.NotNull(context);
        var bytes=await Pdf(run).PrepareAsync(user,context);Assert.Equal(context.DocumentSha256,SHA256.HashData(bytes));
        return(context,new SignerReceiptProtection(run.Record.Keys,run.Record.Time).Create(context));
    }
    private sealed class LostCommit:DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)
            =>throw new IOException("Synthetic unknown signer SQL acknowledgement.");
    }
    internal sealed class Holds:IDisposable
    {
        internal readonly ProductionHoldArchiveReleaseTests.Provider Provider=new();
        private readonly SqlDatabaseFixture fixture;private readonly ProductionInvitationWorkerAdmissionTests.Delivered run;private readonly BlobServiceClient service;
        private readonly IProductionHoldObjectSource objects;
        private readonly IProductionCompletionInputSource? completionInputs;
        internal Holds(SqlDatabaseFixture fixture,ProductionInvitationWorkerAdmissionTests.Delivered run,
            IProductionHoldObjectSource? objects=null,IProductionCompletionInputSource? completionInputs=null)
        {
            this.fixture=fixture;this.run=run;this.objects=objects??run.Ready.Prepared.Blobs;this.completionInputs=completionInputs;
            foreach(var pair in run.Ready.Prepared.Blobs.Objects)Provider.SourceFiles.Add(run.Ready.Prepared.Blobs.Address(pair.Key),pair.Value.ToArray());
            var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03){Transport=new HttpClientTransport(new HttpClient(Provider,false))};options.Retry.MaxRetries=0;
            service=new(new Uri("https://storage.example.invalid"),new ProductionHoldArchiveReleaseTests.Credential(),options);
        }
        internal ProductionHoldCoordinator Coordinator()=>new(fixture.Open,run.Record.Keys,run.Record.Time,run.Record.Journal,objects,new(service),new(service),
            reviewInputs:run.Ready.Prepared.Blobs,completionInputs:completionInputs);
        internal async Task<ProductionHoldCommand> Place(long expected)
        {
            var command=ProductionHoldWitnessJournalTests.Place(run.Record.Id,expected);
            await Preserve(command);return command;
        }
        internal async Task Preserve(ProductionHoldCommand command)
        {
            await Coordinator().SubmitAsync(Authority(run.Record.Time,command.Permission),Operators,command);
            Assert.True((await Coordinator().PreserveAsync(run.Record.Id,command.HoldId,Guid.NewGuid())).Holds[command.HoldId].Effective);
        }
        internal async Task<bool> Release(ProductionHoldCommand place,long revision)
        {
            var release=place with{CommandId=Guid.NewGuid(),Operation=ProductionHoldOperation.Release,ExpectedRevision=revision};
            await Coordinator().SubmitAsync(Authority(run.Record.Time,release.Permission),Operators,release);
            return(await Coordinator().ReleaseAsync(run.Record.Id,place.HoldId)).Frozen;
        }
        public void Dispose()=>Provider.Dispose();
    }
}
