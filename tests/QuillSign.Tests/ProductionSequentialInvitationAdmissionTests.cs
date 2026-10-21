using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionSequentialInvitationAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Actual_second_initial_invitation_uses_processed_checkpoint_and_preserves_prior_party_tokens()
    {
        await using var run=await Next.Create(fixture);var previous=await run.Tokens();
        var lease=await run.Claim();Assert.NotNull(lease);Assert.Equal(WorkOutcome.Completed,(await run.Execute(lease!)).Outcome);await run.Finish(lease!);
        await using var db=fixture.Open();var token=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Id&&x.Purpose==TokenPurpose.SignerAccess&&x.PartyId==run.Party.Id);
        Assert.Equal(run.FinishRow.PdfObjectId,token.DocumentId);Assert.Equal(run.FinishRow.PdfSha256,token.DocumentSha256);
        Assert.Equal(run.Party.Email,token.Email);Assert.Equal(1,run.Sender.Calls);Assert.Null(token.UsedAt);
        Assert.Equal(previous,await run.Tokens(priorOnly:true));Assert.Equal(2,await db.AuthTokens.CountAsync(x=>x.EnvelopeId==run.Id&&x.Purpose==TokenPurpose.SignerAccess));
        Assert.Equal(SignerStatus.Notified,(await db.Signers.SingleAsync(x=>x.Id==run.Party.Id)).Status);
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.SingleAsync(x=>x.Id==run.WorkId)).Status);
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.Null(state.OutstandingOperation);Assert.True(state.DispatchStarts!.ContainsKey(lease!.Owner));
    }

    [Fact]
    public async Task Hold_before_second_claim_has_no_target_issuance_and_original_provider_cut_is_unchanged()
    {
        await using var run=await Next.Create(fixture);var previous=await run.Tokens();var command=Place(run.Id);
        await run.Record.Journal.IntentAsync(Authority(run.Record.Time,command.Permission),Operators,command,Guid.NewGuid());
        Assert.Null(await run.Claim());Assert.Equal(0,run.Sender.Calls);Assert.Equal(previous,await run.Tokens());
        await using var db=fixture.Open();Assert.Equal(0,(await db.WorkItems.SingleAsync(x=>x.Id==run.WorkId)).Attempts);
    }

    [Theory]
    [InlineData("predecessor")][InlineData("source")][InlineData("earlier-status")][InlineData("target-token")][InlineData("target-consent")]
    public async Task Changed_prefix_or_preissued_target_is_refused_before_second_claim(string fault)
    {
        await using var run=await Next.Create(fixture);
        await using(var db=fixture.Open())
        {
            if(fault=="predecessor")await db.SignerFinishAcceptances.Where(x=>x.Id==run.FinishRow.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.NextInvitationId,Guid.NewGuid()));
            if(fault=="source")await db.SignerFinishAcceptances.Where(x=>x.Id==run.FinishRow.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PdfSha256,new byte[32]));
            if(fault=="earlier-status")await db.Signers.Where(x=>x.Id==run.FinishRow.SignerId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Viewed));
            if(fault=="target-consent")await db.Signers.Where(x=>x.Id==run.Party.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ConsentAt,run.Record.Time.Now));
            if(fault=="target-token")
            {db.AuthTokens.Add(new(){EnvelopeId=run.Id,PartyId=run.Party.Id,PartyType=PartyType.Signer,Purpose=TokenPurpose.SignerAccess,Email=run.Party.Email,ExpiresAt=run.Record.Time.Now.AddHours(1),TokenSha256=new byte[32]});await db.SaveChangesAsync();}
        }
        Assert.Null(await run.Claim());Assert.Equal(0,run.Sender.Calls);await using var check=fixture.Open();Assert.Equal(0,(await check.WorkItems.SingleAsync(x=>x.Id==run.WorkId)).Attempts);
    }

    [Fact]
    public async Task Once_admitted_second_invitation_can_drain_a_new_hold_but_cannot_admit_a_new_worker()
    {
        await using var run=await Next.Create(fixture);var lease=(await run.Claim())!;var command=Place(run.Id);
        run.Sender.Before=async()=>await run.Record.Journal.IntentAsync(Authority(run.Record.Time,command.Permission),Operators,command,Guid.NewGuid());
        Assert.Equal(WorkOutcome.Completed,(await run.Execute(lease)).Outcome);await run.Finish(lease);
        var state=await run.Record.Journal.ReadAsync(run.Id);Assert.Equal(command,state.Unacknowledged);Assert.Null(state.OutstandingOperation);Assert.Equal(1,run.Sender.Calls);
    }

    [Fact]
    public async Task Same_lease_restore_after_unknown_second_provider_outcome_never_reissues_target_token_or_permit()
    {
        await using var run=await Next.Create(fixture);var previous=await run.Tokens();var lease=(await run.Claim())!;string original;
        await using(var db=fixture.Open())original=(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId)).PayloadJson;
        run.Sender.Failure=new IOException("Synthetic unknown second invitation acknowledgement");
        await Assert.ThrowsAsync<IOException>(()=>run.Execute(lease));Assert.Equal(1,run.Sender.Calls);
        await using(var db=fixture.Open())
        {
            await using var tx=await db.Database.BeginTransactionAsync();
            await db.AuthTokens.Where(x=>x.EnvelopeId==run.Id&&x.Purpose==TokenPurpose.SignerAccess&&x.PartyId==run.Party.Id).ExecuteDeleteAsync();
            await db.EmailOutbox.Where(x=>x.Id==run.WorkId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,original).SetProperty(x=>x.SubmissionStartedAt,(DateTimeOffset?)null).SetProperty(x=>x.Attempts,0));
            await tx.CommitAsync();
        }
        run.Sender.Failure=null;await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.Execute(lease));
        Assert.Equal(previous,await run.Tokens());Assert.Equal(1,run.Sender.Calls);Assert.Equal(lease.Owner,(await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task Unknown_second_dispatch_start_ack_has_no_provider_call_or_new_SQL_token_and_never_replays()
    {
        await using var run=await Next.Create(fixture);var previous=await run.Tokens();var lease=(await run.Claim())!;run.Record.External.LostAck=true;
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.Execute(lease));await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.Execute(lease));
        Assert.Equal(0,run.Sender.Calls);Assert.Equal(previous,await run.Tokens());
        await using var db=fixture.Open();Assert.Null((await db.EmailOutbox.SingleAsync(x=>x.Id==run.WorkId)).SubmissionStartedAt);
    }

    [Theory]
    [InlineData("prior-head")][InlineData("source")][InlineData("lease-clock")][InlineData("token-clock")]
    public async Task Second_provider_callback_cannot_change_original_source_head_or_deadline_and_obtain_receipt(string fault)
    {
        await using var run=await Next.Create(fixture);var lease=(await run.Claim())!;
        run.Sender.Before=async()=>
        {
            await using var db=fixture.Open();
            if(fault=="prior-head")await db.SignerFinishAcceptances.Where(x=>x.Id==run.FinishRow.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.NextInvitationId,Guid.NewGuid()));
            if(fault=="source")await db.SignerFinishAcceptances.Where(x=>x.Id==run.FinishRow.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PdfSha256,new byte[32]));
            if(fault=="lease-clock")run.Record.Time.Now=lease.Until;
            if(fault=="token-clock")await db.AuthTokens.Where(x=>x.EnvelopeId==run.Id&&x.PartyId==run.Party.Id&&x.Purpose==TokenPurpose.SignerAccess).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,run.Record.Time.Now));
        };
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.Execute(lease));Assert.Equal(1,run.Sender.Calls);
        await using var check=fixture.Open();Assert.Null((await check.EmailOutbox.SingleAsync(x=>x.Id==run.WorkId)).ProviderMessageId);
        Assert.False((await run.Record.Journal.ReadAsync(run.Id)).HandlerOutcomes!.ContainsKey(lease.Owner));
    }

    [Fact]
    public async Task Sealing_remains_closed_even_when_unattempted_and_deterministically_named()
    {
        await using var run=await Next.Create(fixture);var id=CompletionJobs.WorkId(run.Id);
        await using(var db=fixture.Open())
        {db.WorkItems.Add(new(){Id=id,EnvelopeId=run.Id,Kind=WorkKind.Sealing,AvailableAt=run.Record.Time.Now,PayloadJson=JsonSerializer.Serialize(new CompletionWorkPayload(CompletionJobs.Version,run.FinishRow.Id,1,Convert.ToHexStringLower(run.FinishRow.PdfSha256),Convert.ToHexStringLower(run.FinishRow.DisclosureSha256)))});await db.SaveChangesAsync();}
        await using var read=fixture.Open();var claim=await run.Store(read).ClaimAsync(id,default);Assert.Null(claim.Lease);Assert.False(claim.Terminal);
        Assert.Equal(0,(await read.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)).Attempts);Assert.Equal(0,run.Sender.Calls);
    }

    private sealed class Next(SqlDatabaseFixture fixture,ProductionSignerReviewRuntimeContractTests.Flow flow,SignerFinishAcceptance finish,Signer party):IAsyncDisposable
    {
        internal ProductionRuntimeAdmissionTests.Run Record=>flow.Record;
        internal Guid Id=>flow.Id;internal Guid WorkId=>FinishRow.NextInvitationId!.Value;
        internal readonly SignerFinishAcceptance FinishRow=finish;internal readonly Signer Party=party;
        internal readonly ProductionInvitationWorkerAdmissionTests.Capture Sender=new();
        internal static async Task<Next> Create(SqlDatabaseFixture fixture)
        {
            var flow=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture);
            try
            {
                var review=(await flow.Prepare())!;var accepted=await flow.Finish(review.Receipt);Assert.Equal(SignerFinishOutcome.Accepted,accepted.Outcome);
                await flow.Process(accepted.Acceptance!.Id);await using var db=fixture.Open();
                var finish=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==accepted.Acceptance.Id);
                var party=await db.Signers.AsNoTracking().SingleAsync(x=>x.EnvelopeId==flow.Id&&x.Order==2);
                Assert.NotNull(finish.NextInvitationId);return new(fixture,flow,finish,party);
            }
            catch{await flow.DisposeAsync();throw;}
        }
        internal WorkStore Store(QuillSignDbContext db)=>new(db,new(){Enabled=true},Record.Time,new ProductionWorkAdmission(fixture.Open,Record.Admission));
        internal async Task<WorkLease?> Claim(){await using var db=fixture.Open();return(await Store(db).ClaimAsync(WorkId,default)).Lease;}
        internal async Task<string> Tokens(bool priorOnly=false)
        {await using var db=fixture.Open();var rows=await db.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==Id&&x.Purpose==TokenPurpose.SignerAccess&&(!priorOnly||x.PartyId!=Party.Id)).OrderBy(x=>x.Id).ToArrayAsync();return JsonSerializer.Serialize(rows);}
        internal async Task<WorkResult> Execute(WorkLease lease)
        {
            var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SignerAccess).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
            builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddScoped<RazorEmailViews>();
            await using var app=builder.Build();using var scope=app.Services.CreateScope();await using var db=fixture.Open();
            var views=scope.ServiceProvider.GetRequiredService<RazorEmailViews>();var protection=new SignerInvitationProtection(Record.Keys);
            var email=new EmailOptions{Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};
            var delivery=new SignerInvitationDelivery(db,new(db,new(db,Record.Time),new(),Record.Time),new(new(),Record.Time),protection,new(email,views),Sender,email,new(db,Record.Time),Record.Time,
                new(db,protection,new(Record.Keys),new(Record.Keys),Record.Time));
            var handler=new EmailWorkHandler(db,email,new(Record.Keys),new(email,views),Sender,Record.Time,invitations:delivery){HoldAdmission=new ProductionWorkAdmission(fixture.Open,Record.Admission)};
            return await handler.ExecuteAsync(lease,default);
        }
        internal async Task Finish(WorkLease lease){await using var db=fixture.Open();await Store(db).FinishAsync(lease,new(WorkOutcome.Completed),default);}
        public ValueTask DisposeAsync()=>flow.DisposeAsync();
    }
}
