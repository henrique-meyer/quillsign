using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionInvitationWorkerAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_initial_invitation_has_one_exact_token_provider_receipt_handler_checkpoint_and_Finish()
    {
        await using var run=await Delivered.Create(fixture);await using var db=fixture.Open();
        var record=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id);
        var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId);
        var work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId);
        Assert.Equal(1,run.Sender.Calls);Assert.Equal(EmailStatus.Sent,mail.Status);Assert.Equal(WorkStatus.Completed,work.Status);
        Assert.Equal("SyntheticInitialCapture",mail.Provider);Assert.Equal("synthetic-initial-receipt",mail.ProviderMessageId);
        Assert.Equal(SignerStatus.Notified,(await db.Signers.SingleAsync(x=>x.Id==run.TokenRecord.PartyId)).Status);
        Assert.Equal(record.Id,run.TokenRecord.EnvelopeId);Assert.Equal(TokenPurpose.SignerAccess,run.TokenRecord.Purpose);Assert.Null(run.TokenRecord.UsedAt);
        Assert.Equal(record.SentPdfBlob,run.TokenRecord.DocumentId!.Value.ToString("N"));Assert.Equal(record.SentPdfSha256,run.TokenRecord.DocumentSha256);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(run.Token)),run.TokenRecord.TokenSha256);
        Assert.Equal(run.TokenRecord.Id,new SignerInvitationProtection(run.Record.Keys).Read(mail.PayloadJson).LastTokenId);
        var state=await run.Record.Journal.ReadAsync(run.Record.Id);Assert.True(state.HandlerOutcomes!.ContainsKey(run.Lease.Owner));Assert.Null(state.OutstandingOperation);
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==run.Record.Id && x.Event=="invitation_submitted").ToArrayAsync());
    }

    [Fact]
    public async Task Hold_before_claim_has_no_lease_token_or_provider_effect()
    {
        await using var run=await Delivered.Pending(fixture);var hold=Place(run.Record.Id);
        await run.Record.Journal.IntentAsync(Authority(run.Record.Time,hold.Permission),Operators,hold,Guid.NewGuid());
        await using var db=fixture.Open();Assert.Null((await run.Store(db).ClaimAsync(run.WorkId,default)).Lease);
        Assert.Equal(0,run.Sender.Calls);Assert.Equal(0,(await db.WorkItems.SingleAsync(x=>x.Id==run.WorkId)).Attempts);
        Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess));
    }

    [Fact]
    public async Task Hold_intent_during_provider_only_allows_the_original_admitted_invitation_to_drain()
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();var hold=Place(run.Record.Id);
        run.Sender.Before=async()=>await run.Record.Journal.IntentAsync(Authority(run.Record.Time,hold.Permission),Operators,hold,Guid.NewGuid());
        Assert.Equal(WorkOutcome.Completed,(await run.ExecuteAsync()).Outcome);await run.FinishAsync();
        var state=await run.Record.Journal.ReadAsync(run.Record.Id);Assert.Equal(hold,state.Unacknowledged);Assert.Null(state.OutstandingOperation);Assert.Equal(1,run.Sender.Calls);
    }

    [Fact]
    public async Task Foreign_worker_tuple_cannot_issue_a_token_or_send()
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();
        foreach(var lease in new[]{run.Lease with{Owner=Guid.NewGuid()},run.Lease with{Attempt=run.Lease.Attempt+1},
            run.Lease with{Until=run.Lease.Until.AddSeconds(1)},run.Lease with{Kind=WorkKind.Sealing}})
            await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync(lease:lease));
        Assert.Equal(0,run.Sender.Calls);
        await using var db=fixture.Open();Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess));
    }

    [Fact]
    public async Task Dirty_or_already_transactional_caller_cannot_flush_foreign_pending_rows()
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();await using var db=fixture.Open();
        var foreign=new Envelope{SenderEmail="synthetic-unadmitted@example.invalid"};db.Add(foreign);
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync(db));Assert.Equal(0,run.Sender.Calls);
        await using(var check=fixture.Open())Assert.False(await check.Envelopes.AnyAsync(x=>x.Id==foreign.Id));
        db.ChangeTracker.Clear();await using var tx=await db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync(db));
    }

    [Fact]
    public async Task Unknown_provider_outcome_and_same_lease_SQL_restore_cannot_mint_or_send_again()
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();string original;
        await using(var db=fixture.Open())original=(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId)).PayloadJson;
        run.Sender.Failure=new IOException("Synthetic unknown provider acknowledgement");
        await Assert.ThrowsAsync<IOException>(()=>run.ExecuteAsync());Assert.Equal(1,run.Sender.Calls);
        await using(var restore=fixture.Open())
        {
            await using var tx=await restore.Database.BeginTransactionAsync();
            await restore.AuthTokens.Where(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess).ExecuteDeleteAsync();
            await restore.EmailOutbox.Where(x=>x.Id==run.WorkId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,original)
                .SetProperty(x=>x.SubmissionStartedAt,(DateTimeOffset?)null).SetProperty(x=>x.Attempts,0));await tx.CommitAsync();
        }
        run.Sender.Failure=null;await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync());
        Assert.Equal(1,run.Sender.Calls);await using var check=fixture.Open();Assert.False(await check.AuthTokens.AnyAsync(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess));
        Assert.Equal(run.Lease.Owner,(await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task Lost_external_dispatch_start_ack_rolls_back_SQL_and_never_returns_a_second_provider_permit()
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();run.Record.External.LostAck=true;
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync());Assert.Equal(0,run.Sender.Calls);
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync());
        await using var db=fixture.Open();Assert.Null((await db.EmailOutbox.SingleAsync(x=>x.Id==run.WorkId)).SubmissionStartedAt);
        Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess));
    }

    [Fact]
    public async Task Restoring_post_claim_invitation_rows_after_handler_receipt_cannot_become_Finish()
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();Assert.Equal(WorkOutcome.Completed,(await run.ExecuteAsync()).Outcome);
        var checkpoint=(await run.Record.Journal.ReadAsync(run.Record.Id)).HandlerOutcomes![run.Lease.Owner];
        await using(var restore=fixture.Open())await restore.AuthTokens.Where(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess).ExecuteDeleteAsync();
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.FinishAsync());
        Assert.Equal(checkpoint,(await run.Record.Journal.ReadAsync(run.Record.Id)).HandlerOutcomes![run.Lease.Owner]);Assert.Equal(1,run.Sender.Calls);
    }

    [Theory]
    [InlineData("payload")][InlineData("token")][InlineData("source")][InlineData("lease")][InlineData("clock")]
    public async Task Provider_callback_substitution_cannot_get_a_receipt_or_handler_checkpoint(string fault)
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();
        run.Sender.Before=async()=> {
            await using var changed=fixture.Open();
            if(fault=="payload")await changed.EmailOutbox.Where(x=>x.Id==run.WorkId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
            if(fault=="token")await changed.AuthTokens.Where(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,run.Record.Time.Now.AddDays(3)));
            if(fault=="source")await changed.Envelopes.Where(x=>x.Id==run.Record.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,new byte[32]));
            if(fault=="lease")await changed.WorkItems.Where(x=>x.Id==run.WorkId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.LeaseExpiresAt,run.Lease.Until.AddMinutes(1)));
            if(fault=="clock")run.Record.Time.Now=run.Lease.Until;
        };
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync());var state=await run.Record.Journal.ReadAsync(run.Record.Id);
        Assert.False(state.HandlerOutcomes!.ContainsKey(run.Lease.Owner));Assert.Equal(1,run.Sender.Calls);
        await using var db=fixture.Open();Assert.Null((await db.EmailOutbox.SingleAsync(x=>x.Id==run.WorkId)).ProviderMessageId);
    }

    [Fact]
    public async Task Original_requested_access_deadline_crossed_after_provider_cannot_mint_receipt_even_with_live_lease()
    {
        await using var run=new Delivered(fixture,await ProductionRecordSendAdmissionTests.Ready.Create(fixture,requestedDeadline:true));
        run.WorkId=(await run.Ready.Send())!.InvitationWorkId;DateTimeOffset deadline;
        await using(var saved=fixture.Open())deadline=(await saved.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id)).ExpiresAt!.Value;
        run.Record.Time.Now=deadline.AddSeconds(-10);await run.ClaimAsync();Assert.True(run.Lease.Until>deadline);
        run.Sender.Before=()=>{run.Record.Time.Now=deadline;return Task.CompletedTask;};
        await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync());
        await using var db=fixture.Open();var token=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess);
        Assert.Equal(deadline,token.ExpiresAt);Assert.Null((await db.EmailOutbox.SingleAsync(x=>x.Id==run.WorkId)).ProviderMessageId);
        Assert.Equal(1,run.Sender.Calls);Assert.False((await run.Record.Journal.ReadAsync(run.Record.Id)).HandlerOutcomes!.ContainsKey(run.Lease.Owner));
    }

    [Fact]
    public async Task Known_not_submitted_cleanup_is_owned_but_does_not_unblock_retry_or_renew_the_token()
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();run.Sender.Failure=new EmailNotSubmittedException(true);
        Assert.Equal(WorkOutcome.Retry,(await run.ExecuteAsync()).Outcome);
        await using var db=fixture.Open();var token=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Record.Id && x.Purpose==TokenPurpose.SignerAccess);
        Assert.Equal(run.Record.Time.Now,token.ExpiresAt);Assert.Null((await db.EmailOutbox.SingleAsync(x=>x.Id==run.WorkId)).SubmissionStartedAt);
        Assert.Equal(run.Lease.Owner,(await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
        run.Sender.Failure=null;await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>run.ExecuteAsync());Assert.Equal(1,run.Sender.Calls);
    }

    [Fact]
    public async Task Lost_Finish_ack_is_reconciled_from_exact_SQL_without_provider_replay()
    {
        await using var run=await Delivered.Pending(fixture);await run.ClaimAsync();await run.ExecuteAsync();string connection;
        await using(var source=fixture.Open())connection=source.Database.GetConnectionString()!;
        await using(var lost=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
            await Assert.ThrowsAsync<IOException>(()=>run.FinishAsync(lost));
        await using var db=fixture.Open();await run.Store(db).ReconcileCompletedAsync(run.Lease,run.Record.Id);Assert.Equal(1,run.Sender.Calls);
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
    }

    [Theory]
    [InlineData("future")][InlineData("duplicate")]
    public void Closed_initial_payload_reader_rejects_correctly_protected_unknown_or_duplicate_properties(string fault)
    {
        var keys=new EphemeralDataProtectionProvider();var protection=new SignerInvitationProtection(keys);
        var payload=new SignerInvitationPayload(Guid.NewGuid(),DocumentId:Guid.NewGuid(),DocumentSha256:new('b',64),DisclosureSha256:new('c',64));
        Assert.Equal(payload,protection.ReadCanonical(protection.Protect(payload)));
        var plain=JsonSerializer.Serialize(payload);
        if(fault=="future") {var node=JsonNode.Parse(plain)!;node["FutureObjectReference"]=Guid.NewGuid();plain=node.ToJsonString();}
        else plain=plain[..^1]+",\"SignerId\":\""+payload.SignerId+"\"}";
        var encoded=JsonSerializer.Serialize(new ProtectedWorkPayload(keys.CreateProtector("QuillSign.SignerInvitationPayload.v1").Protect(plain)));
        Assert.Throws<InvalidDataException>(()=>protection.ReadCanonical(encoded));
    }

    private sealed class LostCommit:DbTransactionInterceptor
    {public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData data,CancellationToken ct=default)=>throw new IOException("Synthetic lost Finish acknowledgement");}

    internal sealed class Capture:IEmailSender
    {
        internal int Calls;internal OutgoingEmail? Message;internal Func<Task>? Before;internal Exception? Failure;
        public async Task<EmailDelivery> SendAsync(OutgoingEmail message,CancellationToken ct=default)
        {ct.ThrowIfCancellationRequested();Assert.EndsWith("@example.invalid",message.To);Calls++;Message=message;if(Before is not null)await Before();if(Failure is not null)throw Failure;return new("SyntheticInitialCapture","synthetic-initial-receipt");}
    }

    internal sealed class Delivered(SqlDatabaseFixture fixture,ProductionRecordSendAdmissionTests.Ready ready):IAsyncDisposable
    {
        internal readonly ProductionRecordSendAdmissionTests.Ready Ready=ready;
        internal ProductionRuntimeAdmissionTests.Run Record=>Ready.Prepared.Run;
        internal readonly Capture Sender=new();internal Guid WorkId;internal WorkLease Lease=null!;internal string Token="";internal AuthToken TokenRecord=null!;
        private readonly WorkOptions work=new(){Enabled=true};
        private readonly EmailOptions email=new(){Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};
        internal static async Task<Delivered> Pending(SqlDatabaseFixture fixture,bool demo=false,bool withFields=false,bool twoSigners=false)
        {var run=new Delivered(fixture,await ProductionRecordSendAdmissionTests.Ready.Create(fixture,demo:demo,withFields:withFields,twoSigners:twoSigners));run.WorkId=(await run.Ready.Send())!.InvitationWorkId;return run;}
        internal static async Task<Delivered> Create(SqlDatabaseFixture fixture,bool demo=false,bool withFields=false,bool twoSigners=false)
        {var run=await Pending(fixture,demo,withFields,twoSigners);await run.ClaimAsync();Assert.Equal(WorkOutcome.Completed,(await run.ExecuteAsync()).Outcome);await run.FinishAsync();return run;}
        internal WorkStore Store(QuillSignDbContext db)=>new(db,work,Record.Time,new ProductionWorkAdmission(fixture.Open,Record.Admission));
        internal async Task<WorkLease> ClaimAsync()
        {await using var db=fixture.Open();Lease=(await Store(db).ClaimAsync(WorkId,default)).Lease!;Assert.NotNull(Lease);return Lease;}
        internal async Task<WorkResult> ExecuteAsync(QuillSignDbContext? supplied=null,WorkLease? lease=null)
        {
            var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SignerAccess).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
            builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddScoped<RazorEmailViews>();
            await using var app=builder.Build();using var services=app.Services.CreateScope();await using var owned=supplied is null?fixture.Open():null;var db=supplied??owned!;
            var views=services.ServiceProvider.GetRequiredService<RazorEmailViews>();var protection=new SignerInvitationProtection(Record.Keys);
            var delivery=new SignerInvitationDelivery(db,new(db,new(db,Record.Time),new(),Record.Time),new(new(),Record.Time),protection,new(email,views),Sender,email,new(db,Record.Time),Record.Time,
                new(db,protection,new(Record.Keys),new(Record.Keys),Record.Time));
            var handler=new EmailWorkHandler(db,email,new(Record.Keys),new(email,views),Sender,Record.Time,invitations:delivery)
                {HoldAdmission=new ProductionWorkAdmission(fixture.Open,Record.Admission)};
            var result=await handler.ExecuteAsync(lease??Lease,default);
            if(Sender.Message is not null)
            {
                Token=Regex.Match(Sender.Message.Text,"token=([A-Za-z0-9_-]{43})",RegexOptions.CultureInvariant).Groups[1].Value;Assert.Equal(43,Token.Length);
                TokenRecord=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==Record.Id && x.Purpose==TokenPurpose.SignerAccess);
            }
            return result;
        }
        internal async Task FinishAsync(QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;await Store(supplied??owned!).FinishAsync(Lease,new(WorkOutcome.Completed),default);}
        public ValueTask DisposeAsync()=>Ready.DisposeAsync();
    }
}
