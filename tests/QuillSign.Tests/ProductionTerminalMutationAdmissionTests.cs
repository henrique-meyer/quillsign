using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using QuillSign.Email;

namespace QuillSign.Tests;

public sealed class ProductionTerminalMutationAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Void_is_frozen_before_SQL_then_exact_release_allows_one_original_sender_command_and_bounded_notices()
    {
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run);
        var hold=await holds.Place(0);await using var db=fixture.Open();
        var original=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id);
        var checkpoints=new SignerCheckpointState(db,run.Record.Time);
        var audit=new AuditWriter(db,run.Record.Time);
        var jobs=new VoidNotificationJobs(db,new(db,checkpoints,run.Record.Time),new(run.Record.Keys),()=>run.Ready.Signals,new(){Enabled=true},audit,run.Record.Time);
        var action=new SenderVoid(db,checkpoints,audit,run.Record.Time,()=>jobs){HoldAdmission=new(run.Record.Admission)};
        var ticketUntil=run.Record.Time.Now.AddHours(1);
        Task<SenderVoidResult> Void()=>action.VoidAsync(run.Ready.Prepared.Sender,original.PublicId,ticketUntil,
            original.RowVersion,true,SenderVoidStatement.Version,"Synthetic void",null,null);
        Assert.Equal(SenderVoidOutcome.InvalidContext,(await Void()).Outcome);
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="voided"));
        Assert.False(await holds.Release(hold,1));
        Assert.Equal(SenderVoidOutcome.Voided,(await Void()).Outcome);
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="voided"));
        Assert.Equal(1,await db.ProductionRetentionTerminals.CountAsync(x=>x.EnvelopeId==run.Record.Id));
        Assert.Equal(2,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Template==VoidNotificationJobs.Template));
        Assert.Equal(original.ExpiresAt,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id)).ExpiresAt);
        Assert.Equal(SenderVoidOutcome.AlreadyVoided,(await Void()).Outcome);
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SignerAccess).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddScoped<RazorEmailViews>();
        await using var app=builder.Build();using var viewsScope=app.Services.CreateScope();
        var views=viewsScope.ServiceProvider.GetRequiredService<RazorEmailViews>();
        var email=new EmailOptions{Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};
        var admission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission);
        var store=new WorkStore(db,new(){Enabled=true},run.Record.Time,admission);
        var handler=new EmailWorkHandler(db,email,new(run.Record.Keys),new(email,views),run.Sender,run.Record.Time,
            voids:()=>new(db,jobs,new(run.Record.Keys),()=>new(views),run.Sender,email,audit,run.Record.Time)){HoldAdmission=admission};
        var notices=await db.EmailOutbox.Where(x=>x.EnvelopeId==run.Record.Id&&x.Template==VoidNotificationJobs.Template).Select(x=>x.Id).ToArrayAsync();
        foreach(var id in notices)
        {
            var lease=(await store.ClaimAsync(id,default)).Lease;Assert.NotNull(lease);
            var delivered=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,delivered.Outcome);
            await store.FinishAsync(lease,delivered,default);
        }
        Assert.Equal(3,run.Sender.Calls);
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
        Assert.Equal(2,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="void_notification_submitted"));
        // Reuse this exact runtime record after both provider/Finish receipts;
        // the connected coordinator must accept the complete terminal history.
        var terminalHold=await holds.Place(2);
        Assert.True((await holds.Coordinator().ReadVerifiedAsync(run.Record.Id)).Holds[terminalHold.HoldId].Effective);
        Assert.False(await holds.Release(terminalHold,3));
    }

    [Fact]
    public async Task Due_expiry_Claim_is_frozen_before_attempt_then_drains_one_exact_handler_and_Finish_after_release()
    {
        var ready=await ProductionRecordSendAdmissionTests.Ready.Create(fixture,requestedDeadline:true);
        await using var run=new ProductionInvitationWorkerAdmissionTests.Delivered(fixture,ready);
        Assert.NotNull(await ready.Send());
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run);
        var hold=await holds.Place(0);await using var db=fixture.Open();
        var original=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id);
        run.Record.Time.Now=original.ExpiresAt!.Value.AddSeconds(1);
        var id=SigningExpiryJobs.WorkId(run.Record.Id);
        var admission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission);
        var store=new WorkStore(db,new(){Enabled=true},run.Record.Time,admission);
        Assert.Null((await store.ClaimAsync(id,default)).Lease);
        Assert.Equal(0,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)).Attempts);
        Assert.False(await holds.Release(hold,1));
        var lease=(await store.ClaimAsync(id,default)).Lease;Assert.NotNull(lease);
        var expiry=new SigningExpiry(db,new(db,run.Record.Time),new(db,run.Record.Time),run.Record.Time)
            {HoldAdmission=new(run.Record.Admission),WorkHoldAdmission=admission};
        var handler=new SigningExpiryHandler(db,expiry);
        var result=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);
        await store.FinishAsync(lease,result,default);
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
        Assert.Equal(EnvelopeStatus.Expired,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id)).Status);
        Assert.Equal(original.ExpiresAt,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Record.Id)).ExpiresAt);
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Record.Id&&x.Event=="expired"));
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)).Status);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Deliberate_resend_or_contact_correction_waits_for_release_then_its_original_worker_finishes_once(bool correction)
    {
        // Contact retirement preserves the actual assigned field definitions;
        // a fieldless helper is not a valid contact-correction fixture.
        await using var run=await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture,withFields:correction);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run);await using var db=fixture.Open();
        var work=new WorkOptions{Enabled=true};var email=new EmailOptions{Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};
        var access=new SignerAccess(db,new(db,run.Record.Time),new(),run.Record.Time);
        var originals=new SignerInvitationProtection(run.Record.Keys);var resends=new InvitationResendProtection(run.Record.Keys);
        var successors=new InvitationSuccessorProtection(run.Record.Keys);var lineage=new InvitationLineage(db,originals,resends,successors,run.Record.Time);
        var audit=new AuditWriter(db,run.Record.Time);
        var contactOptions=new SignerContactCorrectionOptions{Enabled=true,DailyAddressRequests=10,DailyIpRequests=10,DailySenderRequests=10,DailyRequests=10};
        var contactPolicy=new SignerContactCorrectionPolicy(db,contactOptions,email,work,run.Record.Time);
        var jobs=new InvitationSuccessorJobs(db,access,lineage,successors,[contactPolicy],work,email,()=>run.Ready.Signals,audit,run.Record.Time);
        var resendOptions=new InvitationResendOptions{Enabled=true,DailyAddressRequests=10,DailyIpRequests=10,DailySenderRequests=10,DailyRequests=10};
        var contact=new SignerContactCorrections(db,contactOptions,email,work,access,lineage,jobs,audit,run.Record.Time){HoldAdmission=new(run.Record.Admission)};
        var resend=new InvitationResends(db,resendOptions,email,work,resends,originals,access,audit,()=>run.Ready.Signals,run.Record.Time,lineage,successors)
            {HoldAdmission=new(run.Record.Admission)};
        var until=run.Record.Time.Now.AddHours(1);var reviewUntil=run.Record.Time.Now.AddMinutes(5);var request=Guid.NewGuid();
        var contactReview=correction?(await contact.PreviewAsync(run.Ready.Prepared.Sender,run.Ready.Original.PublicId,until,"corrected@example.invalid"))!.Review:null;
        var resendReview=correction?null:await resend.ReviewAsync(run.Ready.Prepared.Sender,run.Ready.Original.PublicId,until);
        async Task Request(bool blocked)
        {
            if(correction)Assert.Equal(blocked?SignerContactCorrectionOutcome.Unavailable:SignerContactCorrectionOutcome.Queued,
                await contact.RequestAsync(run.Ready.Prepared.Sender,run.Ready.Original.PublicId,until,request,contactReview!,true,
                SignerContactCorrectionStatement.Version,"127.0.0.1",null,reviewExpiresAt:reviewUntil));
            else Assert.Equal(blocked?InvitationResendOutcome.Unavailable:InvitationResendOutcome.Queued,
                await resend.RequestAsync(run.Ready.Prepared.Sender,run.Ready.Original.PublicId,until,request,resendReview!,true,
                InvitationResendStatement.Version,"127.0.0.1",null,reviewExpiresAt:reviewUntil));
        }
        var hold=await holds.Place(0);await Request(true);
        Assert.False(await holds.Release(hold,1));
        await Request(false);
        var mailId=correction?InvitationSuccessorJobs.CorrectionWorkId(request):request;
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SignerAccess).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddScoped<RazorEmailViews>();
        await using var app=builder.Build();using var viewsScope=app.Services.CreateScope();var views=viewsScope.ServiceProvider.GetRequiredService<RazorEmailViews>();
        var admission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission);
        var store=new WorkStore(db,work,run.Record.Time,admission);
        var handler=new EmailWorkHandler(db,email,new(run.Record.Keys),new(email,views),run.Sender,run.Record.Time,
            resends:()=>new(db,resendOptions,resends,access,new(new(),run.Record.Time),new(email,views),run.Sender,email,work,audit,run.Record.Time,lineage,successors),
            successors:()=>new(db,successors,jobs,lineage,access,new(new(),run.Record.Time),new(email,views),run.Sender,email,work,audit,run.Record.Time)){HoldAdmission=admission};
        var lease=(await store.ClaimAsync(mailId,default)).Lease;Assert.NotNull(lease);
        var result=await handler.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);
        await store.FinishAsync(lease,result,default);
        Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
        Assert.Equal(2,run.Sender.Calls);
        Assert.Equal(EmailStatus.Sent,(await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==mailId)).Status);
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==mailId)).Status);
        Assert.Equal(correction?"corrected@example.invalid":run.TokenRecord.Email,(await db.Signers.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Record.Id)).Email);
        Assert.True((await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==run.TokenRecord.Id)).ExpiresAt<=run.TokenRecord.ExpiresAt);
    }
}
