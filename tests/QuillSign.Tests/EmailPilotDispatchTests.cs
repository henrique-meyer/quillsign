using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Completion;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotDispatchTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Newly_issued_completion_link_obeys_caller_authority_limit_without_rewriting_saved_tokens(bool expired)
    {
        await using var f=await CompletionDownloadTests.Flow.Create(fixture);
        await using var db=fixture.Open();var access=CompletionAccessTests.Service(f,db);
        var prepared=(await access.PrepareAsync(f.Id,default))!;
        var limit=f.Clock.GetUtcNow().AddMinutes(expired?-1:10);
        var before=await db.AuthTokens.CountAsync(x=>x.EnvelopeId==f.Id);
        await using var transaction=await db.Database.BeginTransactionAsync();
        var link=await access.PrepareBoundedLockedAsync(prepared,PartyType.Sender,null,default,limit);
        if(expired)Assert.Null(link);
        else {
            Assert.NotNull(link);Assert.Equal(limit,link.ExpiresAt);
            Assert.Equal(limit,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==link.TokenId)).ExpiresAt);
        }
        await transaction.CommitAsync();
        Assert.Equal(before+(expired?0:1),await db.AuthTokens.CountAsync(x=>x.EnvelopeId==f.Id));
    }

    [Theory]
    [InlineData("disabled")][InlineData("expired")][InlineData("different-run")][InlineData("public-enabled")]
    public async Task Persisted_pilot_cohort_never_falls_back_to_ordinary_delivery(string change)
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());var lease=await Claim(h);
        var ordinary=new Capture();var pilotCalls=0;
        var dispatch=Dispatch(h,ordinary,(_,_,_)=>{pilotCalls++;return Task.FromResult(new EmailDelivery("Capture","unused"));});
        if(change=="disabled")h.Options.Enabled=false;
        if(change=="expired")h.Clock.Now+=TimeSpan.FromHours(1);
        if(change=="different-run")h.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="public-enabled")h.Email.Enabled=true;
        var decision=await dispatch.DecideAsync(lease,default);
        Assert.Equal(WorkOutcome.Failed,decision.Refusal!.Outcome);
        await Assert.ThrowsAsync<EmailDisabledException>(()=>dispatch.SendAsync(lease,new(h.Options.Mailboxes.Sender,"subject","text","html"),default));
        Assert.Equal(0,pilotCalls);Assert.Equal(0,ordinary.Calls);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Unenrolled_work_retains_ordinary_public_gate(bool enabled)
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());h.Email.Enabled=enabled;
        var ordinary=new Capture();var dispatch=Dispatch(h,ordinary,(_,_,_)=>throw new Exception("No pilot provider"));
        var envelope=new Envelope{SenderEmail="other@example.invalid"};var work=new WorkItem{EnvelopeId=envelope.Id,Kind=WorkKind.Email};
        h.Db.AddRange(envelope,work);await h.Db.SaveChangesAsync();
        var lease=new WorkLease(work.Id,Guid.NewGuid(),WorkKind.Email,1,h.Clock.Now.AddMinutes(1));
        var decision=await dispatch.DecideAsync(lease,default);Assert.Null(decision.Scope);
        if(enabled)Assert.Null(decision.Refusal);else Assert.Equal(WorkOutcome.Retry,decision.Refusal!.Outcome);
    }

    [Theory]
    [InlineData("success")][InlineData("rejected")][InlineData("unknown")]
    public async Task Normal_verification_intent_and_token_are_used_with_separate_captured_pilot_boundary(string outcome)
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());h.Email.BaseUrl="https://example.invalid/";
        var admitted=(await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion))!;
        h.Clock.Now+=TimeSpan.FromMinutes(58);
        var lease=(await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(admitted.VerificationWorkId,default)).Lease!;
        var ordinary=new Capture();var calls=0;
        var dispatch=Dispatch(h,ordinary,async(current,message,ct)=>{
            calls++;Assert.Equal(lease,current);Assert.Equal(h.Options.Mailboxes.Sender,message.To);
            var intent=await h.Db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==lease.Id,ct);
            Assert.NotNull(intent.SubmissionStartedAt);Assert.Null(h.Db.Database.CurrentTransaction);
            var token=await h.Db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==intent.EnvelopeId,ct);
            Assert.Equal(new DateTimeOffset(2026,10,18,11,0,0,TimeSpan.Zero),token.ExpiresAt);
            Assert.Contains("/sender/verify?token=",message.Text);
            Assert.Null((await h.Db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==intent.EnvelopeId,ct)).SenderVerifiedAt);
            if(outcome=="rejected")throw new EmailNotSubmittedException(false);
            if(outcome=="unknown")throw new IOException("Synthetic unknown provider acknowledgement.");
            return new EmailDelivery("Capture","synthetic-receipt");
        });
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(EmailOptions).Assembly.FullName,
            ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddSingleton(h.Email);builder.Services.AddScoped<RazorEmailViews>();
        await using var app=builder.Build();using var scope=app.Services.CreateScope();
        var template=new VerificationEmailTemplate(h.Email,scope.ServiceProvider.GetRequiredService<RazorEmailViews>());
        var handler=new EmailWorkHandler(h.Db,h.Email,h.Payload,template,ordinary,h.Clock,pilot:dispatch);
        if(outcome=="unknown")await Assert.ThrowsAsync<IOException>(()=>handler.ExecuteAsync(lease,default));
        else Assert.Equal(outcome=="success"?WorkOutcome.Completed:WorkOutcome.Failed,(await handler.ExecuteAsync(lease,default)).Outcome);
        Assert.Equal(1,calls);Assert.Equal(0,ordinary.Calls);Assert.False(h.Email.Enabled);
        var saved=await h.Db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==lease.Id);
        Assert.Equal(outcome=="success"?EmailStatus.Sent:EmailStatus.Queued,saved.Status);
        Assert.Equal(outcome!="rejected",saved.SubmissionStartedAt is not null);
    }

    private static EmailPilotDispatch Dispatch(EmailPilotAdmissionTests.Harness h,IEmailSender ordinary,
        Func<WorkLease,OutgoingEmail,CancellationToken,Task<EmailDelivery>> send)=>new(h.Db,h.Email,
            ()=>new(h.Options,h.Email,h.Work,h.Admission,()=>h.Ledger,()=>h.Db,()=>h.Payload,h.Clock),send,ordinary);
    private static async Task<WorkLease> Claim(EmailPilotAdmissionTests.Harness h)
    {
        var admitted=(await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion))!;
        return(await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(admitted.VerificationWorkId,default)).Lease!;
    }
    private sealed class Capture:IEmailSender
    {
        internal int Calls;
        public Task<EmailDelivery> SendAsync(OutgoingEmail message,CancellationToken ct=default)
        {Calls++;return Task.FromResult(new EmailDelivery("Capture","ordinary"));}
    }
}
