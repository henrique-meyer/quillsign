using System.Text.RegularExpressions;
using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotReadBoundsTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";

    [Fact]
    public void Empty_optional_composition_and_exception_filter_resolve_without_SQL_keys_or_provider()
    {
        var services=new ServiceCollection();services.AddEmailPilotReadScopeFoundation(new ConfigurationBuilder().Build());
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<EmailPilotReadBounds>());
        Assert.NotNull(ActivatorUtilities.CreateInstance<PreparationRetentionExceptionFilter>(scope.ServiceProvider));
    }

    [Theory]
    [InlineData("disabled")][InlineData("expired")][InlineData("run")][InlineData("capability")][InlineData("public")]
    public async Task Known_cohort_denial_does_not_consume_a_captured_normal_verification_link(string change)
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());
        var (id,raw)=await CapturedVerification(h);var bounds=Bounds(h);
        Change(h,change);
        var verified=await Workflow(h,bounds).VerifyAsync(raw,null,null);
        Assert.Null(verified);
        Assert.Null((await h.Db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id)).SenderVerifiedAt);
        Assert.Null((await h.Db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id)).UsedAt);
    }

    [Theory]
    [InlineData("disabled")][InlineData("expired")][InlineData("run")][InlineData("capability")][InlineData("public")]
    public async Task Captured_verified_sender_is_bounded_and_existing_party_claims_cannot_restore_access(string change)
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());
        var (id,raw)=await CapturedVerification(h);var bounds=Bounds(h);
        var sender=Assert.IsType<VerifiedSender>(await Workflow(h,bounds).VerifyAsync(raw,null,null));
        var end=new DateTimeOffset(2026,10,18,11,0,0,TimeSpan.Zero);Assert.Equal(end,sender.AccessExpiresAt);
        var principal=SenderConfiguration.Principal(sender);
        var details=new DraftDetails(h.Db,new(h.Db,h.Clock),new(),h.Clock,bounds);
        Assert.NotNull(await details.GetAsync(principal,sender.PublicId));
        var originalCreated=(await h.Db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id)).CreatedAt;
        Change(h,change);
        await Assert.ThrowsAsync<EmailPilotAccessUnavailableException>(()=>details.GetAsync(principal,sender.PublicId));
        Assert.Equal(originalCreated,(await h.Db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id)).CreatedAt);
        Assert.Equal(change=="public",h.Email.Enabled);
    }

    [Fact]
    public async Task Ordinary_verified_sender_keeps_normal_session_contract_and_has_no_pilot_deadline()
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());
        var envelope=new Envelope{SenderEmail="ordinary@example.invalid",SenderVerifiedAt=h.Clock.Now};h.Db.Envelopes.Add(envelope);await h.Db.SaveChangesAsync();
        var bounds=Bounds(h);Assert.Null(await bounds.ReadAsync(envelope,default));
        var principal=SenderConfiguration.Principal(new(envelope.Id,envelope.PublicId,envelope.SenderEmail));
        Assert.NotNull(await new DraftDetails(h.Db,new(h.Db,h.Clock),new(),h.Clock,bounds).GetAsync(principal,envelope.PublicId));
        Assert.False(h.Email.Enabled);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Disable_during_verification_never_returns_a_browser_identity_and_preserves_commit_truth(bool afterCommit)
    {
        using var source=fixture.Open();Action? invalidate=null;
        var save=new SaveTransition(()=>{if(!afterCommit)invalidate?.Invoke();});
        var commit=new CommitTransition(()=>{if(afterCommit)invalidate?.Invoke();});
        await using var h=new EmailPilotAdmissionTests.Harness(new(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(save,commit).Options));
        var (id,raw)=await CapturedVerification(h);var bounds=Bounds(h);
        invalidate=()=>{h.Options.Enabled=false;invalidate=null;};
        await Assert.ThrowsAsync<EmailPilotAccessUnavailableException>(()=>Workflow(h,bounds).VerifyAsync(raw,null,null));
        h.Db.ChangeTracker.Clear();
        Assert.Equal(afterCommit,(await h.Db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id)).SenderVerifiedAt is not null);
        Assert.Equal(afterCommit,(await h.Db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id)).UsedAt is not null);
        Assert.Null(await Workflow(h,bounds).VerifyAsync(raw,null,null));
        Assert.False(h.Email.Enabled);
    }

    private sealed class SaveTransition(Action transition):SaveChangesInterceptor
    {
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData data,int result,CancellationToken ct=default)
        {transition();return ValueTask.FromResult(result);}
    }
    private sealed class CommitTransition(Action transition):DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData data,CancellationToken ct=default)
        {transition();return Task.CompletedTask;}
    }

    private static void Change(EmailPilotAdmissionTests.Harness h,string change)
    {
        if(change=="disabled")h.Options.Enabled=false;
        if(change=="expired")h.Clock.Now+=TimeSpan.FromHours(1);
        if(change=="run")h.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="capability")h.Admission.CapabilitySha256=new string('a',64);
        if(change=="public")h.Email.Enabled=true;
    }
    private static EmailPilotReadBounds Bounds(EmailPilotAdmissionTests.Harness h)=>new(()=>h.Db,
        ()=>new(()=>h.Db,()=>h.Ledger,()=>h.Payload,h.Admission,h.Work),h.Clock);
    private static SenderWorkflow Workflow(EmailPilotAdmissionTests.Harness h,EmailPilotReadBounds bounds)=>
        new(h.Db,h.Sender,h.Availability,()=>h.Writer,new(h.Db,h.Clock),h.Clock,bounds);

    // This is a captured local delivery boundary, not an actual mailbox-delivery claim.
    private static async Task<(Guid,string)> CapturedVerification(EmailPilotAdmissionTests.Harness h)
    {
        h.Email.BaseUrl="https://example.invalid/";
        var admitted=(await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion))!;
        var lease=(await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(admitted.VerificationWorkId,default)).Lease!;
        OutgoingEmail? captured=null;var ordinary=new UnavailableSender();
        var dispatch=new EmailPilotDispatch(h.Db,h.Email,()=>new(h.Options,h.Email,h.Work,h.Admission,()=>h.Ledger,()=>h.Db,()=>h.Payload,h.Clock),
            (_,message,_)=>{captured=message;return Task.FromResult(new EmailDelivery("Capture","local"));},ordinary);
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(EmailOptions).Assembly.FullName,
            ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddSingleton(h.Email);builder.Services.AddScoped<RazorEmailViews>();
        await using var app=builder.Build();using var scope=app.Services.CreateScope();
        var template=new VerificationEmailTemplate(h.Email,scope.ServiceProvider.GetRequiredService<RazorEmailViews>());
        Assert.Equal(WorkOutcome.Completed,(await new EmailWorkHandler(h.Db,h.Email,h.Payload,template,ordinary,h.Clock,pilot:dispatch).ExecuteAsync(lease,default)).Outcome);
        Assert.NotNull(captured);Assert.Equal(h.Options.Mailboxes.Sender,captured.To);
        var match=Regex.Match(captured.Text,"/sender/verify\\?token=([A-Za-z0-9_-]{43})");Assert.True(match.Success);
        Assert.False(h.Email.Enabled);return(admitted.EnvelopeId,match.Groups[1].Value);
    }
    private sealed class UnavailableSender:IEmailSender
    {
        public Task<EmailDelivery> SendAsync(OutgoingEmail email,CancellationToken ct=default)=>throw new Exception("Public sender must stay unavailable.");
    }
}
