using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;

namespace QuillSign.Tests;

public sealed class EmailPilotOperatorTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";
    [Fact]
    public async Task Authenticated_status_reports_only_the_protected_lower_allowance_and_does_not_renew_it()
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());
        h.Options.Allowance=new(13,7,2,31440842);var (service,_,session)=Setup(h);
        Assert.Equal(EmailPilotOperatorNotice.EnvelopeSaved,await service.EnvelopeAsync(session,EmailPilotScenario.Completion,null,null));
        var status=await service.ReadAsync(session);Assert.NotNull(status);
        Assert.Equal(h.Options.Allowance,status.Allowance);Assert.Equal(new EmailPilotBudget(0,0,0,0),status.Budget);
        Assert.Equal(status.ExpiresAt,(await service.ReadAsync(session))!.ExpiresAt);
        h.Options.Allowance=EmailPilotLimits.Maximum;
        await Assert.ThrowsAsync<InvalidDataException>(()=>service.ReadAsync(session));
    }
    [Fact]
    public async Task Status_GET_cannot_start_a_run_or_schedule_any_work()
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());var (service,_,session)=Setup(h);
        Assert.Null(await service.ReadAsync(session));
        Assert.False(await h.Db.EmailPilotRuns.AnyAsync(x=>x.Id==h.RunId));Assert.Empty(h.Signals.Published);
    }
    [Fact]
    public async Task Explicit_admission_prepares_delayed_cleanup_first_and_retries_recover_the_same_unverified_scenario()
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());var (service,_,session)=Setup(h);
        Assert.Equal(EmailPilotOperatorNotice.EnvelopeSaved,await service.EnvelopeAsync(session,EmailPilotScenario.Completion,null,null));
        var id=EmailPilotSecretJobs.WorkId(h.RunId);var cleanup=await h.Db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id);
        Assert.Equal(WorkKind.Purge,cleanup.Kind);Assert.Null(cleanup.EnvelopeId);Assert.Equal(h.Clock.Now.AddDays(7),cleanup.AvailableAt);
        Assert.DoesNotContain(Capability,cleanup.PayloadJson);Assert.DoesNotContain(h.Options.Mailboxes.Sender,cleanup.PayloadJson);
        Assert.Contains(id,h.Signals.Published);
        var first=await service.ReadAsync(session);Assert.NotNull(first);Assert.Single(first.Envelopes);
        var parent=await h.Db.Envelopes.AsNoTracking().SingleAsync(x=>x.SenderEmail==h.Options.Mailboxes.Sender);
        Assert.Null(parent.SenderVerifiedAt);Assert.False(await h.Db.AuthTokens.AnyAsync(x=>x.EnvelopeId==parent.Id));
        Assert.Equal(EmailPilotOperatorNotice.EnvelopeSaved,await service.EnvelopeAsync(session,EmailPilotScenario.Completion,null,null));
        Assert.Equal(first.ExpiresAt,(await service.ReadAsync(session))!.ExpiresAt);
        Assert.Equal(1,await h.Db.EmailPilotEnrollments.CountAsync(x=>x.RunId==h.RunId));
        Assert.Equal(1,await h.Db.WorkItems.CountAsync(x=>x.Id==id));Assert.False(h.Email.Enabled);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Failed_cleanup_hint_or_uncertain_wakeup_admits_no_email_then_recovers_without_renewing_run(bool uncertain)
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());var (service,_,session)=Setup(h);
        h.Signals.FailHint=!uncertain;h.Signals.FailPublish=uncertain;
        if(uncertain)Assert.Equal(EmailPilotOperatorNotice.WakePending,await service.EnvelopeAsync(session,EmailPilotScenario.Void,null,null));
        else await Assert.ThrowsAsync<IOException>(()=>service.EnvelopeAsync(session,EmailPilotScenario.Void,null,null));
        Assert.False(await h.Db.EmailPilotEnrollments.AnyAsync(x=>x.RunId==h.RunId));
        Assert.False(await h.Db.Envelopes.AnyAsync(x=>x.SenderEmail==h.Options.Mailboxes.Sender));
        var created=await h.Db.EmailPilotRuns.AsNoTracking().SingleAsync(x=>x.Id==h.RunId);
        h.Signals.FailHint=false;h.Signals.FailPublish=false;h.Clock.Now+=TimeSpan.FromMinutes(5);
        Assert.Equal(EmailPilotOperatorNotice.EnvelopeSaved,await service.EnvelopeAsync(session,EmailPilotScenario.Void,null,null));
        Assert.Equal(created.ExpiresAt,(await service.ReadAsync(session))!.ExpiresAt);
    }
    [Fact]
    public async Task Configuration_disable_during_cleanup_never_reaches_admission()
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());var (service,_,session)=Setup(h);
        h.Signals.OnHint=()=>h.Options.Enabled=false;
        await Assert.ThrowsAsync<EmailDisabledException>(()=>service.EnvelopeAsync(session,EmailPilotScenario.Decline,null,null));
        Assert.False(await h.Db.EmailPilotEnrollments.AnyAsync(x=>x.RunId==h.RunId));
        Assert.False(await h.Db.Envelopes.AnyAsync(x=>x.SenderEmail==h.Options.Mailboxes.Sender));
    }
    [Fact]
    public async Task Expired_run_is_readable_with_new_operator_login_but_no_action_can_renew_it()
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());var (service,browser,session)=Setup(h);
        Assert.Equal(EmailPilotOperatorNotice.EnvelopeSaved,await service.EnvelopeAsync(session,EmailPilotScenario.Completion,null,null));
        var fixedExpiry=(await service.ReadAsync(session))!.ExpiresAt;h.Clock.Now+=TimeSpan.FromMinutes(61);
        await Assert.ThrowsAsync<EmailDisabledException>(()=>service.ReadAsync(session));
        var replacement=Login(browser);var status=await service.ReadAsync(replacement);
        Assert.NotNull(status);Assert.True(status.Expired);Assert.Equal(fixedExpiry,status.ExpiresAt);
        await Assert.ThrowsAsync<InvalidDataException>(()=>service.EnvelopeAsync(replacement,EmailPilotScenario.Void,null,null));
        Assert.Equal(1,await h.Db.EmailPilotEnrollments.CountAsync(x=>x.RunId==h.RunId));
    }
    [Fact]
    public async Task Invalid_fixed_actions_resolve_no_backend_and_changed_cookie_cannot_authorize_status()
    {
        await using var h=new EmailPilotAdmissionTests.Harness(fixture.Open());var (service,_,session)=Setup(h);
        Assert.Equal(EmailPilotOperatorNotice.Unavailable,await service.EnvelopeAsync(session,(EmailPilotScenario)99,null,null));
        Assert.Equal(EmailPilotOperatorNotice.Unavailable,await service.SimulatorAsync(session,(EmailPilotSimulatorKind)99));
        Assert.Equal(EmailPilotOperatorNotice.Unavailable,await service.LookupAsync(session,null));
        Assert.False(await h.Db.EmailPilotRuns.AnyAsync(x=>x.Id==h.RunId));
        h.Options.RunId=Guid.NewGuid().ToString("N");await Assert.ThrowsAsync<EmailDisabledException>(()=>service.ReadAsync(session));
    }
    private static (EmailPilotOperator,EmailPilotOperatorBrowser,EmailPilotOperatorSession) Setup(EmailPilotAdmissionTests.Harness h)
    {
        var keys=new EphemeralDataProtectionProvider();var browser=new EmailPilotOperatorBrowser(h.Options,h.Admission,h.Email,h.Work,h.Clock,new Environment(),()=>keys);
        var service=new EmailPilotOperator(browser,()=>h.Ledger,()=>new(h.Db,()=>h.Signals,h.Clock),()=>h.Service,
            ()=>throw new Exception("No lookup expected."),()=>new(h.Options,h.Email,h.Work,h.Admission,()=>h.Ledger,()=>h.Signals));
        return(service,browser,Login(browser));
    }
    private static EmailPilotOperatorSession Login(EmailPilotOperatorBrowser browser)
    {
        var http=new DefaultHttpContext();http.Request.Scheme="http";http.Request.Host=new("localhost");Assert.True(browser.Unlock(http,Capability));
        var next=new DefaultHttpContext();next.Request.Headers.Cookie=http.Response.Headers.SetCookie.Single()!.Split(';')[0];return browser.Read(next)!;
    }
    private sealed class Environment:IHostEnvironment
    {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Synthetic";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}
