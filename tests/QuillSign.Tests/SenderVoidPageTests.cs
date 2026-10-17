using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Work;
using Flow=QuillSign.Tests.SenderSendPageTests.Flow;

namespace QuillSign.Tests;

public sealed class SenderVoidPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Confirmation_GET_is_metadata_only_and_explicit_CSRF_protected_POST_redirects_to_verified_saved_status_once()
    {
        await using var f=await Sent();var before=await Counts(f);var page=await f.Page(Path(f));Assert.Contains(SenderVoidStatement.Text,page);Assert.Contains("Synthetic NO AGREEMENT",page);
        Assert.Contains("Review void action",await f.Page(f.Status));Assert.Equal(before,await Counts(f));
        using(var rejected=await f.Client.PostAsync(Path(f),new FormUrlEncodedContent(Values(page))))Assert.Equal(HttpStatusCode.BadRequest,rejected.StatusCode);
        Assert.Equal(before,await Counts(f));
        var reason="Synthetic <script>reason()</script>\nNO AGREEMENT";
        using(var saved=await f.Post(Path(f),page,Values(page,reason))) {
            Assert.Equal(HttpStatusCode.Redirect,saved.StatusCode);Assert.Equal(f.Status,saved.Headers.Location!.OriginalString);Assert.DoesNotContain("?",saved.Headers.Location.OriginalString);
            Assert.Contains("httponly",Assert.Single(saved.Headers.GetValues("Set-Cookie")));
        }
        var status=await f.Page(f.Status);Assert.Contains("The request was voided",status);Assert.Contains("Recorded void",status);Assert.Contains("&lt;script&gt;",status);Assert.DoesNotContain("<script>reason",status);Assert.DoesNotContain("Review void action",status);
        Assert.DoesNotContain("The request was voided",await f.Page(f.Status));
        using(var replay=await f.Post(Path(f),page,Values(page,reason)))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
        await using var db=fixture.Open();Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==f.H.Envelope.Id && x.Event=="voided"));Assert.Equal(3,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==f.H.Envelope.Id && x.Template==VoidNotificationJobs.Template));Assert.Equal(0,f.H.Sender.Calls);
    }
    [Theory]
    [InlineData("affirmation")][InlineData("statement")][InlineData("version")][InlineData("length")][InlineData("control")]
    public async Task Missing_intent_version_or_bounded_reason_never_voids_and_keeps_attempted_input(string kind)
    {
        await using var f=await Sent();var page=await f.Page(Path(f));var before=await Counts(f);var values=Values(page,"Synthetic attempted reason");
        if(kind=="affirmation")values["Confirmed"]="false";if(kind=="statement")values["StatementVersion"]="old";if(kind=="version")values["Version"]="forged";
        if(kind=="length")values["Reason"]=new string('x',513);if(kind=="control")values["Reason"]="bad\0reason";
        using var failed=await f.Post(Path(f),page,values);Assert.Equal(kind=="version" ? HttpStatusCode.Conflict : HttpStatusCode.BadRequest,failed.StatusCode);
        if(kind!="control")Assert.Contains(kind=="length" ? "Check the reason" : "Synthetic attempted reason",await failed.Content.ReadAsStringAsync());Assert.Equal(before,await Counts(f));
    }
    [Fact]
    public async Task Stale_confirmation_keeps_reason_and_requires_explicit_metadata_refresh_and_new_affirmation()
    {
        await using var f=await Sent();var page=await f.Page(Path(f));
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==f.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PurgeAfter,(DateTimeOffset?)f.H.Clock.GetUtcNow().AddDays(10)));
        const string reason="Synthetic reason to keep";string stale;
        using(var failed=await f.Post(Path(f),page,Values(page,reason))) {Assert.Equal(HttpStatusCode.Conflict,failed.StatusCode);stale=await failed.Content.ReadAsStringAsync();Assert.Contains(reason,stale);Assert.DoesNotContain("name=\"Confirmed\"",stale);}
        var before=await Counts(f);string refreshed;
        using(var refresh=await f.Post(Path(f)+"?handler=Refresh",stale,Values(stale,reason))) {Assert.Equal(HttpStatusCode.OK,refresh.StatusCode);refreshed=await refresh.Content.ReadAsStringAsync();Assert.Contains(reason,refreshed);Assert.DoesNotContain("checked=",refreshed);Assert.Contains("action=\""+Path(f)+"\"",refreshed);}
        Assert.Equal(before,await Counts(f));Assert.NotEqual(Flow.Value(page,"Version"),Flow.Value(refreshed,"Version"));
        using var saved=await f.Post(Path(f),refreshed,Values(refreshed,reason));Assert.Equal(HttpStatusCode.Redirect,saved.StatusCode);
    }
    [Theory]
    [InlineData("audit")][InlineData("hint")][InlineData("lost-commit")]
    public async Task Unknown_or_failed_commit_is_unconfirmed_preserves_reason_and_can_be_checked_without_replaying_action(string fault)
    {
        await using var f=await Sent();var page=await f.Page(Path(f));f.H.Faults.Event="void_notification_queued";f.H.Faults.FailAudit=fault=="audit";f.H.Faults.FailCommit=fault=="lost-commit";f.H.Signals.FailHint=fault=="hint";
        using(var failed=await f.Post(Path(f),page,Values(page,"Synthetic uncertainty"))) {
            Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode);var body=await failed.Content.ReadAsStringAsync();Assert.Contains("Void could not be confirmed",body);Assert.Contains("Synthetic uncertainty",body);
            Assert.DoesNotContain("The request was voided",body);Assert.DoesNotContain("?notice=",body);
        }
        f.H.Faults.FailAudit=false;f.H.Faults.FailCommit=false;f.H.Signals.FailHint=false;
        var before=await Counts(f);var saved=await f.Page(f.Status);Assert.Equal(fault=="lost-commit",saved.Contains("Recorded void"));Assert.Equal(before,await Counts(f));
        await using var db=fixture.Open();Assert.Equal(fault=="lost-commit" ? EnvelopeStatus.Voided : EnvelopeStatus.Sent,(await db.Envelopes.SingleAsync(x=>x.Id==f.H.Envelope.Id)).Status);
    }
    [Fact]
    public async Task JSON_has_clean_confirmation_and_original_cookie_expiry_is_not_replaced_by_a_form_expiry()
    {
        await using var f=await Sent();var page=await f.Page(Path(f));f.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        var values=Values(page);values["senderTicketExpiresAt"]=f.H.Clock.GetUtcNow().AddYears(10).ToString("O");f.H.Clock.Advance(TimeSpan.FromHours(3));
        using(var expired=await f.Post(Path(f),page,values))Assert.Equal(HttpStatusCode.Unauthorized,expired.StatusCode);
        await using(var db=fixture.Open())Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.SingleAsync(x=>x.Id==f.H.Envelope.Id)).Status);
        using(var session=await f.Client.GetAsync("/test-session"))f.Take(session);f.Client.DefaultRequestHeaders.Accept.Clear();page=await f.Page(Path(f));f.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using var response=await f.Post(Path(f),page,Values(page));Assert.Equal(HttpStatusCode.OK,response.StatusCode);using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());Assert.Equal(f.Status,json.RootElement.GetProperty("confirmation").GetString());Assert.False(response.Headers.TryGetValues("Set-Cookie",out _));
    }
    [Fact]
    public async Task Foreign_and_closed_requests_cannot_be_voided_and_action_rate_limit_is_independent_of_read_status()
    {
        await using var f=await Sent();var page=await f.Page(Path(f));var before=await Counts(f);
        using(var foreign=await f.Client.GetAsync("/draft/"+Guid.NewGuid().ToString("N")+"/void"))Assert.Equal(HttpStatusCode.NotFound,foreign.StatusCode);
        for(var i=0;i<10;i++) {var values=Values(page);values["Confirmed"]="false";using var invalid=await f.Post(Path(f),page,values);Assert.Equal(HttpStatusCode.BadRequest,invalid.StatusCode);}
        using(var limited=await f.Post(Path(f),page,Values(page))) {Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode);Assert.True(limited.Headers.CacheControl!.NoStore);Assert.Contains("Check saved request status",await limited.Content.ReadAsStringAsync());}
        Assert.Contains("Review void action",await f.Page(f.Status));Assert.Equal(before,await Counts(f));
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==f.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Declined));
        Assert.Contains("closed and cannot be voided",await f.Page(Path(f)));Assert.Equal(before,await Counts(f));
    }
    private async Task<Flow> Sent() {var f=await Flow.Create(fixture);Assert.NotNull(await f.H.Send());return f;}
    private static string Path(Flow f)=>"/draft/"+f.H.Envelope.PublicId+"/void";
    private static Dictionary<string,string> Values(string page,string reason="")=>new() {{"Version",Flow.Value(page,"Version")},{"Confirmed","true"},{"StatementVersion",SenderVoidStatement.Version},{"Reason",reason}};
    private async Task<string> Counts(Flow f) {await using var db=fixture.Open();var id=f.H.Envelope.Id;return string.Join(',',await db.AuditEvents.CountAsync(x=>x.EnvelopeId==id),await db.WorkItems.CountAsync(x=>x.EnvelopeId==id),await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==id),await db.AuthTokens.CountAsync(x=>x.EnvelopeId==id),f.H.Blobs.Created.Count,f.H.Sender.Calls);}
}
