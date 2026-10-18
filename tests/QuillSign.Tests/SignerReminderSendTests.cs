using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Work;
using Flow=QuillSign.Tests.SenderSendPageTests.Flow;

namespace QuillSign.Tests;

public sealed class SignerReminderSendTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private static SignerReminderOptions Enable(Flow f)
    {
        var options=f.H.App.Services.GetRequiredService<SignerReminderOptions>();options.Enabled=true;
        options.DailyRequests=options.DailySenderRequests=options.DailyAddressRequests=1000;return options;
    }
    [Fact]
    public async Task Default_review_is_empty_even_when_old_mutable_array_contains_day_three_and_seven()
    {
        await using var f=await Flow.Create(fixture);var page=await f.Page();Assert.Contains("No automatic reminders are scheduled",page);
        using(var sent=await f.Send(page))Assert.Equal(HttpStatusCode.Redirect,sent.StatusCode);
        var policy=await Saved(f);Assert.Empty(policy.Days);await using var db=fixture.Open();
        Assert.Equal("[3,7]",(await db.Envelopes.SingleAsync(x=>x.Id==f.H.Envelope.Id)).ReminderDaysJson);
        Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==f.H.Envelope.Id).ToArrayAsync());
        Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==f.H.Envelope.Id)); // Original invitation and expiry only.
    }
    [Fact]
    public async Task Enabled_review_hash_is_frozen_once_and_cannot_be_changed_by_later_options_or_mutable_array()
    {
        await using var f=await Flow.Create(fixture);var options=Enable(f);var page=await f.Page();
        Assert.Contains("3 and 7 day(s)",page);Assert.Contains("Automatic scheduling is not available yet",page);
        var hash=Flow.Value(page,"ReminderSha256");Assert.Equal(options.Freeze(false).Sha256,hash);
        using(var sent=await f.Send(page))Assert.Equal(HttpStatusCode.Redirect,sent.StatusCode);
        options.Days=[1];options.Enabled=false;
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==f.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ReminderDaysJson,"[30]"));
        var frozen=await Saved(f);Assert.Equal(new[]{3,7},frozen.Days);Assert.Equal(hash,frozen.Sha256);
        using(var replay=await f.Send(page))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
        Assert.Equal(hash,(await Saved(f)).Sha256);await using var check=fixture.Open();
        Assert.Single(await check.AuditEvents.Where(x=>x.EnvelopeId==f.H.Envelope.Id && x.Event=="sent").ToArrayAsync());
    }
    [Theory][InlineData("missing")][InlineData("forged")][InlineData("days")][InlineData("disabled")][InlineData("enabled-after-review")]
    public async Task New_or_changed_schedule_requires_a_fresh_deliberate_review(string change)
    {
        await using var f=await Flow.Create(fixture);var options=change=="enabled-after-review" ? f.H.App.Services.GetRequiredService<SignerReminderOptions>() : Enable(f);
        var page=await f.Page();var body=new Dictionary<string,string>();
        if(change=="missing")body["ReminderSha256"]="";
        if(change=="forged")body["ReminderSha256"]=new string('a',64);
        if(change=="days")options.Days=[2,5];
        if(change=="disabled")options.Enabled=false;
        if(change=="enabled-after-review")Enable(f);
        using var response=await f.Send(page,body);Assert.Equal(HttpStatusCode.Conflict,response.StatusCode);
        Assert.Contains("Reload and check",await response.Content.ReadAsStringAsync());await f.H.AssertUnsent(fixture);Assert.Empty(f.H.Blobs.Created);
    }
    [Fact]
    public async Task Slow_storage_cannot_commit_a_policy_that_changed_after_review_check()
    {
        await using var f=await Flow.Create(fixture);var options=Enable(f);var page=await f.Page();f.H.Blobs.AfterWrite=()=>options.Days=[1];
        using var response=await f.Send(page);Assert.Equal(HttpStatusCode.Conflict,response.StatusCode);await f.H.AssertUnsent(fixture);
        Assert.Single(f.H.Blobs.Deleted);
    }
    [Fact]
    public async Task Legacy_empty_review_bridge_never_authorizes_an_enabled_schedule()
    {
        var empty=new SignerReminderOptions().Freeze(false);SignerReminderSendEvidence.DemandReview(empty,null);
        var enabled=new SignerReminderOptions {Enabled=true,DailyRequests=1,DailySenderRequests=1,DailyAddressRequests=1}.Freeze(false);
        Assert.Throws<DocumentConflictException>(()=>SignerReminderSendEvidence.DemandReview(enabled,null));
        Assert.Throws<DocumentConflictException>(()=>SignerReminderSendEvidence.DemandReview(empty,enabled.Sha256));
    }
    [Theory][InlineData("legacy")][InlineData("empty")][InlineData("enabled")][InlineData("missing-policy")][InlineData("missing-hash")]
    [InlineData("hash")][InlineData("noncanonical")][InlineData("demo-enabled")]
    public void Immutable_evidence_has_a_verified_legacy_empty_bridge_and_strict_new_pair(string kind)
    {
        var policy=new SignerReminderOptions {Enabled=true,DailyRequests=1,DailySenderRequests=1,DailyAddressRequests=1}.Freeze(kind=="empty");
        var data=new Dictionary<string,object?>();
        if(kind!="legacy") {
            if(kind!="missing-policy")data["reminderPolicy"]=kind=="noncanonical" ? policy.CanonicalJson+" " : policy.CanonicalJson;
            if(kind!="missing-hash")data["reminderPolicySha256"]=kind=="hash" ? new string('a',64) : policy.Sha256;
        }
        using var json=JsonDocument.Parse(JsonSerializer.Serialize(data));
        if(kind is "legacy" or "empty")Assert.Empty(SignerReminderSendEvidence.Read(json.RootElement,false).Days);
        else if(kind=="enabled")Assert.Equal(policy.Sha256,SignerReminderSendEvidence.Read(json.RootElement,false).Sha256);
        else Assert.Throws<InvalidDataException>(()=>SignerReminderSendEvidence.Read(json.RootElement,kind=="demo-enabled"));
    }
    [Fact]
    public void Duplicate_policy_members_are_not_a_legacy_or_new_authority_bridge()
    {
        using var json=JsonDocument.Parse("{\"reminderPolicy\":\"\",\"reminderPolicy\":\"\"}");
        Assert.Throws<InvalidDataException>(()=>SignerReminderSendEvidence.Read(json.RootElement,false));
    }
    [Fact]
    public async Task Demo_review_stays_empty_even_when_generic_policy_is_enabled()
    {
        await using var f=await Flow.Create(fixture);Enable(f);using var scope=f.H.App.Services.CreateScope();
        var draft=(await scope.ServiceProvider.GetRequiredService<DraftReview>().GetAsync(f.H.Principal,f.H.Envelope.PublicId))!;
        var result=scope.ServiceProvider.GetRequiredService<SenderSendReadiness>().Read(f.H.Principal,draft with {IsDemo=true});
        Assert.Empty(result.Reminders!.Days);Assert.Equal(new SignerReminderOptions().Freeze(true).Sha256,result.Reminders.Sha256);
    }
    private static async Task<SignerReminderPolicy> Saved(Flow f)
    {
        using var scope=f.H.App.Services.CreateScope();var state=await scope.ServiceProvider.GetRequiredService<SenderSentStatus>().GetAsync(f.H.Principal,f.H.Envelope.PublicId);
        return state!.Sent.Reminders!;
    }
    // Disposable loopback browser fixture; no production test route or policy.
    public sealed class BrowserSession:IAsyncDisposable
    {
        private readonly SendDraftWorkflowTests.Harness h;
        private BrowserSession(SendDraftWorkflowTests.Harness h)=>this.h=h;
        public string PublicId=>h.Envelope.PublicId;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port)
        {
            var h=await SendDraftWorkflowTests.Harness.Create(fixture,browser:true,browserPort:port);
            var policy=h.App.Services.GetRequiredService<SignerReminderOptions>();policy.Enabled=true;
            policy.DailyRequests=policy.DailySenderRequests=policy.DailyAddressRequests=1000;
            h.Clock.TrackElapsed();return new(h);
        }
        public ValueTask DisposeAsync()=>h.DisposeAsync();
    }
}
