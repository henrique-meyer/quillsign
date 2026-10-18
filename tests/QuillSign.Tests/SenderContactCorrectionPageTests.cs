using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Shared = QuillSign.Tests.SendDraftWorkflowTests.Harness;
using Forms = QuillSign.Tests.SenderSendPageTests.Flow;

namespace QuillSign.Tests;

public sealed class SenderContactCorrectionPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Enabled_service_registration_reads_the_current_signer_metadata()
    {
        await using var r = await Run.Create(fixture); using var scope = r.H.App.Services.CreateScope();
        var preview = await scope.ServiceProvider.GetRequiredService<SignerContactCorrections>()
            .PreviewAsync(r.H.Principal, r.H.Envelope.PublicId, r.H.Clock.GetUtcNow().AddHours(2), null);
        Assert.NotNull(preview); Assert.Null(preview.Blocked); Assert.Equal(r.H.First.Id, preview.Review.SignerId);
    }

    [Fact]
    public async Task Address_review_is_private_read_only_and_confirmation_is_deliberate_idempotent_and_revokes_old_access()
    {
        await using var r = await Run.Create(fixture); var originalToken = r.RawToken; var before = await Counts(r);
        var start = await r.Page(r.Path); Assert.Contains("Only the current sequential signer", start);
        Assert.DoesNotContain("name=\"ReviewProof\"", start); Assert.Contains("Review current signer", await r.Page(r.Status));
        using var preview = await r.Review(start, new() { ["Confirmed"] = "true" }); Assert.Equal(HttpStatusCode.OK, preview.StatusCode); Private(preview);
        var review = await preview.Content.ReadAsStringAsync(); Assert.Contains(r.Address, review); Assert.Contains("&lt;b&gt;Synthetic NO AGREEMENT&lt;/b&gt;", review);
        Assert.DoesNotContain("checked=", review); Assert.DoesNotContain(originalToken, review); Assert.DoesNotContain("rel=\"canonical\"", review);
        Assert.DoesNotContain("googletagmanager", review); Assert.Equal(before, await Counts(r));
        using (var rejected = await r.Client.PostAsync(r.Path, new FormUrlEncodedContent(Confirm(review)))) { Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode); Private(rejected); }
        Assert.Equal(before, await Counts(r));
        using (var saved = await r.Post(review, Confirm(review))) {
            Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode); Private(saved); Assert.Equal(r.Status, saved.Headers.Location!.OriginalString);
            Assert.DoesNotContain("?", saved.Headers.Location.OriginalString); Assert.Contains("httponly", Assert.Single(saved.Headers.GetValues("Set-Cookie")));
        }
        var status = await r.Page(r.Status); Assert.Contains("The signer email correction was recorded", status); Assert.Contains(r.Address, status);
        Assert.DoesNotContain("The signer email correction was recorded", await r.Page(r.Status));
        var committed = await Counts(r); using (var replay = await r.Post(review, Confirm(review))) Assert.Equal(HttpStatusCode.Redirect, replay.StatusCode);
        Assert.Equal(committed, await Counts(r));
        using (var scope = r.H.App.Services.CreateScope()) Assert.Null(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(originalToken, "127.0.0.1", "synthetic"));
        await using var db = fixture.Open(); Assert.Equal(r.Address, await db.Signers.Where(x => x.Id == r.H.First.Id).Select(x => x.Email).SingleAsync());
        Assert.Single(await db.SignerContactRevisions.Where(x => x.EnvelopeId == r.H.Envelope.Id).ToArrayAsync());
        Assert.Equal(1, r.H.Sender.Calls); // Admission is distinct from captured transport execution.
    }

    [Theory]
    [InlineData("intent")][InlineData("statement")][InlineData("tampered")][InlineData("expired")]
    [InlineData("ticket")][InlineData("foreign")][InlineData("stale")]
    public async Task Rejected_confirmation_cannot_change_contact_or_mint_a_fresh_implicit_command(string kind)
    {
        await using var r = await Run.Create(fixture); var start = await r.Page(r.Path);
        using var preview = await r.Review(start); var review = await preview.Content.ReadAsStringAsync(); var values = Confirm(review); var before = await Counts(r);
        if (kind == "intent") values["Confirmed"] = "false";
        if (kind == "statement") values["StatementVersion"] = "old";
        if (kind == "tampered") values["ReviewProof"] += "changed";
        if (kind == "expired") r.H.Clock.Advance(TimeSpan.FromMinutes(10));
        if (kind == "ticket") { r.H.Clock.Advance(TimeSpan.FromMinutes(1)); await r.Session(); }
        if (kind == "stale") { await using var db = fixture.Open(); await db.Envelopes.Where(x => x.Id == r.H.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "Synthetic changed review")); }
        var path = kind == "foreign" ? "/draft/" + Guid.NewGuid().ToString("N") + "/correct-contact" : r.Path;
        using var rejected = await r.Post(review, values, path); Private(rejected);
        Assert.Equal(kind == "foreign" ? HttpStatusCode.NotFound : kind is "intent" or "statement" ? HttpStatusCode.BadRequest : HttpStatusCode.Conflict, rejected.StatusCode);
        var body = await rejected.Content.ReadAsStringAsync(); Assert.DoesNotContain("checked=", body); Assert.Equal(before, await Counts(r));
        if (kind is "intent" or "statement") Assert.Equal(Forms.Value(review, "ReviewProof"), Forms.Value(body, "ReviewProof"));
        else Assert.DoesNotContain("Confirm email correction</button>", body);
    }

    [Theory][InlineData("lost-commit")][InlineData("audit")][InlineData("hint")]
    public async Task Uncertain_or_failed_confirmation_preserves_its_command_and_status_get_does_not_resubmit(string fault)
    {
        await using var r = await Run.Create(fixture); var start = await r.Page(r.Path); using var preview = await r.Review(start); var review = await preview.Content.ReadAsStringAsync();
        r.H.Faults.Event = "signer_contact_corrected"; r.H.Faults.FailCommit = fault == "lost-commit"; r.H.Faults.FailAudit = fault == "audit"; r.H.Signals.FailHint = fault == "hint";
        using var response = await r.Post(review, Confirm(review)); Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode); Private(response);
        var failed = await response.Content.ReadAsStringAsync(); Assert.Contains("Confirmation could not be verified", failed);
        Assert.Equal(Forms.Value(review, "ReviewProof"), Forms.Value(failed, "ReviewProof")); Assert.DoesNotContain("checked=", failed);
        Assert.DoesNotContain("Review email correction</button>", failed);
        r.H.Faults.FailCommit = r.H.Faults.FailAudit = r.H.Signals.FailHint = false;
        var beforeRead = await Counts(r); await r.Page(r.Status); Assert.Equal(beforeRead, await Counts(r));
        using var retry = await r.Post(failed, Confirm(failed)); Assert.Equal(HttpStatusCode.Redirect, retry.StatusCode);
        await using var db = fixture.Open(); Assert.Single(await db.SignerContactRevisions.Where(x => x.EnvelopeId == r.H.Envelope.Id).ToArrayAsync());
        Assert.Equal(1, r.H.Sender.Calls);
    }

    [Fact]
    public async Task Invalid_address_disabled_settings_and_anonymous_requests_never_expose_confirmation_authority()
    {
        await using var r = await Run.Create(fixture); var start = await r.Page(r.Path); var before = await Counts(r);
        using (var invalid = await r.Review(start, new() { ["NewEmail"] = "not-an-address" })) {
            Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode); Private(invalid); var body = await invalid.Content.ReadAsStringAsync();
            Assert.Contains("not-an-address", body); Assert.DoesNotContain("name=\"ReviewProof\"", body);
        }
        r.Options.Enabled = false;
        using (var disabled = await r.Client.GetAsync(r.Path)) { Assert.Equal(HttpStatusCode.ServiceUnavailable, disabled.StatusCode); Private(disabled); }
        using var anonymous = r.H.App.GetTestClient(); anonymous.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using (var denied = await anonymous.GetAsync(r.Path)) { Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode); Private(denied); }
        Assert.Equal(before, await Counts(r));
    }

    [Theory][InlineData("slash")][InlineData("case")]
    public async Task Route_aliases_keep_private_rejections_and_share_the_action_limit(string alias)
    {
        await using var r = await Run.Create(fixture);
        r.H.App.Services.GetRequiredService<SenderOptions>().RequestsPerWindow = 2;
        var path = alias == "slash" ? r.Path + "/" : r.Path.Replace("/draft/", "/DRAFT/").Replace("/correct-contact", "/CORRECT-CONTACT");
        using var anonymous = r.H.App.GetTestClient(); anonymous.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using (var denied = await anonymous.GetAsync(path)) { Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode); Private(denied); }
        var start = await r.Page(r.Path); using var preview = await r.Review(start); var review = await preview.Content.ReadAsStringAsync();
        var before = await Counts(r); var uncheckedValues = Confirm(review); uncheckedValues["Confirmed"] = "false";
        using (var uncheckedResponse = await r.Post(review, uncheckedValues, path)) { Assert.Equal(HttpStatusCode.BadRequest, uncheckedResponse.StatusCode); Private(uncheckedResponse); }
        using (var capped = await r.Post(review, Confirm(review))) { Assert.Equal(HttpStatusCode.TooManyRequests, capped.StatusCode); Private(capped); }
        Assert.Equal(before, await Counts(r));
    }

    private static Dictionary<string, string> Confirm(string page) => new() { ["Step"] = "confirm", ["ReviewProof"] = Forms.Value(page, "ReviewProof"), ["NewEmail"] = Forms.Value(page, "NewEmail"), ["Confirmed"] = "true", ["StatementVersion"] = SignerContactCorrectionStatement.Version };
    private static void Private(HttpResponseMessage response) { Assert.True(response.Headers.CacheControl?.NoStore); Assert.Contains("noindex", Assert.Single(response.Headers.GetValues("X-Robots-Tag"))); Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy"))); }
    private async Task<string> Counts(Run r) { await using var db = fixture.Open(); var id = r.H.Envelope.Id; return string.Join(':', await db.AuditEvents.CountAsync(x => x.EnvelopeId == id), await db.WorkItems.CountAsync(x => x.EnvelopeId == id), await db.EmailOutbox.CountAsync(x => x.EnvelopeId == id), await db.AuthTokens.CountAsync(x => x.EnvelopeId == id), await db.SignerContactRevisions.CountAsync(x => x.EnvelopeId == id), r.H.Sender.Calls); }

    private sealed class Run(Shared h) : IAsyncDisposable
    {
        public Shared H => h; public HttpClient Client = h.App.GetTestClient(); private readonly Dictionary<string, string> cookies = [];
        public string Address { get; } = "corrected-" + Guid.NewGuid().ToString("N") + "@example.invalid";
        public SignerContactCorrectionOptions Options => h.App.Services.GetRequiredService<SignerContactCorrectionOptions>();
        public string Path => "/draft/" + h.Envelope.PublicId + "/correct-contact"; public string Status => "/draft/" + h.Envelope.PublicId + "/sent";
        public string RawToken => Regex.Match(h.Sender.Last?.Text ?? "", "token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        public static async Task<Run> Create(SqlDatabaseFixture fixture)
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["SignerContactCorrection:Enabled"] = "true", ["SignerContactCorrection:DailyRequests"] = "1000",
                ["SignerContactCorrection:DailyAddressRequests"] = "1000", ["SignerContactCorrection:DailyIpRequests"] = "1000", ["SignerContactCorrection:DailySenderRequests"] = "1000"
            }).Build();
            var h = await Shared.Create(fixture, browser: true, configure: services => services.AddQuillSignSignerContactCorrections(config));
            h.Clock.Advance(new DateTimeOffset(DateTime.UtcNow.Date.AddDays(2), TimeSpan.Zero).AddHours(1) - h.Clock.GetUtcNow());
            using (var scope = h.App.Services.CreateScope())
            {
                // Use the actual roster workflow so contact-history verification has
                // the same canonical sender evidence as a prepared browser request.
                var setup = scope.ServiceProvider.GetRequiredService<SignerSetup>();
                var roster = (await setup.GetAsync(h.Principal, h.Envelope.PublicId))!;
                var changed = await setup.ChangeAsync(h.Principal, h.Envelope.PublicId,
                    new(SignerChangeKind.Save, roster.Version, h.First.Id, h.First.FullName, h.First.Email, h.First.Role),
                    "127.0.0.1", "Synthetic roster NO AGREEMENT");
                Assert.Equal(SignerSetupError.None, changed.Error);
                h.Version = Convert.FromBase64String((await setup.GetAsync(h.Principal, h.Envelope.PublicId))!.Version);
            }
            var run = new Run(h); await run.Session(); var sent = (await h.Send())!;
            for (var i = 0; i < 12; i++) { await using var db = fixture.Open(); if (await db.WorkItems.Where(x => x.Id == sent.InvitationWorkId).Select(x => x.Status).SingleAsync() == WorkStatus.Completed) return run; Assert.True(await h.Once()); }
            throw new InvalidOperationException("Synthetic original invitation did not settle.");
        }
        private void Take(HttpResponseMessage response)
        {
            if (response.Headers.TryGetValues("Set-Cookie", out var values)) foreach (var value in values) { var pair = value.Split(';')[0].Split('=', 2); if (pair[1].Length == 0) cookies.Remove(pair[0]); else cookies[pair[0]] = pair[1]; }
            Client.DefaultRequestHeaders.Remove("Cookie"); Client.DefaultRequestHeaders.Add("Cookie", string.Join("; ", cookies.Select(x => x.Key + "=" + x.Value)));
        }
        public async Task Session() { using var response = await Client.GetAsync("/test-session"); Assert.Equal(HttpStatusCode.OK, response.StatusCode); Take(response); }
        public async Task<string> Page(string path) { using var response = await Client.GetAsync(path); Take(response); var body = await response.Content.ReadAsStringAsync(); Assert.True(response.StatusCode == HttpStatusCode.OK, $"{response.StatusCode}: {Regex.Match(body, "<p class=\"document-error\" role=\"alert\">([^<]*)").Groups[1].Value}"); return body; }
        public Task<HttpResponseMessage> Review(string page, Dictionary<string, string>? changes = null) {
            var values = new Dictionary<string, string> { ["Step"] = "review", ["NewEmail"] = Address }; if (changes is not null) foreach (var pair in changes) values[pair.Key] = pair.Value;
            return Post(page, values);
        }
        public async Task<HttpResponseMessage> Post(string page, Dictionary<string, string> values, string? path = null) {
            values["__RequestVerificationToken"] = SignaturePageTests.Browser.Token(page); var response = await Client.PostAsync(path ?? Path, new FormUrlEncodedContent(values)); Take(response); return response;
        }
        public async ValueTask DisposeAsync() { Client.Dispose(); await h.DisposeAsync(); }
    }
}
