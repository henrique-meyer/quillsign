using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Shared = QuillSign.Tests.SendDraftWorkflowTests.Harness;
using Forms = QuillSign.Tests.SenderSendPageTests.Flow;

namespace QuillSign.Tests;

public sealed class SenderResendPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Public_sender_review_confirmation_status_and_replacement_link_are_private_deliberate_and_idempotent()
    {
        await using var r = await Run.Create(fixture); var old = r.RawToken; var before = await Counts(r);
        Assert.Contains("Review replacement invitation", await r.Page(r.Status));
        var page = await r.Page(r.Path); Assert.Contains(InvitationResendStatement.Text, page); Assert.Contains("&lt;b&gt;Synthetic NO AGREEMENT&lt;/b&gt;", page);
        Assert.DoesNotContain(old, page); Assert.DoesNotContain(r.H.First.Id.ToString(), page); Assert.Equal(before, await Counts(r));
        using (var csrf = await r.Client.PostAsync(r.Path, new FormUrlEncodedContent(Values(page)))) { Assert.Equal(HttpStatusCode.BadRequest, csrf.StatusCode); Private(csrf); }
        Assert.Equal(before, await Counts(r));
        using (var saved = await r.Post(page)) {
            Assert.Equal(HttpStatusCode.Redirect, saved.StatusCode); Assert.Equal(r.Status, saved.Headers.Location!.OriginalString);
            Assert.DoesNotContain("?", saved.Headers.Location.OriginalString); Assert.Contains("httponly", Assert.Single(saved.Headers.GetValues("Set-Cookie"))); Private(saved);
        }
        var status = await r.Page(r.Status); Assert.Contains("A replacement invitation was queued", status); Assert.Contains("Replacement invitation queued", status);
        Assert.DoesNotContain("Review replacement invitation", status); Assert.DoesNotContain("A replacement invitation was queued", await r.Page(r.Status));
        using (var replay = await r.Post(page)) Assert.Equal(HttpStatusCode.Redirect, replay.StatusCode);
        using (var scope = r.H.App.Services.CreateScope()) Assert.Null(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(old, "127.0.0.1", "synthetic"));
        var id = await r.LatestId(); await r.Drain(id); Assert.NotEqual(old, r.RawToken); Assert.Equal(2, r.H.Sender.Calls);
        status = await r.Page(r.Status); Assert.Contains("Replacement invitation submitted", status); Assert.Contains("does not confirm inbox delivery", status);
        var landing = await r.Page("/sign/invitation?token=" + r.RawToken);
        using (var opened = await r.PostTo("/sign/invitation", landing, new() { ["Token"] = r.RawToken })) Assert.Equal(HttpStatusCode.Redirect, opened.StatusCode);
        Assert.Contains("Electronic Record", await r.Page("/sign/" + r.H.Envelope.PublicId));
        Assert.Contains("Opened; consent pending", await r.Page(r.Status));
        await using var db = fixture.Open(); Assert.Single(await db.EmailOutbox.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Template == InvitationResendProtection.Template).ToArrayAsync());
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "invitation_resend_requested").ToArrayAsync());
    }

    [Theory]
    [InlineData("queued")][InlineData("submitted")][InlineData("bounced")][InlineData("complained")]
    [InlineData("rejected")][InlineData("ambiguous")][InlineData("expired")][InlineData("disabled")]
    public async Task Status_uses_latest_replacement_evidence_instead_of_the_successful_original(string kind)
    {
        await using var r = await Run.Create(fixture); var page = await r.Page(r.Path); using (var queued = await r.Post(page)) Assert.Equal(HttpStatusCode.Redirect, queued.StatusCode);
        var id = await r.LatestId();
        if (kind == "rejected") r.H.Sender.Failure = new EmailNotSubmittedException(false);
        if (kind == "ambiguous") r.H.Sender.Failure = new IOException("Synthetic uncertain transport");
        if (kind == "expired") r.H.Clock.Advance(TimeSpan.FromDays(1));
        if (kind == "disabled") r.Options.Enabled = false;
        if (kind == "ambiguous") await Assert.ThrowsAsync<IOException>(() => r.H.Once());
        else if (kind is not ("queued" or "expired" or "disabled")) await r.Drain(id);
        if (kind is "bounced" or "complained") { await using var db = fixture.Open(); await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, kind == "bounced" ? EmailStatus.Bounced : EmailStatus.Complained)); }
        if (kind == "expired") await r.Session();
        var expected = kind switch {
            "queued" or "disabled" => "Replacement invitation queued", "submitted" => "Replacement invitation submitted",
            "bounced" => "Replacement invitation bounced; delivery needs attention", "complained" => "Replacement invitation complaint reported",
            "rejected" => "Replacement invitation not sent; delivery needs attention", "expired" => "Replacement invitation not sent; dispatch window ended",
            _ => "Replacement invitation submission not confirmed"
        };
        var status = await r.Page(r.Status); Assert.Contains(expected, status); Assert.DoesNotContain("<p>Invitation submitted</p>", status);
        r.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json"); using var response = await r.Client.GetAsync(r.Status); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadAsStringAsync(); Assert.Contains(expected, json); Assert.DoesNotContain(id.ToString(), json); Assert.DoesNotContain("synthetic-receipt", json); Assert.DoesNotContain(r.RawToken, json);
    }

    [Theory]
    [InlineData("intent")][InlineData("statement")][InlineData("tamper")][InlineData("expired-proof")]
    [InlineData("stale")][InlineData("reauthenticated")][InlineData("new-day")][InlineData("foreign")]
    public async Task Untrusted_or_stale_confirmation_cannot_enqueue_and_must_be_reviewed_again(string kind)
    {
        await using var r = await Run.Create(fixture);
        if (kind == "new-day") { r.H.Clock.Advance(TimeSpan.FromHours(22).Add(TimeSpan.FromMinutes(58))); await r.Session(); }
        var page = await r.Page(r.Path); var values = Values(page); var before = await Counts(r);
        if (kind == "intent") values["Confirmed"] = "false";
        if (kind == "statement") values["StatementVersion"] = "old";
        if (kind == "tamper") values["ReviewProof"] += "tampered";
        if (kind == "expired-proof") r.H.Clock.Advance(TimeSpan.FromMinutes(11));
        if (kind == "new-day") r.H.Clock.Advance(TimeSpan.FromMinutes(2));
        if (kind == "reauthenticated") { r.H.Clock.Advance(TimeSpan.FromMinutes(1)); await r.Session(); }
        if (kind == "stale") { await using var db = fixture.Open(); await db.Envelopes.Where(x => x.Id == r.H.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "Synthetic changed revision")); }
        using var rejected = kind == "foreign" ? await r.PostTo("/draft/" + Guid.NewGuid().ToString("N") + "/resend", page, values) : await r.Post(page, values);
        Assert.Equal(kind == "foreign" ? HttpStatusCode.NotFound : kind is "intent" or "statement" ? HttpStatusCode.BadRequest : HttpStatusCode.Conflict, rejected.StatusCode);
        Private(rejected); var body = await rejected.Content.ReadAsStringAsync(); Assert.DoesNotContain("checked=", body);
        Assert.Equal(before, await Counts(r)); Assert.Equal(1, r.H.Sender.Calls);
        if (kind is "intent" or "statement") Assert.Equal(Forms.Value(page, "ReviewProof"), Forms.Value(body, "ReviewProof"));
        else Assert.DoesNotContain("Confirm replacement invitation</button>", body);
    }

    [Theory][InlineData("lost-commit")][InlineData("audit")][InlineData("hint")]
    public async Task Failed_or_unknown_admission_keeps_the_same_proof_and_read_only_status_does_not_resend(string fault)
    {
        await using var r = await Run.Create(fixture); var page = await r.Page(r.Path);
        r.H.Faults.Event = "invitation_resend_requested"; r.H.Faults.FailCommit = fault == "lost-commit"; r.H.Faults.FailAudit = fault == "audit"; r.H.Signals.FailHint = fault == "hint";
        string failed;
        using (var response = await r.Post(page)) { Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode); failed = await response.Content.ReadAsStringAsync(); Assert.Contains("Confirmation could not be verified", failed); }
        Assert.Equal(Forms.Value(page, "ReviewProof"), Forms.Value(failed, "ReviewProof")); Assert.DoesNotContain("checked=", failed);
        r.H.Faults.FailCommit = r.H.Faults.FailAudit = r.H.Signals.FailHint = false;
        var before = await Counts(r); var status = await r.Page(r.Status); Assert.Equal(fault == "lost-commit", status.Contains("Replacement invitation queued")); Assert.Equal(before, await Counts(r));
        using (var retry = await r.Post(failed)) Assert.Equal(HttpStatusCode.Redirect, retry.StatusCode);
        await using var db = fixture.Open(); Assert.Single(await db.EmailOutbox.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Template == InvitationResendProtection.Template).ToArrayAsync()); Assert.Equal(1, r.H.Sender.Calls);
    }

    [Fact]
    public async Task Expiry_crossed_during_admission_rolls_back_mail_audit_and_old_link_revocation()
    {
        await using var r = await Run.Create(fixture); var page = await r.Page(r.Path); var old = r.RawToken; var before = await Counts(r);
        r.H.Faults.Event = "invitation_resend_requested";
        r.H.Faults.BeforeAudit = _ => { r.H.Clock.Advance(TimeSpan.FromMinutes(11)); return Task.CompletedTask; };
        using (var response = await r.Post(page)) Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(before, await Counts(r));
        using var scope = r.H.App.Services.CreateScope(); Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(old, "127.0.0.1", "synthetic"));
    }

    [Theory][InlineData("resend")][InlineData("email")][InlineData("work")][InlineData("suppressed")][InlineData("pending")][InlineData("uncertain")]
    public async Task Disabled_or_unsettled_delivery_does_not_offer_a_new_confirmation(string kind)
    {
        await using var r = await Run.Create(fixture, dispatch: kind is not ("pending" or "uncertain"));
        if (kind == "uncertain") { r.H.Sender.Failure = new IOException("Synthetic unknown original"); await Assert.ThrowsAsync<IOException>(() => r.H.Once()); }
        if (kind == "resend") r.Options.Enabled = false;
        if (kind == "email") r.H.App.Services.GetRequiredService<EmailOptions>().Enabled = false;
        if (kind == "work") r.H.App.Services.GetRequiredService<WorkOptions>().Enabled = false;
        if (kind == "suppressed") { await using var db = fixture.Open(); db.Suppressions.Add(new() { Email = r.H.First.Email, Reason = SuppressionReason.Complaint }); await db.SaveChangesAsync(); }
        var before = await Counts(r); using var read = await r.Client.GetAsync(r.Path); Assert.Contains(read.StatusCode, new[] { HttpStatusCode.Conflict, HttpStatusCode.ServiceUnavailable });
        var body = await read.Content.ReadAsStringAsync(); Assert.DoesNotContain("name=\"ReviewProof\"", body); Assert.DoesNotContain("Confirm replacement invitation</button>", body);
        Assert.DoesNotContain("Review replacement invitation</a>", await r.Page(r.Status)); Assert.Equal(before, await Counts(r));
    }

    [Fact]
    public async Task Previously_reviewed_gate_changes_caps_and_suppression_remain_authoritative_on_POST()
    {
        await using var r = await Run.Create(fixture); var page = await r.Page(r.Path); var before = await Counts(r);
        r.Options.Enabled = false; using (var disabled = await r.Post(page)) Assert.Equal(HttpStatusCode.ServiceUnavailable, disabled.StatusCode); Assert.Equal(before, await Counts(r)); r.Options.Enabled = true;
        await using (var db = fixture.Open()) { db.Suppressions.Add(new() { Email = r.H.First.Email, Reason = SuppressionReason.Complaint }); await db.SaveChangesAsync(); }
        using (var suppressed = await r.Post(page)) Assert.Equal(HttpStatusCode.Conflict, suppressed.StatusCode); Assert.Equal(before, await Counts(r));
        await using (var db = fixture.Open()) await db.Suppressions.Where(x => x.Email == r.H.First.Email).ExecuteDeleteAsync();
        r.Options.DailyAddressRequests = 1; using (var first = await r.Post(page)) Assert.Equal(HttpStatusCode.Redirect, first.StatusCode); await r.Drain(await r.LatestId());
        page = await r.Page(r.Path); before = await Counts(r); using var capped = await r.Post(page); Assert.Equal(HttpStatusCode.TooManyRequests, capped.StatusCode); Assert.Contains("resend limit was reached", await capped.Content.ReadAsStringAsync()); Assert.Equal(before, await Counts(r));
    }

    [Fact]
    public async Task Existing_signer_session_and_consent_survive_the_sender_UI_and_keep_separate_delivery_progress()
    {
        await using var r = await Run.Create(fixture); VerifiedSigner identity;
        using (var scope = r.H.App.Services.CreateScope()) {
            identity = (await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(r.RawToken, "127.0.0.1", "synthetic"))!;
            var principal = SignerAccessConfiguration.Principal(identity); var proof = scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(identity);
            Assert.Equal(ConsentResult.Accepted, await scope.ServiceProvider.GetRequiredService<SignerConsent>().AcceptAsync(principal, identity.PublicId, proof, true, true, "preview", "127.0.0.1", "synthetic"));
        }
        var page = await r.Page(r.Path); using (var posted = await r.Post(page)) Assert.Equal(HttpStatusCode.Redirect, posted.StatusCode);
        var status = await r.Page(r.Status); Assert.Contains("Consent recorded; signing incomplete", status); Assert.Contains("Latest invitation: Replacement invitation queued", status);
        await r.Drain(await r.LatestId()); status = await r.Page(r.Status); Assert.Contains("Consent recorded; signing incomplete", status); Assert.Contains("Latest invitation: Replacement invitation submitted", status);
        using var verify = r.H.App.Services.CreateScope(); var current = await verify.ServiceProvider.GetRequiredService<SignerAccess>().GetContextAsync(SignerAccessConfiguration.Principal(identity), identity.PublicId);
        Assert.NotNull(current); Assert.Equal(identity.SessionExpiresAt, current.Identity.SessionExpiresAt);
    }

    [Fact]
    public async Task Genuine_accepted_Finish_removes_the_action_and_rejects_an_earlier_sender_review()
    {
        await using var r = await Run.Create(fixture); var page = await r.Page(r.Path);
        using (var scope = r.H.App.Services.CreateScope()) {
            var services = scope.ServiceProvider;
            var identity = (await services.GetRequiredService<SignerAccess>().RedeemAsync(r.RawToken, "127.0.0.1", "synthetic"))!;
            var principal = SignerAccessConfiguration.Principal(identity);
            var context = (await services.GetRequiredService<SignerAccess>().GetContextAsync(principal, identity.PublicId))!;
            Assert.NotEmpty(await services.GetRequiredService<SignerPdfAccess>().PrepareAsync(principal, context));
            var proof = services.GetRequiredService<SignerReceiptProtection>().Create(identity);
            Assert.Equal(ConsentResult.Accepted, await services.GetRequiredService<SignerConsent>().AcceptAsync(principal, identity.PublicId, proof, true, true, "preview", "127.0.0.1", "synthetic"));
            var adoption = services.GetRequiredService<SignatureAdoption>();
            var preview = (await adoption.PrepareAsync(principal, identity.PublicId, new(SignatureAdoptionTests.Mark(), SignatureAdoptionTests.Mark(60), SignatureMethod.Drawn)))!;
            Assert.Equal(SignatureAdoptionResult.Adopted, await adoption.AdoptAsync(principal, identity.PublicId, preview.Receipt, true, SignatureAdoptionStatement.Version, "127.0.0.1", "synthetic"));
            var fields = services.GetRequiredService<SignerFields>(); var snapshot = (await fields.GetAsync(principal, identity.PublicId))!;
            foreach (var field in snapshot.Fields.Where(x => x.Type == FieldType.Signature)) Assert.Equal(SignerFieldOutcome.Applied,
                (await fields.ChangeAsync(principal, identity.PublicId, new(field.Id, field.Version, SignerFieldAction.Apply, AdoptionId: preview.Id), "127.0.0.1", "synthetic")).Outcome);
            var candidate = (await services.GetRequiredService<SignerReviewCandidates>().PrepareAsync(principal, identity.PublicId))!;
            Assert.Equal(SignerFinishOutcome.Accepted, (await services.GetRequiredService<SignerFinish>().AcceptAsync(principal, identity.PublicId, candidate.Receipt, true, SignerFinishStatement.Version, "127.0.0.1", "synthetic")).Outcome);
        }
        using (var rejected = await r.Post(page)) Assert.Equal(HttpStatusCode.Conflict, rejected.StatusCode);
        var status = await r.Page(r.Status); Assert.Contains("Finish accepted; signing copy processing", status); Assert.DoesNotContain("Review replacement invitation", status);
        await using var db = fixture.Open(); Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == r.H.Envelope.Id && x.Template == InvitationResendProtection.Template));
    }

    [Fact]
    public async Task Concurrent_posts_use_one_server_command_even_with_forged_form_authority()
    {
        await using var r = await Run.Create(fixture); var page = await r.Page(r.Path);
        Dictionary<string, string> Form() { var v = Values(page); v["__RequestVerificationToken"] = SignaturePageTests.Browser.Token(page); v["requestId"] = Guid.NewGuid().ToString(); v["senderTicketExpiresAt"] = r.H.Clock.GetUtcNow().AddYears(1).ToString("O"); v["email"] = "other@example.invalid"; return v; }
        var responses = await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => r.Client.PostAsync(r.Path, new FormUrlEncodedContent(Form()))));
        foreach (var response in responses) { using (response) Assert.Equal(HttpStatusCode.Redirect, response.StatusCode); }
        await using var db = fixture.Open(); var row = Assert.Single(await db.EmailOutbox.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Template == InvitationResendProtection.Template).ToArrayAsync()); Assert.Equal(r.H.First.Email, row.To); Assert.Equal(1, r.H.Sender.Calls);
    }

    [Fact]
    public async Task Sender_scope_expiry_and_entry_rate_limits_protect_private_resend_without_limiting_status_reads()
    {
        await using var r = await Run.Create(fixture); r.H.App.Services.GetRequiredService<SenderOptions>().RequestsPerWindow = 3;
        var page = await r.Page(r.Path); var before = await Counts(r);
        for (var i = 0; i < 3; i++) { var v = Values(page); v["Confirmed"] = "false"; using var invalid = await r.Post(page, v); Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode); }
        using (var limited = await r.Post(page)) { Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode); Private(limited); Assert.Contains("Check saved request status", await limited.Content.ReadAsStringAsync()); }
        Assert.Contains("Review replacement invitation", await r.Page(r.Status)); Assert.Equal(before, await Counts(r));
        using var anonymous = r.H.App.GetTestClient(); anonymous.DefaultRequestHeaders.Accept.ParseAdd("application/json"); using (var denied = await anonymous.GetAsync(r.Path)) { Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode); Private(denied); }
        r.H.Clock.Advance(TimeSpan.FromHours(3)); r.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json"); using var expired = await r.Client.GetAsync(r.Path); Assert.Equal(HttpStatusCode.Unauthorized, expired.StatusCode); Private(expired);
    }

    [Fact]
    public async Task JSON_review_and_confirmation_use_opaque_proof_and_clean_status_without_a_notice_cookie()
    {
        await using var r = await Run.Create(fixture); var html = await r.Page(r.Path);
        r.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using var read = await r.Client.GetAsync(r.Path); Assert.Equal(HttpStatusCode.OK, read.StatusCode); Private(read);
        var body = await read.Content.ReadAsStringAsync(); using var json = JsonDocument.Parse(body);
        var proof = json.RootElement.GetProperty("reviewProof").GetString()!; Assert.True(json.RootElement.GetProperty("canResend").GetBoolean());
        Assert.DoesNotContain(r.H.First.Id.ToString(), body); Assert.DoesNotContain(r.RawToken, body); Assert.DoesNotContain("documentSha256", body);
        using var response = await r.Post(html, new() { ["ReviewProof"] = proof, ["Confirmed"] = "true", ["StatementVersion"] = InvitationResendStatement.Version });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode); Private(response); Assert.False(response.Headers.TryGetValues("Set-Cookie", out _));
        using var result = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); Assert.Equal(r.Status, result.RootElement.GetProperty("confirmation").GetString());
        Assert.DoesNotContain((await r.LatestId()).ToString(), await response.Content.ReadAsStringAsync());
    }

    [Theory][InlineData("audit")][InlineData("payload")][InlineData("work")]
    [InlineData("audit-json")][InlineData("audit-signer")][InlineData("missing-audit")][InlineData("missing-work")]
    public async Task Corrupt_latest_replacement_fails_closed_in_status_and_JSON_never_exposes_private_evidence(string kind)
    {
        await using var r = await Run.Create(fixture); var page = await r.Page(r.Path); using (var posted = await r.Post(page)) Assert.Equal(HttpStatusCode.Redirect, posted.StatusCode); var id = await r.LatestId();
        await using (var db = fixture.Open()) {
            if (kind == "audit") await db.AuditEvents.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "invitation_resend_requested").ExecuteUpdateAsync(s => s.SetProperty(x => x.Hash, new byte[32]));
            if (kind == "payload") await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, "{}"));
            if (kind == "work") await db.WorkItems.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, "{}"));
            if (kind == "audit-json") await db.AuditEvents.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "invitation_resend_requested").ExecuteUpdateAsync(s => s.SetProperty(x => x.DataJson, "{}"));
            if (kind == "audit-signer") { var row = await db.AuditEvents.AsNoTracking().SingleAsync(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "invitation_resend_requested"); var json = System.Text.Json.Nodes.JsonNode.Parse(row.DataJson)!; json["signerId"] = r.H.Second.Id; var value = json.ToJsonString(); await db.AuditEvents.Where(x => x.Id == row.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.DataJson, value)); }
            if (kind == "missing-audit") await db.AuditEvents.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "invitation_resend_requested").ExecuteDeleteAsync();
            if (kind == "missing-work") await db.WorkItems.Where(x => x.Id == id).ExecuteDeleteAsync();
        }
        r.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json"); using var response = await r.Client.GetAsync(r.Status); Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode); Private(response);
        var body = await response.Content.ReadAsStringAsync(); Assert.Contains("could not be verified", body); Assert.DoesNotContain(r.H.First.Email, body); Assert.DoesNotContain("Synthetic NO AGREEMENT", body);
        var before = await Counts(r); using var preview = await r.Client.GetAsync(r.Path); Assert.Equal(HttpStatusCode.ServiceUnavailable, preview.StatusCode); Assert.Equal(before, await Counts(r));
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Expired_or_unverifiable_retention_exposes_no_review_or_status_metadata(bool expired)
    {
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(2), TimeSpan.Zero).AddHours(1);
        await using var retained = await RetentionSigningDeadlineTests.Retained.Create(fixture, browser: true, initialTime: start);
        var r = new Run(retained.H, fixture); using var client = r.Client;
        r.Options.Enabled = true; r.Options.DailyRequests = r.Options.DailyAddressRequests = r.Options.DailyIpRequests = r.Options.DailySenderRequests = 1000;
        await r.Session(); var review = (await retained.Review())!;
        var sent = (await r.H.Send(reviewedRetentionSha256: review.RetentionSha256))!; await r.Drain(sent.InvitationWorkId);
        var page = await r.Page(r.Path);
        if (expired) { r.H.Clock.Advance(retained.Policy.DeleteAfter - r.H.Clock.GetUtcNow()); await r.Session(); }
        else { await using var db = fixture.Open(); await db.DocumentRetentionSnapshots.Where(x => x.EnvelopeId == r.H.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Days, 8).SetProperty(x => x.DeleteAfter, retained.Policy.StartedAt.AddDays(8))); }
        var before = await Counts(r); r.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using (var post = await r.Post(page)) { Assert.Equal(expired ? HttpStatusCode.Conflict : HttpStatusCode.ServiceUnavailable, post.StatusCode); Private(post); var body = await post.Content.ReadAsStringAsync(); Assert.DoesNotContain(r.H.First.Email, body); Assert.DoesNotContain("NO AGREEMENT", body); }
        using (var status = await r.Client.GetAsync(r.Status)) { Assert.Equal(expired ? HttpStatusCode.Gone : HttpStatusCode.ServiceUnavailable, status.StatusCode); Private(status); var body = await status.Content.ReadAsStringAsync(); Assert.DoesNotContain(r.H.First.Email, body); Assert.DoesNotContain("NO AGREEMENT", body); }
        Assert.Equal(before, await Counts(r));
    }

    private static Dictionary<string, string> Values(string page) => new() { ["ReviewProof"] = Forms.Value(page, "ReviewProof"), ["Confirmed"] = "true", ["StatementVersion"] = InvitationResendStatement.Version };
    private static void Private(HttpResponseMessage response) { Assert.True(response.Headers.CacheControl?.NoStore); Assert.Contains("noindex", Assert.Single(response.Headers.GetValues("X-Robots-Tag"))); Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy"))); }
    private async Task<string> Counts(Run r) { await using var db = fixture.Open(); var id = r.H.Envelope.Id; return string.Join(':', await db.AuditEvents.CountAsync(x => x.EnvelopeId == id), await db.WorkItems.CountAsync(x => x.EnvelopeId == id), await db.EmailOutbox.CountAsync(x => x.EnvelopeId == id), await db.AuthTokens.CountAsync(x => x.EnvelopeId == id), r.H.Sender.Calls); }

    private sealed class Run(Shared h, SqlDatabaseFixture fixture) : IAsyncDisposable
    {
        public Shared H => h; public HttpClient Client = h.App.GetTestClient(); private readonly Dictionary<string, string> cookies = [];
        public InvitationResendOptions Options => h.App.Services.GetRequiredService<InvitationResendOptions>();
        public string Path => "/draft/" + h.Envelope.PublicId + "/resend"; public string Status => "/draft/" + h.Envelope.PublicId + "/sent";
        public string RawToken => Regex.Match(h.Sender.Last?.Text ?? "", "token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        public static async Task<Run> Create(SqlDatabaseFixture fixture, bool dispatch = true)
        {
            var h = await Shared.Create(fixture, browser: true);
            h.Clock.Advance(new DateTimeOffset(DateTime.UtcNow.Date.AddDays(2), TimeSpan.Zero).AddHours(1) - h.Clock.GetUtcNow());
            var r = new Run(h, fixture); r.Options.Enabled = true; r.Options.DailyRequests = r.Options.DailyAddressRequests = r.Options.DailyIpRequests = r.Options.DailySenderRequests = 1000;
            await r.Session(); var sent = (await h.Send())!; if (dispatch) await r.Drain(sent.InvitationWorkId); return r;
        }
        private void Take(HttpResponseMessage response)
        {
            if (response.Headers.TryGetValues("Set-Cookie", out var values)) foreach (var value in values) { var pair = value.Split(';')[0].Split('=', 2); if (pair[1].Length == 0) cookies.Remove(pair[0]); else cookies[pair[0]] = pair[1]; }
            Client.DefaultRequestHeaders.Remove("Cookie"); Client.DefaultRequestHeaders.Add("Cookie", string.Join("; ", cookies.Select(x => x.Key + "=" + x.Value)));
        }
        public async Task Session() { using var response = await Client.GetAsync("/test-session"); Assert.Equal(HttpStatusCode.OK, response.StatusCode); Take(response); }
        public async Task<string> Page(string path) { using var response = await Client.GetAsync(path); Take(response); var body = await response.Content.ReadAsStringAsync(); Assert.True(response.StatusCode == HttpStatusCode.OK, $"{response.StatusCode}: {body.Split('\n')[0]}"); return body; }
        public Task<HttpResponseMessage> Post(string page, Dictionary<string, string>? values = null) => PostTo(Path, page, values ?? Values(page));
        public async Task<HttpResponseMessage> PostTo(string path, string page, Dictionary<string, string> values) { values["__RequestVerificationToken"] = SignaturePageTests.Browser.Token(page); var response = await Client.PostAsync(path, new FormUrlEncodedContent(values)); Take(response); return response; }
        public async Task<Guid> LatestId() { await using var db = fixture.Open(); return await db.EmailOutbox.Where(x => x.EnvelopeId == h.Envelope.Id && x.Template == InvitationResendProtection.Template).OrderByDescending(x => x.AvailableAt).Select(x => x.Id).FirstAsync(); }
        public async Task Drain(Guid id)
        {
            for (var i = 0; i < 12; i++) { await using var db = fixture.Open(); if ((await db.WorkItems.Where(x => x.Id == id).Select(x => x.Status).SingleAsync()) is WorkStatus.Completed or WorkStatus.Failed) return; Assert.True(await h.Once()); }
            throw new InvalidOperationException("Synthetic mail work did not settle.");
        }
        public async ValueTask DisposeAsync()
        {
            Client.Dispose(); await using var db = fixture.Open();
            var ids = await db.EmailOutbox.Where(x => x.EnvelopeId == h.Envelope.Id && x.Template == InvitationResendProtection.Template).Select(x => x.Id).ToArrayAsync();
            await db.WorkItems.Where(x => ids.Contains(x.Id) && x.EnvelopeId == h.Envelope.Id).ExecuteDeleteAsync();
            await db.EmailOutbox.Where(x => ids.Contains(x.Id) && x.EnvelopeId == h.Envelope.Id).ExecuteDeleteAsync();
            await db.AuditEvents.Where(x => x.EnvelopeId == h.Envelope.Id && x.Event.StartsWith("invitation_resend_")).ExecuteDeleteAsync(); await h.DisposeAsync();
        }
    }
}
