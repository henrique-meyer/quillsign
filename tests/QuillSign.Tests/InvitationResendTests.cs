using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Shared = QuillSign.Tests.SendDraftWorkflowTests.Harness;
using Retained = QuillSign.Tests.RetentionSigningDeadlineTests.Retained;

namespace QuillSign.Tests;

public sealed class InvitationResendTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Replacement_revokes_the_old_unused_link_and_preserves_the_exact_sent_copy_and_audit()
    {
        await using var r = await Run.Create(fixture); var old = r.Token; var review = await r.Review(); var id = Guid.NewGuid();
        await using var inspect = fixture.Open(); var before = await inspect.Envelopes.AsNoTracking().SingleAsync(x => x.Id == r.H.Envelope.Id);
        var bytes = await r.H.Read(Guid.Parse(before.SentPdfBlob!));
        var sent = await inspect.AuditEvents.AsNoTracking().SingleAsync(x => x.EnvelopeId == before.Id && x.Event == "sent");
        Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id, review)); Assert.Null(await r.Redeem(old));
        Assert.Equal(InvitationResendOutcome.AlreadyRequested, await r.Request(id, review));
        await r.Drain(id); Assert.NotEqual(old, r.Token); Assert.NotNull(await r.Redeem(r.Token));
        var after = await inspect.Envelopes.AsNoTracking().SingleAsync(x => x.Id == before.Id);
        Assert.Equal(before.RowVersion, after.RowVersion); Assert.Equal(before.SentPdfSha256, after.SentPdfSha256); Assert.Equal(before.ErsdText, after.ErsdText);
        Assert.Equal(before.ExpiresAt, after.ExpiresAt); Assert.Equal(bytes, await r.H.Read(Guid.Parse(after.SentPdfBlob!)));
        Assert.Equal(sent.Hash, (await inspect.AuditEvents.AsNoTracking().SingleAsync(x => x.Id == sent.Id)).Hash);
        Assert.Equal(2, r.H.Sender.Calls); Assert.Single(await inspect.EmailOutbox.Where(x => x.EnvelopeId == before.Id && x.Template == "signer-invitation-resend").ToArrayAsync());
        Assert.Single(await inspect.AuditEvents.Where(x => x.EnvelopeId == before.Id && x.Event == "invitation_resend_requested").ToArrayAsync());
        Assert.Single(await inspect.AuditEvents.Where(x => x.EnvelopeId == before.Id && x.Event == "invitation_resend_submitted").ToArrayAsync());
        Assert.DoesNotContain(r.Token, (await inspect.EmailOutbox.SingleAsync(x => x.Id == id)).PayloadJson);
        Assert.DoesNotContain(await inspect.AuditEvents.Where(x => x.EnvelopeId == before.Id).ToArrayAsync(), x => x.DataJson.Contains(r.Token));
    }

    [Fact]
    public async Task A_redeemed_session_and_genuine_consent_survive_resend_without_rewriting_evidence()
    {
        await using var r = await Run.Create(fixture, browser: true); var identity = (await r.Redeem(r.Token))!; var principal = SignerAccessConfiguration.Principal(identity);
        using (var scope = r.H.App.Services.CreateScope()) {
            var receipt = scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(identity);
            Assert.Equal(ConsentResult.Accepted, await scope.ServiceProvider.GetRequiredService<SignerConsent>().AcceptAsync(principal, r.H.Envelope.PublicId, receipt, true, true, "preview", "127.0.0.1", "synthetic"));
        }
        await using var inspect = fixture.Open(); var before = await inspect.Signers.AsNoTracking().SingleAsync(x => x.Id == identity.SignerId);
        var consent = await inspect.AuditEvents.AsNoTracking().SingleAsync(x => x.EnvelopeId == identity.EnvelopeId && x.Event == "consent_given");
        var used = await inspect.AuthTokens.AsNoTracking().SingleAsync(x => x.EnvelopeId == identity.EnvelopeId);
        var id = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id)); await r.Drain(id);
        using (var scope = r.H.App.Services.CreateScope()) Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SignerAccess>().GetContextAsync(principal, identity.PublicId));
        Assert.NotNull(await r.Redeem(r.Token));
        var after = await inspect.Signers.AsNoTracking().SingleAsync(x => x.Id == identity.SignerId);
        Assert.Equal(before.ConsentAt, after.ConsentAt); Assert.Equal(before.ConsentIp, after.ConsentIp); Assert.Equal(before.ConsentUa, after.ConsentUa);
        Assert.Equal(before.SignatureAdoptionId, after.SignatureAdoptionId);
        Assert.Equal(consent.Hash, (await inspect.AuditEvents.AsNoTracking().SingleAsync(x => x.Id == consent.Id)).Hash);
        var token = await inspect.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == used.Id); Assert.Equal(used.UsedAt, token.UsedAt); Assert.Equal(used.ExpiresAt, token.ExpiresAt);
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Concurrent_admission_is_once_only_and_new_requests_cannot_overtake_pending_delivery(bool sameId)
    {
        await using var r = await Run.Create(fixture); var review = await r.Review(); var id = Guid.NewGuid();
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 3).Select(i => r.Request(sameId ? id : Guid.NewGuid(), review)));
        Assert.Single(outcomes, x => x == InvitationResendOutcome.Queued);
        Assert.Equal(2, outcomes.Count(x => x == (sameId ? InvitationResendOutcome.AlreadyRequested : InvitationResendOutcome.Busy)));
        await using var db = fixture.Open(); Assert.Single(await db.EmailOutbox.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Template == "signer-invitation-resend").ToArrayAsync());
        Assert.Equal(1, r.H.Sender.Calls);
    }

    [Theory][InlineData("queued")][InlineData("leased")][InlineData("ambiguous")]
    public async Task Resend_cannot_bypass_an_unsettled_original_invitation(string state)
    {
        await using var r = await Run.Create(fixture, dispatch: false);
        if (state == "leased") { using var scope = r.H.App.Services.CreateScope(); Assert.NotNull((await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(r.Sent.InvitationWorkId, default)).Lease); }
        if (state == "ambiguous") {
            r.H.Sender.Failure = new IOException("synthetic uncertain acceptance"); await Assert.ThrowsAsync<IOException>(() => r.H.Once());
            r.H.Sender.Failure = null; r.H.Clock.Advance(TimeSpan.FromMinutes(6)); await r.H.Signals.PublishAsync(r.Sent.InvitationWorkId, TimeSpan.Zero, default); await r.Drain(r.Sent.InvitationWorkId);
        }
        Assert.Equal(InvitationResendOutcome.Busy, await r.Request(Guid.NewGuid()));
        await using var db = fixture.Open(); Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == r.H.Envelope.Id && x.Template == "signer-invitation-resend"));
    }

    [Theory][InlineData("wrong-sender")][InlineData("anonymous")][InlineData("expired-ticket")][InlineData("confirmation")]
    [InlineData("statement")][InlineData("signer")][InlineData("document")][InlineData("disclosure")][InlineData("revision")]
    public async Task Current_sender_authority_and_exact_deliberate_review_are_required(string changed)
    {
        await using var r = await Run.Create(fixture); var review = await r.Review(); var sender = r.H.Principal; var until = r.Until;
        if (changed == "wrong-sender") sender = SenderConfiguration.Principal(new(r.H.Envelope.Id, r.H.Envelope.PublicId, "other@example.invalid"));
        if (changed == "anonymous") sender = new ClaimsPrincipal(new ClaimsIdentity());
        if (changed == "expired-ticket") until = r.H.Clock.GetUtcNow();
        if (changed == "signer") review = review with { SignerId = r.H.Second.Id };
        if (changed == "document") review = review with { DocumentId = Guid.NewGuid() };
        if (changed == "disclosure") review = review with { DisclosureSha256 = new string('a', 64) };
        if (changed == "revision") review = review with { Version = Convert.ToBase64String(new byte[8]) };
        using var scope = r.H.App.Services.CreateScope();
        var outcome = await scope.ServiceProvider.GetRequiredService<InvitationResends>().RequestAsync(sender, r.H.Envelope.PublicId, until, Guid.NewGuid(), review,
            changed != "confirmation", changed == "statement" ? "wrong" : InvitationResendStatement.Version, "127.0.0.1", null);
        Assert.Contains(outcome, new[] { InvitationResendOutcome.InvalidContext, InvitationResendOutcome.InvalidConfirmation, InvitationResendOutcome.Closed, InvitationResendOutcome.Conflict });
        Assert.NotNull(await r.Redeem(r.Token));
        await using var db = fixture.Open(); Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "invitation_resend_requested"));
    }

    [Fact]
    public async Task Disabled_resend_is_lazy_and_enabling_requires_explicit_caps()
    {
        await using var r = await Run.Create(fixture); r.Options.Enabled = false;
        using var scope = r.H.App.Services.CreateScope(); var db = scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
        var service = scope.ServiceProvider.GetRequiredService<InvitationResends>();
        Assert.Null(await service.ReviewAsync(r.H.Principal, r.H.Envelope.PublicId, r.Until));
        Assert.Equal(InvitationResendOutcome.Unavailable, await service.RequestAsync(r.H.Principal, r.H.Envelope.PublicId, r.Until, Guid.Empty, null!, false, null, null, null));
        Assert.Equal(System.Data.ConnectionState.Closed, db.Database.GetDbConnection().State);
        var options = new InvitationResendOptions { Enabled = true }; Assert.Throws<InvalidOperationException>(options.Validate);
    }

    [Theory][InlineData("address")][InlineData("ip")][InlineData("sender")][InlineData("global")]
    public async Task Daily_reservations_include_completed_and_failed_attempts_without_spending_again_on_replay(string cap)
    {
        await using var r = await Run.Create(fixture);
        if (cap == "global") {
            await using var db = fixture.Open(); var start = new DateTimeOffset(r.H.Clock.GetUtcNow().UtcDateTime.Date, TimeSpan.Zero);
            var count = await db.AuditEvents.CountAsync(x => x.Event == "invitation_resend_requested" && x.At >= start && x.At < start.AddDays(1));
            r.Options.DailyRequests = count + 1; r.Options.DailyAddressRequests = r.Options.DailyIpRequests = r.Options.DailySenderRequests = count + 1;
        }
        if (cap == "address") r.Options.DailyAddressRequests = 1;
        if (cap == "sender") r.Options.DailySenderRequests = 1;
        var ip = cap == "ip" ? "192.0.2.93" : "127.0.0.1"; if (cap == "ip") r.Options.DailyIpRequests = 1;
        var review = await r.Review(); var id = Guid.NewGuid();
        Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id, review, ip));
        Assert.Equal(InvitationResendOutcome.AlreadyRequested, await r.Request(id, review, ip));
        await r.Drain(id);
        Assert.Equal(InvitationResendOutcome.Capped, await r.Request(Guid.NewGuid(), review, ip));
    }

    [Theory][InlineData("hint")][InlineData("audit")][InlineData("rollback")][InlineData("ticket-crossing")]
    public async Task Known_admission_failure_rolls_back_revocation_queue_and_audit(string kind)
    {
        await using var r = await Run.Create(fixture); var review = await r.Review(); var id = Guid.NewGuid();
        r.H.Faults.Event = "invitation_resend_requested";
        r.H.Signals.FailHint = kind == "hint"; r.H.Faults.FailAudit = kind == "audit"; r.H.Faults.RejectCommit = kind == "rollback";
        if (kind == "ticket-crossing") r.H.Faults.BeforeAudit = _ => { r.H.Clock.Advance(r.Until - r.H.Clock.GetUtcNow()); return Task.CompletedTask; };
        if (kind == "ticket-crossing") Assert.Equal(InvitationResendOutcome.InvalidContext, await r.Request(id, review));
        else Assert.NotNull(await Record.ExceptionAsync(() => r.Request(id, review)));
        await using var db = fixture.Open(); Assert.False(await db.EmailOutbox.AnyAsync(x => x.Id == id)); Assert.False(await db.WorkItems.AnyAsync(x => x.Id == id));
        Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "invitation_resend_requested"));
        var token = await db.AuthTokens.SingleAsync(x => x.EnvelopeId == r.H.Envelope.Id); Assert.Null(token.UsedAt); Assert.True(token.ExpiresAt > r.H.Clock.GetUtcNow());
    }

    [Fact]
    public async Task Lost_admission_acknowledgement_is_recovered_by_the_same_id_and_its_existing_hint()
    {
        await using var r = await Run.Create(fixture); var review = await r.Review(); var id = Guid.NewGuid();
        r.H.Faults.Event = "invitation_resend_requested"; r.H.Faults.FailCommit = true;
        await Assert.ThrowsAsync<IOException>(() => r.Request(id, review)); r.H.Faults.FailCommit = false;
        Assert.Null(await r.Redeem(r.Token)); Assert.Equal(InvitationResendOutcome.AlreadyRequested, await r.Request(id, review));
        await r.Drain(id); Assert.Equal(2, r.H.Sender.Calls);
    }

    [Theory][InlineData("definite")][InlineData("unknown")][InlineData("receipt")][InlineData("intent")]
    public async Task Only_definite_non_submission_can_retry_transport(string kind)
    {
        await using var r = await Run.Create(fixture); var id = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id));
        if (kind == "intent") {
            using var scope = r.H.App.Services.CreateScope(); var lease = (await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(id, default)).Lease!;
            r.H.Faults.Event = null; r.H.Faults.FailCommit = true;
            await Assert.ThrowsAsync<IOException>(() => scope.ServiceProvider.GetRequiredService<InvitationResendDelivery>().ExecuteAsync(lease, default));
        } else {
            if (kind == "definite") r.H.Sender.Failure = new EmailNotSubmittedException(true);
            if (kind == "unknown") r.H.Sender.Failure = new IOException("synthetic lost acceptance");
            if (kind == "receipt") { r.H.Faults.Event = "invitation_resend_submitted"; r.H.Faults.FailCommit = true; }
            if (kind == "definite") await r.Drain(id, terminal: false);
            else await Assert.ThrowsAsync<IOException>(() => r.Drain(id));
        }
        r.H.Sender.Failure = null; r.H.Faults.FailCommit = false; r.H.Clock.Advance(TimeSpan.FromMinutes(6));
        await r.H.Signals.PublishAsync(id, TimeSpan.Zero, default); await r.Drain(id);
        Assert.Equal(kind == "definite" ? 3 : kind == "intent" ? 1 : 2, r.H.Sender.Calls);
        await using var db = fixture.Open(); var row = await db.EmailOutbox.SingleAsync(x => x.Id == id);
        Assert.Equal(kind is "unknown" or "intent" ? EmailStatus.Failed : EmailStatus.Sent, row.Status);
        if (kind is "unknown" or "intent") Assert.Equal(InvitationResendOutcome.Busy, await r.Request(Guid.NewGuid()));
    }

    [Fact]
    public async Task Replayed_original_work_is_fenced_after_replacement_admission()
    {
        await using var r = await Run.Create(fixture); var id = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id));
        await using (var db = fixture.Open()) {
            await db.WorkItems.Where(x => x.Id == r.Sent.InvitationWorkId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, WorkStatus.Queued));
            await db.EmailOutbox.Where(x => x.Id == r.Sent.InvitationWorkId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, EmailStatus.Queued).SetProperty(x => x.SubmissionStartedAt, (DateTimeOffset?)null));
        }
        await r.H.Signals.PublishAsync(r.Sent.InvitationWorkId, TimeSpan.Zero, default); await r.Drain(id); await r.Drain(r.Sent.InvitationWorkId);
        Assert.Equal(2, r.H.Sender.Calls); await using var check = fixture.Open(); Assert.Equal("invitation-replaced", (await check.WorkItems.SingleAsync(x => x.Id == r.Sent.InvitationWorkId)).LastError);
    }

    [Theory][InlineData("void")][InlineData("expiry")][InlineData("suppression")][InlineData("source")][InlineData("party")][InlineData("payload")]
    [InlineData("audit")][InlineData("attachments")][InlineData("outbox-time")][InlineData("disabled")]
    public async Task Dispatch_revalidates_scope_and_never_issues_or_sends_after_a_boundary_change(string kind)
    {
        await using var r = await Run.Create(fixture); var id = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id));
        await using (var db = fixture.Open()) {
            if (kind == "void") await db.Envelopes.Where(x => x.Id == r.H.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, EnvelopeStatus.Voided));
            if (kind == "expiry") await db.Envelopes.Where(x => x.Id == r.H.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, r.H.Clock.GetUtcNow()));
            if (kind == "source") await db.Envelopes.Where(x => x.Id == r.H.Envelope.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SentPdfSha256, new byte[32]));
            if (kind == "party") await db.Signers.Where(x => x.Id == r.H.First.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Email, "changed@example.invalid"));
            if (kind == "suppression") { db.Suppressions.Add(new() { Email = r.H.First.Email, Reason = SuppressionReason.Complaint }); await db.SaveChangesAsync(); }
            if (kind == "payload") { var row = await db.EmailOutbox.SingleAsync(x => x.Id == id); row.PayloadJson = "{}"; await db.SaveChangesAsync(); }
            if (kind == "audit") await db.AuditEvents.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "invitation_resend_requested").ExecuteUpdateAsync(s => s.SetProperty(x => x.Hash, new byte[32]));
            if (kind == "attachments") await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.AttachmentsJson, "[{}]"));
            if (kind == "outbox-time") await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.AvailableAt, r.H.Clock.GetUtcNow().AddDays(-1)));
        }
        if (kind == "disabled") r.Options.Enabled = false;
        await r.Drain(id, terminal: kind != "disabled");
        Assert.Equal(1, r.H.Sender.Calls); await using var check = fixture.Open(); Assert.Equal(1, await check.AuthTokens.CountAsync(x => x.EnvelopeId == r.H.Envelope.Id));
    }

    [Fact]
    public async Task The_fixed_retention_cutoff_cannot_erase_an_active_daily_reservation()
    {
        var start = new DateTimeOffset(DateTime.UtcNow.Date.AddDays(1), TimeSpan.Zero).AddHours(12);
        await using var retained = await Retained.Create(fixture, initialTime: start); var h = retained.H;
        var reviewed = (await retained.Review())!; var sent = (await h.Send(reviewedRetentionSha256: reviewed.RetentionSha256))!; Assert.True(await h.Once());
        Configure(h);
        h.Clock.Advance(retained.Policy.DeleteAfter - h.Clock.GetUtcNow() - TimeSpan.FromHours(1));
        using var scope = h.App.Services.CreateScope(); var service = scope.ServiceProvider.GetRequiredService<InvitationResends>(); var until = h.Clock.GetUtcNow().AddHours(2);
        var review = (await service.ReviewAsync(h.Principal, h.Envelope.PublicId, until))!;
        Assert.Equal(InvitationResendOutcome.Unavailable, await service.RequestAsync(h.Principal, h.Envelope.PublicId, until, Guid.NewGuid(), review, true, InvitationResendStatement.Version, "127.0.0.1", null));
        await using var db = fixture.Open(); Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == h.Envelope.Id && x.Template == "signer-invitation-resend"));
        Assert.Equal(retained.Policy.DeleteAfter, (await db.DocumentRetentionSnapshots.SingleAsync(x => x.EnvelopeId == h.Envelope.Id)).DeleteAfter);
    }

    [Theory][InlineData("owner")][InlineData("attempt")][InlineData("until")][InlineData("kind")]
    public async Task A_forged_worker_lease_cannot_activate_a_replacement_token(string kind)
    {
        await using var r = await Run.Create(fixture); var id = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id));
        using var scope = r.H.App.Services.CreateScope(); var lease = (await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(id, default)).Lease!;
        lease = kind switch { "owner" => lease with { Owner = Guid.NewGuid() }, "attempt" => lease with { Attempt = lease.Attempt + 1 },
            "until" => lease with { Until = lease.Until.AddTicks(1) }, _ => lease with { Kind = WorkKind.Purge } };
        await Assert.ThrowsAsync<InvalidOperationException>(() => scope.ServiceProvider.GetRequiredService<InvitationResendDelivery>().ExecuteAsync(lease, default));
        Assert.Equal(1, r.H.Sender.Calls); await using var db = fixture.Open(); Assert.Equal(1, await db.AuthTokens.CountAsync(x => x.EnvelopeId == r.H.Envelope.Id));
    }

    [Theory][InlineData("ip")][InlineData("global")][InlineData("moved-counter")][InlineData("oversized-proof")][InlineData("oversized-payload")]
    public async Task Multiple_instances_share_cap_reservations_and_cannot_hide_an_unreadable_counter(string kind)
    {
        await using var first = await Run.Create(fixture); var id = Guid.NewGuid();
        Assert.Equal(InvitationResendOutcome.Queued, await first.Request(id, ip: "192.0.2.100"));
        var keys = new InvitationResendProtection(first.H.App.Services.GetRequiredService<IDataProtectionProvider>());
        await using var second = await Run.Create(fixture, sharedProtection: keys);
        if (kind == "ip") second.Options.DailyIpRequests = 1;
        if (kind == "global") second.Options.DailyRequests = second.Options.DailyAddressRequests = second.Options.DailyIpRequests = second.Options.DailySenderRequests = 1;
        if (kind == "moved-counter") { await using var db = fixture.Open(); await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.AvailableAt, first.H.Clock.GetUtcNow().AddDays(-1))); }
        if (kind == "oversized-proof") {
            await using var db = fixture.Open(); var value = JsonSerializer.Serialize(new { padding = new string('x', 13000) });
            await db.AuditEvents.Where(x => x.EnvelopeId == first.H.Envelope.Id && x.Event == "invitation_resend_requested").ExecuteUpdateAsync(s => s.SetProperty(x => x.DataJson, value));
        }
        if (kind == "oversized-payload") {
            await using var db = fixture.Open(); var value = JsonSerializer.Serialize(new { padding = new string('x', 13000) });
            await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, value));
        }
        if (kind is "ip" or "global") Assert.Equal(InvitationResendOutcome.Capped, await second.Request(Guid.NewGuid(), ip: kind == "ip" ? "192.0.2.100" : "192.0.2.101"));
        else await Assert.ThrowsAsync<InvalidDataException>(() => second.Request(Guid.NewGuid()));
        Assert.NotNull(await second.Redeem(second.Token));
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Dispatch_is_bound_to_its_original_UTC_day_and_does_not_extend_sender_authority(bool nextDay)
    {
        await using var r = await Run.Create(fixture); var id = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id));
        r.H.Clock.Advance(nextDay ? TimeSpan.FromDays(1) : TimeSpan.FromHours(3));
        Assert.Equal(InvitationResendOutcome.InvalidContext, await r.Request(id, new(r.H.First.Id, "", "", Convert.ToBase64String(new byte[8]), Guid.NewGuid(), "", "")));
        await r.Drain(id); Assert.Equal(nextDay ? 1 : 2, r.H.Sender.Calls);
        await using var db = fixture.Open(); Assert.Equal(nextDay ? EmailStatus.Failed : EmailStatus.Sent, (await db.EmailOutbox.SingleAsync(x => x.Id == id)).Status);
        if (nextDay) {
            r.Until = r.H.Clock.GetUtcNow().AddHours(2); var newId = Guid.NewGuid();
            Assert.Equal(InvitationResendOutcome.Queued, await r.Request(newId)); await r.Drain(newId); Assert.Equal(2, r.H.Sender.Calls);
        }
    }

    [Fact]
    public async Task A_definitely_failed_attempt_still_consumes_its_admission_cap()
    {
        await using var r = await Run.Create(fixture); r.Options.DailyAddressRequests = 1; var id = Guid.NewGuid();
        Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id)); r.H.Sender.Failure = new EmailNotSubmittedException(false);
        await r.Drain(id); r.H.Sender.Failure = null;
        Assert.Equal(InvitationResendOutcome.Capped, await r.Request(Guid.NewGuid()));
    }

    [Fact]
    public async Task Older_replacement_work_cannot_be_reactivated_after_a_newer_request()
    {
        await using var r = await Run.Create(fixture); var first = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(first)); await r.Drain(first);
        var second = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(second));
        await using (var db = fixture.Open()) {
            var row = await db.EmailOutbox.SingleAsync(x => x.Id == first);
            var codec = r.H.App.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("QuillSign.InvitationResend.Payload.v1");
            var mail = JsonNode.Parse(codec.Unprotect(JsonSerializer.Deserialize<ProtectedWorkPayload>(row.PayloadJson)!.Protected))!;
            mail["issued"] = null; row.PayloadJson = JsonSerializer.Serialize(new ProtectedWorkPayload(codec.Protect(mail.ToJsonString())));
            row.Status = EmailStatus.Queued; row.SubmissionStartedAt = null; await db.SaveChangesAsync();
            await db.WorkItems.Where(x => x.Id == first).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status, WorkStatus.Queued));
        }
        await r.H.Signals.PublishAsync(first, TimeSpan.Zero, default); await r.Drain(second); await r.Drain(first);
        Assert.Equal(3, r.H.Sender.Calls);
        await using var inspect = fixture.Open(); Assert.Equal("resend-scope-unavailable", (await inspect.WorkItems.SingleAsync(x => x.Id == first)).LastError);
    }

    [Fact]
    public async Task Equivalent_IP_spelling_cannot_bypass_a_resend_cap()
    {
        await using var r = await Run.Create(fixture); r.Options.DailyIpRequests = 1; var review = await r.Review(); var id = Guid.NewGuid();
        Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id, review, "192.0.2.102"));
        Assert.Equal(InvitationResendOutcome.AlreadyRequested, await r.Request(id, review, "::ffff:192.0.2.102")); await r.Drain(id);
        Assert.Equal(InvitationResendOutcome.Capped, await r.Request(Guid.NewGuid(), review, "::ffff:192.0.2.102"));
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Genuine_Finish_and_in_flight_delivery_preserve_the_accepted_evidence(bool duringProvider)
    {
        await using var r = await Run.Create(fixture, browser: true); var finish = await PrepareFinish(r); var review = await r.Review(); var id = Guid.NewGuid();
        Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id, review));
        async Task Accept() {
            using var scope = r.H.App.Services.CreateScope();
            Assert.Equal(SignerFinishOutcome.Accepted, (await scope.ServiceProvider.GetRequiredService<SignerFinish>().AcceptAsync(finish.Principal,
                r.H.Envelope.PublicId, finish.Receipt, true, SignerFinishStatement.Version, "127.0.0.1", "synthetic-finish")).Outcome);
        }
        if (duringProvider) r.H.Sender.BeforeReturn = Accept; else await Accept();
        await r.Drain(id); Assert.Equal(duringProvider ? 2 : 1, r.H.Sender.Calls);
        Assert.Equal(InvitationResendOutcome.Closed, await r.Request(Guid.NewGuid(), review));
        await using var db = fixture.Open(); var accepted = await db.SignerFinishAcceptances.SingleAsync(x => x.EnvelopeId == r.H.Envelope.Id);
        Assert.Null(accepted.ProcessedAt); Assert.Equal(SignerStatus.Viewed, (await db.Signers.SingleAsync(x => x.Id == r.H.First.Id)).Status);
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == r.H.Envelope.Id && x.Event == "signer_finish_accepted").ToArrayAsync());
    }

    private static async Task<(ClaimsPrincipal Principal, string Receipt)> PrepareFinish(Run r)
    {
        var identity = (await r.Redeem(r.Token))!; var principal = SignerAccessConfiguration.Principal(identity);
        using var scope = r.H.App.Services.CreateScope(); var services = scope.ServiceProvider;
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
        return (principal, candidate.Receipt);
    }

    [Fact]
    public async Task Local_Mailpit_delivers_a_new_redeemable_replacement_link()
    {
        await using var r = await Run.Create(fixture, smtp: true); var id = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await r.Request(id)); await r.Drain(id);
        using var http = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT")) };
        using var found = JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query=" + Uri.EscapeDataString("to:" + r.H.First.Email)));
        Assert.Equal(2, found.RootElement.GetProperty("messages").GetArrayLength()); var raw = new List<string>();
        foreach (var message in found.RootElement.GetProperty("messages").EnumerateArray()) {
            using var detail = JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/" + message.GetProperty("ID").GetString()));
            raw.Add(Token(detail.RootElement.GetProperty("Text").GetString()!));
        }
        var identities = await Task.WhenAll(raw.Select(r.Redeem)); Assert.Single(identities, x => x is not null);
        Assert.Equal(r.H.First.Id, identities.Single(x => x is not null)!.SignerId);
    }

    private static InvitationResendOptions Configure(Shared h)
    {
        var options = h.App.Services.GetRequiredService<InvitationResendOptions>(); options.Enabled = true;
        options.DailyRequests = options.DailyAddressRequests = options.DailyIpRequests = options.DailySenderRequests = 1000; return options;
    }
    private static string Token(string text) => Regex.Match(text, "token=([A-Za-z0-9_-]{43})").Groups[1].Value;

    // Test-only host for captured-mail desktop/mobile validation. No test route
    // or sender-authority shortcut is added to the production application.
    public sealed class BrowserSession : IAsyncDisposable
    {
        private readonly Run run;
        private BrowserSession(Run run) { this.run = run; }
        public string PublicId => run.H.Envelope.PublicId;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture, int port)
        {
            var run = await Run.Create(fixture, browser: true, smtp: true, port: port);
            run.H.Clock.TrackElapsed(); return new(run);
        }
        public Task<bool> Dispatch() => run.H.Once();
        public async Task<string[]> Links()
        {
            using var http = new HttpClient { BaseAddress = new Uri("http://127.0.0.1:" + Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT")) };
            using var found = JsonDocument.Parse(await http.GetStringAsync("/api/v1/search?query=" + Uri.EscapeDataString("to:" + run.H.First.Email)));
            var links = new List<string>();
            foreach (var message in found.RootElement.GetProperty("messages").EnumerateArray()) {
                using var detail = JsonDocument.Parse(await http.GetStringAsync("/api/v1/message/" + message.GetProperty("ID").GetString()));
                var raw = InvitationResendTests.Token(detail.RootElement.GetProperty("Text").GetString()!);
                links.Add(run.H.App.Services.GetRequiredService<EmailOptions>().BaseUrl + "/sign/invitation?token=" + raw);
            }
            return links.ToArray();
        }
        public async Task Resend()
        { var id = Guid.NewGuid(); Assert.Equal(InvitationResendOutcome.Queued, await run.Request(id)); await run.Drain(id); }
        public ValueTask DisposeAsync() => run.DisposeAsync();
    }

    private sealed class Run(Shared h, SqlDatabaseFixture fixture, SentDraft sent) : IAsyncDisposable
    {
        public Shared H => h; public SentDraft Sent => sent; public InvitationResendOptions Options = Configure(h);
        public DateTimeOffset Until = h.Clock.GetUtcNow().AddHours(2);
        public string Token => InvitationResendTests.Token(h.Sender.Last?.Text ?? "");
        public static async Task<Run> Create(SqlDatabaseFixture fixture, bool dispatch = true, bool browser = false, bool smtp = false, InvitationResendProtection? sharedProtection = null, int? port = null)
        {
            var h = await Shared.Create(fixture, smtp, browser, browserPort: port, configure: services => { if (sharedProtection is not null) services.AddSingleton(sharedProtection); });
            if (port is not null) h.App.Services.GetRequiredService<EmailOptions>().BaseUrl = "http://localhost:" + port;
            // Use one explicit future UTC day before Send so a CI midnight cannot
            // turn short expiry/cap cases into unrelated day-boundary failures.
            h.Clock.Advance(new DateTimeOffset(DateTime.UtcNow.Date.AddDays(2), TimeSpan.Zero).AddHours(1) - h.Clock.GetUtcNow());
            var sent = (await h.Send())!;
            var r = new Run(h, fixture, sent); if (dispatch) await r.Drain(sent.InvitationWorkId); return r;
        }
        public async Task<InvitationResendReview> Review()
        { using var scope = h.App.Services.CreateScope(); return (await scope.ServiceProvider.GetRequiredService<InvitationResends>().ReviewAsync(h.Principal, h.Envelope.PublicId, Until))!; }
        public async Task<InvitationResendOutcome> Request(Guid id, InvitationResendReview? review = null, string ip = "127.0.0.1")
        { review ??= await Review(); using var scope = h.App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<InvitationResends>().RequestAsync(h.Principal, h.Envelope.PublicId, Until, id, review, true, InvitationResendStatement.Version, ip, "synthetic-resend"); }
        public async Task<VerifiedSigner?> Redeem(string token)
        { using var scope = h.App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(token, "127.0.0.1", "synthetic"); }
        public async Task Drain(Guid id, bool terminal = true)
        {
            for (var i = 0; i < 12; i++) {
                await using var db = fixture.Open(); var state = await db.WorkItems.Where(x => x.Id == id).Select(x => x.Status).SingleAsync();
                if (state is WorkStatus.Completed or WorkStatus.Failed) return;
                Assert.True(await h.Once());
                if (!terminal && await db.WorkItems.Where(x => x.Id == id).Select(x => x.Attempts).SingleAsync() > 0) return;
            }
            throw new InvalidOperationException("Synthetic targeted work did not settle.");
        }
        public async ValueTask DisposeAsync()
        {
            // Each synthetic app has its own key ring. Retire this app's cap
            // records with its fixture, rather than presenting them as another
            // deployment's unreadable counters to later tests in the same DB.
            await using var db = fixture.Open();
            var ids = await db.EmailOutbox.Where(x => x.EnvelopeId == h.Envelope.Id && x.Template == "signer-invitation-resend").Select(x => x.Id).ToArrayAsync();
            await db.WorkItems.Where(x => ids.Contains(x.Id) && x.EnvelopeId == h.Envelope.Id).ExecuteDeleteAsync();
            await db.EmailOutbox.Where(x => ids.Contains(x.Id) && x.EnvelopeId == h.Envelope.Id).ExecuteDeleteAsync();
            await db.AuditEvents.Where(x => x.EnvelopeId == h.Envelope.Id && x.Event.StartsWith("invitation_resend_")).ExecuteDeleteAsync();
            await h.DisposeAsync();
        }
    }
}
