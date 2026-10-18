using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed partial class DocumentLookupDeliveryTests
{
    [Fact]
    public async Task Lookup_contact_policy_and_both_recovery_hints_are_saved_with_original_deadlines_and_no_generic_contact_data()
    {
        await using var h = new Harness(fixture); var first = Guid.NewGuid(); await h.Request(first);
        await using var db = fixture.Open(); var policy = await db.LookupContactRetentionSnapshots.AsNoTracking().SingleAsync(x => x.RequestId == first);
        Assert.Equal(7, policy.Days); Assert.Equal(h.Start, policy.StartedAt); Assert.Equal(h.Start.AddDays(7), policy.DeleteAfter);
        var cleanup = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == LookupContactRetention.WorkId(first));
        Assert.Null(cleanup.EnvelopeId); Assert.Equal(WorkKind.Purge, cleanup.Kind); Assert.Equal(policy.DeleteAfter, cleanup.AvailableAt);
        Assert.DoesNotContain(h.Address, cleanup.PayloadJson); Assert.DoesNotContain(h.Ip, cleanup.PayloadJson);
        Assert.Equal(policy.DeleteAfter, await h.Signals.ReadDueAsync(cleanup.Id, default)); Assert.Equal(h.Start, await h.Signals.ReadDueAsync(first, default));
        h.App.Services.GetRequiredService<LookupContactRetentionOptions>().Days = 3;
        using (var scope = h.App.Services.CreateScope()) await scope.ServiceProvider.GetRequiredService<LookupContactRetention>().ResumeAsync(first);
        Assert.Equal(policy.DeleteAfter, (await db.LookupContactRetentionSnapshots.AsNoTracking().SingleAsync(x => x.RequestId == first)).DeleteAfter);
        var second = Guid.NewGuid(); await h.Request(second);
        Assert.Equal(h.Start.AddDays(3), (await db.LookupContactRetentionSnapshots.AsNoTracking().SingleAsync(x => x.RequestId == second)).DeleteAfter);
        Assert.False(await h.Tokens(db).AnyAsync());
    }

    [Fact]
    public async Task An_unset_contact_retention_policy_refuses_new_admission_before_SQL_or_storage()
    {
        await using var h = new Harness(fixture); h.App.Services.GetRequiredService<LookupContactRetentionOptions>().Days = null;
        var before = h.Connections.Opens; Assert.Equal(LookupRequestOutcome.Unavailable, await h.Request(Guid.NewGuid()));
        Assert.Equal(before, h.Connections.Opens); Assert.Equal(0, h.Signals.Puts); Assert.Equal(0, h.Transport.Calls);
    }

    [Theory]
    [InlineData("missing-policy")][InlineData("missing-job")][InlineData("job-purpose")][InlineData("job-whitespace")]
    public async Task Dispatch_without_the_exact_saved_contact_cleanup_scope_never_issues_or_sends(string fault)
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id); var purge = LookupContactRetention.WorkId(id);
        await using (var db = fixture.Open()) {
            if (fault == "missing-policy") await db.LookupContactRetentionSnapshots.Where(x => x.RequestId == id).ExecuteDeleteAsync();
            if (fault == "missing-job") await db.WorkItems.Where(x => x.Id == purge).ExecuteDeleteAsync();
            if (fault == "job-purpose") await db.WorkItems.Where(x => x.Id == purge).ExecuteUpdateAsync(s => s.SetProperty(x => x.Kind, WorkKind.Rendering));
            if (fault == "job-whitespace") await db.WorkItems.Where(x => x.Id == purge).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, x => x.PayloadJson + " "));
        }
        Assert.True(await h.Once()); Assert.Equal(0, h.Transport.Calls); await using var check = fixture.Open(); Assert.False(await h.Tokens(check).AnyAsync());
    }

    [Fact]
    public async Task A_one_day_policy_cannot_dispatch_yesterdays_queued_request_and_erase_todays_sending_counters()
    {
        await using var h = new Harness(fixture); h.App.Services.GetRequiredService<LookupContactRetentionOptions>().Days = 1;
        h.Clock.Advance(TimeSpan.FromHours(23)); var first = Guid.NewGuid(); var delayed = Guid.NewGuid(); await h.Request(first); await h.Request(delayed);
        h.App.Services.GetRequiredService<LookupContactRetentionOptions>().Days = 30;
        h.Limits.DailyRequests = h.Limits.DailyIpRequests = h.Limits.DailyAddressRequests = 1;
        Assert.True(await h.Once()); Assert.True(await h.Once()); Assert.Equal(1, h.Transport.Calls);
        h.Clock.Advance(TimeSpan.FromHours(2)); await h.Signals.PublishAsync(delayed, TimeSpan.Zero, default); Assert.True(await h.Once());
        Assert.Equal(1, h.Transport.Calls);
        await using var db = fixture.Open(); Assert.Equal("lookup-request-expired", (await db.WorkItems.SingleAsync(x => x.Id == delayed)).LastError);
        var today = Guid.NewGuid(); await h.Request(today); Assert.True(await h.Once()); Assert.Equal(2, h.Transport.Calls);
        Assert.Equal(h.Start.AddHours(47), (await db.LookupContactRetentionSnapshots.SingleAsync(x => x.RequestId == first)).DeleteAfter);
    }

    [Theory]
    [InlineData("queued")][InlineData("sent")][InlineData("ambiguous")][InlineData("rejected")]
    public async Task Expired_lookup_contacts_are_removed_without_revoking_independent_access_or_touching_neighbors(string state)
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id);
        if (state != "queued") {
            if (state == "ambiguous") h.Transport.Failure = new IOException("Synthetic unknown acceptance.");
            if (state == "rejected") h.Transport.Failure = new EmailNotSubmittedException(false);
            if (state == "ambiguous") await Assert.ThrowsAsync<IOException>(() => h.Once()); else Assert.True(await h.Once());
        }
        var lease = await CleanupLease(h, id); h.KeysUnavailable = true; h.Email.Enabled = false;
        var neighbor = Guid.NewGuid(); var address = "suppressed-" + Guid.NewGuid().ToString("N") + "@example.invalid";
        await using (var db = fixture.Open()) {
            db.Envelopes.Add(new() { Id = neighbor, SenderEmail = "neighbor@example.invalid" });
            db.EmailOutbox.Add(new() { Id = neighbor, To = "unrelated@example.invalid", Template = "other" });
            db.Suppressions.Add(new() { Email = address, Reason = SuppressionReason.Complaint }); await db.SaveChangesAsync();
        }
        h.KeysUnavailable = false; DocumentLookupLink link;
        using (var scope = h.App.Services.CreateScope()) link = await scope.ServiceProvider.GetRequiredService<DocumentLookup>().IssueAsync(h.Address);
        h.KeysUnavailable = true;
        Assert.True(await Remove(h, lease)); Assert.False(await Remove(h, lease));
        await using (var db = fixture.Open()) {
            Assert.False(await db.EmailOutbox.AnyAsync(x => x.Id == id)); Assert.False(await db.LookupContactRetentionSnapshots.AnyAsync(x => x.RequestId == id));
            Assert.True(await db.Envelopes.AnyAsync(x => x.Id == neighbor)); Assert.True(await db.EmailOutbox.AnyAsync(x => x.Id == neighbor));
            Assert.True(await db.Suppressions.AnyAsync(x => x.Email == address));
            var work = await db.WorkItems.SingleAsync(x => x.Id == id);
            Assert.Equal(state == "sent" ? WorkStatus.Completed : WorkStatus.Failed, work.Status); Assert.Null(work.LeaseOwner); Assert.Null(work.LeaseExpiresAt);
            Assert.Equal(state == "ambiguous" ? "submission-ambiguous" : state == "sent" ? "lookup-contact-sent" : "lookup-contact-expired", work.LastError);
            Assert.Equal(JsonSerializer.Serialize(new { emailId = id }), work.PayloadJson);
        }
        h.KeysUnavailable = false;
        using (var scope = h.App.Services.CreateScope()) {
            var lookup = scope.ServiceProvider.GetRequiredService<DocumentLookup>(); var session = (await lookup.RedeemAsync(link.Transport))!;
            Assert.NotNull(session); Assert.NotNull(await lookup.ListAsync(DocumentLookupProtection.Principal(session.Identity), session.Receipt));
        }
        var calls = h.Transport.Calls; h.Email.Enabled = true; await h.Request(id); Assert.Equal(calls, h.Transport.Calls);
        await using (var db = fixture.Open()) Assert.False(await db.EmailOutbox.AnyAsync(x => x.Id == id));
        Assert.Null(await h.Signals.ReadDueAsync(id, default));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task A_live_email_or_outbox_lease_defers_cleanup_until_the_actual_lease_has_expired(bool outbox)
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); var purge = await CleanupLease(h, id);
        using (var scope = h.App.Services.CreateScope()) Assert.NotNull((await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(id, default)).Lease);
        if (outbox) { await using var db = fixture.Open();
            await db.WorkItems.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.LeaseExpiresAt, DateTimeOffset.UtcNow.AddSeconds(-1)));
            await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.LeaseOwner, Guid.NewGuid()).SetProperty(x => x.LeaseExpiresAt, DateTimeOffset.UtcNow.AddMinutes(5)));
        }
        var busy = await Assert.ThrowsAsync<SqlException>(() => Remove(h, purge)); Assert.Equal(50002, busy.Number);
        await using (var db = fixture.Open()) {
            Assert.True(await db.EmailOutbox.AnyAsync(x => x.Id == id));
            await db.WorkItems.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.LeaseExpiresAt, DateTimeOffset.UtcNow.AddSeconds(-1)));
            if (outbox) await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.LeaseExpiresAt, DateTimeOffset.UtcNow.AddSeconds(-1)));
        }
        Assert.True(await Remove(h, purge));
    }

    [Theory]
    [InlineData("owner")][InlineData("attempt")][InlineData("kind")][InlineData("whitespace")][InlineData("policy")]
    [InlineData("parent")][InlineData("template")][InlineData("mail-work")][InlineData("future-server-time")]
    public async Task Cleanup_rejects_wrong_lease_saved_policy_or_outbox_scope_and_never_uses_a_fake_clock_as_SQL_authority(string fault)
    {
        await using var h = fault == "future-server-time" ? new Harness(fixture) : Past(); var id = Guid.NewGuid(); await h.Request(id);
        if (fault == "future-server-time") h.Clock.Advance(TimeSpan.FromDays(8));
        var lease = await CleanupLease(h, id);
        await using (var db = fixture.Open()) {
            if (fault == "whitespace") await db.WorkItems.Where(x => x.Id == lease.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, x => x.PayloadJson + " "));
            if (fault == "policy") await db.LookupContactRetentionSnapshots.Where(x => x.RequestId == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Days, 8).SetProperty(x => x.DeleteAfter, x => x.DeleteAfter.AddDays(1)));
            if (fault == "parent") { var parent = new Envelope { SenderEmail = "parent@example.invalid" }; db.Envelopes.Add(parent); await db.SaveChangesAsync(); await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.EnvelopeId, parent.Id)); }
            if (fault == "template") await db.EmailOutbox.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Template, "document-lookup "));
            if (fault == "mail-work") await db.WorkItems.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Kind, WorkKind.Rendering));
        }
        lease = fault switch { "owner" => lease with { Owner = Guid.NewGuid() }, "attempt" => lease with { Attempt = lease.Attempt + 1 }, "kind" => lease with { Kind = WorkKind.Email }, _ => lease };
        var error = await Record.ExceptionAsync(() => Remove(h, lease)); Assert.True(error is UnauthorizedAccessException or InvalidDataException or IOException or SqlException, error?.ToString());
        await using var check = fixture.Open(); Assert.True(await check.EmailOutbox.AnyAsync(x => x.Id == id)); Assert.True(await check.LookupContactRetentionSnapshots.AnyAsync(x => x.RequestId == id));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Rejected_or_lost_cleanup_commit_recovers_without_another_send_or_extending_retention(bool lost)
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); var lease = await CleanupLease(h, id);
        h.Faults.Mode = lost ? "cleanup-lost" : "cleanup-rejected";
        await Assert.ThrowsAsync<IOException>(() => Remove(h, lease)); h.Faults.Mode = "";
        await using (var db = fixture.Open()) Assert.Equal(!lost, await db.EmailOutbox.AnyAsync(x => x.Id == id));
        Assert.NotNull(await h.Signals.ReadDueAsync(id, default)); Assert.Equal(!lost, await Remove(h, lease));
        using (var scope = h.App.Services.CreateScope()) await scope.ServiceProvider.GetRequiredService<WorkStore>().FinishAsync(lease, new(WorkOutcome.Completed), default);
        Assert.Equal(0, h.Transport.Calls); await h.Signals.PublishAsync(id, TimeSpan.Zero, default); Assert.True(await h.Once()); Assert.Equal(0, h.Transport.Calls);
    }

    [Fact]
    public async Task Storage_hint_recovery_runs_lookup_cleanup_while_email_and_private_keys_are_disabled()
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); h.Clock.Advance(DateTimeOffset.UtcNow - h.Clock.GetUtcNow());
        h.Email.Enabled = false; h.KeysUnavailable = true; var before = h.Connections.Opens;
        await h.Signals.RecoverAsync(h.Clock.GetUtcNow(), default); Assert.Equal(before, h.Connections.Opens);
        for (var i = 0; i < 5; i++) { await using var db = fixture.Open(); if (!await db.EmailOutbox.AnyAsync(x => x.Id == id)) break; await h.Once(); }
        await using var check = fixture.Open(); Assert.False(await check.EmailOutbox.AnyAsync(x => x.Id == id));
        Assert.Equal(WorkStatus.Completed, (await check.WorkItems.SingleAsync(x => x.Id == LookupContactRetention.WorkId(id))).Status);
        Assert.Equal(0, h.Transport.Calls);
        for (var i = 0; i < 4 && await h.Once(); i++) { }
        before = h.Connections.Opens; Assert.False(await h.Once()); Assert.Equal(before, h.Connections.Opens);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Tracked_contact_policy_edits_and_deletes_are_rejected_before_SQL(bool delete)
    {
        await using var h = new Harness(fixture); var id = Guid.NewGuid(); await h.Request(id);
        await using var db = fixture.Open(); var saved = await db.LookupContactRetentionSnapshots.SingleAsync(x => x.RequestId == id);
        if (delete) db.LookupContactRetentionSnapshots.Remove(saved); else saved.PolicyVersion = "changed";
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task Explicit_legacy_enrollment_uses_original_request_time_and_resumes_saved_policy_without_keys_or_new_config()
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); await RemoveEnrollment(id);
        h.App.Services.GetRequiredService<LookupContactRetentionOptions>().Days = 3;
        using (var scope = h.App.Services.CreateScope()) Assert.Equal(LookupContactRetention.WorkId(id), await scope.ServiceProvider.GetRequiredService<LookupContactRetention>().ResumeAsync(id));
        await using (var db = fixture.Open()) Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(h.Start.ToUnixTimeSeconds()).AddDays(3), (await db.LookupContactRetentionSnapshots.SingleAsync(x => x.RequestId == id)).DeleteAfter);
        h.KeysUnavailable = true; h.App.Services.GetRequiredService<LookupContactRetentionOptions>().Days = null;
        using (var scope = h.App.Services.CreateScope()) Assert.Equal(LookupContactRetention.WorkId(id), await scope.ServiceProvider.GetRequiredService<LookupContactRetention>().ResumeAsync(id));
        Assert.True(await Remove(h, await CleanupLease(h, id)));
        using (var scope = h.App.Services.CreateScope()) Assert.Null(await scope.ServiceProvider.GetRequiredService<LookupContactRetention>().ResumeAsync(id));
    }

    [Fact]
    public async Task A_one_day_legacy_enrollment_cannot_discard_a_later_UTC_day_submission_counter()
    {
        await using var h = Past(); var id = Guid.NewGuid(); await h.Request(id); await RemoveEnrollment(id);
        // Construct an otherwise valid legacy v1 protected submission crossing UTC
        // midnight, rather than failing earlier because its issued binding is absent.
        var intent = new DateTimeOffset(h.Start.UtcDateTime.Date.AddDays(1).AddMinutes(1), TimeSpan.Zero);
        var protector = h.App.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("QuillSign.LookupDelivery.Payload.v1");
        await using (var db = fixture.Open()) {
            var email = await db.EmailOutbox.SingleAsync(x => x.Id == id);
            var wrapper = JsonNode.Parse(email.PayloadJson)!; var payload = JsonNode.Parse(protector.Unprotect(wrapper["Protected"]!.GetValue<string>()))!;
            payload["Issued"] = JsonSerializer.SerializeToNode(new { Id = Guid.NewGuid(), Revision = Convert.ToBase64String(new byte[8]), Sha256 = new string('0', 64), ExpiresAt = intent.AddMinutes(15) });
            wrapper["Protected"] = protector.Protect(payload.ToJsonString());
            email.PayloadJson = wrapper.ToJsonString(); email.SubmissionStartedAt = intent; email.Status = EmailStatus.Sent; await db.SaveChangesAsync();
        }
        h.App.Services.GetRequiredService<LookupContactRetentionOptions>().Days = 1;
        using var scope = h.App.Services.CreateScope(); await Assert.ThrowsAsync<InvalidDataException>(() => scope.ServiceProvider.GetRequiredService<LookupContactRetention>().ResumeAsync(id));
        await using var check = fixture.Open(); Assert.False(await check.LookupContactRetentionSnapshots.AnyAsync(x => x.RequestId == id)); Assert.True(await check.EmailOutbox.AnyAsync(x => x.Id == id));
        h.App.Services.GetRequiredService<LookupContactRetentionOptions>().Days = 2;
        Assert.Equal(LookupContactRetention.WorkId(id), await scope.ServiceProvider.GetRequiredService<LookupContactRetention>().ResumeAsync(id));
    }

    [Theory]
    [InlineData(1)][InlineData(2)]
    public async Task Failure_of_either_storage_hint_rolls_back_all_contact_policy_and_work_rows(int hint)
    {
        await using var h = Past(); var id = Guid.NewGuid(); h.Signals.FailHint = true; h.Signals.FailHintAt = hint;
        await Assert.ThrowsAsync<IOException>(() => h.Request(id)); h.Signals.FailHint = false;
        h.Clock.Advance(DateTimeOffset.UtcNow - h.Clock.GetUtcNow()); await h.Signals.RecoverAsync(h.Clock.GetUtcNow(), default);
        for (var i = 0; i < 4 && await h.Once(); i++) { }
        await using var db = fixture.Open(); Assert.False(await db.EmailOutbox.AnyAsync(x => x.Id == id));
        Assert.False(await db.LookupContactRetentionSnapshots.AnyAsync(x => x.RequestId == id));
        Assert.False(await db.WorkItems.AnyAsync(x => x.Id == id || x.Id == LookupContactRetention.WorkId(id)));
        Assert.Null(await h.Signals.ReadDueAsync(LookupContactRetention.WorkId(id), default)); Assert.Equal(0, h.Transport.Calls);
    }

    private Harness Past()
    {
        var h = new Harness(fixture, DateTimeOffset.UtcNow.AddDays(-8 - Interlocked.Increment(ref pastSequence) * 10));
        h.Limits.DailyRequests = h.Limits.DailyIpRequests = h.Limits.DailyAddressRequests = 1000; return h;
    }
    private static int pastSequence;
    private static async Task<WorkLease> CleanupLease(Harness h, Guid id)
    {
        if (h.Clock.GetUtcNow() < DateTimeOffset.UtcNow) h.Clock.Advance(DateTimeOffset.UtcNow - h.Clock.GetUtcNow());
        using var scope = h.App.Services.CreateScope(); return Assert.IsType<WorkLease>((await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(LookupContactRetention.WorkId(id), default)).Lease);
    }
    private static async Task<bool> Remove(Harness h, WorkLease lease)
    {
        using var scope = h.App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<LookupContactCleanup>().RemoveAsync(lease);
    }
    private async Task RemoveEnrollment(Guid id)
    {
        await using var db = fixture.Open(); await db.LookupContactRetentionSnapshots.Where(x => x.RequestId == id).ExecuteDeleteAsync();
        await db.WorkItems.Where(x => x.Id == LookupContactRetention.WorkId(id)).ExecuteDeleteAsync();
    }
}
