using System.Text.Json;
using Azure;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Work;

public enum LookupRequestOutcome { Neutral, Unavailable }
internal sealed record PilotLookupPrepared(EmailOutbox Outbox, LookupMailPayload Payload, LookupContactRetentionSnapshot Retention);

// Internal request admission only. A public caller must never receive a private link.
public sealed class DocumentLookupRequests(QuillSignDbContext db, LookupDeliveryOptions options, LookupDeliveryProtection protection,
    EmailOptions emailOptions, WorkOptions workOptions, Func<IWorkSignals> signals, TimeProvider time, LookupContactRetention retention)
{
    // Only the capability-bound pilot admission owns this transaction. Ordinary
    // public admission keeps its existing global email gate and neutral result.
    internal async Task<PilotLookupPrepared?> PreparePilotLockedAsync(Email.Pilot.EmailPilotLookupAdmissionScope scope, string? ip, CancellationToken ct)
    {
        if (emailOptions.Enabled || !workOptions.Enabled || !retention.Configured) throw new EmailDisabledException();
        options.Validate(); var now = time.GetUtcNow(); scope.Demand(db, now);
        var email = EmailAddress.Normalize(scope.Sender); var ipHash = LookupDeliveryProtection.IpHash(ip);
        await LookupDeliveryRules.LockAsync(db, ct);
        var requestId = scope.RequestId;
        if (await db.EmailOutbox.AnyAsync(x => x.Id == requestId, ct) || await db.WorkItems.AnyAsync(x => x.Id == requestId, ct) ||
            await db.Suppressions.AnyAsync(x => x.Email == email, ct) ||
            !await LookupDeliveryRules.WithinCapsAsync(db, options, protection, email, ipHash, now, false, ct)) return null;
        var deadline = new[] { scope.Deadline, now.AddHours(options.RequestHours) }.Min();
        var payload = new LookupMailPayload("lookup-mail-v1", requestId, email, ipHash, now, deadline, null, scope.RunId);
        var outbox = new EmailOutbox { Id = requestId, To = email, Template = LookupDeliveryProtection.Template,
            PayloadJson = protection.Protect(payload), AvailableAt = now };
        db.EmailOutbox.Add(outbox);
        db.WorkItems.Add(new() { Id = requestId, Kind = WorkKind.Email, AvailableAt = now, PayloadJson = JsonSerializer.Serialize(new { emailId = requestId }) });
        await db.SaveChangesAsync(ct);
        var policy = await retention.EnrollLockedAsync(outbox, false, ct);
        payload = payload with { Deadline = new[] { deadline, LookupContactRetention.DispatchDeadline(payload, options, policy) }.Min() };
        if (payload.Deadline <= time.GetUtcNow() || emailOptions.Enabled || !workOptions.Enabled) throw new EmailDisabledException();
        outbox.PayloadJson = protection.Protect(payload); await db.SaveChangesAsync(ct);
        await signals().PutHintAsync(requestId, now, ct);
        return new(outbox, payload, policy);
    }

    public async Task<LookupRequestOutcome> RequestAsync(Guid requestId, string address, string? ip, CancellationToken ct = default)
    {
        options.Validate();
        if (!emailOptions.Enabled || !workOptions.Enabled || !retention.Configured) return LookupRequestOutcome.Unavailable;
        if (requestId == Guid.Empty) throw new ArgumentException("A lookup request identifier is required.");
        var email = EmailAddress.Normalize(address); var ipHash = LookupDeliveryProtection.IpHash(ip);
        if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Lookup admission requires a clean standalone unit of work.");
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        DateTimeOffset cleanupDue;
        try {
            await using (var tx = await db.Database.BeginTransactionAsync(ct)) {
                await LookupDeliveryRules.LockAsync(db, ct);
                // The identifier is not a capability. Any existing purpose/scope is left intact.
                if (await db.EmailOutbox.AnyAsync(x => x.Id == requestId, ct) || await db.WorkItems.AnyAsync(x => x.Id == requestId, ct)) return LookupRequestOutcome.Neutral;
                var now = time.GetUtcNow();
                if (await db.Suppressions.AnyAsync(x => x.Email == email, ct) ||
                    !await LookupDeliveryRules.WithinCapsAsync(db, options, protection, email, ipHash, now, false, ct)) return LookupRequestOutcome.Neutral;
                if (!emailOptions.Enabled || !workOptions.Enabled) return LookupRequestOutcome.Unavailable;
                var payload = new LookupMailPayload("lookup-mail-v1", requestId, email, ipHash, now, now.AddHours(options.RequestHours), null);
                var outbox = new EmailOutbox { Id = requestId, To = email, Template = LookupDeliveryProtection.Template,
                    PayloadJson = protection.Protect(payload), AvailableAt = now };
                db.EmailOutbox.Add(outbox);
                db.WorkItems.Add(new() { Id = requestId, Kind = WorkKind.Email, AvailableAt = now, PayloadJson = JsonSerializer.Serialize(new { emailId = requestId }) });
                await db.SaveChangesAsync(ct);
                cleanupDue = (await retention.EnrollLockedAsync(outbox, false, ct)).DeleteAfter;
                await signals().PutHintAsync(requestId, now, ct);
                await tx.CommitAsync(ct);
            }
        } catch { db.ChangeTracker.Clear(); throw; }
        // The committed storage hint recovers a lost publication or acknowledgement.
        try { await signals().PublishAsync(requestId, TimeSpan.Zero, ct); }
        catch (Exception e) when (e is RequestFailedException or IOException or OperationCanceledException or HttpRequestException) { }
        await retention.PublishAsync(requestId, cleanupDue, ct);
        return LookupRequestOutcome.Neutral;
    }
}
