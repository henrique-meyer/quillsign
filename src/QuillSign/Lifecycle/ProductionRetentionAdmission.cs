using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Legal;

namespace QuillSign.Lifecycle;

// Not bound to startup until the complete disclosure/publication/access integration
// is available. A retention interval alone never selects production admission.
public sealed class RecordLifecycleOptions
{
    public string Mode { get; set; } = "Demo";
    public ProductionRetentionPolicyOptions Production { get; set; } = new();
}

internal sealed record RecordAdmissionPlan(Envelope Envelope, ProductionRetentionPolicyOptions? Policy);

// Internal creation boundary, not participant verification, delivery or migration.
// The normal request workflow must own its transaction and subsequent audit/outbox.
internal sealed class ProductionRetentionAdmission(QuillSignDbContext db, AuditWriter audit, TimeProvider time)
{
    internal static RecordAdmissionPlan Prepare(string address, DateTimeOffset now, RecordLifecycleOptions options,
        ElectronicRecordOptions disclosure)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (now == default || now.Offset != TimeSpan.Zero) throw new InvalidOperationException("Use the server's UTC creation time.");
        if (options.Mode is not ("Demo" or "Production")) throw new InvalidOperationException("Select an explicit supported record mode.");
        var envelope = new Envelope { SenderEmail = EmailAddress.Normalize(address), CreatedAt = now, IsDemo = options.Mode == "Demo" };
        if (envelope.IsDemo) return new(envelope, null);
        ProductionRetentionDisclosure.RequireOperatorPolicies(disclosure);
        var frozen = ProductionRetentionPolicyContract.Freeze(envelope.Id, ProductionRetentionLedger.Seconds(now), options.Production);
        // Validate the exact original clock as well as its normalized snapshot clock.
        var verified = new VerifiedProductionRetention(frozen, now, now, 1, new string('0', 64));
        _ = ProductionRetentionDisclosure.Build(envelope, "Untitled draft", verified, disclosure);
        var p = frozen.Policy;
        return new(envelope, new() { Version=p.Version, ArchiveResponsibility=p.ArchiveResponsibility,
            AbandonedDraftDays=p.AbandonedDraftDays, ExpiredDays=p.ExpiredDays, DeclinedDays=p.DeclinedDays,
            VoidedDays=p.VoidedDays, CompletedDays=p.CompletedDays });
    }

    internal async Task<Envelope> CreateLockedAsync(string address, RecordLifecycleOptions options,
        ElectronicRecordOptions disclosure, CancellationToken ct = default)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Record admission requires its request transaction.");
        var plan = Prepare(address, time.GetUtcNow(), options, disclosure);
        db.Envelopes.Add(plan.Envelope);
        if (plan.Policy is null) await db.SaveChangesAsync(ct);
        else await new ProductionRetentionLedger(db, audit, time).PrepareNewLockedAsync(plan.Envelope, plan.Policy, ct);
        return plan.Envelope;
    }
}
