using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Legal;

// Pure text snapshot builder. Only callers that already verified enrollment may
// use its result. Text and hashes confer no session, storage or deletion authority.
internal static class ProductionRetentionDisclosure
{
    internal const string Version = "production-retention-2026-10-20.1";
    internal static void RequireOperatorPolicies(ElectronicRecordOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!string.IsNullOrEmpty(options.Profile)) throw new DisclosureRejectedException("Production requires complete operator-supplied disclosure policies.");
    }

    internal static DisclosureSnapshot Build(Envelope e, string title, VerifiedProductionRetention enrollment,
        ElectronicRecordOptions options)
    {
        RequireOperatorPolicies(options);
        var snapshot = enrollment.Snapshot;
        ProductionRetentionPolicyContract.Validate(snapshot);
        if (e.IsDemo || snapshot.RecordId != e.Id || e.CreatedAt != enrollment.OriginalCreatedAt ||
            e.CreatedAt.Offset != TimeSpan.Zero || snapshot.CreatedAt != ProductionRetentionLedger.Seconds(e.CreatedAt))
            throw new DisclosureRejectedException("Use this record's verified frozen production policy.");
        var original = new ElectronicRecordDisclosure(options).Build(e.PublicId, title, e.SenderEmail);
        var prefix = $"Electronic Record and Signature Disclosure\nVersion: {original.Version}\n";
        if (!original.Text.StartsWith(prefix, StringComparison.Ordinal)) throw new DisclosureRejectedException("The disclosure layout is unsupported.");
        var text = $"Electronic Record and Signature Disclosure\nVersion: {Version}\n" + original.Text[prefix.Length..] + Notice(enrollment);
        if (text.Length > ElectronicRecordDisclosure.MaximumTextCharacters) throw new DisclosureRejectedException("The disclosure exceeds the supported length.");
        var result = original with { Version=Version, Text=text, Sha256=SHA256.HashData(Encoding.UTF8.GetBytes(text)) };
        if (!ElectronicRecordDisclosure.Verify(result)) throw new DisclosureRejectedException("The production disclosure could not be verified.");
        return result;
    }

    internal static string Notice(VerifiedProductionRetention enrollment)
    {
        var snapshot = enrollment.Snapshot;
        ProductionRetentionPolicyContract.Validate(snapshot);
        if (enrollment.OriginalCreatedAt.Offset != TimeSpan.Zero ||
            ProductionRetentionLedger.Seconds(enrollment.OriginalCreatedAt) != snapshot.CreatedAt)
            throw new DisclosureRejectedException("The original production creation clock is invalid.");
        var p = snapshot.Policy;
        var draft = ProductionRetentionPolicyContract.AddDays(enrollment.OriginalCreatedAt, p.AbandonedDraftDays);
        // Validate all exact earliest deadlines before disclosing a usable policy.
        foreach (var days in new[] { p.ExpiredDays, p.DeclinedDays, p.VoidedDays, p.CompletedDays })
            _ = ProductionRetentionPolicyContract.AddDays(enrollment.OriginalCreatedAt, days);
        var completed = p.CompletedDays == 0 ? "Completed records have explicitly selected indefinite retention."
            : $"Completed records have a retention interval of {p.CompletedDays} days from actual completion.";
        return FormattableString.Invariant($"""

            Frozen production retention policy
            Policy version: {p.Version}
            Policy reference: {ProductionRetentionPolicyContract.Digest(snapshot)}
            Archive responsibility: {p.ArchiveResponsibility}
            An unsent abandoned draft reaches its fixed retention deadline at {draft.ToString("O", CultureInfo.InvariantCulture)} UTC, measured from original record creation. Saving or replacing its document does not restart this clock.
            {completed}
            Expired requests have an interval of {p.ExpiredDays} days from effective expiry, declined requests {p.DeclinedDays} days from actual decline, and voided requests {p.VoidedDays} days from actual void.
            While signing is pending, or accepted signing evidence awaits completion recovery, this policy sets no automatic deletion deadline. Existing session and invitation limits still apply.
            Later settings changes do not replace this saved policy. Download and retain the copies delivered to you according to your own obligations.
            A retention deadline is not a promise of immediate physical erasure. Legal holds, storage protection, recovery, backups and service logs can affect preservation or deletion. Ordinary indefinite retention is separate from a case-specific legal hold.

            """);
    }
}
