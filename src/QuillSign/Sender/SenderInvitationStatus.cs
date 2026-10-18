using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Sender;

public sealed record SenderInvitationProgress(string Kind, string State, DateTimeOffset? RequestedAt);

internal static class SenderInvitationStatus
{
    // The enclosing status read owns the envelope lock. At most one bounded
    // canonical admission and outbox/work pair is read per signer, not history.
    internal static async Task<SenderInvitationProgress?> LatestAsync(QuillSignDbContext db, Envelope envelope, Signer signer,
        InvitationResendProtection? protection, TimeProvider time, CancellationToken ct)
    {
        var audit = await InvitationResendRules.LatestAuditAsync(db, envelope.Id, signer.Id, ct);
        if (audit is null) return null;
        if (protection is null) throw InvitationResendRules.Invalid();
        var rules = new InvitationResendRules(db, new(), protection, time);
        var saved = await rules.FromAuditAsync(audit, ct); var p = saved.Mail.Request; var row = saved.Row;
        if (p.SignerId != signer.Id || p.Email != signer.Email || p.SenderEmail != envelope.SenderEmail || p.RequestedAt < envelope.SentAt ||
            p.RequestedAt > time.GetUtcNow() || audit.At > time.GetUtcNow() || envelope.ErsdSha256 is not { Length: 32 } ||
            p.DisclosureSha256 != Convert.ToHexStringLower(envelope.ErsdSha256)) throw InvitationResendRules.Invalid();
        var settled = await rules.SettledAsync(row, saved.Work, signer.Id, p.DocumentSha256, p.DisclosureSha256, saved.Mail.Issued?.Id, ct);
        var state = row.Status switch {
            EmailStatus.Sent when settled => "Replacement invitation submitted",
            EmailStatus.Bounced when settled => "Replacement invitation bounced; delivery needs attention",
            EmailStatus.Complained when settled => "Replacement invitation complaint reported",
            EmailStatus.Failed when settled => "Replacement invitation not sent; delivery needs attention",
            EmailStatus.Queued when row.SubmissionStartedAt is null && saved.Work.Status is WorkStatus.Queued or WorkStatus.Leased =>
                p.Deadline <= time.GetUtcNow() ? "Replacement invitation not sent; dispatch window ended" : "Replacement invitation queued",
            _ => "Replacement invitation submission not confirmed"
        };
        return new("Replacement", state, p.RequestedAt);
    }
}
