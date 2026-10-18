using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Sender;

internal sealed record ContactCorrectionAdmission(string Version, Guid Id, Guid EnvelopeId, string SenderEmail, string IpHash,
    SignerContactCorrectionReview Review, DateTimeOffset AdmittedAt, DateTimeOffset SenderTicketExpiresAt,
    DateTimeOffset? ReviewExpiresAt, DateTimeOffset CounterUntil, Guid PreviousInvitationId, string RevisionSha256);

// Immutable audit reservations survive until the counter day ends. Dispatch
// revalidates this same reservation instead of creating a second allowance.
internal sealed class SignerContactCorrectionPolicy(QuillSignDbContext db, SignerContactCorrectionOptions options,
    EmailOptions email, WorkOptions work, TimeProvider time) : IInvitationSuccessorPolicy
{
    internal const string Event = "signer_contact_correction_requested";
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        MaxDepth = 5, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    public InvitationSuccessorReason Reason => InvitationSuccessorReason.ContactCorrection;
    public bool Enabled => options.Enabled && email.Enabled && work.Enabled;
    public async Task<bool> ValidateLockedAsync(Envelope envelope, InvitationSuccessorScope scope, CancellationToken ct)
    {
        options.Validate(); if (!Enabled || db.Database.CurrentTransaction is null || scope.Reason != Reason || scope.EnvelopeId != envelope.Id) return false;
        var reservation = await FindAsync(db, envelope.Id, scope.Contact.RevisionId, ct);
        return reservation is not null && scope.Id == InvitationSuccessorJobs.CorrectionWorkId(reservation.Id) &&
            scope.Contact.Number == reservation.Review.ContactRevisionNumber + 1 && scope.Recipient == reservation.Review.NewEmail &&
            scope.SignerId == reservation.Review.SignerId && scope.SenderEmail == reservation.SenderEmail &&
            scope.PreviousId == reservation.PreviousInvitationId && scope.DocumentId == reservation.Review.DocumentId &&
            scope.DocumentSha256 == reservation.Review.DocumentSha256 && scope.DisclosureSha256 == reservation.Review.DisclosureSha256 &&
            scope.AdmittedAt == reservation.AdmittedAt && scope.AuthorizationSha256 == reservation.RevisionSha256 &&
            scope.Deadline <= reservation.CounterUntil && await WithinCapsAsync(reservation, true, ct);
    }
    // Reason-specific limits remain separate, but admission scans share the
    // AuditEvents table. Take the same global lock before either feature writes
    // evidence, avoiding read-committed cross-envelope lock cycles.
    internal static Task LockAsync(QuillSignDbContext db, CancellationToken ct) => InvitationResendRules.LockAsync(db, ct);
    internal async Task<bool> WithinCapsAsync(ContactCorrectionAdmission candidate, bool reserved, CancellationToken ct)
    {
        options.Validate(); if (!Enabled || candidate.CounterUntil != InvitationResendProtection.DayEnd(time.GetUtcNow())) return false;
        var start = candidate.CounterUntil.AddDays(-1);
        var query = db.AuditEvents.AsNoTracking().Where(x => x.Event == Event && x.At >= start && x.At < candidate.CounterUntil);
        var sizes = await query.Select(x => new { x.Id, Bytes = EF.Functions.DataLength(x.DataJson) }).Take(1001).ToArrayAsync(ct);
        if (sizes.Length > 1000) return false;
        if (sizes.Any(x => x.Bytes is null or > 24000)) throw Invalid();
        var ids = sizes.Select(x => x.Id).ToArray();
        var rows = await query.Where(x => ids.Contains(x.Id)).ToArrayAsync(ct);
        if (rows.Length != sizes.Length) throw Invalid();
        var saved = rows.Select(Read).ToArray();
        if (saved.Select(x => x.Id).Distinct().Count() != saved.Length) throw Invalid();
        if (reserved && !saved.Contains(candidate)) throw Invalid();
        var extra = reserved ? 0 : 1;
        return saved.Length + extra <= options.DailyRequests &&
            saved.Count(x => x.Review.NewEmail == candidate.Review.NewEmail) + extra <= options.DailyAddressRequests &&
            saved.Count(x => x.SenderEmail == candidate.SenderEmail) + extra <= options.DailySenderRequests &&
            saved.Count(x => x.IpHash == candidate.IpHash) + extra <= options.DailyIpRequests;
    }
    internal static async Task<ContactCorrectionAdmission?> FindAsync(QuillSignDbContext db, Guid envelopeId, Guid id, CancellationToken ct)
    {
        var query = db.AuditEvents.FromSqlInterpolated($"SELECT * FROM [AuditEvents] WHERE [EnvelopeId]={envelopeId} AND [Event]={Event} AND JSON_VALUE([DataJson],'$.id')={id.ToString()}").AsNoTracking();
        var sizes = await query.Select(x => EF.Functions.DataLength(x.DataJson)).Take(2).ToArrayAsync(ct);
        if (sizes.Length > 1 || sizes.Any(x => x is null or > 24000)) throw Invalid();
        return sizes.Length == 0 ? null : Read(await query.SingleAsync(ct));
    }
    internal static string Canonical(ContactCorrectionAdmission p) { Validate(p); return JsonSerializer.Serialize(p, Json); }
    private static ContactCorrectionAdmission Read(AuditEvent row)
    {
        ContactCorrectionAdmission p;
        try { p = JsonSerializer.Deserialize<ContactCorrectionAdmission>(row.DataJson, Json) ?? throw Invalid(); }
        catch (JsonException) { throw Invalid(); }
        if (row.Event != Event || row.ActorType != PartyType.Sender || row.ActorId is not null || row.EnvelopeId != p.EnvelopeId ||
            row.ActorEmail != p.SenderEmail || row.At != p.AdmittedAt || row.DataJson != Canonical(p) ||
            !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(row), row.Hash) || InvitationResendProtection.IpHash(row.Ip) != p.IpHash) throw Invalid();
        return p;
    }
    private static void Validate(ContactCorrectionAdmission p)
    {
        if (p.Version != "contact-correction-admission-v1" || p.Id == Guid.Empty || p.EnvelopeId == Guid.Empty || p.PreviousInvitationId == Guid.Empty ||
            !InvitationResendProtection.Hash(p.IpHash) || !InvitationResendProtection.Hash(p.RevisionSha256) || p.Review is null ||
            p.AdmittedAt.Offset != TimeSpan.Zero || p.SenderTicketExpiresAt.Offset != TimeSpan.Zero || p.SenderTicketExpiresAt <= p.AdmittedAt ||
            p.CounterUntil != InvitationResendProtection.DayEnd(p.AdmittedAt) || p.ReviewExpiresAt is { } end &&
            (end.Offset != TimeSpan.Zero || end <= p.AdmittedAt || end > p.SenderTicketExpiresAt || end > p.CounterUntil)) throw Invalid();
        try { if (EmailAddress.Normalize(p.SenderEmail) != p.SenderEmail || EmailAddress.Normalize(p.Review.NewEmail) != p.Review.NewEmail) throw Invalid(); }
        catch (ArgumentException) { throw Invalid(); }
        if (!InvitationResendProtection.RowVersion(p.Review.Version) || !InvitationResendProtection.RowVersion(p.Review.SignerVersion) ||
            p.Review.SignerId == Guid.Empty || p.Review.DocumentId == Guid.Empty || !InvitationResendProtection.Hash(p.Review.DocumentSha256) ||
            !InvitationResendProtection.Hash(p.Review.DisclosureSha256) || p.Review.ContactRevisionNumber is < 0 or >= 100 ||
            (p.Review.ContactRevisionNumber == 0) != (p.Review.ContactRevisionId == Guid.Empty)) throw Invalid();
    }
    internal static InvalidDataException Invalid() => new("Signer contact correction evidence is unavailable.");
}
