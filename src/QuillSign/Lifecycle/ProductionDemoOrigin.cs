using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Factual original creation metadata. Only its authenticated original mail
// carrier can prove non-production origin; this DTO grants no session or access.
public sealed record DemoCreationOrigin(string Version, Guid RecordId, string PublicId,
    string SenderEmail, DateTimeOffset CreatedAt, bool IsDemo);

internal static class ProductionDemoOrigin
{
    internal const string Version = "original-demo-creation-v1";
    private static readonly JsonSerializerOptions Strict = new() {
        MaxDepth = 4, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
    };

    internal static DemoCreationOrigin CaptureNew(QuillSignDbContext db, Envelope e, TimeProvider time)
    {
        if (db.Database.CurrentTransaction is null || db.Entry(e).State != EntityState.Added || !e.IsDemo ||
            e.Id == Guid.Empty || !Guid.TryParseExact(e.PublicId, "N", out var publicId) || publicId == Guid.Empty ||
            e.SenderEmail != EmailAddress.Normalize(e.SenderEmail) || e.CreatedAt == default ||
            e.CreatedAt.Offset != TimeSpan.Zero || e.CreatedAt > time.GetUtcNow() || e.Status != EnvelopeStatus.Draft ||
            e.RowVersion.Length != 0 || e.SenderVerifiedAt is not null || e.SentAt is not null || e.CompletedAt is not null ||
            e.PdfBlob is not null || e.OriginalBlob is not null || e.PreviewConfirmedAt is not null || e.ErsdSha256 is not null)
            throw Invalid();
        return new(Version, e.Id, e.PublicId, e.SenderEmail, e.CreatedAt, true);
    }

    internal static bool Matches(DemoCreationOrigin origin, Envelope e) =>
        origin.Version == Version && origin.IsDemo && e.IsDemo && origin.RecordId == e.Id &&
        origin.PublicId == e.PublicId && origin.SenderEmail == e.SenderEmail && origin.CreatedAt == e.CreatedAt;

    internal static async Task<bool> DemandOriginalAsync(QuillSignDbContext db, Envelope e,
        IDataProtectionProvider keys, CancellationToken ct)
    {
        try {
            var mails = await db.EmailOutbox.AsNoTracking().Where(x => x.EnvelopeId == e.Id && x.Template == "sender-verification")
                .Take(65).ToArrayAsync(ct);
            if (mails.Length > 64) throw Invalid();
            var found = 0;
            foreach (var mail in mails) {
                if (mail.PayloadJson.Length > 16384) throw Invalid();
                var wrapper = JsonSerializer.Deserialize<ProtectedWorkPayload>(mail.PayloadJson, Strict) ?? throw Invalid();
                if (JsonSerializer.Serialize(wrapper) != mail.PayloadJson) throw Invalid();
                var plain = keys.CreateProtector("QuillSign.EmailPayload.v1").Unprotect(wrapper.Protected);
                if (plain.Length > 4096) throw Invalid();
                var payload = JsonSerializer.Deserialize<VerificationPayload>(plain, Strict) ?? throw Invalid();
                if (JsonSerializer.Serialize(payload) != plain) throw Invalid();
                if (payload.DemoOrigin is not { } origin) continue;
                if (!Matches(origin, e) || mail.To != origin.SenderEmail || mail.AttachmentsJson != "[]" ||
                    mail.AvailableAt < origin.CreatedAt || payload.TokenId == Guid.Empty || payload.Token is not {Length:43} ||
                    !Enum.IsDefined(mail.Status)) throw Invalid();
                found++;
            }
            if (found == 0) return false;
            if (found != 1) throw Invalid();
            var first = await db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == e.Id && x.Sequence <= 2)
                .OrderBy(x => x.Sequence).ToArrayAsync(ct);
            if (first.Length != 2 || first[0].Sequence != 1 || first[0].Event != "draft_created" || first[1].Sequence != 2 ||
                first[1].Event != "sender_verification_requested" || first.Any(x => x.ActorType != PartyType.Sender ||
                    x.ActorEmail != e.SenderEmail || x.At < e.CreatedAt || x.DataJson != "{}" ||
                    !x.Hash.AsSpan().SequenceEqual(AuditHash.Compute(x))) || first[0].PrevHash is not null ||
                first[1].PrevHash is null || !first[1].PrevHash!.AsSpan().SequenceEqual(first[0].Hash)) throw Invalid();
            return true;
        }
        catch (Exception error) when (error is JsonException or CryptographicException or ArgumentException or InvalidOperationException) {
            throw Invalid();
        }
    }

    private static InvalidDataException Invalid() => new("Original record classification is unavailable.");
}
