using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;
using static QuillSign.Lifecycle.ProductionRetentionLedger;

namespace QuillSign.Lifecycle;

internal static class ProductionRetentionTerminalSource
{
    private sealed record Decline(string? reason, Guid notificationId, string documentSha256, string disclosureSha256);
    private sealed record Expiry(string Version, string BeforeVersion, DateTimeOffset Deadline, DateTimeOffset ExpiredAt, string SourceSha256);

    internal static async Task<(AuditEvent Event, DateTimeOffset At)?> ReadAsync(QuillSignDbContext db,
        Envelope e, AuditEvent[] chain, TimeProvider time, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Terminal provenance requires the parent lock.");
        if (e.Status is EnvelopeStatus.Draft or EnvelopeStatus.Sent) return null;
        if (!Enum.IsDefined(e.Status) || e.IsDemo || e.SentAt is null || e.SentAt > time.GetUtcNow()) throw Invalid();
        var name = e.Status switch { EnvelopeStatus.Completed => "completed", EnvelopeStatus.Voided => "voided",
            EnvelopeStatus.Declined => "declined", EnvelopeStatus.Expired => "expired", _ => throw Invalid() };
        var terminal = chain.Where(x => x.Event is "completed" or "voided" or "declined" or "expired").ToArray();
        if (terminal.Length != 1 || terminal[0].Event != name) throw Invalid();
        var proof = terminal[0]; DateTimeOffset at;
        var checkpoints = new SignerCheckpointState(db, time);
        if (e.Status == EnvelopeStatus.Completed)
        {
            var publication = await CompletionDownloadState.ReadAsync(db, e.Id, time, ct) ?? throw Invalid();
            if (publication.CompletedAt != e.CompletedAt) throw Invalid();
            at = publication.CompletedAt;
        }
        else if (e.Status == EnvelopeStatus.Voided)
        {
            var saved = await new SenderVoidState(db, checkpoints, time).ReadLockedAsync(e.Id, ct) ?? throw Invalid();
            if (saved.Audit.Sequence != proof.Sequence || !Same(saved.Audit.Hash, proof.Hash)) throw Invalid();
            at = saved.Evidence.VoidedAt;
        }
        else
        {
            var source = await new SenderVoidState(db, checkpoints, time).SourceLockedAsync(e, ct);
            var signers = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == e.Id).OrderBy(x => x.Order).Take(101).ToArrayAsync(ct);
            if (signers.Length is < 1 or > 100 || signers.Where((s, i) => s.Order != i + 1 || !Enum.IsDefined(s.Status)).Any()) throw Invalid();
            if (e.Status == EnvelopeStatus.Declined)
            {
                var declined = signers.Where(x => x.Status == SignerStatus.Declined).ToArray();
                var data = Read<Decline>(proof.DataJson);
                if (declined.Length != 1 || declined[0].Order != source.Version + 1 || proof.ActorType != PartyType.Signer ||
                    proof.ActorId != declined[0].Id || proof.ActorEmail != declined[0].Email || data.reason != declined[0].DeclineReason ||
                    data.reason is { Length: > 512 } || data.notificationId == Guid.Empty ||
                    data.documentSha256 != Hex(source.Sha256) || data.disclosureSha256 != Hex(e.ErsdSha256!)) throw Invalid();
                if (!await db.EmailOutbox.AnyAsync(x => x.Id == data.notificationId && x.EnvelopeId == e.Id &&
                    x.Template == "signer-declined" && x.To == e.SenderEmail, ct)) throw Invalid();
                at = proof.At;
                if (e.ExpiresAt <= at) throw Invalid();
            }
            else
            {
                var data = Read<Expiry>(proof.DataJson);
                if (proof.ActorType != PartyType.System || proof.ActorId is not null || proof.ActorEmail is not null ||
                    proof.Ip is not null || proof.UserAgent is not null || data.Version != "signing-expiry-v1" ||
                    !Revision(data.BeforeVersion) || data.Deadline.Offset != TimeSpan.Zero || data.Deadline != e.ExpiresAt ||
                    data.ExpiredAt.Offset != TimeSpan.Zero || data.ExpiredAt < data.Deadline || data.ExpiredAt > proof.At ||
                    signers.Any(x => x.Status == SignerStatus.Declined) || signers.All(x => x.Status == SignerStatus.Signed) ||
                    await db.SignerFinishAcceptances.AnyAsync(x => x.EnvelopeId == e.Id && x.ProcessedAt == null, ct)) throw Invalid();
                var binding = Hex(System.Security.Cryptography.SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
                {
                    e.Id, e.PublicId, e.SenderEmail, e.SenderVerifiedAt, e.Title, e.Message, e.SentAt, e.ExpiresAt,
                    e.SentPdfBlob, e.SentPdfSha256, e.PdfSha256, e.ErsdVersion, e.ErsdSha256, e.CurrentFinishId, e.CurrentCopyVersion, source,
                    roster = signers.Select(s => new { s.Id, s.Order, s.FullName, s.Email, s.Role })
                })));
                if (data.SourceSha256 != binding) throw Invalid();
                at = data.Deadline; // Effective expiry, never late worker execution time.
            }
        }
        if (at.Offset != TimeSpan.Zero || at < e.CreatedAt || at < e.SentAt || at > proof.At || at > time.GetUtcNow()) throw Invalid();
        return (proof, at);
    }

    private static T Read<T>(string json)
    {
        try
        {
            if (json.Length > 4096) throw Invalid();
            var value = JsonSerializer.Deserialize<T>(json, new JsonSerializerOptions { MaxDepth = 8 }) ?? throw Invalid();
            if (JsonSerializer.Serialize(value) != json) throw Invalid();
            return value;
        }
        catch (Exception e) when (e is JsonException or ArgumentException) { throw new InvalidDataException("The production terminal event is invalid.", e); }
    }
    private static bool Revision(string value)
    {
        try { return Convert.FromBase64String(value) is { Length: 8 } bytes && Convert.ToBase64String(bytes) == value; }
        catch (Exception e) when (e is ArgumentException or FormatException) { return false; }
    }
}
