using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Documents;

public sealed class PreparationOptions { public int MaximumRecipients { get; set; } = 20; }
public sealed record RecipientItem(Guid Id, string Name, string Email);
public sealed record DraftDetailsSnapshot(string PublicId, string Version, bool PreviewConfirmed, string? Title,
    string? Message, IReadOnlyList<RecipientItem> Recipients);
public enum DetailsChangeKind { SaveDetails, SaveRecipient, RemoveRecipient }
public sealed record DetailsChange(DetailsChangeKind Kind, string Version, Guid? RecipientId = null,
    string? Title = null, string? Message = null, string? Name = null, string? Email = null);
public enum DetailsError { None, NotFound, PreviewRequired, Conflict, Invalid, Duplicate, Limit }
public sealed record DetailsResult(DetailsError Error, string? Message = null, string? Field = null);

public sealed class DraftDetails(QuillSignDbContext db, AuditWriter audit, PreparationOptions options,TimeProvider? time=null,QuillSign.Email.Pilot.EmailPilotReadBounds? pilotBounds=null)
{
    public async Task<DraftDetailsSnapshot?> GetAsync(ClaimsPrincipal sender, string publicId, CancellationToken ct = default)
    {
        var identity = Identity(sender, publicId); if (identity is null) return null;
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var envelope = await Locked(identity.Value.Id).AsNoTracking().SingleOrDefaultAsync(ct);
        if (!Owns(envelope, identity.Value.Email, publicId)) return null;
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope!,time??TimeProvider.System,ct,pilotBounds);
        var recipients = await db.Recipients.AsNoTracking().Where(x => x.EnvelopeId == envelope!.Id).OrderBy(x => x.Name).ThenBy(x => x.Id)
            .Select(x => new RecipientItem(x.Id, x.Name, x.Email)).ToListAsync(ct);
        var snapshot = new DraftDetailsSnapshot(publicId, Convert.ToBase64String(envelope!.RowVersion), Confirmed(envelope),
            envelope.Title, envelope.Message, recipients);
        DocumentRetentionAccess.Check(deadline,time??TimeProvider.System);await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,ct); return snapshot;
    }

    public async Task<DetailsResult> ChangeAsync(ClaimsPrincipal sender, string publicId, DetailsChange change,
        string? ip, string? userAgent, CancellationToken ct = default)
    {
        var identity = Identity(sender, publicId); if (identity is null) return new(DetailsError.NotFound);
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var envelope = await Locked(identity.Value.Id).SingleOrDefaultAsync(ct);
        if (!Owns(envelope, identity.Value.Email, publicId)) return new(DetailsError.NotFound);
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope!,time??TimeProvider.System,ct,pilotBounds);
        if (!Confirmed(envelope!)) return new(DetailsError.PreviewRequired, "Confirm the current PDF before editing document details.");
        if (!Matches(change.Version, envelope!.RowVersion)) return new(DetailsError.Conflict, "This draft changed. Review the saved details and your attempted edits before trying again.");
        string eventName; object data;
        if (change.Kind == DetailsChangeKind.SaveDetails)
        {
            var title = change.Title?.Trim() ?? "";
            var message = string.IsNullOrWhiteSpace(change.Message) ? null : change.Message.Trim();
            if (title.Length is < 1 or > 512 || title.Any(char.IsControl)) return new(DetailsError.Invalid, "Enter a title of at most 512 characters without control characters.", "Details.Title");
            if (message is { Length: > 4000 } || message?.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t')) == true)
                return new(DetailsError.Invalid, "Enter a message of at most 4,000 characters.", "Details.Message");
            envelope.Title = title; envelope.Message = message;
            eventName = "envelope_details_updated"; data = new { title, message };
        }
        else if (change.Kind is DetailsChangeKind.SaveRecipient or DetailsChangeKind.RemoveRecipient)
        {
            var recipients = await db.Recipients.Where(x => x.EnvelopeId == envelope.Id).ToListAsync(ct);
            var selected = change.RecipientId is null ? null : recipients.SingleOrDefault(x => x.Id == change.RecipientId);
            if (change.RecipientId is not null && selected is null) return new(DetailsError.NotFound);
            if (change.Kind == DetailsChangeKind.RemoveRecipient)
            {
                if (selected is null) return new(DetailsError.NotFound);
                db.Recipients.Remove(selected); recipients.Remove(selected); eventName = "recipient_removed";
            }
            else
            {
                var name = change.Name?.Trim() ?? ""; string email;
                if (name.Length is < 1 or > 512 || name.Any(char.IsControl)) return new(DetailsError.Invalid, "Enter a name of at most 512 characters.", "Recipient.Name");
                try { email = EmailAddress.Normalize(change.Email?.Trim() ?? ""); }
                catch (ArgumentException) { return new(DetailsError.Invalid, "Enter one valid email address.", "Recipient.Email"); }
                if (recipients.Any(x => x.Id != selected?.Id && string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase)))
                    return new(DetailsError.Duplicate, "This email address is already a completion recipient.", "Recipient.Email");
                if (selected is null)
                {
                    if (recipients.Count >= options.MaximumRecipients) return new(DetailsError.Limit, $"This draft allows at most {options.MaximumRecipients} completion recipients.");
                    selected = new Recipient { EnvelopeId = envelope.Id }; db.Recipients.Add(selected); recipients.Add(selected); eventName = "recipient_added";
                }
                else eventName = "recipient_updated";
                selected.Name = name; selected.Email = email;
            }
            data = new { recipientId = selected.Id, recipients = recipients.OrderBy(x => x.Name).ThenBy(x => x.Id).Select(x => new { x.Id, x.Name, x.Email }) };
        }
        else return new(DetailsError.Invalid, "Choose a valid preparation action.");
        db.Entry(envelope).Property(x => x.Status).IsModified = true;
        await audit.AppendAsync(envelope.Id, eventName, identity.Value.Email, ip, userAgent, ct, JsonSerializer.Serialize(data));
        DocumentRetentionAccess.Check(deadline,time??TimeProvider.System);
        await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,ct); return new(DetailsError.None);
    }
    private IQueryable<Envelope> Locked(Guid id) => db.Envelopes.FromSqlInterpolated(
        $"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}");
    private static bool Owns(Envelope? e, string email, string publicId) => e is not null && e.PublicId == publicId &&
        e.SenderVerifiedAt is not null && e.Status == EnvelopeStatus.Draft && string.Equals(e.SenderEmail, email, StringComparison.OrdinalIgnoreCase);
    private static bool Confirmed(Envelope e) => e.PreviewConfirmedAt is not null && e.PdfBlob is not null && e.PdfSha256 is not null && e.PageCount > 0;
    private static bool Matches(string? encoded, byte[] version)
    {
        Span<byte> decoded = stackalloc byte[8];
        return encoded is { Length: <= 16 } && version.Length == 8 && Convert.TryFromBase64String(encoded, decoded, out var length) &&
            length == 8 && CryptographicOperations.FixedTimeEquals(decoded, version);
    }
    private static (Guid Id, string Email)? Identity(ClaimsPrincipal principal, string publicId)
    {
        var identities = principal.Identities.Where(x => x.IsAuthenticated && x.AuthenticationType == EnvelopeStorageAuthorization.SenderScheme).ToArray();
        var ids = identities.SelectMany(x => x.FindAll(EnvelopeStorageAuthorization.EnvelopeClaim)).ToArray();
        var emails = identities.SelectMany(x => x.FindAll(ClaimTypes.Email)).ToArray();
        var publicIds = identities.SelectMany(x => x.FindAll(SenderConfiguration.PublicIdClaim)).ToArray();
        return ids.Length == 1 && Guid.TryParse(ids[0].Value, out var id) && id != Guid.Empty && emails.Length == 1 &&
            publicIds.Length == 1 && publicIds[0].Value == publicId ? (id, emails[0].Value) : null;
    }
}
