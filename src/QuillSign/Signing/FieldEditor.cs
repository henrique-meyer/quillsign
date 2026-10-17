using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Signing;

public sealed class FieldEditorOptions
{
    public int MaximumFields { get; set; } = 200;
}

public sealed record FieldInput(Guid Id, Guid? SignerId, string Type, int Page, decimal X, decimal Y,
    decimal Width, decimal Height, bool Required, string? Label = null, string? Value = null);
public sealed record FieldEditorSnapshot(string PublicId, string DocumentId, string Version,
    IReadOnlyList<PageGeometry> Pages, IReadOnlyList<SignerListItem> Signers, IReadOnlyList<FieldInput> Fields);
public sealed record FieldSave(string Version, string DocumentId, IReadOnlyList<FieldInput>? Fields);
public enum FieldEditorError { None, NotFound, PreviewRequired, Conflict, Invalid }
public sealed record FieldSaveResult(FieldEditorError Error, string? Message = null, string? Version = null);

public sealed class FieldEditor(QuillSignDbContext db, AuditWriter audit, FieldEditorOptions options, TimeProvider time)
{
    public async Task<FieldEditorSnapshot?> GetAsync(ClaimsPrincipal sender, string publicId, CancellationToken ct = default)
    {
        var identity = SenderIdentity(sender, publicId);
        if (identity is null) return null;
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        // Keep metadata, signers and fields on one draft revision, including during concurrent replacements.
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var envelope = await LockedAsync(identity.Value.Id, ct);
        if (!Owns(envelope, identity.Value.Email, publicId)) return null;
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope!,time,ct);
        if(!Confirmed(envelope!))return null;
        var signers = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == envelope!.Id).OrderBy(x => x.Order)
            .Select(x => new SignerListItem(x.Id, x.Order, x.FullName, x.Email, x.Role)).ToListAsync(ct);
        var fields = await db.Fields.AsNoTracking().Where(x => x.EnvelopeId == envelope!.Id).OrderBy(x => x.Page).ThenBy(x => x.Id)
            .ToListAsync(ct);
        var result = new FieldEditorSnapshot(publicId, envelope!.PdfBlob!, Convert.ToBase64String(envelope.RowVersion),
            JsonSerializer.Deserialize<List<PageGeometry>>(envelope.PageSizesJson!)!, signers,
            fields.Select(x => new FieldInput(x.Id, x.SignerId, x.Type.ToString(), x.Page, x.X, x.Y, x.Width, x.Height,
                x.Required, x.Label, x.Value)).ToList());
        DocumentRetentionAccess.Check(deadline,time);await transaction.CommitAsync(ct);
        return result;
    }

    public async Task<FieldSaveResult> SaveAsync(ClaimsPrincipal sender, string publicId, FieldSave save,
        string? ip, string? userAgent, CancellationToken ct = default)
    {
        var identity = SenderIdentity(sender, publicId);
        if (identity is null) return new(FieldEditorError.NotFound);
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var envelope = await LockedAsync(identity.Value.Id, ct);
        if (!Owns(envelope, identity.Value.Email, publicId)) return new(FieldEditorError.NotFound);
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope!,time,ct);
        if (!Confirmed(envelope!)) return new(FieldEditorError.PreviewRequired, "Confirm the current PDF before placing fields.");
        if (save.DocumentId != envelope!.PdfBlob || !Matches(save.Version, envelope.RowVersion))
            return new(FieldEditorError.Conflict, "This draft changed in another tab. Your edits are still here; copy or export them before reloading.");
        if (save.Fields is null || save.Fields.Count > options.MaximumFields)
            return Invalid($"Use at most {options.MaximumFields} fields.");
        var signerIds = await db.Signers.Where(x => x.EnvelopeId == envelope.Id).Select(x => x.Id).ToListAsync(ct);
        var ids = new HashSet<Guid>();
        foreach (var field in save.Fields)
        {
            if (field is null || field.Id == Guid.Empty || !ids.Add(field.Id)) return Invalid("Each field needs a unique ID.");
            if (!Enum.TryParse<FieldType>(field.Type, out var type) || type.ToString() != field.Type || !Enum.IsDefined(type))
                return Invalid("Choose a valid field type.");
            if (field.Page < 1 || field.Page > envelope.PageCount || !FieldGeometry.InBounds(field.X, field.Y, field.Width, field.Height))
                return Invalid("Place every field entirely inside a document page, with a positive width and height.");
            if (field.SignerId is Guid owner && !signerIds.Contains(owner)) return Invalid("Choose a signer from this draft.");
            if (field.SignerId is null && type is not (FieldType.Text or FieldType.Checkbox or FieldType.Date))
                return Invalid("Assign signature, initials, full name and date signed fields to a signer.");
            if (field.Label is { Length: > 512 } || field.Label?.Any(char.IsControl) == true)
                return Invalid("Use a field label of at most 512 characters without control characters.");
            if (field.Value is { Length: > 4000 } || field.Value?.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t')) == true)
                return Invalid("Use a sender value of at most 4,000 characters.");
            if (field.SignerId is not null && field.Value is not null)
                return Invalid("Signer fields are filled during signing. Remove their sender value.");
            if (field.SignerId is null && field.Value is not null)
            {
                if (type == FieldType.Checkbox && field.Value is not ("true" or "false"))
                    return Invalid("Use true or false for a sender checkbox.");
                if (type == FieldType.Date && !DateOnly.TryParseExact(field.Value, "yyyy-MM-dd", CultureInfo.InvariantCulture,
                        DateTimeStyles.None, out _)) return Invalid("Use a valid date in YYYY-MM-DD format.");
            }
        }
        // Client-generated IDs support stable autosaves, but may never attach or overwrite another draft's rows.
        if (await db.Fields.AnyAsync(x => ids.Contains(x.Id) && x.EnvelopeId != envelope.Id, ct))
            return Invalid("A field ID is unavailable. Duplicate that field to create a new ID.");
        var existing = await db.Fields.Where(x => x.EnvelopeId == envelope.Id).ToListAsync(ct);
        db.Fields.RemoveRange(existing.Where(x => !ids.Contains(x.Id)));
        var persisted = new List<FieldInput>();
        foreach (var input in save.Fields)
        {
            var field = existing.SingleOrDefault(x => x.Id == input.Id);
            if (field is null) { field = new DocumentField { Id = input.Id, EnvelopeId = envelope.Id, Source = FieldSource.Manual }; db.Fields.Add(field); }
            var valueChanged = field.Value != input.Value || field.SignerId != input.SignerId || field.Type.ToString() != input.Type;
            field.SignerId = input.SignerId; field.Type = Enum.Parse<FieldType>(input.Type); field.Page = input.Page;
            field.X = FieldGeometry.Round(input.X); field.Y = FieldGeometry.Round(input.Y);
            field.Width = FieldGeometry.Round(input.Width); field.Height = FieldGeometry.Round(input.Height);
            field.Required = input.Required; field.Label = string.IsNullOrWhiteSpace(input.Label) ? null : input.Label.Trim();
            field.Value = input.Value; field.DateFormat = field.Type is FieldType.Date or FieldType.DateSigned ? "yyyy-MM-dd" : null;
            if (valueChanged)
            {
                field.FilledAt = input.Value is null ? null : time.GetUtcNow();
                field.FilledBy = input.Value is null ? null : PartyType.Sender;
            }
            persisted.Add(new(field.Id, field.SignerId, field.Type.ToString(), field.Page, field.X, field.Y,
                field.Width, field.Height, field.Required, field.Label, field.Value));
        }
        db.Entry(envelope).Property(x => x.Status).IsModified = true;
        await audit.AppendAsync(envelope.Id, "fields_saved", identity.Value.Email, ip, userAgent, ct,
            JsonSerializer.Serialize(new { documentId = envelope.PdfBlob, fields = persisted }));
        DocumentRetentionAccess.Check(deadline,time);
        await transaction.CommitAsync(ct);
        return new(FieldEditorError.None, Version: Convert.ToBase64String(envelope.RowVersion));
    }

    private Task<Envelope?> LockedAsync(Guid id, CancellationToken ct) => db.Envelopes.FromSqlInterpolated(
        $"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}").SingleOrDefaultAsync(ct);
    private static bool Owns(Envelope? e, string email, string publicId) => e is not null && e.PublicId == publicId &&
        e.SenderVerifiedAt is not null && e.Status == EnvelopeStatus.Draft && string.Equals(e.SenderEmail, email, StringComparison.OrdinalIgnoreCase);
    private static bool Confirmed(Envelope e) => e.PreviewConfirmedAt is not null && e.PdfBlob is not null &&
        e.PdfSha256 is not null && e.PageCount > 0 && e.PageSizesJson is not null;
    private static FieldSaveResult Invalid(string message) => new(FieldEditorError.Invalid, message);
    private static bool Matches(string? encoded, byte[] version)
    {
        Span<byte> decoded = stackalloc byte[8];
        return encoded is { Length: <= 16 } && version.Length == 8 && Convert.TryFromBase64String(encoded, decoded, out var length) &&
            length == 8 && CryptographicOperations.FixedTimeEquals(decoded, version);
    }
    private static (Guid Id, string Email)? SenderIdentity(ClaimsPrincipal principal, string publicId)
    {
        var identities = principal.Identities.Where(x => x.IsAuthenticated && x.AuthenticationType == EnvelopeStorageAuthorization.SenderScheme).ToArray();
        var ids = identities.SelectMany(x => x.FindAll(EnvelopeStorageAuthorization.EnvelopeClaim)).ToArray();
        var emails = identities.SelectMany(x => x.FindAll(ClaimTypes.Email)).ToArray();
        var publicIds = identities.SelectMany(x => x.FindAll(SenderConfiguration.PublicIdClaim)).ToArray();
        return ids.Length == 1 && Guid.TryParse(ids[0].Value, out var id) && id != Guid.Empty && emails.Length == 1 &&
            publicIds.Length == 1 && publicIds[0].Value == publicId ? (id, emails[0].Value) : null;
    }
}
