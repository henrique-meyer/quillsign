using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Documents;

public sealed record PreparationIssue(string Message, string Step);
public sealed record DraftReviewSnapshot(string PublicId, string Version, string? Title, string? Message,
    bool HasPdf, bool PreviewConfirmed, int? PageCount, IReadOnlyList<SignerListItem> Signers,
    IReadOnlyList<FieldInput> Fields, IReadOnlyList<RecipientItem> Recipients,
    IReadOnlyList<PreparationIssue> Errors, IReadOnlyList<PreparationIssue> Warnings)
{
    public bool ChecksPassed => Errors.Count == 0;
    public DateTimeOffset? ExpiresAt { get; init; }
    public DateTimeOffset? RetentionDeleteAfter {get;init;}
    public string? RetentionSha256 {get;init;}
}

public sealed class DraftReview(QuillSignDbContext db,TimeProvider? time=null)
{
    public async Task<DraftReviewSnapshot?> GetAsync(ClaimsPrincipal sender, string publicId, CancellationToken ct = default)
    {
        var identity = Identity(sender, publicId); if (identity is null) return null;
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        // All preparation writers take this envelope lock. Read every collection under it,
        // without tracking, so neither concurrent writes nor an older tracked entity mix revisions.
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var envelope = await db.Envelopes.FromSqlInterpolated(
            $"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {identity.Value.Id}")
            .AsNoTracking().SingleOrDefaultAsync(ct);
        if (envelope is null || envelope.PublicId != publicId || envelope.SenderVerifiedAt is null ||
            envelope.Status != EnvelopeStatus.Draft || !string.Equals(envelope.SenderEmail, identity.Value.Email, StringComparison.OrdinalIgnoreCase)) return null;
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope,time??TimeProvider.System,ct);
        var signers = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Order)
            .Select(x => new SignerListItem(x.Id, x.Order, x.FullName, x.Email, x.Role)).ToListAsync(ct);
        var fields = await db.Fields.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Page).ThenBy(x => x.Id).ToListAsync(ct);
        var recipients = await db.Recipients.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Name).ThenBy(x => x.Id)
            .Select(x => new RecipientItem(x.Id, x.Name, x.Email)).ToListAsync(ct);
        var result = CheckPreparation(envelope, signers, fields, recipients);
        var limit=await RetentionSigningDeadline.ReadAsync(db,envelope,ct);
        result=result with {ExpiresAt=limit.Effective,RetentionDeleteAfter=limit.Policy?.DeleteAfter,RetentionSha256=limit.Digest};
        if(limit.Policy is not null && limit.Effective<=(time ?? TimeProvider.System).GetUtcNow())
            result=result with {Errors=result.Errors.Append(new PreparationIssue("This demo document has reached its signing or retention deadline.","details")).ToArray()};
        DocumentRetentionAccess.Check(deadline,time??TimeProvider.System);await transaction.CommitAsync(ct); return result;
    }

    // Pure preparation checks; this method grants no access and does not authorize sending.
    // A future mutation must load an authorized, locked snapshot and rerun checks itself.
    public static DraftReviewSnapshot CheckPreparation(Envelope envelope, IReadOnlyList<SignerListItem> signers,
        IReadOnlyList<DocumentField> fields, IReadOnlyList<RecipientItem> recipients)
    {
        var errors = new List<PreparationIssue>(); var warnings = new List<PreparationIssue>();
        var hasPdf = !string.IsNullOrWhiteSpace(envelope.PdfBlob) && envelope.PdfSha256 is { Length: 32 } && envelope.PageCount > 0;
        if (!hasPdf) errors.Add(new("Upload a PDF before reviewing preparation.", ""));
        if (envelope.PreviewConfirmedAt is null) errors.Add(new("Review and confirm the current PDF preview.", ""));
        if (!ValidPages(envelope.PageSizesJson, envelope.PageCount)) errors.Add(new("The PDF page information is incomplete. Replace the PDF and confirm its preview.", ""));
        if (string.IsNullOrWhiteSpace(envelope.Title) || envelope.Title.Length > 512 || envelope.Title.Any(char.IsControl))
            errors.Add(new("Save a document title of at most 512 characters.", "details"));
        if (signers.Count == 0) errors.Add(new("Add at least one signer.", "signers"));
        var signerIds = signers.Select(x => x.Id).ToHashSet();
        foreach (var field in fields)
        {
            var label = string.IsNullOrWhiteSpace(field.Label) ? $"{field.Type} field on page {field.Page}" : $"“{field.Label}” on page {field.Page}";
            if (!Enum.IsDefined(field.Type) || field.Page < 1 || field.Page > (envelope.PageCount ?? 0) ||
                !FieldGeometry.InBounds(field.X, field.Y, field.Width, field.Height))
                errors.Add(new($"Fix the type or placement of {label}.", "fields"));
            if (field.SignerId is Guid owner)
            {
                if (!signerIds.Contains(owner)) errors.Add(new($"Assign {label} to a signer in this draft.", "fields"));
                if (field.Value is not null) errors.Add(new($"Remove the sender value from signer-owned {label}.", "fields"));
            }
            else if (field.Type is not (FieldType.Text or FieldType.Checkbox or FieldType.Date))
                errors.Add(new($"Assign {label} to a signer.", "fields"));
            else if (!ValidSenderValue(field)) errors.Add(new($"Fill or delete sender-owned {label}. Use a valid value.", "fields"));
        }
        foreach (var signer in signers.Where(s => !fields.Any(f => f.SignerId == s.Id && f.Type == FieldType.Signature)))
            warnings.Add(new($"{signer.FullName} has no Signature field. Review their fields before sending.", "fields"));
        return new DraftReviewSnapshot(envelope.PublicId, Convert.ToBase64String(envelope.RowVersion), envelope.Title, envelope.Message,
            hasPdf, envelope.PreviewConfirmedAt is not null, envelope.PageCount, signers,
            fields.Select(f => new FieldInput(f.Id, f.SignerId, f.Type.ToString(), f.Page, f.X, f.Y, f.Width, f.Height, f.Required, f.Label, f.Value)).ToList(),
            recipients, errors, warnings) { ExpiresAt=envelope.ExpiresAt };
    }

    private static bool ValidSenderValue(DocumentField field)
    {
        var value = field.Value;
        if (string.IsNullOrWhiteSpace(value) || value.Length > 4000 || value.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t'))) return false;
        return field.Type switch
        {
            FieldType.Checkbox => value is "true" or "false",
            FieldType.Date => DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _),
            FieldType.Text => true,
            _ => false
        };
    }
    private static bool ValidPages(string? json, int? count)
    {
        if (count is not (>= 1 and <= 200) || string.IsNullOrWhiteSpace(json) || json.Length > 262144) return false;
        try
        {
            var pages = JsonSerializer.Deserialize<List<PageGeometry?>>(json, new JsonSerializerOptions { MaxDepth = 16 });
            return pages?.Count == count && pages.All(p => p is not null && p.Rotation is 0 or 90 or 180 or 270 &&
                double.IsFinite(p.UserUnit) && p.UserUnit > 0 && double.IsFinite(p.Width) && p.Width is > 0 and <= 14400 &&
                double.IsFinite(p.Height) && p.Height is > 0 and <= 14400 && ValidBox(p.MediaBox) && ValidBox(p.CropBox) &&
                p.CropBox[0] >= p.MediaBox[0] && p.CropBox[1] >= p.MediaBox[1] && p.CropBox[2] <= p.MediaBox[2] && p.CropBox[3] <= p.MediaBox[3] &&
                Math.Abs(p.Width - (p.CropBox[2] - p.CropBox[0]) * p.UserUnit) < .001 &&
                Math.Abs(p.Height - (p.CropBox[3] - p.CropBox[1]) * p.UserUnit) < .001);
        }
        catch (JsonException) { return false; }
    }
    private static bool ValidBox(double[]? box) => box is { Length: 4 } && box.All(double.IsFinite) && box[2] > box[0] && box[3] > box[1];
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
