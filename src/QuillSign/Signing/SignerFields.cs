using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Signing;

public enum SignerFieldAction { Apply, Clear }
public enum SignerFieldOutcome { Applied, AlreadyApplied, NotFound, Conflict, InvalidValue, InvalidAdoption, ReadOnly }
public sealed record SignerFieldChange(Guid FieldId,string Version,SignerFieldAction Action,string? Value = null,Guid? AdoptionId = null);
public sealed record SignerFieldItem(Guid Id,string Version,FieldType Type,int Page,decimal X,decimal Y,decimal Width,decimal Height,
    bool Required,string? Label,string? Value,DateTimeOffset? FilledAt,Guid? AdoptionId,string? ImageSha256,bool Filled,bool Stale);
public sealed record SignerFieldSnapshot(string PublicId,string DocumentSha256,string DisclosureSha256,string SignerName,
    Guid? AdoptionId,IReadOnlyList<SignerFieldItem> Fields);
public sealed record SignerFieldResult(SignerFieldOutcome Outcome,SignerFieldItem? Field = null);

// Each call applies or clears exactly one owned field. No batch-signing or Finish path.
public sealed class SignerFields(QuillSignDbContext db,SignerAccess access,SignatureAdoption adoption,AuditWriter audit,TimeProvider time)
{
    public async Task<SignerFieldSnapshot?> GetAsync(ClaimsPrincipal principal,string publicId,CancellationToken ct = default)
    {
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var context = await access.GetLockedContextAsync(principal,publicId,ct); if (context?.ConsentAt is null) return null;
        var signer = await Signer(context.Identity,ct);
        var pageCount = await PageCount(context.Identity.EnvelopeId,ct);
        var fields = await db.Fields.AsNoTracking().Where(x => x.EnvelopeId == context.Identity.EnvelopeId && x.SignerId == signer.Id)
            .OrderBy(x => x.Page).ThenBy(x => x.Y).ThenBy(x => x.X).ThenBy(x => x.Id).Take(201).ToListAsync(ct);
        if (pageCount is not (>= 1 and <= 200) || fields.Count > 200 || fields.Any(x => !ValidField(x,pageCount))) return null;
        var result = new SignerFieldSnapshot(publicId,context.Identity.DocumentHash,context.Identity.DisclosureHash,signer.FullName,
            signer.SignatureAdoptionId,fields.Select(x => Item(x,signer)).ToArray());
        if ((await access.GetLockedContextAsync(principal,publicId,ct))?.ConsentAt is null) return null;
        await transaction.CommitAsync(ct); return result;
    }

    public async Task<SignerFieldResult> ChangeAsync(ClaimsPrincipal principal,string publicId,SignerFieldChange change,string? ip,string? ua,CancellationToken ct = default)
    {
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var context = await access.GetLockedContextAsync(principal,publicId,ct); if (context?.ConsentAt is null) return new(SignerFieldOutcome.NotFound);
        var field = await db.Fields.AsNoTracking().SingleOrDefaultAsync(x => x.Id == change.FieldId && x.EnvelopeId == context.Identity.EnvelopeId && x.SignerId == context.Identity.SignerId,ct);
        if (field is null || !ValidField(field,await PageCount(context.Identity.EnvelopeId,ct))) return new(SignerFieldOutcome.NotFound);
        var signer = await Signer(context.Identity,ct); var version = Version(change.Version);
        if (version is null || !Enum.IsDefined(change.Action)) return new(SignerFieldOutcome.InvalidValue);
        if (field.Type == FieldType.DateSigned) return new(SignerFieldOutcome.ReadOnly);
        string? value = null; Guid? adoptionId = null; byte[]? imageHash = null;
        if (change.Action == SignerFieldAction.Clear)
        { if (change.Value is not null || change.AdoptionId is not null) return new(SignerFieldOutcome.InvalidValue); }
        else if (field.Type is FieldType.Signature or FieldType.Initials)
        {
            if (change.Value is not null || change.AdoptionId is null || change.AdoptionId != signer.SignatureAdoptionId) return new(SignerFieldOutcome.InvalidAdoption);
            var assets = await adoption.GetCurrentLockedAsync(context.Identity,ct); if (assets is null) return new(SignerFieldOutcome.InvalidAdoption);
            adoptionId = assets.Preview.Id;
            value = (field.Type == FieldType.Signature ? assets.Preview.SignatureObjectId : assets.Preview.InitialsObjectId).ToString("N");
            imageHash = field.Type == FieldType.Signature ? assets.Preview.SignatureSha256 : assets.Preview.InitialsSha256;
        }
        else
        {
            if (change.AdoptionId is not null || field.Type == FieldType.FullName && change.Value is not null) return new(SignerFieldOutcome.InvalidValue);
            value = Canonical(field.Type == FieldType.FullName ? signer.FullName : change.Value);
            if (value is null || field.Type == FieldType.Checkbox && value is not ("true" or "false") ||
                field.Type == FieldType.Date && !DateOnly.TryParseExact(value,"yyyy-MM-dd",CultureInfo.InvariantCulture,DateTimeStyles.None,out _)) return new(SignerFieldOutcome.InvalidValue);
        }
        if ((await access.GetLockedContextAsync(principal,publicId,ct))?.ConsentAt is null) return new(SignerFieldOutcome.NotFound);
        var clear = change.Action == SignerFieldAction.Clear;
        if (field.Value == value && field.SignatureAdoptionId == adoptionId && Same(field.ImageSha256,imageHash) &&
            (clear ? field.FilledAt is null && field.FilledBy is null : field.FilledAt is not null && field.FilledBy == PartyType.Signer))
            return new(SignerFieldOutcome.AlreadyApplied,Item(field,signer));
        if (!CryptographicOperations.FixedTimeEquals(version,field.RowVersion)) return new(SignerFieldOutcome.Conflict,Item(field,signer));
        DateTimeOffset? filledAt = clear ? null : time.GetUtcNow(); PartyType? filledBy = clear ? null : PartyType.Signer;
        var changed = await db.Fields.Where(x => x.Id == field.Id && x.EnvelopeId == context.Identity.EnvelopeId && x.SignerId == signer.Id && x.RowVersion == version)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.Value,value).SetProperty(x => x.FilledAt,filledAt).SetProperty(x => x.FilledBy,filledBy)
                .SetProperty(x => x.SignatureAdoptionId,adoptionId).SetProperty(x => x.ImageSha256,imageHash),ct);
        if (changed != 1) return new(SignerFieldOutcome.Conflict);
        await audit.AppendAsync(context.Identity.EnvelopeId,clear ? "field_cleared" : "field_filled",context.Identity.Email,ip,ua,ct,
            JsonSerializer.Serialize(new { fieldId = field.Id,type = field.Type.ToString(),previousValue = field.Value,value,previousAdoptionId = field.SignatureAdoptionId,
                adoptionId,previousImageSha256 = Hex(field.ImageSha256),imageSha256 = Hex(imageHash),valueSha256 = value is null ? null : Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value))),
                documentSha256 = context.Identity.DocumentHash,disclosureSha256 = context.Identity.DisclosureHash,
                input = field.Type == FieldType.FullName ? "server_signer_record" : "explicit_owned_field_request" }),PartyType.Signer,signer.Id);
        if ((await access.GetLockedContextAsync(principal,publicId,ct))?.ConsentAt is null) return new(SignerFieldOutcome.NotFound);
        var saved = await db.Fields.AsNoTracking().SingleAsync(x => x.Id == field.Id,ct);
        await transaction.CommitAsync(ct); return new(SignerFieldOutcome.Applied,Item(saved,signer));
    }

    private Task<Signer> Signer(VerifiedSigner identity,CancellationToken ct) => db.Signers.AsNoTracking().SingleAsync(x => x.Id == identity.SignerId && x.EnvelopeId == identity.EnvelopeId,ct);
    private Task<int?> PageCount(Guid envelopeId,CancellationToken ct) => db.Envelopes.AsNoTracking().Where(x => x.Id == envelopeId).Select(x => x.PageCount).SingleAsync(ct);
    private static bool ValidField(DocumentField field,int? pages) => pages is >= 1 and <= 200 && field.Page >= 1 && field.Page <= pages && Enum.IsDefined(field.Type) && FieldGeometry.InBounds(field.X,field.Y,field.Width,field.Height);
    internal static SignerFieldItem Item(DocumentField f,Signer signer)
    {
        var mark = f.Type is FieldType.Signature or FieldType.Initials;
        var expectedHash = f.Type == FieldType.Signature ? signer.SignatureImageSha256 : signer.InitialsImageSha256;
        var expectedObject = f.Type == FieldType.Signature ? signer.SignatureImageBlob : signer.InitialsImageBlob;
        var bound = signer.SignatureAdoptionId is not null && f.SignatureAdoptionId == signer.SignatureAdoptionId && expectedHash is { Length: 32 } &&
            Same(f.ImageSha256,expectedHash) && f.Value == expectedObject;
        var hasMarkState = f.Value is not null || f.SignatureAdoptionId is not null || f.ImageSha256 is not null || f.FilledAt is not null;
        var filled = f.Value is not null && f.FilledAt is not null && f.FilledBy == PartyType.Signer && (!mark || bound);
        if (f.Type == FieldType.Text && string.IsNullOrWhiteSpace(f.Value)) filled = false;
        if (f.Type == FieldType.FullName && f.Value != Canonical(signer.FullName)) filled = false;
        if (f.Type == FieldType.DateSigned) filled = false;
        return new(f.Id,Convert.ToBase64String(f.RowVersion),f.Type,f.Page,f.X,f.Y,f.Width,f.Height,f.Required,f.Label,mark ? null : f.Value,
            f.FilledAt,f.SignatureAdoptionId,Hex(f.ImageSha256),filled,mark && hasMarkState && !bound);
    }
    private static string? Canonical(string? value)
    {
        if (value is null || value.Length > 4000) return null;
        try
        {
            _ = new UTF8Encoding(false,true).GetBytes(value);
            value = value.Replace("\r\n","\n").Replace('\r','\n').Normalize(NormalizationForm.FormC);
            return value.Length <= 4000 && !value.EnumerateRunes().Any(r => Rune.GetUnicodeCategory(r) == UnicodeCategory.Format ||
                Rune.GetUnicodeCategory(r) == UnicodeCategory.Control && r.Value is not (10 or 9)) ? value : null;
        }
        catch (ArgumentException) { return null; }
    }
    private static byte[]? Version(string? value) { if (value is null || value.Length != 12) return null; try { var bytes = Convert.FromBase64String(value); return bytes.Length == 8 && Convert.ToBase64String(bytes) == value ? bytes : null; } catch (FormatException) { return null; } }
    private static bool Same(byte[]? a,byte[]? b) => a is null || b is null ? a is null && b is null : CryptographicOperations.FixedTimeEquals(a,b);
    private static string? Hex(byte[]? bytes) => bytes is null ? null : Convert.ToHexStringLower(bytes);
}
