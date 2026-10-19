using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Documents;

namespace QuillSign.Signing;

public sealed class SignerSetupOptions
{
    public int MaximumSigners { get; set; } = 10;
}

public sealed record SignerListItem(Guid Id, int Order, string FullName, string Email, string? Role);
public sealed record SignerSetupSnapshot(string PublicId, string SenderEmail, string? SenderName,
    string Version, bool PreviewConfirmed, IReadOnlyList<SignerListItem> Signers);
public enum SignerChangeKind { Save, Remove, MoveUp, MoveDown }
public sealed record SignerChange(SignerChangeKind Kind, string Version, Guid? SignerId = null,
    string? FullName = null, string? Email = null, string? Role = null);
public enum SignerSetupError { None, NotFound, PreviewRequired, Conflict, Invalid, Duplicate, Limit, ReferencedFields }
public sealed record SignerChangeResult(SignerSetupError Error, string? Message = null, string? Field = null);

public sealed class SignerSetup(QuillSignDbContext db, AuditWriter audit, SignerSetupOptions options,TimeProvider? time=null,QuillSign.Email.Pilot.EmailPilotReadBounds? pilotBounds=null)
{
    public async Task<SignerSetupSnapshot?> GetAsync(ClaimsPrincipal sender, string publicId,
        CancellationToken cancellationToken = default)
    {
        var identity = SenderIdentity(sender, publicId);
        if (identity is null) return null;
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(cancellationToken), cancellationToken);
        await using var transaction=await db.Database.BeginTransactionAsync(cancellationToken);
        var envelope = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {identity.Value.Id}").AsNoTracking().SingleOrDefaultAsync(x => x.Id == identity.Value.Id &&
            x.PublicId == publicId && x.SenderEmail == identity.Value.Email && x.SenderVerifiedAt != null &&
            x.Status == EnvelopeStatus.Draft, cancellationToken);
        if (envelope is null) return null;
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope,time??TimeProvider.System,cancellationToken,pilotBounds);
        var signers = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Order)
            .Select(x => new SignerListItem(x.Id, x.Order, x.FullName, x.Email, x.Role)).ToListAsync(cancellationToken);
        var result=new SignerSetupSnapshot(envelope.PublicId, envelope.SenderEmail, envelope.SenderName,
            Convert.ToBase64String(envelope.RowVersion), IsConfirmed(envelope), signers);
        DocumentRetentionAccess.Check(deadline,time??TimeProvider.System);await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,cancellationToken);return result;
    }

    public async Task<SignerChangeResult> ChangeAsync(ClaimsPrincipal sender, string publicId, SignerChange change,
        string? ip, string? userAgent, CancellationToken cancellationToken = default)
    {
        var identity = SenderIdentity(sender, publicId);
        if (identity is null) return new(SignerSetupError.NotFound);
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(cancellationToken), cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        // The same envelope lock serializes upload/confirmation, signer-list changes, and audit sequencing.
        var envelope = await db.Envelopes.FromSqlInterpolated(
            $"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {identity.Value.Id}")
            .SingleOrDefaultAsync(cancellationToken);
        if (envelope is null || envelope.PublicId != publicId || envelope.SenderVerifiedAt is null ||
            envelope.Status != EnvelopeStatus.Draft || !string.Equals(envelope.SenderEmail, identity.Value.Email, StringComparison.OrdinalIgnoreCase))
            return new(SignerSetupError.NotFound);
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope,time??TimeProvider.System,cancellationToken,pilotBounds);
        if (!IsConfirmed(envelope)) return new(SignerSetupError.PreviewRequired, "Confirm the current PDF preview before setting up signers.");
        if (!MatchesVersion(change.Version, envelope.RowVersion))
            return new(SignerSetupError.Conflict, "This draft changed. Reload the signer list before trying again.");
        if (!Enum.IsDefined(change.Kind)) return new(SignerSetupError.Invalid, "Choose a valid signer action.");

        var signers = await db.Signers.Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Order)
            .ToListAsync(cancellationToken);
        var selected = change.SignerId is null ? null : signers.SingleOrDefault(x => x.Id == change.SignerId);
        if (change.SignerId is not null && selected is null) return new(SignerSetupError.NotFound);
        string eventName;
        if (change.Kind == SignerChangeKind.Save)
        {
            var validation = Validate(change, out var name, out var email, out var role);
            if (validation is not null) return validation;
            if (signers.Any(x => x.Id != selected?.Id && string.Equals(x.Email, email, StringComparison.OrdinalIgnoreCase)))
                return new(SignerSetupError.Duplicate, "This email address is already a signer.", "Email");
            if (selected is null)
            {
                if (signers.Count >= options.MaximumSigners)
                    return new(SignerSetupError.Limit, $"This draft allows at most {options.MaximumSigners} signers.");
                selected = new Signer { EnvelopeId = envelope.Id, Order = signers.Count + 1 };
                db.Signers.Add(selected);
                signers.Add(selected);
                eventName = "signer_added";
            }
            else
            {
                if (!string.Equals(selected.Email, email, StringComparison.OrdinalIgnoreCase) &&
                    await db.Fields.AnyAsync(x => x.EnvelopeId == envelope.Id && x.SignerId == selected.Id, cancellationToken))
                    return new(SignerSetupError.ReferencedFields, "Remove this signer's assigned fields before changing their email.", "Email");
                eventName = "signer_updated";
            }
            selected.FullName = name;
            selected.Email = email;
            selected.Role = role;
        }
        else
        {
            if (selected is null) return new(SignerSetupError.NotFound);
            if (change.Kind == SignerChangeKind.Remove)
            {
                if (await db.Fields.AnyAsync(x => x.EnvelopeId == envelope.Id && x.SignerId == selected.Id, cancellationToken))
                    return new(SignerSetupError.ReferencedFields, "Remove this signer's assigned fields before removing the signer.");
                db.Signers.Remove(selected);
                signers.Remove(selected);
                eventName = "signer_removed";
            }
            else
            {
                var index = signers.IndexOf(selected);
                var next = index + (change.Kind == SignerChangeKind.MoveUp ? -1 : 1);
                if (next < 0 || next >= signers.Count)
                    return new(SignerSetupError.Invalid, "The signer is already at that end of the list.");
                (signers[index], signers[next]) = (signers[next], signers[index]);
                eventName = "signers_reordered";
            }
        }

        // SQL has a unique (EnvelopeId, Order) index and Order > 0 constraint. Move every survivor
        // outside the occupied range, save, then assign final consecutive positions in this transaction.
        var offset = checked(signers.Select(x => x.Order).DefaultIfEmpty(0).Max() + signers.Count + 1);
        for (var i = 0; i < signers.Count; i++) signers[i].Order = checked(offset + i + 1);
        await db.SaveChangesAsync(cancellationToken);
        for (var i = 0; i < signers.Count; i++) signers[i].Order = i + 1;
        // Every list mutation advances the shared draft version, even when no other envelope value changes.
        db.Entry(envelope).Property(x => x.Status).IsModified = true;
        var data = JsonSerializer.Serialize(new
        {
            signerId = selected?.Id,
            signers = signers.Select(x => new { x.Id, x.Order, x.FullName, x.Email, x.Role })
        });
        await audit.AppendAsync(envelope.Id, eventName, identity.Value.Email, ip, userAgent, cancellationToken, data);
        DocumentRetentionAccess.Check(deadline,time??TimeProvider.System);
        await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,cancellationToken);
        return new(SignerSetupError.None);
    }

    private static bool IsConfirmed(Envelope envelope) => envelope.PreviewConfirmedAt is not null &&
        envelope.PdfBlob is not null && envelope.PdfSha256 is not null && envelope.PageCount > 0;

    private static bool MatchesVersion(string? encoded, byte[] version)
    {
        Span<byte> decoded = stackalloc byte[8];
        return encoded is { Length: <= 16 } && version.Length == decoded.Length &&
            Convert.TryFromBase64String(encoded, decoded, out var length) && length == decoded.Length &&
            CryptographicOperations.FixedTimeEquals(decoded, version);
    }

    private static (Guid Id, string Email)? SenderIdentity(ClaimsPrincipal principal, string publicId)
    {
        var identities = principal.Identities.Where(x => x.IsAuthenticated &&
            x.AuthenticationType == EnvelopeStorageAuthorization.SenderScheme).ToArray();
        var ids = identities.SelectMany(x => x.FindAll(EnvelopeStorageAuthorization.EnvelopeClaim)).ToArray();
        var emails = identities.SelectMany(x => x.FindAll(ClaimTypes.Email)).ToArray();
        var publicIds = identities.SelectMany(x => x.FindAll(SenderConfiguration.PublicIdClaim)).ToArray();
        return ids.Length == 1 && Guid.TryParse(ids[0].Value, out var id) && id != Guid.Empty &&
            emails.Length == 1 && publicIds.Length == 1 && publicIds[0].Value == publicId
            ? (id, emails[0].Value) : null;
    }

    private static SignerChangeResult? Validate(SignerChange change, out string name, out string email, out string? role)
    {
        name = change.FullName?.Trim() ?? "";
        email = "";
        role = string.IsNullOrWhiteSpace(change.Role) ? null : change.Role.Trim();
        if (name.Length is < 1 or > 512 || name.Any(char.IsControl))
            return new(SignerSetupError.Invalid, "Enter a full name of at most 512 characters.", "FullName");
        if (role is { Length: > 512 } || role?.Any(char.IsControl) == true)
            return new(SignerSetupError.Invalid, "Enter a role of at most 512 characters.", "Role");
        try { email = EmailAddress.Normalize(change.Email?.Trim() ?? ""); }
        catch (ArgumentException) { return new(SignerSetupError.Invalid, "Enter one valid email address.", "Email"); }
        return null;
    }
}
