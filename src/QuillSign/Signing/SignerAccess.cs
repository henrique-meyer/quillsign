using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Storage;

namespace QuillSign.Signing;

public sealed record SignerInvitation(string RawToken,AuthToken Record);
// Pure factory: the future dispatch transaction must authorize current state and persist only Record.
// Call at actual dispatch, not when work is enqueued. Do not log/store RawToken in plaintext.
public sealed class SignerInvitationFactory(SignerAccessOptions options,TimeProvider time)
{
    public SignerInvitation Create(Guid envelopeId,Guid signerId,string email,DateTimeOffset? envelopeExpiry,Guid documentId,byte[] documentSha256,byte[] disclosureSha256)
    {
        if (options.InvitationHours is < 1 or > 168) throw new InvalidOperationException("Invalid signer invitation lifetime.");
        if (envelopeId == Guid.Empty || signerId == Guid.Empty) throw new ArgumentException("Supply a signer and envelope.");
        if(documentId==Guid.Empty || documentSha256 is not { Length:32 } || disclosureSha256 is not { Length:32 })throw new ArgumentException("Supply the exact invitation document/disclosure binding.");
        var now = time.GetUtcNow(); var expires = now.AddHours(options.InvitationHours);
        if (envelopeExpiry is DateTimeOffset end && end < expires) expires = end;
        if (expires <= now) throw new InvalidOperationException("This envelope has expired.");
        var raw = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        return new(raw,new AuthToken { EnvelopeId = envelopeId,PartyId = signerId,PartyType = PartyType.Signer,
            Purpose = TokenPurpose.SignerAccess,Email = EmailAddress.Normalize(email),ExpiresAt = expires,
            TokenSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(raw)),DocumentId=documentId,DocumentSha256=documentSha256.ToArray(),DisclosureSha256=disclosureSha256.ToArray() });
    }
    internal static byte[]? TokenHash(string? raw)
    {
        if (raw is not { Length: 43 } || !raw.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')) return null;
        try { var bytes = WebEncoders.Base64UrlDecode(raw); return bytes.Length == 32 && WebEncoders.Base64UrlEncode(bytes) == raw ? SHA256.HashData(Encoding.UTF8.GetBytes(raw)) : null; }
        catch (FormatException) { return null; }
    }
}
public sealed record SignerReadContext(VerifiedSigner Identity,string Title,string SignerName,string? Role,
    DocumentBlob Document,byte[] DocumentSha256,DisclosureSnapshot Disclosure,DateTimeOffset? ConsentAt = null,Guid? SignatureAdoptionId = null);

public sealed class SignerAccess(QuillSignDbContext db,AuditWriter audit,SignerAccessOptions options,TimeProvider time)
{
    public async Task<VerifiedSigner?> RedeemAsync(string? rawToken,string? ip,string? userAgent,CancellationToken ct = default)
    {
        var hash = SignerInvitationFactory.TokenHash(rawToken); if (hash is null) return null;
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        // Locate scope without taking a token lock before the common envelope lock.
        var located = await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x => x.TokenSha256 == hash,ct);
        if (located?.EnvelopeId is not Guid envelopeId || located.PartyId is not Guid signerId || located.Purpose != TokenPurpose.SignerAccess ||
            located.PartyType != PartyType.Signer || located.UsedAt is not null || located.ExpiresAt <= time.GetUtcNow() ||
            located.DocumentId is null || located.DocumentSha256 is not { Length:32 } || located.DisclosureSha256 is not { Length:32 }) return null;
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var envelope = await Locked(envelopeId).AsNoTracking().SingleOrDefaultAsync(ct);
        var context = await EligibleAsync(envelope,signerId,ct); if (context is null) return null;
        var token = await db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {located.Id}")
            .AsNoTracking().SingleOrDefaultAsync(ct);
        var now = time.GetUtcNow();
        if (token is null || token.Purpose != TokenPurpose.SignerAccess || token.PartyType != PartyType.Signer || token.UsedAt is not null ||
            token.ExpiresAt <= now || context.Identity.SessionExpiresAt <= now || envelope!.ExpiresAt <= now || token.EnvelopeId != envelopeId || token.PartyId != signerId ||
            token.DocumentId!=context.Identity.DocumentId || token.DocumentSha256 is not { Length:32 } || token.DisclosureSha256 is not { Length:32 } ||
            Convert.ToHexStringLower(token.DocumentSha256)!=context.Identity.DocumentHash || Convert.ToHexStringLower(token.DisclosureSha256)!=context.Identity.DisclosureHash ||
            !CryptographicOperations.FixedTimeEquals(token.TokenSha256,hash) || !string.Equals(token.Email,context.Identity.Email,StringComparison.OrdinalIgnoreCase)) return null;
        var consumed = await db.AuthTokens.Where(x => x.Id == token.Id && x.UsedAt == null).ExecuteUpdateAsync(
            update => update.SetProperty(x => x.UsedAt,now),ct);
        if (consumed != 1) return null;
        await audit.AppendAsync(envelopeId,"link_opened",context.Identity.Email,ip,userAgent,ct,
            JsonSerializer.Serialize(new { signerId,tokenId = token.Id,documentId=context.Identity.DocumentId,documentSha256 = context.Identity.DocumentHash,
                disclosureSha256 = context.Identity.DisclosureHash,authentication = "single_use_email_link" }),PartyType.Signer,signerId);
        await transaction.CommitAsync(ct); return context.Identity;
    }

    public async Task<SignerReadContext?> GetContextAsync(ClaimsPrincipal principal,string publicId,CancellationToken ct = default,bool declinedConfirmation = false)
    {
        var identity = SignerAccessConfiguration.ReadIdentity(principal,time.GetUtcNow()); if (identity is null || identity.PublicId != publicId) return null;
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var context = await GetLockedContextAsync(principal,publicId,ct,declinedConfirmation);
        await transaction.CommitAsync(ct); return context;
    }
    // The caller owns the transaction, so scope validation and mutation share the same lock.
    internal async Task<SignerReadContext?> GetLockedContextAsync(ClaimsPrincipal principal,string publicId,CancellationToken ct,bool declinedConfirmation = false,bool finishConfirmation = false)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("A transaction is required.");
        var identity = SignerAccessConfiguration.ReadIdentity(principal,time.GetUtcNow()); if (identity is null || identity.PublicId != publicId) return null;
        var envelope = await Locked(identity.EnvelopeId).AsNoTracking().SingleOrDefaultAsync(ct);
        if(finishConfirmation && await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==identity.EnvelopeId && x.SignerId==identity.SignerId,ct))
            return await FinishedContext(envelope,identity,ct);
        var context = await EligibleAsync(envelope,identity.SignerId,ct,declinedConfirmation,finishConfirmation);
        if (context is null || identity.SessionExpiresAt <= time.GetUtcNow() || context.Identity.PublicId != identity.PublicId || context.Identity.Email != identity.Email ||
            context.Identity.DocumentId != identity.DocumentId || context.Identity.DocumentHash != identity.DocumentHash ||
            context.Identity.DisclosureHash != identity.DisclosureHash) return null;
        return context with { Identity = identity };
    }
    private IQueryable<Envelope> Locked(Guid id) => db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}");
    internal async Task<SignerReadContext?> GetEligibleLockedAsync(Guid envelopeId,Guid signerId,CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("A transaction is required.");
        return await EligibleAsync(await Locked(envelopeId).AsNoTracking().SingleOrDefaultAsync(ct),signerId,ct);
    }
    private async Task<SignerReadContext?> EligibleAsync(Envelope? envelope,Guid signerId,CancellationToken ct,bool declinedConfirmation = false,bool finishConfirmation = false)
    {
        if (options.SessionHours is < 1 or > 24) throw new InvalidOperationException("Invalid signer session lifetime.");
        var now = time.GetUtcNow();
        if (envelope is null || envelope.Status != (declinedConfirmation ? EnvelopeStatus.Declined : EnvelopeStatus.Sent) || envelope.SenderVerifiedAt is null || envelope.ExpiresAt <= now ||
            !Guid.TryParseExact(envelope.SentPdfBlob,"N",out var documentId) || documentId == Guid.Empty || envelope.SentPdfSha256 is not { Length: 32 } ||
            envelope.ErsdVersion is null || envelope.Title is null || envelope.ErsdText is null || envelope.ErsdSha256 is not { Length: 32 }) return null;
        var disclosure = new DisclosureSnapshot(envelope.ErsdVersion,envelope.PublicId,envelope.Title,envelope.SenderEmail,envelope.ErsdText,envelope.ErsdSha256);
        if (!ElectronicRecordDisclosure.Verify(disclosure)) return null;
        var signer = await db.Signers.AsNoTracking().SingleOrDefaultAsync(x => x.Id == signerId && x.EnvelopeId == envelope.Id,ct);
        if (signer is null || (declinedConfirmation ? signer.Status != SignerStatus.Declined : signer.Status is SignerStatus.Signed or SignerStatus.Declined) ||
            await db.Signers.AnyAsync(x => x.EnvelopeId == envelope.Id && x.Order < signer.Order && x.Status != SignerStatus.Signed,ct)) return null;
        if (!finishConfirmation && await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==envelope.Id && x.SignerId==signer.Id,ct)) return null;
        var expires = now.AddHours(options.SessionHours); if (envelope.ExpiresAt is DateTimeOffset end && end < expires) expires = end;
        expires = DateTimeOffset.FromUnixTimeSeconds(expires.ToUnixTimeSeconds()); if (expires <= now) return null;
        var source=await new SignerCheckpointState(db,time).CurrentAsync(envelope,ct); if(source is null)return null;
        var identity = new VerifiedSigner(envelope.Id,envelope.PublicId,signer.Id,signer.Email,source.ObjectId,
            Convert.ToHexStringLower(source.Sha256),Convert.ToHexStringLower(envelope.ErsdSha256),expires);
        return new(identity,envelope.Title,signer.FullName,signer.Role,new(envelope.Id,DocumentBlobKind.Normalized,source.ObjectId),source.Sha256,disclosure,signer.ConsentAt,signer.SignatureAdoptionId);
    }
    private async Task<SignerReadContext?> FinishedContext(Envelope? envelope,VerifiedSigner identity,CancellationToken ct)
    {
        if(envelope is null || envelope.Status is not (EnvelopeStatus.Sent or EnvelopeStatus.Completed) || envelope.ExpiresAt<=time.GetUtcNow() || envelope.SenderVerifiedAt is null ||
            envelope.PublicId!=identity.PublicId || envelope.Title is null || envelope.ErsdVersion is null || envelope.ErsdText is null || envelope.ErsdSha256 is not { Length:32 } ||
            Convert.ToHexStringLower(envelope.ErsdSha256)!=identity.DisclosureHash)return null;
        var signer=await db.Signers.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==identity.SignerId && x.EnvelopeId==envelope.Id,ct);
        var f=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.EnvelopeId==envelope.Id && x.SignerId==identity.SignerId,ct);
        if(signer?.ConsentAt is null || signer.Email!=identity.Email || signer.SignatureAdoptionId!=f.AdoptionId ||
            (f.ProcessedAt is null ? signer.Status!=SignerStatus.Viewed : signer.Status!=SignerStatus.Signed || signer.SignedAt!=f.FinishedAt) ||
            f.SourceObjectId!=identity.DocumentId || Convert.ToHexStringLower(f.SourceSha256)!=identity.DocumentHash ||
            !SignerCheckpointState.Same(f.SessionSha256,SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity))) ||
            identity.SessionExpiresAt<=time.GetUtcNow())return null;
        var disclosure=new DisclosureSnapshot(envelope.ErsdVersion,envelope.PublicId,envelope.Title,envelope.SenderEmail,envelope.ErsdText,envelope.ErsdSha256);
        return ElectronicRecordDisclosure.Verify(disclosure) ? new(identity,envelope.Title,signer.FullName,signer.Role,
            new(envelope.Id,DocumentBlobKind.Normalized,f.SourceObjectId),f.SourceSha256,disclosure,signer.ConsentAt,signer.SignatureAdoptionId) : null;
    }
}
