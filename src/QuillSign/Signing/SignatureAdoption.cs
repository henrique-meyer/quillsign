using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Signing;

public static class SignatureAdoptionStatement
{
    public const string Version = "2026-10-16.1";
    public const string Text = "By selecting Adopt and Sign, I agree this mark is my electronic signature and initials, legally equivalent to my handwritten signature.";
    public static byte[] Sha256 => SHA256.HashData(Encoding.UTF8.GetBytes(Text));
}
public sealed record SignaturePreviewRequest(byte[] Signature,byte[] Initials,SignatureMethod Method,string? TypedName = null,string? TypedInitials = null);
public sealed record SignaturePreviewData(Guid Id,string Receipt,byte[] Signature,byte[] Initials,int SignatureWidth,int SignatureHeight,
    int InitialsWidth,int InitialsHeight,SignatureMethod Method,string? TypedName,string? TypedInitials,DateTimeOffset ExpiresAt,
    string StatementVersion,string Statement);
public sealed record SignaturePreviewReceipt(Guid Id,VerifiedSigner Identity,DateTimeOffset ExpiresAt,string SignatureHash,string InitialsHash);
public sealed class SignaturePreviewProtection(IDataProtectionProvider provider,TimeProvider time)
{
    private readonly IDataProtector protector = provider.CreateProtector("QuillSign.SignaturePreview.v1");
    internal string Create(SignaturePreview preview,VerifiedSigner identity) => protector.Protect(JsonSerializer.Serialize(
        new SignaturePreviewReceipt(preview.Id,identity,preview.ExpiresAt,Convert.ToHexStringLower(preview.SignatureSha256),Convert.ToHexStringLower(preview.InitialsSha256))));
    public SignaturePreviewReceipt? Read(string? value,VerifiedSigner identity)
    {
        if (value is null || value.Length > 8192) return null;
        try
        {
            var receipt = JsonSerializer.Deserialize<SignaturePreviewReceipt>(protector.Unprotect(value));
            return receipt is not null && receipt.Id != Guid.Empty && receipt.Identity == identity && receipt.ExpiresAt > time.GetUtcNow() &&
                receipt.ExpiresAt <= identity.SessionExpiresAt ? receipt : null;
        }
        catch (Exception e) when (e is CryptographicException or JsonException or ArgumentException) { return null; }
    }
}
public enum SignatureAdoptionResult { Adopted, AlreadyAdopted, InvalidContext, InvalidPreview, InvalidAcknowledgment }
public sealed record AdoptedSignatureData(Guid Id,byte[] Signature,byte[] Initials,int SignatureWidth,int SignatureHeight,
    int InitialsWidth,int InitialsHeight,DateTimeOffset AdoptedAt,SignatureMethod Method,string NormalizationVersion);
internal sealed record CurrentSignatureAssets(SignaturePreview Preview,byte[] Signature,byte[] Initials);

// Backend foundation. Its caller must render the exact returned assets and statement and
// collect an explicit action; a prepared preview alone is never adoption or a field fill.
public sealed class SignatureAdoption(QuillSignDbContext db,SignerAccess access,IBlobStore blobs,
    SignaturePreviewProtection receipts,AuditWriter audit,TimeProvider time)
{
    public const int PreviewMinutes = 10;
    public const int MaximumPreviewsPerSigner = 40;
    public const int MaximumActivePreviews = 5;

    public async Task<SignaturePreviewData?> PrepareAsync(ClaimsPrincipal principal,string publicId,SignaturePreviewRequest request,CancellationToken ct = default)
    {
        var initial = await access.GetContextAsync(principal,publicId,ct);
        if (initial?.ConsentAt is null) return null;
        if (!Enum.IsDefined(request.Method)) throw new ArgumentException("Select a supported signature method.");
        var typedName = Descriptor(request.TypedName,200); var typedInitials = Descriptor(request.TypedInitials,20);
        if (request.Method == SignatureMethod.Typed && (typedName is null || typedInitials is null))
            throw new ArgumentException("Typed marks require a name and initials.");
        if (request.Method != SignatureMethod.Typed && (typedName is not null || typedInitials is not null))
            throw new ArgumentException("Typed descriptors apply only to typed marks.");
        var signature = SignaturePng.Normalize(request.Signature); var initials = SignaturePng.Normalize(request.Initials);
        var committed = false; var commitStarted = false;
        var attempted = new List<DocumentBlob>();
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            var context = await access.GetLockedContextAsync(principal,publicId,ct);
            if (context?.ConsentAt is null) return null;
            var now = time.GetUtcNow();
            if (await db.SignaturePreviews.CountAsync(x => x.EnvelopeId == context.Identity.EnvelopeId && x.SignerId == context.Identity.SignerId,ct) >= MaximumPreviewsPerSigner)
                throw new InvalidOperationException("This signer has reached the preview limit for this request. Reuse an unexpired preview or contact the sender.");
            if (await db.SignaturePreviews.CountAsync(x => x.EnvelopeId == context.Identity.EnvelopeId && x.SignerId == context.Identity.SignerId && x.UsedAt == null && x.ExpiresAt > now,ct) >= MaximumActivePreviews)
                throw new InvalidOperationException("Reuse an unexpired signature preview or wait for it to expire before preparing another.");
            var signer = await CurrentSigner(context.Identity,ct);
            var preview = new SignaturePreview { EnvelopeId = context.Identity.EnvelopeId,SignerId = context.Identity.SignerId,DocumentId = context.Identity.DocumentId,
                SignatureObjectId = Guid.NewGuid(),InitialsObjectId = Guid.NewGuid(),SignatureSha256 = signature.Sha256,InitialsSha256 = initials.Sha256,
                SignatureWidth = signature.Width,SignatureHeight = signature.Height,InitialsWidth = initials.Width,InitialsHeight = initials.Height,
                DocumentSha256 = Convert.FromHexString(context.Identity.DocumentHash),DisclosureSha256 = Convert.FromHexString(context.Identity.DisclosureHash),
                SessionSha256 = SessionHash(context.Identity),BaselineSignerVersion = signer.RowVersion,Method = request.Method,TypedName = typedName,TypedInitials = typedInitials,
                NormalizationVersion = SignaturePng.Version,AdoptionVersion = SignatureAdoptionStatement.Version,CreatedAt = now,
                ExpiresAt = new[] { now.AddMinutes(PreviewMinutes),context.Identity.SessionExpiresAt }.Min() };
            foreach (var pair in new[] { (SignatureBlob(preview),signature.Bytes),(InitialsBlob(preview),initials.Bytes) })
            {
                attempted.Add(pair.Item1);
                using var input = new MemoryStream(pair.Item2,false);
                await blobs.WriteAsync(Capability(context.Identity,pair.Item1,AssetOperation.Write),pair.Item1,input,input.Length,ct);
            }
            var verified = await ReadImages(preview,context.Identity,ct);
            // Storage may have taken time. A session/consent invalidated meanwhile cannot save a preview.
            if (preview.ExpiresAt <= time.GetUtcNow() || (await access.GetLockedContextAsync(principal,publicId,ct))?.ConsentAt is null) return null;
            db.SignaturePreviews.Add(preview); await db.SaveChangesAsync(ct);
            commitStarted = true; await transaction.CommitAsync(ct); committed = true;
            return Data(preview,context.Identity,verified.Signature,verified.Initials);
        }
        finally
        {
            if (!committed && !commitStarted)
                foreach (var blob in attempted)
                    try { await blobs.DeleteAsync(Capability(initial.Identity,blob,AssetOperation.Delete),blob,CancellationToken.None); }
                    catch (Exception e) when (e is not OutOfMemoryException) { /* Later envelope purge handles unreachable objects. */ }
        }
    }

    public async Task<SignaturePreviewData?> ReadAsync(ClaimsPrincipal principal,string publicId,string? receipt,CancellationToken ct = default)
    {
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var context = await access.GetLockedContextAsync(principal,publicId,ct); if (context?.ConsentAt is null) return null;
        var preview = await FindPreview(receipt,context.Identity,ct); if (preview is null) return null;
        var signer = await CurrentSigner(context.Identity,ct);
        if (!MatchesRevision(preview,signer)) return null;
        var images = await ReadImages(preview,context.Identity,ct);
        if (preview.ExpiresAt <= time.GetUtcNow() || (await access.GetLockedContextAsync(principal,publicId,ct))?.ConsentAt is null) return null;
        await transaction.CommitAsync(ct);
        return Data(preview,context.Identity,images.Signature,images.Initials);
    }

    public async Task<SignatureAdoptionResult> AdoptAsync(ClaimsPrincipal principal,string publicId,string? receipt,bool acknowledged,
        string? statementVersion,string? ip,string? ua,CancellationToken ct = default)
    {
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var context = await access.GetLockedContextAsync(principal,publicId,ct);
        if (context?.ConsentAt is null) return SignatureAdoptionResult.InvalidContext;
        if (!acknowledged || statementVersion != SignatureAdoptionStatement.Version) return SignatureAdoptionResult.InvalidAcknowledgment;
        var preview = await FindPreview(receipt,context.Identity,ct); if (preview is null) return SignatureAdoptionResult.InvalidPreview;
        var signer = await CurrentSigner(context.Identity,ct);
        if (!MatchesRevision(preview,signer)) return SignatureAdoptionResult.InvalidPreview;
        _ = await ReadImages(preview,context.Identity,ct);
        if (preview.ExpiresAt <= time.GetUtcNow() || (await access.GetLockedContextAsync(principal,publicId,ct))?.ConsentAt is null)
            return SignatureAdoptionResult.InvalidContext;
        if (preview.UsedAt is not null) return SignatureAdoptionResult.AlreadyAdopted;
        var now = time.GetUtcNow(); var replaced = signer.SignatureAdoptionId;
        var changed = await db.Signers.Where(x => x.Id == signer.Id && x.EnvelopeId == signer.EnvelopeId && x.RowVersion == preview.BaselineSignerVersion)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.SignatureAdoptionId,preview.Id).SetProperty(x => x.SignatureAdoptedAt,now)
                .SetProperty(x => x.SignatureImageBlob,preview.SignatureObjectId.ToString("N")).SetProperty(x => x.InitialsImageBlob,preview.InitialsObjectId.ToString("N"))
                .SetProperty(x => x.SignatureImageSha256,preview.SignatureSha256).SetProperty(x => x.InitialsImageSha256,preview.InitialsSha256)
                .SetProperty(x => x.SignatureMethod,preview.Method).SetProperty(x => x.SignatureTypedName,preview.TypedName).SetProperty(x => x.SignatureTypedInitials,preview.TypedInitials)
                .SetProperty(x => x.SignatureNormalizationVersion,preview.NormalizationVersion).SetProperty(x => x.SignatureAdoptionVersion,preview.AdoptionVersion),ct);
        if (changed != 1) throw new DbUpdateConcurrencyException("The signer revision changed.");
        if (await db.SignaturePreviews.Where(x => x.Id == preview.Id && x.UsedAt == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.UsedAt,now),ct) != 1)
            throw new DbUpdateConcurrencyException("The signature preview changed.");
        await audit.AppendAsync(context.Identity.EnvelopeId,"signature_adopted",context.Identity.Email,ip,ua,ct,
            JsonSerializer.Serialize(new { adoptionId = preview.Id,replacedAdoptionId = replaced,statementVersion = preview.AdoptionVersion,
                statement = SignatureAdoptionStatement.Text,statementSha256 = Convert.ToHexStringLower(SignatureAdoptionStatement.Sha256),acknowledged,
                method = preview.Method.ToString(),reportedTypedName = preview.TypedName,reportedTypedInitials = preview.TypedInitials,
                normalizationVersion = preview.NormalizationVersion,signatureObjectId = preview.SignatureObjectId,initialsObjectId = preview.InitialsObjectId,
                signatureSha256 = Convert.ToHexStringLower(preview.SignatureSha256),initialsSha256 = Convert.ToHexStringLower(preview.InitialsSha256),
                documentSha256 = context.Identity.DocumentHash,disclosureSha256 = context.Identity.DisclosureHash,
                serverEvidence = "previewed_assets_bound_to_explicit_adoption_request",identityEvidence = "email_link_session_with_prior_consent" }),PartyType.Signer,signer.Id);
        await transaction.CommitAsync(ct); return SignatureAdoptionResult.Adopted;
    }

    // Current adopted marks outlive their original preview and may be read from a fresh
    // authorized signer session. This does not refresh a preview or grant storage writes.
    public async Task<AdoptedSignatureData?> ReadCurrentAsync(ClaimsPrincipal principal,string publicId,CancellationToken ct = default)
    {
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var context = await access.GetLockedContextAsync(principal,publicId,ct); if (context?.ConsentAt is null) return null;
        var assets = await GetCurrentLockedAsync(context.Identity,ct); if (assets is null) return null;
        if ((await access.GetLockedContextAsync(principal,publicId,ct))?.ConsentAt is null) return null;
        await transaction.CommitAsync(ct); var p = assets.Preview;
        return new(p.Id,assets.Signature,assets.Initials,p.SignatureWidth,p.SignatureHeight,p.InitialsWidth,p.InitialsHeight,p.UsedAt!.Value,p.Method,p.NormalizationVersion);
    }
    // The caller must have checked live consent/scope under the common envelope lock.
    internal async Task<CurrentSignatureAssets?> GetCurrentLockedAsync(VerifiedSigner identity,CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("A transaction is required.");
        var signer = await CurrentSigner(identity,ct);
        if (signer.SignatureAdoptionId is not Guid id) return null;
        var preview = await db.SignaturePreviews.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id && x.EnvelopeId == identity.EnvelopeId && x.SignerId == identity.SignerId,ct);
        if (preview?.UsedAt is null || preview.DocumentId != identity.DocumentId || !Same(preview.DocumentSha256,Convert.FromHexString(identity.DocumentHash)) ||
            !Same(preview.DisclosureSha256,Convert.FromHexString(identity.DisclosureHash)) || preview.NormalizationVersion != SignaturePng.Version ||
            preview.AdoptionVersion != SignatureAdoptionStatement.Version || !MatchesRevision(preview,signer)) return null;
        var evidence = await db.AuditEvents.FromSqlInterpolated($"SELECT * FROM [AuditEvents] WHERE JSON_VALUE([DataJson], '$.adoptionId') = {id.ToString("D")}")
            .AsNoTracking().Where(x => x.EnvelopeId == identity.EnvelopeId && x.Event == "signature_adopted" &&
                x.ActorType == PartyType.Signer && x.ActorId == identity.SignerId && x.ActorEmail == identity.Email).ToListAsync(ct);
        if (evidence.Count != 1 || !Same(evidence[0].Hash,AuditHash.Compute(evidence[0])) || !MatchesAdoptionEvidence(evidence[0].DataJson,preview,identity)) return null;
        var signature = await ReadImage(identity,SignatureBlob(preview),preview.SignatureSha256,ct);
        if (identity.SessionExpiresAt <= time.GetUtcNow()) return null;
        var initials = await ReadImage(identity,InitialsBlob(preview),preview.InitialsSha256,ct);
        return identity.SessionExpiresAt > time.GetUtcNow() ? new(preview,signature,initials) : null;
    }
    private static bool MatchesAdoptionEvidence(string json,SignaturePreview p,VerifiedSigner identity)=>MatchesAdoptionEvidence(json,p,identity.DocumentHash,identity.DisclosureHash);
    internal static bool MatchesAdoptionEvidence(string json,SignaturePreview p,string documentHash,string disclosureHash)
    {
        try
        {
            using var document = JsonDocument.Parse(json); var root = document.RootElement;
            bool Text(string key,string expected) => root.TryGetProperty(key,out var value) && value.ValueKind == JsonValueKind.String && value.GetString() == expected;
            bool Id(string key,Guid expected) => root.TryGetProperty(key,out var value) && value.ValueKind == JsonValueKind.String && value.TryGetGuid(out var id) && id == expected;
            bool OptionalText(string key,string? expected) => root.TryGetProperty(key,out var value) &&
                (expected is null ? value.ValueKind == JsonValueKind.Null : value.ValueKind == JsonValueKind.String && value.GetString() == expected);
            return Id("adoptionId",p.Id) && Id("signatureObjectId",p.SignatureObjectId) && Id("initialsObjectId",p.InitialsObjectId) &&
                Text("signatureSha256",Convert.ToHexStringLower(p.SignatureSha256)) && Text("initialsSha256",Convert.ToHexStringLower(p.InitialsSha256)) &&
                Text("documentSha256",documentHash) && Text("disclosureSha256",disclosureHash) && Text("statementVersion",p.AdoptionVersion) &&
                Text("statement",SignatureAdoptionStatement.Text) && Text("statementSha256",Convert.ToHexStringLower(SignatureAdoptionStatement.Sha256)) &&
                Text("normalizationVersion",p.NormalizationVersion) && Text("method",p.Method.ToString()) &&
                OptionalText("reportedTypedName",p.TypedName) && OptionalText("reportedTypedInitials",p.TypedInitials) &&
                root.TryGetProperty("acknowledged",out var acknowledged) && acknowledged.ValueKind == JsonValueKind.True;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { return false; }
    }

    private async Task<SignaturePreview?> FindPreview(string? value,VerifiedSigner identity,CancellationToken ct)
    {
        var receipt = receipts.Read(value,identity); if (receipt is null) return null;
        var preview = await db.SignaturePreviews.AsNoTracking().SingleOrDefaultAsync(x => x.Id == receipt.Id && x.EnvelopeId == identity.EnvelopeId && x.SignerId == identity.SignerId,ct);
        return preview is not null && preview.ExpiresAt > time.GetUtcNow() && preview.ExpiresAt == receipt.ExpiresAt && preview.DocumentId == identity.DocumentId &&
            Same(preview.SessionSha256,SessionHash(identity)) && Same(preview.DocumentSha256,Convert.FromHexString(identity.DocumentHash)) &&
            Same(preview.DisclosureSha256,Convert.FromHexString(identity.DisclosureHash)) && preview.NormalizationVersion == SignaturePng.Version &&
            preview.AdoptionVersion == SignatureAdoptionStatement.Version && Convert.ToHexStringLower(preview.SignatureSha256) == receipt.SignatureHash &&
            Convert.ToHexStringLower(preview.InitialsSha256) == receipt.InitialsHash ? preview : null;
    }
    internal static bool MatchesRevision(SignaturePreview preview,Signer signer) => preview.UsedAt is null ? Same(preview.BaselineSignerVersion,signer.RowVersion) :
        signer.SignatureAdoptionId == preview.Id && signer.SignatureImageBlob == preview.SignatureObjectId.ToString("N") && signer.InitialsImageBlob == preview.InitialsObjectId.ToString("N") &&
        Same(signer.SignatureImageSha256,preview.SignatureSha256) && Same(signer.InitialsImageSha256,preview.InitialsSha256) && signer.SignatureAdoptedAt == preview.UsedAt &&
        signer.SignatureMethod == preview.Method && signer.SignatureNormalizationVersion == preview.NormalizationVersion && signer.SignatureAdoptionVersion == preview.AdoptionVersion &&
        signer.SignatureTypedName == preview.TypedName && signer.SignatureTypedInitials == preview.TypedInitials;
    private Task<Signer> CurrentSigner(VerifiedSigner identity,CancellationToken ct) => db.Signers.AsNoTracking().SingleAsync(x => x.Id == identity.SignerId && x.EnvelopeId == identity.EnvelopeId,ct);
    private async Task<(byte[] Signature,byte[] Initials)> ReadImages(SignaturePreview preview,VerifiedSigner identity,CancellationToken ct) =>
        (await ReadImage(identity,SignatureBlob(preview),preview.SignatureSha256,ct),await ReadImage(identity,InitialsBlob(preview),preview.InitialsSha256,ct));
    private async Task<byte[]> ReadImage(VerifiedSigner identity,DocumentBlob blob,byte[] hash,CancellationToken ct)
    {
        using var memory = new MemoryStream(); using var bounded = new BoundedDocumentStream(memory,512 * 1024);
        var length = await blobs.CopyToAsync(Capability(identity,blob,AssetOperation.Read),blob,bounded,ct);
        if (length != memory.Length || length == 0 || !Same(hash,SHA256.HashData(memory.GetBuffer().AsSpan(0,checked((int)memory.Length)))))
            throw new InvalidDataException("The saved signature asset could not be verified.");
        return memory.ToArray();
    }
    private ClaimsPrincipal Capability(VerifiedSigner identity,DocumentBlob blob,AssetOperation operation) => SignatureAssetCapability.Create(identity,blob,operation,time);
    private SignaturePreviewData Data(SignaturePreview p,VerifiedSigner identity,byte[] signature,byte[] initials) => new(p.Id,receipts.Create(p,identity),signature,initials,
        p.SignatureWidth,p.SignatureHeight,p.InitialsWidth,p.InitialsHeight,p.Method,p.TypedName,p.TypedInitials,p.ExpiresAt,p.AdoptionVersion,SignatureAdoptionStatement.Text);
    private static DocumentBlob SignatureBlob(SignaturePreview p) => new(p.EnvelopeId,DocumentBlobKind.Signature,p.SignatureObjectId);
    private static DocumentBlob InitialsBlob(SignaturePreview p) => new(p.EnvelopeId,DocumentBlobKind.Initials,p.InitialsObjectId);
    private static byte[] SessionHash(VerifiedSigner identity) => SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity));
    private static bool Same(byte[]? a,byte[] b) => a is not null && CryptographicOperations.FixedTimeEquals(a,b);
    private static string? Descriptor(string? value,int maximum)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (value.Length > maximum || value.EnumerateRunes().Any(r => Rune.GetUnicodeCategory(r) is System.Globalization.UnicodeCategory.Control or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.Surrogate) ||
            value.Any(c => char.IsSurrogate(c)) && !ValidUnicode(value)) throw new ArgumentException("Use a bounded plain-text name or initials.");
        value = value.Trim().Normalize(NormalizationForm.FormC);
        if (value.Length > maximum) throw new ArgumentException("Use a bounded plain-text name or initials.");
        return value;
    }
    private static bool ValidUnicode(string value) { try { _ = new UTF8Encoding(false,true).GetBytes(value); return true; } catch (EncoderFallbackException) { return false; } }
}
