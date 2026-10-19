using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Signing;

public sealed record PdfAccessReceipt(VerifiedSigner Identity,Guid Id,DateTimeOffset ExpiresAt);
public sealed class SignerReceiptProtection(IDataProtectionProvider provider,TimeProvider time)
{
    private readonly IDataProtector protector = provider.CreateProtector("QuillSign.SignerPdfAccess.v1");
    public string Create(VerifiedSigner identity) => protector.Protect(JsonSerializer.Serialize(new PdfAccessReceipt(identity,Guid.NewGuid(),
        new[] { time.GetUtcNow().AddMinutes(10),identity.SessionExpiresAt }.Min())));
    public string Create(SignerReadContext context)=>protector.Protect(JsonSerializer.Serialize(new PdfAccessReceipt(context.Identity,Guid.NewGuid(),
        new[]{time.GetUtcNow().AddMinutes(10),context.AccessExpiresAt}.Min())));
    public PdfAccessReceipt? Read(string? value,VerifiedSigner identity)
    {
        if (value is null || value.Length > 8192) return null;
        try
        {
            var receipt = JsonSerializer.Deserialize<PdfAccessReceipt>(protector.Unprotect(value));
            return receipt is not null && receipt.Identity == identity && receipt.Id != Guid.Empty && receipt.ExpiresAt > time.GetUtcNow() &&
                receipt.ExpiresAt <= identity.SessionExpiresAt ? receipt : null;
        }
        catch (Exception e) when (e is CryptographicException or JsonException or ArgumentException) { return null; }
    }
}

// Stage the entire bounded object before exposing any bytes or issuing access evidence.
// Validation output is discarded: the response is the exact hash-pinned sent document.
public sealed class SignerPdfAccess(IBlobStore blobs,DocumentOptions options)
{
    private static readonly SemaphoreSlim ParseGate = new(1,1);
    public async Task<byte[]> PrepareAsync(ClaimsPrincipal principal,SignerReadContext context,CancellationToken ct = default)
    {
        using var memory = new MemoryStream();
        using var bounded = new BoundedDocumentStream(memory,64 * 1024 * 1024);
        var length = await blobs.CopyToAsync(principal,context.Document,bounded,ct);
        if (length != memory.Length || length < 16 || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(memory.GetBuffer().AsSpan(0,checked((int)memory.Length))),context.DocumentSha256))
            throw new DocumentRejectedException("The saved document could not be verified. Contact the sender.");
        await ParseGate.WaitAsync(ct);
        try
        {
            memory.Position = 0;
            using var discard = new MemoryStream(); using var output = new BoundedDocumentStream(discard,64 * 1024 * 1024);
            new PdfValidation(new() { MaximumBytes = 64 * 1024 * 1024,MaximumPages = Math.Clamp(options.MaximumPages,1,200) }).Rewrite(memory,output);
        }
        finally { ParseGate.Release(); }
        return memory.ToArray();
    }
}

public enum ConsentResult { Accepted, AlreadyAccepted, InvalidContext, InvalidEvidence }
public sealed class SignerConsent(QuillSignDbContext db,SignerAccess access,SignerReceiptProtection receipts,AuditWriter audit,
    DeclineNotificationWriter notifications,TimeProvider time)
{
    public async Task<ConsentResult> AcceptAsync(ClaimsPrincipal principal,string publicId,string? receipt,bool agreement,bool canRetain,
        string? method,string? ip,string? ua,CancellationToken ct = default)
    {
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var context = await access.GetLockedContextAsync(principal,publicId,ct); if (context is null) return ConsentResult.InvalidContext;
        if (context.ConsentAt is not null) return ConsentResult.AlreadyAccepted;
        var evidence = receipts.Read(receipt,context.Identity);
        if (evidence is null || !agreement || !canRetain || method is not ("preview" or "download")) return ConsentResult.InvalidEvidence;
        var now = time.GetUtcNow();
        await db.Signers.Where(x => x.Id == context.Identity.SignerId).ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsentAt,now)
            .SetProperty(x => x.ConsentIp,ip).SetProperty(x => x.ConsentUa,Limit(ua,2048)).SetProperty(x => x.Status,SignerStatus.Viewed),ct);
        await audit.AppendAsync(context.Identity.EnvelopeId,"consent_given",context.Identity.Email,ip,ua,ct,
            JsonSerializer.Serialize(new { disclosureVersion = context.Disclosure.Version,disclosureSha256 = context.Identity.DisclosureHash,
                documentSha256 = context.Identity.DocumentHash,accessReceiptId = evidence.Id,accessMethod = method,agreement,canRetain,
                serverEvidence = "hash_verified_pdf_prepared",clientEvidence = "signer_reported_access_and_retention" }),PartyType.Signer,context.Identity.SignerId);
        if(!access.IsLive(context))return ConsentResult.InvalidContext;
        await access.CommitAsync(transaction,ct); return ConsentResult.Accepted;
    }
    public async Task<SignerReadContext?> DeclineAsync(ClaimsPrincipal principal,string publicId,string? reason,string? ip,string? ua,CancellationToken ct = default)
    {
        reason = reason?.Trim();
        if (reason is { Length: > 512 } || reason?.Any(c => char.IsControl(c) && c is not ('\n' or '\r' or '\t')) == true)
            throw new ArgumentException("Use a decline reason of up to 512 characters.");
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct),ct);
        Guid notification; SignerReadContext? context;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            context = await access.GetLockedContextAsync(principal,publicId,ct);
            // Current scope already rejects any accepted Finish under this parent lock.
            // Electronic-record consent does not remove the signer's choice to refuse signing.
            if (context is null) return null;
            await db.Signers.Where(x => x.Id == context.Identity.SignerId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status,SignerStatus.Declined)
                .SetProperty(x => x.DeclineReason,reason),ct);
            await db.Envelopes.Where(x => x.Id == context.Identity.EnvelopeId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status,EnvelopeStatus.Declined),ct);
            notification = await notifications.PrepareAsync(context,reason,ct);
            await audit.AppendAsync(context.Identity.EnvelopeId,"declined",context.Identity.Email,ip,ua,ct,
                JsonSerializer.Serialize(new { reason,notificationId = notification,documentSha256 = context.Identity.DocumentHash,
                    disclosureSha256 = context.Identity.DisclosureHash }),PartyType.Signer,context.Identity.SignerId);
            if(!access.IsLive(context))return null;
            await access.CommitAsync(transaction,ct);
        }
        await notifications.PublishAsync(notification,ct); return context;
    }
    private static string? Limit(string? value,int length) => value is { Length: > 2048 } ? value[..length] : value;
}
