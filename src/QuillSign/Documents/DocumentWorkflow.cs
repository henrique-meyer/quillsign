using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Documents;

public sealed class DocumentWorkflow(QuillSignDbContext db, IBlobStore storage, PdfValidation pdf, DocumentOptions options,
    AuditWriter audit, TimeProvider time, ILogger<DocumentWorkflow> logger,DemoRetentionOptions? retentionOptions=null)
{
    public static FileStream TemporaryFile() => new(Path.Combine(Path.GetTempPath(), "quillsign-" + Guid.NewGuid().ToString("N")),
        FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.DeleteOnClose);

    private async Task<Envelope?> DraftAsync(ClaimsPrincipal sender, string publicId, bool locked, CancellationToken ct)
    {
        var claims = sender.Identities.Where(x => x.IsAuthenticated && x.AuthenticationType == EnvelopeStorageAuthorization.SenderScheme)
            .SelectMany(x => x.FindAll(EnvelopeStorageAuthorization.EnvelopeClaim)).ToArray();
        if (claims.Length != 1 || !Guid.TryParse(claims[0].Value, out var id)) return null;
        var email = sender.FindFirstValue(ClaimTypes.Email);
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        var query = locked ? db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {id}") : db.Envelopes.AsNoTracking();
        return await query.SingleOrDefaultAsync(x => x.Id == id && x.PublicId == publicId && x.SenderEmail == email &&
            x.SenderVerifiedAt != null && x.Status == EnvelopeStatus.Draft, ct);
    }

    public Task<Envelope?> GetAsync(ClaimsPrincipal sender, string publicId, CancellationToken ct) => DraftAsync(sender, publicId, false, ct);

    private static void Version(Envelope envelope, byte[] expected)
    { if (expected.Length != 8 || !envelope.RowVersion.AsSpan().SequenceEqual(expected)) throw new DocumentConflictException(); }

    public async Task<bool> UploadAsync(ClaimsPrincipal sender, string publicId, byte[] expectedVersion, string filename, Stream source,
        long declaredLength, string? ip, string? userAgent, CancellationToken ct)
    {
        var before = await DraftAsync(sender, publicId, false, ct);
        if (before is null) return false;
        Version(before, expectedVersion);
        var safeName = Filename(filename);
        if (declaredLength <= 0 || declaredLength > options.MaximumBytes) throw new DocumentRejectedException("Choose a PDF within the upload size limit.");
        await using var original = TemporaryFile();
        await source.CopyToAsync(new BoundedDocumentStream(original, options.MaximumBytes), 65536, ct);
        if (original.Length != declaredLength) throw new DocumentRejectedException("The uploaded PDF size did not match. Try uploading it again.");
        original.Position = 0;
        var originalHash = await SHA256.HashDataAsync(original, ct);
        original.Position = 0;
        await using var normalized = TemporaryFile();
        var pages = pdf.Rewrite(original, new BoundedDocumentStream(normalized, options.MaximumBytes));
        normalized.Position = 0;
        var normalizedHash = await SHA256.HashDataAsync(normalized, ct);
        original.Position = normalized.Position = 0;
        return await PublishUploadAsync(sender,publicId,expectedVersion,before,new(safeName,"application/pdf",original,originalHash,
            normalized,normalizedHash,pages,null),ip,userAgent,ct);
    }

    // Conversion runs outside a SQL transaction/connection. Recheck this after
    // the slow external step, before writing any operation-owned objects.
    internal async Task<Envelope?> CheckConvertedUploadAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null)throw new InvalidOperationException("Document conversion requires a standalone workflow.");
        try
        {
            var before=await DraftAsync(sender,publicId,false,ct);if(before is null)return null;Version(before,expectedVersion);
            var retention=await new UploadRetention(db,retentionOptions ?? new(),time).ReadAsync(before,ct);UploadRetention.CheckDeadline(retention,time.GetUtcNow());return before;
        }
        finally {await db.Database.CloseConnectionAsync();}
    }

    internal async Task<bool> StoreConvertedAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,string title,
        ValidatedDocx source,DocxConversion converted,string? ip,string? userAgent,CancellationToken ct)
    {
        var before=await CheckConvertedUploadAsync(sender,publicId,expectedVersion,ct);if(before is null)return false;
        using var original=source.OpenRead();using var normalized=new MemoryStream(converted.Pdf,false);
        var provenance=new {version="docx-gotenberg-v1",originalFilename=title[..^4]+".docx",
            originalMime=DocxDocumentWorkflow.Mime,originalBytes=source.Length,pdfBytes=converted.Pdf.LongLength};
        return await PublishUploadAsync(sender,publicId,expectedVersion,before,new(title,DocxDocumentWorkflow.Mime,original,source.OriginalSha256,
            normalized,converted.PdfSha256.ToArray(),converted.Pages,provenance),ip,userAgent,ct);
    }

    internal async Task<bool> StoreConvertedImageAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,string title,string extension,
        ImagePdfConversion converted,string? ip,string? userAgent,CancellationToken ct)
    {
        var before=await CheckConvertedUploadAsync(sender,publicId,expectedVersion,ct);if(before is null)return false;
        using var original=converted.OpenOriginal();using var normalized=converted.OpenPdf();
        var provenance=new {version="image-stb-v1",originalFilename=title[..^4]+extension,originalMime=converted.SourceMime,
            originalBytes=converted.OriginalLength,pdfBytes=converted.PdfLength,width=converted.Width,height=converted.Height};
        return await PublishUploadAsync(sender,publicId,expectedVersion,before,new(title,converted.SourceMime,original,converted.OriginalSha256,
            normalized,converted.PdfSha256,converted.Pages,provenance),ip,userAgent,ct);
    }

    private sealed record PreparedUpload(string Filename,string Mime,Stream Original,byte[] OriginalHash,Stream Pdf,byte[] PdfHash,
        IReadOnlyList<PageGeometry> Pages,object? Provenance);

    private async Task<bool> PublishUploadAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,Envelope before,PreparedUpload upload,
        string? ip,string? userAgent,CancellationToken ct)
    {
        var (safeName,originalMime,original,originalHash,normalized,normalizedHash,pages,provenance)=upload;
        var originalBlob = new DocumentBlob(before.Id, DocumentBlobKind.Original, Guid.NewGuid());
        var normalizedBlob = new DocumentBlob(before.Id, DocumentBlobKind.Normalized, Guid.NewGuid());
        var commitStarted = false;
        try
        {
            await storage.WriteAsync(sender, originalBlob, original, original.Length, ct);
            await storage.WriteAsync(sender, normalizedBlob, normalized, normalized.Length, ct);
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            var envelope = await DraftAsync(sender, publicId, true, ct);
            if (envelope is null) throw new DocumentConflictException();
            Version(envelope, expectedVersion);
            var retention=await new UploadRetention(db,retentionOptions ?? new(),time).PrepareLockedAsync(envelope,originalBlob.ObjectId,originalHash,normalizedBlob.ObjectId,normalizedHash,ct);
            var previous = envelope.PdfBlob;
            envelope.Title = safeName;
            envelope.OriginalBlob = originalBlob.ObjectId.ToString("N"); envelope.OriginalSha256 = originalHash; envelope.OriginalMime = originalMime;
            envelope.PdfBlob = normalizedBlob.ObjectId.ToString("N"); envelope.PdfSha256 = normalizedHash;
            envelope.PageCount = pages.Count; envelope.PageSizesJson = JsonSerializer.Serialize(pages);
            envelope.PreviewConfirmedAt = null; envelope.AiRolesJson = null; envelope.AiModel = null;
            await db.Fields.Where(x => x.EnvelopeId == envelope.Id).ExecuteDeleteAsync(ct);
            var data = provenance is null ? JsonSerializer.Serialize(new { filename = safeName, originalSha256 = Convert.ToHexStringLower(originalHash),
                pdfSha256 = Convert.ToHexStringLower(normalizedHash), pageCount = pages.Count, previousDocument = previous,
                retentionSha256=retention is null ? null : UploadRetention.Digest(retention) }) :
                JsonSerializer.Serialize(new {filename=safeName,originalSha256=Convert.ToHexStringLower(originalHash),pdfSha256=Convert.ToHexStringLower(normalizedHash),
                    pageCount=pages.Count,previousDocument=previous,retentionSha256=retention is null ? null : UploadRetention.Digest(retention),conversion=provenance});
            await audit.AppendAsync(envelope.Id, previous is null ? "document_uploaded" : "document_replaced", envelope.SenderEmail, ip, userAgent, ct, data);
            await db.SaveChangesAsync(ct);
            UploadRetention.CheckDeadline(retention,time.GetUtcNow());
            commitStarted = true;
            await transaction.CommitAsync(ct);
        }
        catch
        {
            // An uncertain commit may already reference these objects. Never delete them then.
            if (!commitStarted) { await CleanupAsync(sender, originalBlob); await CleanupAsync(sender, normalizedBlob); }
            throw;
        }
        await CleanupReferenceAsync(sender, before.Id, DocumentBlobKind.Original, before.OriginalBlob);
        await CleanupReferenceAsync(sender, before.Id, DocumentBlobKind.Normalized, before.PdfBlob);
        return true;
    }

    public async Task<bool> ConfirmAsync(ClaimsPrincipal sender, string publicId, byte[] expectedVersion, string documentId,
        bool matches, string? ip, string? userAgent, CancellationToken ct)
    {
        if (!matches) throw new DocumentRejectedException("Confirm that the preview matches your document.");
        var before = await DraftAsync(sender, publicId, false, ct);
        if (before is null) return false;
        Version(before, expectedVersion);
        await using var checkedFile = await ReadVerifiedAsync(sender, before, documentId, ct);
        if (checkedFile is null) throw new DocumentConflictException();
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var envelope = await DraftAsync(sender, publicId, true, ct);
        if (envelope is null) return false;
        Version(envelope, expectedVersion);
        if (envelope.PdfBlob is null || envelope.PdfBlob != documentId || envelope.PdfSha256 is null || envelope.PageCount is null)
            throw new DocumentConflictException();
        if (envelope.PreviewConfirmedAt is not null) return true;
        envelope.PreviewConfirmedAt = time.GetUtcNow();
        await audit.AppendAsync(envelope.Id, "preview_confirmed", envelope.SenderEmail, ip, userAgent, ct,
            JsonSerializer.Serialize(new { document = documentId, pdfSha256 = Convert.ToHexStringLower(envelope.PdfSha256) }));
        await transaction.CommitAsync(ct);
        return true;
    }

    public async Task<FileStream?> ReadAsync(ClaimsPrincipal sender, string publicId, string documentId, CancellationToken ct)
    {
        var envelope = await DraftAsync(sender, publicId, false, ct);
        return envelope is null ? null : await ReadVerifiedAsync(sender, envelope, documentId, ct);
    }

    private async Task<FileStream?> ReadVerifiedAsync(ClaimsPrincipal sender, Envelope envelope, string documentId, CancellationToken ct)
    {
        if (envelope.PdfBlob != documentId || !Guid.TryParseExact(documentId, "N", out var id)) return null;
        var file = TemporaryFile();
        try
        {
            await storage.CopyToAsync(sender, new(envelope.Id, DocumentBlobKind.Normalized, id), new BoundedDocumentStream(file, options.MaximumBytes), ct);
            file.Position = 0;
            if (envelope.PdfSha256 is null || !(await SHA256.HashDataAsync(file, ct)).AsSpan().SequenceEqual(envelope.PdfSha256))
                throw new InvalidDataException("Stored document verification failed.");
            file.Position = 0; return file;
        }
        catch { await file.DisposeAsync(); throw; }
    }

    private async Task CleanupReferenceAsync(ClaimsPrincipal sender, Guid envelopeId, DocumentBlobKind kind, string? reference)
    { if (Guid.TryParseExact(reference, "N", out var id)) await CleanupAsync(sender, new(envelopeId, kind, id)); }
    private async Task CleanupAsync(ClaimsPrincipal sender, DocumentBlob blob)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try { await storage.DeleteAsync(sender, blob, timeout.Token); }
        catch (Exception error) when (error is Azure.RequestFailedException or IOException or OperationCanceledException)
        { logger.LogWarning("Deferred cleanup of a replaced or unreferenced document ({FailureType}).", error.GetType().Name); }
    }
    public static string Filename(string filename)
    {
        var name = filename.Replace('\\', '/').Split('/')[^1];
        if (!name.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase)) throw new DocumentRejectedException("Only PDF files are supported.");
        name = new string(name[..^4].Where(c => !char.IsControl(c) && !"<>:\"/\\|?*".Contains(c)).ToArray()).Trim(' ', '.');
        if (name.Length > 120) name = name[..120];
        return (name.Length == 0 ? "document" : name) + ".pdf";
    }
}
