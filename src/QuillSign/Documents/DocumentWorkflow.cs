using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Work;
using QuillSign.Lifecycle;

namespace QuillSign.Documents;

public sealed class DocumentWorkflow(QuillSignDbContext db, IBlobStore storage, PdfValidation pdf, DocumentOptions options,
    AuditWriter audit, TimeProvider time, ILogger<DocumentWorkflow> logger,DemoRetentionOptions? retentionOptions=null,DemoPurgeJobs? purgeJobs=null,QuillSign.Email.Pilot.EmailPilotReadBounds? pilotBounds=null)
{
    internal ProductionSenderPreparationAdmission? HoldAdmission { get; init; }
    internal ProductionRecordUploadAdmission? HoldUploads { get; init; }
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

    public async Task<Envelope?> GetAsync(ClaimsPrincipal sender, string publicId, CancellationToken ct)
    {
        var envelope=await DraftAsync(sender,publicId,false,ct);
        if(envelope is not null)DocumentRetentionAccess.Check(await DocumentRetentionAccess.ReadAsync(db,envelope,time,ct,pilotBounds),time);
        return envelope;
    }

    private static void Version(Envelope envelope, byte[] expected)
    { if (expected.Length != 8 || !envelope.RowVersion.AsSpan().SequenceEqual(expected)) throw new DocumentConflictException(); }

    public async Task<bool> UploadAsync(ClaimsPrincipal sender, string publicId, byte[] expectedVersion, string filename, Stream source,
        long declaredLength, string? ip, string? userAgent, CancellationToken ct)
    {
        var before = await DraftAsync(sender, publicId, false, ct);
        if (before is null) return false;
        Version(before, expectedVersion);
        DocumentRetentionAccess.Check(await DocumentRetentionAccess.ReadAsync(db,before,time,ct,pilotBounds),time);
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
            DocumentRetentionAccess.Check(await DocumentRetentionAccess.ReadAsync(db,before,time,ct,pilotBounds),time);
            var retention=await new UploadRetention(db,retentionOptions ?? new(),time).ReadAsync(before,ct);UploadRetention.CheckDeadline(retention,time.GetUtcNow());return before;
        }
        // Converted-upload callers have always received a rejection for an
        // expired saved retention policy. Keep that ordinary contract while
        // restricted-run expiry retains its separate access-denial exception.
        catch(DocumentRetentionExpiredException) {throw new DocumentRejectedException("This demo document has reached its retention deadline.");}
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

    internal async Task<bool> StoreConvertedTextAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,string title,
        Stream original,TextConversion converted,string? ip,string? userAgent,CancellationToken ct)
    {
        var before=await CheckConvertedUploadAsync(sender,publicId,expectedVersion,ct);if(before is null)return false;
        original.Position=0;using var normalized=new MemoryStream(converted.Pdf,false);
        var provenance=new {version="text-docx-gotenberg-v1",originalFilename=title[..^4]+".txt",
            originalMime=TextDocumentWorkflow.Mime,originalBytes=original.Length,pdfBytes=converted.Pdf.LongLength};
        return await PublishUploadAsync(sender,publicId,expectedVersion,before,new(title,TextDocumentWorkflow.Mime,original,converted.OriginalSha256.ToArray(),
            normalized,converted.PdfSha256.ToArray(),converted.Pages,provenance),ip,userAgent,ct);
    }

    internal async Task<bool> StoreConvertedOfficeAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,string title,
        ValidatedOfficeSource source,DocxConversion converted,string? ip,string? userAgent,CancellationToken ct)
    {
        var before=await CheckConvertedUploadAsync(sender,publicId,expectedVersion,ct);if(before is null)return false;
        using var original=source.OpenRead();using var normalized=new MemoryStream(converted.Pdf,false);var family=OfficeDocumentWorkflow.Family(source.Kind);var inputHash=source.ConversionSha256;
        try
        {
            var provenance=new {version=family.Pipeline,originalFilename=title[..^4]+family.Extension,originalMime=family.Mime,
                originalBytes=source.Length,pdfBytes=converted.Pdf.LongLength,conversionInputBytes=source.ConversionLength,conversionInputSha256=Convert.ToHexStringLower(inputHash)};
            return await PublishUploadAsync(sender,publicId,expectedVersion,before,new(title,family.Mime,original,source.OriginalSha256,
                normalized,converted.PdfSha256.ToArray(),converted.Pages,provenance),ip,userAgent,ct);
        }
        finally {Array.Clear(inputHash);}
    }

    private sealed record PreparedUpload(string Filename,string Mime,Stream Original,byte[] OriginalHash,Stream Pdf,byte[] PdfHash,
        IReadOnlyList<PageGeometry> Pages,object? Provenance);

    private async Task<bool> PublishUploadAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,Envelope before,PreparedUpload upload,
        string? ip,string? userAgent,CancellationToken ct)
    {
        if (HoldUploads is null) return await PublishUploadCoreAsync(sender,publicId,expectedVersion,before,upload,ip,userAgent,null,ct);
        return await HoldUploads.ExecuteAsync(db,before.Id,before.SenderEmail,publicId,
            operation => PublishUploadCoreAsync(sender,publicId,expectedVersion,before,upload,ip,userAgent,operation,ct),ct);
    }

    private async Task<bool> PublishUploadCoreAsync(ClaimsPrincipal sender,string publicId,byte[] expectedVersion,Envelope before,PreparedUpload upload,
        string? ip,string? userAgent,ProductionRecordOperation? operation,CancellationToken ct)
    {
        var (safeName,originalMime,original,originalHash,normalized,normalizedHash,pages,provenance)=upload;
        var originalBlob = new DocumentBlob(before.Id, DocumentBlobKind.Original, Guid.NewGuid());
        var normalizedBlob = new DocumentBlob(before.Id, DocumentBlobKind.Normalized, Guid.NewGuid());
        var commitStarted = false;
        Guid? purgeId=null;DateTimeOffset? purgeDue=null;
        try
        {
            if (operation is not null)
            {
                // Local preprocessing/conversion precedes reservation. A saved
                // layout/detail change in that interval is a known no-effect
                // stale request, not authority to write an unpublished pair.
                await using var starting = await db.Database.BeginTransactionAsync(ct);
                var current = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={before.Id}")
                    .AsNoTracking().SingleOrDefaultAsync(ct);
                await HoldUploads!.DemandStartingLockedAsync(db,operation,ct);
                if (current is null || current.PublicId != publicId || current.SenderEmail != before.SenderEmail ||
                    current.SenderVerifiedAt is null || current.Status != EnvelopeStatus.Draft ||
                    expectedVersion.Length != 8 || !current.RowVersion.AsSpan().SequenceEqual(expectedVersion)) return false;
                DocumentRetentionAccess.Check(await DocumentRetentionAccess.ReadAsync(db,current,time,ct,pilotBounds),time);
                await starting.RollbackAsync(ct);
            }
            if (operation is null)
            {
                await storage.WriteAsync(sender, originalBlob, original, original.Length, ct);
                await storage.WriteAsync(sender, normalizedBlob, normalized, normalized.Length, ct);
            }
            else
            {
                var originalItem = new ProductionRecordWriteDescriptor(originalBlob,original.Length,Convert.ToHexStringLower(originalHash));
                var normalizedItem = new ProductionRecordWriteDescriptor(normalizedBlob,normalized.Length,Convert.ToHexStringLower(normalizedHash));
                await HoldUploads!.PrepareAsync(operation,originalItem,normalizedItem,ct);
                await HoldUploads.WriteAsync(operation,sender,originalItem,original,ct);
                await HoldUploads.WriteAsync(operation,sender,normalizedItem,normalized,ct);
            }
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            var envelope = await DraftAsync(sender, publicId, true, ct);
            if (operation is not null) await HoldUploads!.DemandStartingLockedAsync(db,operation,ct);
            if (envelope is null) throw new DocumentConflictException();
            Version(envelope, expectedVersion);
            DocumentRetentionAccess.Check(await DocumentRetentionAccess.ReadAsync(db,envelope,time,ct,pilotBounds),time);
            var retention=await new UploadRetention(db,retentionOptions ?? new(),time).PrepareLockedAsync(envelope,originalBlob.ObjectId,originalHash,normalizedBlob.ObjectId,normalizedHash,ct);
            var newlyEnrolled=retention is not null && db.Entry(retention).State==EntityState.Added;
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
            if(retention is not null) {
                if(purgeJobs is null)throw new DocumentRejectedException("This demo's document retention service is not ready.");
                purgeId=await purgeJobs.PrepareLockedAsync(envelope.Id,newlyEnrolled,ct);purgeDue=retention.DeleteAfter;
            }
            UploadRetention.CheckDeadline(retention,time.GetUtcNow());
            if (operation is not null)
            {
                await HoldUploads!.PrepareOutcomeLockedAsync(db,operation,ct);
                DocumentRetentionAccess.Check(await DocumentRetentionAccess.ReadAsync(db,envelope,time,ct,pilotBounds),time);
            }
            commitStarted = true;
            await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,ct);
        }
        catch
        {
            // An uncertain commit may already reference these objects. Never delete them then.
            if (!commitStarted && operation is null) { await CleanupAsync(sender, originalBlob); await CleanupAsync(sender, normalizedBlob); }
            throw;
        }
        if(purgeId is Guid scheduled)await purgeJobs!.PublishAsync(scheduled,purgeDue!.Value,ct);
        // Production history and unpublished attempted versions remain owned
        // evidence until exact hold-aware deletion reconciles them. Default/demo
        // cleanup is unchanged; a failed operation never guesses that no write occurred.
        if (operation is null)
        {
            await CleanupReferenceAsync(sender, before.Id, DocumentBlobKind.Original, before.OriginalBlob);
            await CleanupReferenceAsync(sender, before.Id, DocumentBlobKind.Normalized, before.PdfBlob);
        }
        return true;
    }

    public async Task<bool> ConfirmAsync(ClaimsPrincipal sender, string publicId, byte[] expectedVersion, string documentId,
        bool matches, string? ip, string? userAgent, CancellationToken ct)
    {
        if (!matches) throw new DocumentRejectedException("Confirm that the preview matches your document.");
        if (HoldAdmission is null) return await ConfirmCoreAsync(sender, publicId, expectedVersion, documentId, ip, userAgent, null, ct);
        var before = await DraftAsync(sender, publicId, false, ct);
        if (before is null) return false;
        Version(before, expectedVersion);
        if (before.PdfBlob != documentId || !Guid.TryParseExact(documentId, "N", out _)) throw new DocumentConflictException();
        return await HoldAdmission.ExecuteAsync(db, before.Id, before.SenderEmail, publicId, "sender/preview-confirm",
            operation => ConfirmCoreAsync(sender, publicId, expectedVersion, documentId, ip, userAgent, operation, ct), false, false, ct);
    }

    private async Task<bool> ConfirmCoreAsync(ClaimsPrincipal sender, string publicId, byte[] expectedVersion, string documentId,
        string? ip, string? userAgent, ProductionRecordOperation? operation, CancellationToken ct)
    {
        var before = await DraftAsync(sender, publicId, false, ct);
        if (before is null && operation is not null) throw new DocumentConflictException();
        if (before is null) return false;
        Version(before, expectedVersion);
        await using var checkedFile = await ReadVerifiedAsync(sender, before, documentId, ct);
        if (checkedFile is null) throw new DocumentConflictException();
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var envelope = await DraftAsync(sender, publicId, true, ct);
        if (operation is not null) await HoldAdmission!.DemandStartingLockedAsync(db, operation, ct);
        if (envelope is null) return false;
        Version(envelope, expectedVersion);
        var retentionDeadline=await DocumentRetentionAccess.ReadAsync(db,envelope,time,ct,pilotBounds);
        DocumentRetentionAccess.Check(retentionDeadline,time);
        if (envelope.PdfBlob is null || envelope.PdfBlob != documentId || envelope.PdfSha256 is null || envelope.PageCount is null)
            throw new DocumentConflictException();
        if (envelope.PreviewConfirmedAt is not null) return true;
        envelope.PreviewConfirmedAt = time.GetUtcNow();
        await audit.AppendAsync(envelope.Id, "preview_confirmed", envelope.SenderEmail, ip, userAgent, ct,
            JsonSerializer.Serialize(new { document = documentId, pdfSha256 = Convert.ToHexStringLower(envelope.PdfSha256) }));
        DocumentRetentionAccess.Check(retentionDeadline,time);
        if (operation is not null)
        {
            await HoldAdmission!.PrepareOutcomeLockedAsync(db, operation, ct);
            DocumentRetentionAccess.Check(retentionDeadline,time);
        }
        await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,ct);
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
        var deadline=await DocumentRetentionAccess.ReadAsync(db,envelope,time,ct,pilotBounds);
        DocumentRetentionAccess.Check(deadline,time);
        var file = TemporaryFile();
        try
        {
            await storage.CopyToAsync(sender, new(envelope.Id, DocumentBlobKind.Normalized, id), new BoundedDocumentStream(file, options.MaximumBytes), ct);
            file.Position = 0;
            if (envelope.PdfSha256 is null || !(await SHA256.HashDataAsync(file, ct)).AsSpan().SequenceEqual(envelope.PdfSha256))
                throw new InvalidDataException("Stored document verification failed.");
            ct.ThrowIfCancellationRequested();
            DocumentRetentionAccess.Check(deadline,time);
            if(pilotBounds is not null)await pilotBounds.ReadAsync(envelope,ct);
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
