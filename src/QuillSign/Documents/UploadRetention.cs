using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Documents;

public sealed class DemoRetentionOptions
{
    public int? PurgeAfterDays { get; set; }
    public void Validate()
    {
        if(PurgeAfterDays is <1 or >36500)
            throw new InvalidOperationException("Demo:PurgeAfterDays must be unset or between 1 and 36500.");
    }
}

// Captures a policy decision, not purge authority. Construction performs no I/O.
public sealed class UploadRetention(QuillSignDbContext db,DemoRetentionOptions options,TimeProvider time)
{
    public const string Version="demo-upload-retention-v1";
    public static string Digest(DocumentRetentionSnapshot row)=>Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
        row.EnvelopeId,row.PolicyVersion,row.Days,row.StartedAt,row.DeleteAfter,row.OriginalObjectId,row.OriginalSha256,row.PdfObjectId,row.PdfSha256 })));

    public async Task<DocumentRetentionSnapshot?> ReadAsync(Envelope envelope,CancellationToken ct=default)
    {
        var row=await db.DocumentRetentionSnapshots.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==envelope.Id,ct);
        if(row is null)return null;
        if(!envelope.IsDemo || row.PolicyVersion!=Version || row.Days is <1 or >36500 || row.StartedAt.Offset!=TimeSpan.Zero || row.DeleteAfter.Offset!=TimeSpan.Zero ||
            row.DeleteAfter!=row.StartedAt.AddDays(row.Days) || row.OriginalObjectId==Guid.Empty || row.PdfObjectId==Guid.Empty || row.OriginalObjectId==row.PdfObjectId ||
            row.OriginalSha256 is not {Length:32} || row.PdfSha256 is not {Length:32})throw Invalid();
        var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Event=="document_uploaded").Take(2).ToArrayAsync(ct);
        if(events.Length!=1 || events[0].ActorType!=PartyType.Sender || events[0].ActorEmail!=envelope.SenderEmail || events[0].At<row.StartedAt ||
            events[0].At>=row.DeleteAfter || events[0].DataJson.Length>16384 || !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(events[0]),events[0].Hash))throw Invalid();
        try
        {
            using var data=JsonDocument.Parse(events[0].DataJson,new JsonDocumentOptions {MaxDepth=8});var p=data.RootElement;
            if(p.GetProperty("retentionSha256").GetString()!=Digest(row) || p.GetProperty("originalSha256").GetString()!=Convert.ToHexStringLower(row.OriginalSha256) ||
                p.GetProperty("pdfSha256").GetString()!=Convert.ToHexStringLower(row.PdfSha256))throw Invalid();
        }
        catch(Exception e) when(e is JsonException or KeyNotFoundException or InvalidOperationException) {throw new InvalidDataException("The upload retention evidence could not be verified.",e);}
        return row;
    }

    // The caller holds the common envelope lock and commits the first upload/audit atomically.
    internal async Task<DocumentRetentionSnapshot?> PrepareLockedAsync(Envelope envelope,Guid original,byte[] originalHash,Guid pdf,byte[] pdfHash,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Upload retention requires the upload transaction.");
        var existing=await ReadAsync(envelope,ct);
        if(existing is not null) {CheckDeadline(existing,time.GetUtcNow());return existing;}
        options.Validate();
        if(!envelope.IsDemo || options.PurgeAfterDays is not int days)return null;
        if(envelope.PdfBlob is not null || envelope.OriginalBlob is not null || await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==envelope.Id && x.Event=="document_uploaded",ct))
            throw new DocumentRejectedException("This existing demo document needs an explicit retention migration before replacement.");
        var at=time.GetUtcNow().ToUniversalTime();
        var row=new DocumentRetentionSnapshot {EnvelopeId=envelope.Id,PolicyVersion=Version,Days=days,StartedAt=at,DeleteAfter=at.AddDays(days),
            OriginalObjectId=original,OriginalSha256=originalHash.ToArray(),PdfObjectId=pdf,PdfSha256=pdfHash.ToArray()};
        db.DocumentRetentionSnapshots.Add(row);return row;
    }

    internal static void CheckDeadline(DocumentRetentionSnapshot? row,DateTimeOffset now)
    {
        if(row is not null && now>=row.DeleteAfter)throw new DocumentRejectedException("This demo document has reached its retention deadline.");
    }
    private static InvalidDataException Invalid()=>new("The upload retention evidence could not be verified.");
}
