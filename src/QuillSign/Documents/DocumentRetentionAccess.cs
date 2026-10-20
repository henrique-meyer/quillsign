using System.Text.Json;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Documents;

public sealed class DocumentRetentionExpiredException() : Exception("This document has reached its retention deadline and is no longer available.");

// Call only after the caller's envelope authorization. This verifies a policy;
// it grants no blob capability and performs no enrollment or maintenance.
internal static class DocumentRetentionAccess
{
    internal static async Task<DateTimeOffset?> ReadAsync(QuillSignDbContext db,Envelope envelope,TimeProvider time,CancellationToken ct,Email.Pilot.EmailPilotReadBounds? pilotBounds=null)
    {
        await using var owned=db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var access=pilotBounds is null ? null : await pilotBounds.ReadAsync(envelope,ct);
        var production=await ProductionRecordRetentionAccess.ReadLockedAsync(db,envelope,time,ct);
        var row=await new UploadRetention(db,new(),time).ReadAsync(envelope,ct);
        if(production.Kind==ProductionEnrollmentKind.MissingRecord)throw Invalid();
        if(row is not null) {
            if(production.Kind==ProductionEnrollmentKind.Enrolled)throw Invalid();
            if(owned is not null)await owned.CommitAsync(ct);
            return Email.Pilot.EmailPilotReadBounds.Earlier(row.DeleteAfter,access);
        }
        // A removed enrolled policy must not silently become an ordinary read.
        var uploads=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Event=="document_uploaded").Take(2).ToArrayAsync(ct);
        if(uploads.Length>1)throw Invalid();
        if(uploads.Length==1)
        {
            try
            {
                var upload=uploads[0];
                if(upload.ActorType!=PartyType.Sender || upload.ActorEmail!=envelope.SenderEmail || upload.DataJson.Length>16384 ||
                    !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(upload),upload.Hash))throw Invalid();
                using var data=JsonDocument.Parse(upload.DataJson,new JsonDocumentOptions{MaxDepth=8});
                if(data.RootElement.TryGetProperty("retentionSha256",out var marker) && marker.ValueKind!=JsonValueKind.Null)throw Invalid();
            }
            catch(Exception e) when(e is JsonException or InvalidOperationException) {throw Invalid();}
        }
        if(owned is not null)await owned.CommitAsync(ct);
        return Email.Pilot.EmailPilotReadBounds.Earlier(production.Deadline,access);
    }
    internal static void Check(DateTimeOffset? deadline,TimeProvider time)
    {if(deadline<=time.GetUtcNow())throw new DocumentRetentionExpiredException();}
    private static InvalidDataException Invalid()=>new("The document retention evidence could not be verified.");
}
