using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Documents;

internal sealed record RetentionSigningLimit(DocumentRetentionSnapshot? Policy,DateTimeOffset? Requested,DateTimeOffset? Effective)
{
    public string? Digest=>Policy is null ? null : UploadRetention.Digest(Policy);
}

internal static class RetentionSigningDeadline
{
    internal const string Version="retention-signing-v1";
    internal static async Task<RetentionSigningLimit> ReadAsync(QuillSignDbContext db,Envelope envelope,CancellationToken ct)
    {
        var row=await new UploadRetention(db,new(),TimeProvider.System).ReadAsync(envelope,ct);
        if(row is null)
        {
            // An enrolled upload must not become an ordinary request if its policy
            // row is missing. Old uploads without a policy marker remain ordinary.
            var uploads=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id && x.Event=="document_uploaded").Select(x=>x.DataJson).Take(2).ToArrayAsync(ct);
            if(uploads.Length>1)throw Invalid();
            if(uploads.Length==1)
            {
                try {using var data=JsonDocument.Parse(uploads[0],new JsonDocumentOptions{MaxDepth=8});if(data.RootElement.TryGetProperty("retentionSha256",out var hash) && hash.ValueKind!=JsonValueKind.Null)throw Invalid();}
                catch(JsonException) {throw Invalid();}
            }
            return new(null,envelope.ExpiresAt,envelope.ExpiresAt);
        }
        var requested=envelope.ExpiresAt?.ToUniversalTime();return new(row,requested,Earlier(requested,row.DeleteAfter));
    }
    private static DateTimeOffset Earlier(DateTimeOffset? requested,DateTimeOffset cutoff)=>requested is { } at && at<cutoff ? at : cutoff;
    internal static void DemandReview(RetentionSigningLimit limit,string? reviewedDigest)
    {if(limit.Digest!=reviewedDigest && !(limit.Digest is null && string.IsNullOrEmpty(reviewedDigest)))throw new DocumentConflictException();}
    internal static void CheckDeadline(RetentionSigningLimit limit,DateTimeOffset now)
    {if(limit.Policy is not null && limit.Effective<=now)throw new DocumentRejectedException("This demo document has reached its signing or retention deadline.");}
    internal static object Evidence(RetentionSigningLimit limit)=>new {version=Version,uploadRetentionSha256=limit.Digest,
        requestedDeadline=limit.Requested,effectiveDeadline=limit.Effective,deleteAfter=limit.Policy!.DeleteAfter};

    internal static async Task VerifyEvidenceAsync(QuillSignDbContext db,Envelope envelope,JsonElement sent,CancellationToken ct)
    {
        if(!sent.TryGetProperty("retentionSigning",out var value))return; // Historical sent evidence is never rewritten.
        try
        {
            var row=await new UploadRetention(db,new(),TimeProvider.System).ReadAsync(envelope,ct);if(row is null)throw Invalid();
            var requested=value.GetProperty("requestedDeadline").ValueKind==JsonValueKind.Null ? (DateTimeOffset?)null : value.GetProperty("requestedDeadline").GetDateTimeOffset();
            var effective=value.GetProperty("effectiveDeadline").GetDateTimeOffset();var cutoff=value.GetProperty("deleteAfter").GetDateTimeOffset();
            if(value.GetProperty("version").GetString()!=Version || value.GetProperty("uploadRetentionSha256").GetString()!=UploadRetention.Digest(row) ||
                requested is {Offset:var offset} && offset!=TimeSpan.Zero || effective.Offset!=TimeSpan.Zero || cutoff.Offset!=TimeSpan.Zero ||
                cutoff!=row.DeleteAfter || effective!=Earlier(requested,row.DeleteAfter) || envelope.ExpiresAt!=effective ||
                envelope.SentAt is null || envelope.SentAt<row.StartedAt || envelope.SentAt>=effective)throw Invalid();
        }
        catch(Exception e) when(e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException) {throw Invalid();}
    }
    private static InvalidDataException Invalid()=>new("The signing retention evidence could not be verified.");
}
