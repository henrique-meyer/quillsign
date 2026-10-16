using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Completion;

internal sealed record DownloadPublication(Guid EnvelopeId,string PublicId,string Title,Guid Id,byte[] Recipe,byte[] Revision,
    DateTimeOffset CompletedAt,DateTimeOffset? PurgeAfter,FinalStoredDocument Executed,FinalStoredDocument Certificate,
    PublishedCompletionSource Source,byte[] FrozenState,long AuditSequence,byte[] AuditAnchor)
{
    internal bool Matches(PublishedCompletion value)=>value.EnvelopeId==EnvelopeId && value.PublicationId==Id &&
        CompletionEvidenceValidation.Same(value.PublicationRecipeSha256,Recipe) && value.PublicationRowVersion.AsSpan().SequenceEqual(Revision) &&
        CompletionEvidenceValidation.Same(Reference(value.Executed),Reference(Executed)) && CompletionEvidenceValidation.Same(Reference(value.Certificate),Reference(Certificate));
    internal static byte[] Reference(FinalStoredDocument value)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value));
}

// Recorded publication metadata only. It grants no storage capability and makes no claim
// that files are currently retrievable; preparation/GET independently verify the actual pair.
internal static class CompletionDownloadState
{
    private sealed record Documents(FinalStoredDocument Executed,FinalStoredDocument Certificate);
    private sealed record Stages(Guid Id,Guid EnvelopeId,byte[] RecipeSha256,byte[] RowVersion,byte[] FrozenStateSha256,long AuditSequence,byte[] AuditAnchor,Output[] outputs);
    private sealed record Output(Guid Id,Guid PdfObjectId,CompletionSealKind Kind,byte[] RecipeSha256,byte[] RowVersion,long AuditSequence,byte[] AuditHash,byte[] Sha256);
    internal static async Task<DownloadPublication?> ReadAsync(QuillSignDbContext db,Guid id,TimeProvider time,CancellationToken ct)
    {
        try {return await ReadCore(db,id,time,ct);}
        catch(Exception e) when(e is JsonException or ArgumentException or InvalidOperationException or NullReferenceException) {throw new InvalidDataException("Recorded completion publication could not be verified.",e);}
    }
    private static async Task<DownloadPublication?> ReadCore(QuillSignDbContext db,Guid id,TimeProvider time,CancellationToken ct)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        var size=await db.Database.SqlQuery<long>($"SELECT COALESCE((SELECT SUM(CONVERT(bigint,DATALENGTH([BeforeEnvelopeJson]))+DATALENGTH([StageBindingsJson])) FROM [CompletionPublicationIntents] WHERE [EnvelopeId]={id}),0)+COALESCE((SELECT SUM(CONVERT(bigint,DATALENGTH([FinalDocumentsJson]))) FROM [CompletionPublicationResults] WHERE [EnvelopeId]={id}),0) AS [Value]").SingleAsync(ct);
        if(size>589824)throw Invalid();
        var e=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct); if(e?.Status!=EnvelopeStatus.Completed)return null;
        var result=await db.CompletionPublicationResults.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==id,ct);
        var intent=await db.CompletionPublicationIntents.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==id,ct);
        if(result is null || intent is null || result.Id==Guid.Empty || result.IntentId!=intent.Id || intent.Id==Guid.Empty ||
            result.RowVersion.Length!=8 || intent.RowVersion.Length!=8 || result.AuditSequence is <1 or >512 ||
            result.CompletedAt<intent.PreparedAt || result.CompletedAt>time.GetUtcNow() || result.CompletedAt!=e.CompletedAt ||
            !Same(result.RecipeSha256,CompletionPublication.Recipe(result)) || !Same(intent.RecipeSha256,CompletionPublication.Recipe(intent)) ||
            !Same(result.IntentRecipeSha256,intent.RecipeSha256))throw Invalid();
        var context=new PublishedCompletionSource(intent.BeforeEnvelopeJson,result.AfterEnvelopeSha256,result.AuditSequence);
        var before=context.Project(e);
        if(before.Id!=id || before.PublicId!=e.PublicId || before.Status!=EnvelopeStatus.Sent || before.RowVersion.Length!=8)throw Invalid();
        var dataBytes=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={id} AND [Event] IN ('completion_publication_prepared','completed')").SingleAsync(ct);
        if(dataBytes>65536)throw Invalid();
        var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==id && (x.Event=="completion_publication_prepared" || x.Event=="completed")).Take(3).ToArrayAsync(ct);
        if(events.Length!=2 || events.Any(x=>x.ActorType!=PartyType.System || x.ActorId is not null || x.ActorEmail is not null || x.Ip is not null || x.UserAgent is not null ||
            x.At>time.GetUtcNow() || !Same(x.Hash,AuditHash.Compute(x))))throw Invalid();
        var prepared=events.SingleOrDefault(x=>x.Event=="completion_publication_prepared"); var completed=events.SingleOrDefault(x=>x.Event=="completed");
        if(prepared is null || completed is null || prepared.DataJson!=CompletionPublication.Evidence(intent) || completed.DataJson!=CompletionPublication.Evidence(result) ||
            prepared.At<intent.PreparedAt || completed.At<result.CompletedAt || prepared.Sequence>=completed.Sequence || completed.Sequence!=result.AuditSequence)throw Invalid();
        var documents=JsonSerializer.Deserialize<Documents>(result.FinalDocumentsJson) ?? throw Invalid();
        if(documents.Executed is null || documents.Certificate is null)throw Invalid();
        Check(documents.Executed,id,intent.ExecutedObjectId,FinalDocumentKind.Executed,e.FinalBlob,e.FinalSha256);
        Check(documents.Certificate,id,intent.CertificateObjectId,FinalDocumentKind.Certificate,e.CertificateBlob,e.CertificateSha256);
        var stages=JsonSerializer.Deserialize<Stages>(intent.StageBindingsJson) ?? throw Invalid();
        if(stages.Id!=intent.CandidateId || stages.EnvelopeId!=id || stages.RowVersion is not {Length:8} || stages.FrozenStateSha256 is not {Length:32} ||
            stages.AuditSequence is <1 or >512 || stages.AuditAnchor is not {Length:32} || stages.outputs is not {Length:2})throw Invalid();
        var candidate=await db.CompletionCandidates.AsNoTracking().Where(x=>x.Id==stages.Id && x.EnvelopeId==id)
            .Select(x=>new {x.RowVersion,x.RecipeSha256,x.FrozenStateSha256,x.AuditSequence,x.AuditAnchor}).SingleOrDefaultAsync(ct);
        if(candidate is null || !candidate.RowVersion.AsSpan().SequenceEqual(stages.RowVersion) || !Same(candidate.RecipeSha256,stages.RecipeSha256) ||
            !Same(candidate.FrozenStateSha256,stages.FrozenStateSha256) || candidate.AuditSequence!=stages.AuditSequence || !Same(candidate.AuditAnchor,stages.AuditAnchor))throw Invalid();
        foreach(var output in stages.outputs) {
            var row=await db.CompletionSealOutputs.AsNoTracking().Where(x=>x.Id==output.Id && x.EnvelopeId==id && x.CandidateId==stages.Id)
                .Select(x=>new {x.RowVersion,x.RecipeSha256,x.Kind,x.PdfObjectId,x.PdfSha256}).SingleOrDefaultAsync(ct);
            var proof=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==id && x.Sequence==output.AuditSequence).Select(x=>x.Hash).SingleOrDefaultAsync(ct);
            if(row is null || output.RowVersion is not {Length:8} || !row.RowVersion.AsSpan().SequenceEqual(output.RowVersion) || row.Kind!=output.Kind || row.PdfObjectId!=output.PdfObjectId ||
                !Same(row.RecipeSha256,output.RecipeSha256) || !Same(row.PdfSha256,output.Sha256) || !Same(proof,output.AuditHash))throw Invalid();
        }
        return new(id,e.PublicId,e.Title ?? "document",result.Id,result.RecipeSha256.ToArray(),result.RowVersion.ToArray(),result.CompletedAt,e.PurgeAfter,documents.Executed,documents.Certificate,
            context,stages.FrozenStateSha256.ToArray(),stages.AuditSequence,stages.AuditAnchor.ToArray());
    }
    private static void Check(FinalStoredDocument value,Guid envelope,Guid expected,FinalDocumentKind kind,string? blob,byte[]? sha)
    {
        if(expected==Guid.Empty || value.Document!=new FinalDocument(envelope,kind,expected) || blob!=expected.ToString("N") || value.Length is <16 or >64*1024*1024 ||
            !Same(value.Sha256,sha) || !Enum.IsDefined(value.Protection) || value.ETag is not {Length:>0 and <=256} || value.VersionId is null || value.VersionId.Length>256 || value.CreatedAt==default)throw Invalid();
    }
    private static bool Same(byte[]? a,byte[]? b)=>CompletionEvidenceValidation.Same(a,b);
    private static InvalidDataException Invalid()=>new("Recorded completion publication could not be verified.");
}
