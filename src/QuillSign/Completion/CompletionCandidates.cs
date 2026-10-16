using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;

namespace QuillSign.Completion;

public sealed record CompletionCandidateData(Guid Id,Guid EnvelopeId,Guid FinishId,Guid SourceObjectId,Guid PdfObjectId,
    CompletionEvidence Evidence,PreparedCompletionPacket Packet,IReadOnlyList<PageGeometry> SourcePages,
    byte[] RecipeSha256,byte[] FrozenStateSha256,long AuditSequence,byte[] AuditAnchor,byte[] RowVersion);

// Internal explicit preparation/read service. No public authority, worker enqueue, seal or mail.
public sealed class CompletionCandidates(QuillSignDbContext db,CompletionEvidenceCollector collector,
    CompletionCertificateRenderer renderer,IBlobStore blobs,AuditWriter audit,TimeProvider time,CompletionCommitScope? scope=null)
{
    public const string SnapshotVersion="completion-candidate-v1";
    private const long MaximumPdfBytes=64*1024*1024;
    private const int MaximumEvidenceBytes=32*1024*1024;

    public async Task<CompletionCandidateData?> PrepareAsync(Guid envelopeId,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(envelopeId==Guid.Empty)return null;
        CompletionCandidate? attempt=null; var commitStarted=false; var committed=false; var cleanupAllowed=false;
        try
        {
            var existing=await Row(envelopeId,ct); if(existing is not null)return await Verified(existing,ct);
            var source=await collector.CollectAsync(envelopeId,ct); if(source is null)return null;
            var packet=renderer.PreparePacket(source.Source,source.Pages,source.Evidence,ct);
            attempt=Create(source,packet); var blob=Blob(attempt);
            try
            {
                using var input=new MemoryStream(packet.Bytes,false);
                await blobs.WriteAsync(Capability(blob,AssetOperation.Write),blob,input,input.Length,ct);
                cleanupAllowed=true;
            }
            catch(Exception error) when(error is IOException or Azure.RequestFailedException)
            {
                // A conditional upload may have committed despite a lost acknowledgement.
                // The same new object is usable only if its full exact bytes verify.
                ct.ThrowIfCancellationRequested(); _=await ReadPdf(attempt,ct); cleanupAllowed=true;
            }
            _=await ReadPdf(attempt,ct);
            CompletionCandidate saved;
            try
            {
                await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
                await using var transaction=await db.Database.BeginTransactionAsync(ct);
                _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={envelopeId}").AsNoTracking().SingleAsync(ct);
                existing=await Row(envelopeId,ct);
                if(existing is not null)saved=existing;
                else
                {
                    await collector.RecheckLockedAsync(envelopeId,source.StateSha256,ct);
                    if(scope is not null)await scope.CheckLockedAsync(envelopeId,ct);
                    db.CompletionCandidates.Add(attempt); await db.SaveChangesAsync(ct);
                    await audit.AppendAsync(envelopeId,"completion_prepared",null,null,null,ct,PreparationJson(attempt),PartyType.System);
                    await collector.RecheckLockedAsync(envelopeId,attempt.FrozenStateSha256,ct,attempt.AuditSequence,attempt.AuditAnchor);
                    if(scope is not null)await scope.CheckLockedAsync(envelopeId,ct);
                    saved=attempt;
                }
                commitStarted=existing is null;
                await transaction.CommitAsync(ct); committed=existing is null;
            }
            catch(Exception error) when(commitStarted && error is not OperationCanceledException && error is not OutOfMemoryException)
            {
                // The transaction is disposed before recovery. Never delete after a possible commit.
                db.ChangeTracker.Clear(); var recovered=await Row(envelopeId,ct);
                if(recovered is null)throw;
                return await Verified(recovered,ct);
            }
            // A concurrent winner owns its earlier snapshot/bytes; the losing attempt is unreferenced.
            return await Verified(saved,ct);
        }
        catch(Azure.RequestFailedException) {throw new IOException("Completion candidate storage is unavailable.");}
        catch(Exception error) when(error is JsonException or FormatException or InvalidOperationException or ArgumentException or UnauthorizedAccessException or KeyNotFoundException or DocumentRejectedException)
        {throw Invalid();}
        finally
        {
            if(attempt is not null && cleanupAllowed && !committed && !commitStarted)await CleanupUnreferenced(attempt);
        }
    }

    public async Task<CompletionCandidateData?> ReadAsync(Guid envelopeId,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(envelopeId==Guid.Empty)return null;
        try {var row=await Row(envelopeId,ct); return row is null ? null : await Verified(row,ct);}
        catch(Azure.RequestFailedException) {throw new IOException("Completion candidate storage is unavailable.");}
        catch(Exception error) when(error is JsonException or FormatException or InvalidOperationException or ArgumentException or UnauthorizedAccessException or KeyNotFoundException or DocumentRejectedException)
        {throw Invalid();}
    }

    internal async Task<CompletionCandidateData?> ReadPublishedAsync(Guid id,PublishedCompletionSource source,CancellationToken ct)
    {var row=await Row(id,ct); return row is null ? null : await Verified(row,ct,source);}

    private static CompletionCandidate Create(CompletionMaterialization source,PreparedCompletionPacket packet)
    {
        var json=JsonSerializer.Serialize(source.Evidence); if(Encoding.UTF8.GetByteCount(json)>MaximumEvidenceBytes)throw Invalid();
        var row=new CompletionCandidate {
            EnvelopeId=source.EnvelopeId,FinishId=source.FinishId,CopyVersion=source.CopyVersion,SourceObjectId=source.SourceObjectId,
            SourceSha256=packet.SourceSha256.ToArray(),PdfObjectId=Guid.NewGuid(),PdfLength=packet.Bytes.LongLength,PdfSha256=packet.Sha256.ToArray(),
            DocumentPages=packet.DocumentPages,CertificatePages=packet.CertificatePages,GeometryJson=JsonSerializer.Serialize(source.Pages),
            EvidenceJson=json,EvidenceSha256=packet.EvidenceSha256.ToArray(),FrozenStateSha256=source.FrozenStateSha256.ToArray(),
            AuditSequence=source.Evidence.Events.Count,AuditAnchor=source.Evidence.AuditAnchor.ToArray(),RendererVersion=packet.RendererVersion,
            SnapshotVersion=SnapshotVersion,PreparedAt=source.Evidence.PreparedAt
        };
        row.RecipeSha256=Recipe(row); return row;
    }

    private async Task<CompletionCandidate?> Row(Guid id,CancellationToken ct)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        // Bound private JSON in SQL before EF allocates it, including malicious/corrupt saved rows.
        var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([EvidenceJson]))+CONVERT(bigint,DATALENGTH([GeometryJson]))),0) AS [Value] FROM [CompletionCandidates] WHERE [EnvelopeId]={id}").SingleAsync(ct);
        if(size>2L*MaximumEvidenceBytes+131072)throw Invalid();
        return await db.CompletionCandidates.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==id,ct);
    }

    private async Task<CompletionCandidateData?> Verified(CompletionCandidate row,CancellationToken ct,PublishedCompletionSource? published=null)
    {
        if(row.Id==Guid.Empty || row.EnvelopeId==Guid.Empty || row.FinishId==Guid.Empty || row.SourceObjectId==Guid.Empty || row.PdfObjectId==Guid.Empty ||
            row.SourceObjectId==row.PdfObjectId || row.PdfLength is <16 or >MaximumPdfBytes || row.CopyVersion is <1 or >20 ||
            row.DocumentPages<1 || row.CertificatePages is <1 or >64 || row.DocumentPages+row.CertificatePages>200 ||
            row.AuditSequence is <1 or >512 || row.PreparedAt==default || row.PreparedAt>time.GetUtcNow() ||
            row.RendererVersion!=CompletionCertificateRenderer.Version || row.SnapshotVersion!=SnapshotVersion ||
            !Same(row.RecipeSha256,Recipe(row)) || Encoding.UTF8.GetByteCount(row.EvidenceJson)>MaximumEvidenceBytes || row.GeometryJson.Length>65536)throw Invalid();
        var evidence=CompletionEvidenceValidation.Own(JsonSerializer.Deserialize<CompletionEvidence>(row.EvidenceJson) ?? throw Invalid(),ct);
        if(evidence.PreparedAt!=row.PreparedAt || evidence.Events.Count!=row.AuditSequence || !Same(evidence.AuditAnchor,row.AuditAnchor) ||
            !Same(evidence.Document.CurrentSha256,row.SourceSha256) || !Same(CompletionEvidenceValidation.Digest(evidence),row.EvidenceSha256))throw Invalid();
        var current=published is null ? await collector.CollectAsync(row.EnvelopeId,ct) : await collector.CollectPublishedAsync(row.EnvelopeId,published,ct); if(current is null)return null;
        if(current.FinishId!=row.FinishId || current.CopyVersion!=row.CopyVersion || current.SourceObjectId!=row.SourceObjectId ||
            !Same(current.FrozenStateSha256,row.FrozenStateSha256) || current.Evidence.Events.Count<row.AuditSequence ||
            !Same(current.Evidence.Events[checked((int)row.AuditSequence)-1].Hash,row.AuditAnchor))throw Invalid();
        var prefix=current.Evidence with {PreparedAt=row.PreparedAt,Events=current.Evidence.Events.Take(checked((int)row.AuditSequence)).ToArray(),AuditAnchor=row.AuditAnchor};
        if(!Same(CompletionEvidenceValidation.Digest(CompletionEvidenceValidation.Own(prefix,ct)),row.EvidenceSha256))throw Invalid();
        var geometry=JsonSerializer.Deserialize<PageGeometry[]>(row.GeometryJson) ?? throw Invalid();
        if(geometry.Length!=row.DocumentPages || !SenderPdfRenderer.GeometryMatches(current.Pages,geometry))throw Invalid();
        var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==row.EnvelopeId && x.Event=="completion_prepared").Take(2).ToArrayAsync(ct);
        if(events.Length!=1 || events[0].Sequence<=row.AuditSequence || events[0].At<row.PreparedAt || events[0].ActorType!=PartyType.System ||
            events[0].ActorId is not null || events[0].ActorEmail is not null || events[0].Ip is not null || events[0].UserAgent is not null ||
            !Same(events[0].Hash,AuditHash.Compute(events[0])) || events[0].DataJson!=PreparationJson(row) ||
            !current.Evidence.Events.Any(x=>x.Sequence==events[0].Sequence && Same(x.Hash,events[0].Hash)))throw Invalid();
        var bytes=await ReadPdf(row,ct);
        // Recheck after candidate I/O under the same lock used by all signing/audit producers.
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using(var transaction=await db.Database.BeginTransactionAsync(ct))
        {
            await collector.RecheckLockedAsync(row.EnvelopeId,row.FrozenStateSha256,ct,row.AuditSequence,row.AuditAnchor,published);
            var saved=await Row(row.EnvelopeId,ct);
            if(saved is null || saved.Id!=row.Id || !saved.RowVersion.AsSpan().SequenceEqual(row.RowVersion) || !Same(saved.RecipeSha256,row.RecipeSha256))throw new DocumentConflictException();
            // The preparation event is immutable too; detect even a valid rehashed change during I/O.
            var still=await db.AuditEvents.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==events[0].Id,ct);
            if(still is null || !Same(still.Hash,events[0].Hash) || still.DataJson!=PreparationJson(row))throw new DocumentConflictException();
            await transaction.CommitAsync(ct);
        }
        return new(row.Id,row.EnvelopeId,row.FinishId,row.SourceObjectId,row.PdfObjectId,evidence,
            new(bytes,row.PdfSha256.ToArray(),row.SourceSha256.ToArray(),row.EvidenceSha256.ToArray(),[],row.DocumentPages,row.CertificatePages,row.RendererVersion),geometry,
            row.RecipeSha256.ToArray(),row.FrozenStateSha256.ToArray(),row.AuditSequence,row.AuditAnchor.ToArray(),row.RowVersion.ToArray());
    }

    private async Task<byte[]> ReadPdf(CompletionCandidate row,CancellationToken ct)
    {
        using var memory=new MemoryStream(); using var bounded=new BoundedDocumentStream(memory,MaximumPdfBytes); var blob=Blob(row);
        var length=await blobs.CopyToAsync(Capability(blob,AssetOperation.Read),blob,bounded,ct);
        if(length!=row.PdfLength || length!=memory.Length || !Same(row.PdfSha256,SHA256.HashData(memory.GetBuffer().AsSpan(0,checked((int)memory.Length)))))throw Invalid();
        return memory.ToArray();
    }

    private async Task CleanupUnreferenced(CompletionCandidate attempt)
    {
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10)); var ct=timeout.Token;
        try
        {
            db.ChangeTracker.Clear();
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            await using var transaction=await db.Database.BeginTransactionAsync(ct);
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={attempt.EnvelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
            if(!await db.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==attempt.EnvelopeId && x.PdfObjectId==attempt.PdfObjectId,ct))
                await blobs.DeleteAsync(Capability(Blob(attempt),AssetOperation.Delete),Blob(attempt),ct);
            await transaction.CommitAsync(ct);
        }
        catch(Exception error) when(error is not OutOfMemoryException) { /* Unknown objects remain private for privileged envelope retention; never guess ownership. */ }
    }

    private static byte[] Recipe(CompletionCandidate row)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
        row.Id,row.EnvelopeId,row.FinishId,row.CopyVersion,row.SourceObjectId,row.SourceSha256,row.PdfObjectId,row.PdfLength,row.PdfSha256,
        row.DocumentPages,row.CertificatePages,geometrySha256=SHA256.HashData(Encoding.UTF8.GetBytes(row.GeometryJson)),
        row.EvidenceSha256,row.FrozenStateSha256,row.AuditSequence,row.AuditAnchor,row.RendererVersion,row.SnapshotVersion,row.PreparedAt
    }));
    private static string PreparationJson(CompletionCandidate row)=>JsonSerializer.Serialize(new {
        candidateId=row.Id,row.FinishId,row.CopyVersion,row.SourceObjectId,row.PdfObjectId,row.PdfLength,row.DocumentPages,row.CertificatePages,
        sourceSha256=Hex(row.SourceSha256),pdfSha256=Hex(row.PdfSha256),evidenceSha256=Hex(row.EvidenceSha256),
        frozenStateSha256=Hex(row.FrozenStateSha256),recipeSha256=Hex(row.RecipeSha256),row.AuditSequence,auditAnchor=Hex(row.AuditAnchor),
        row.RendererVersion,row.SnapshotVersion,row.PreparedAt,serverEvidence="immutable_unsigned_completion_prepared_not_final_publication"
    });
    private ClaimsPrincipal Capability(DocumentBlob blob,AssetOperation operation)=>CompletionCandidateCapability.Create(blob,operation,time);
    private static DocumentBlob Blob(CompletionCandidate row)=>new(row.EnvelopeId,DocumentBlobKind.CompletionCandidate,row.PdfObjectId);
    private static bool Same(byte[]? a,byte[]? b)=>CompletionEvidenceValidation.Same(a,b);
    private static string Hex(byte[] bytes)=>Convert.ToHexStringLower(bytes);
    private static InvalidDataException Invalid()=>new("The immutable completion candidate could not be verified.");
}
