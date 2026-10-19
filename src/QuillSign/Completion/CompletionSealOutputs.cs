using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email.Pilot;
using QuillSign.Sealing;
using QuillSign.Storage;

namespace QuillSign.Completion;

public sealed record CompletionSealData(Guid Id,Guid PdfObjectId,CompletionSealKind Kind,SealedPdf Pdf,
    byte[] RecipeSha256,byte[] RowVersion,long AuditSequence,byte[] AuditHash);
public sealed record CompletionSealPair(Guid EnvelopeId,Guid CandidateId,CompletionSealData Executed,CompletionSealData Certificate);

// Explicit internal stages only. Final publication, Completed, work production and delivery are separate.
public sealed class CompletionSealOutputs(QuillSignDbContext db,CompletionCandidates candidates,CompletionEvidenceCollector collector,
    CompletionCertificateRenderer renderer,PlatformPdfSeal engine,SealCms verifier,IBlobStore blobs,AuditWriter audit,TimeProvider time,CompletionCommitScope? scope=null,
    PilotTimestampBoundary? timestamps=null)
{
    public const string RecipeVersion="completion-seal-v1";
    private const long MaximumBytes=64*1024*1024;
    private sealed record Metadata(string Provider,string CertificateSha256,string CertificateDer,DateTimeOffset SealedAt,
        DateTimeOffset TimestampAt,string TimestampCertificateSha256,string TimestampPolicy);

    public async Task<CompletionSealPair?> PrepareAsync(Guid envelopeId,CancellationToken ct=default,CompletionTimestampWork? timestampWork=null)
    {
        ct.ThrowIfCancellationRequested(); if(envelopeId==Guid.Empty)return null;
        try
        {
            if(timestampWork is not null)
            {
                if(timestamps is null || timestampWork.EnvelopeId!=envelopeId)throw new PilotTimestampDeniedException();
                await timestamps.DemandWorkAsync(timestampWork,ct);
            }
            else if(await db.EmailPilotEnrollments.AsNoTracking().AnyAsync(x=>x.SubjectEnvelopeId==envelopeId,ct))
                throw new PilotTimestampDeniedException();
            var candidate=await candidates.ReadAsync(envelopeId,ct); if(candidate is null)return null;
            var rows=await Rows(envelopeId,ct);
            if(rows.Any(x=>x.CandidateId!=candidate.Id) || rows.Any(x=>x.Kind==CompletionSealKind.Certificate) && rows.All(x=>x.Kind!=CompletionSealKind.Executed))throw Invalid();
            var first=rows.SingleOrDefault(x=>x.Kind==CompletionSealKind.Executed);
            var executed=first is null ? await PrepareStage(candidate,CompletionSealKind.Executed,null,ct,timestampWork) : await ReadStage(first,candidate,null,ct);
            rows=await Rows(envelopeId,ct); var second=rows.SingleOrDefault(x=>x.Kind==CompletionSealKind.Certificate);
            var certificate=second is null ? await PrepareStage(candidate,CompletionSealKind.Certificate,executed,ct,timestampWork) : await ReadStage(second,candidate,executed,ct);
            return new(envelopeId,candidate.Id,executed,certificate);
        }
        catch(Azure.RequestFailedException) {throw new IOException("Completion seal storage is unavailable.");}
        catch(Exception error) when(error is JsonException or FormatException or InvalidOperationException or ArgumentException or UnauthorizedAccessException or KeyNotFoundException or DocumentRejectedException or CryptographicException)
        {throw Invalid();}
    }

    public async Task<CompletionSealPair?> ReadAsync(Guid envelopeId,CancellationToken ct=default)
        =>await ReadCore(envelopeId,null,ct);
    internal Task<CompletionSealPair?> ReadPublishedAsync(Guid id,PublishedCompletionSource source,CancellationToken ct)=>ReadCore(id,source,ct);
    private async Task<CompletionSealPair?> ReadCore(Guid envelopeId,PublishedCompletionSource? published,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); if(envelopeId==Guid.Empty)return null;
        try
        {
            var candidate=published is null ? await candidates.ReadAsync(envelopeId,ct) : await candidates.ReadPublishedAsync(envelopeId,published,ct); if(candidate is null)return null;
            var rows=await Rows(envelopeId,ct); if(rows.Length==0)return null;
            var first=rows.SingleOrDefault(x=>x.Kind==CompletionSealKind.Executed) ?? throw Invalid();
            var executed=await ReadStage(first,candidate,null,ct,published);
            var second=rows.SingleOrDefault(x=>x.Kind==CompletionSealKind.Certificate); if(second is null)return null;
            return new(envelopeId,candidate.Id,executed,await ReadStage(second,candidate,executed,ct,published));
        }
        catch(Azure.RequestFailedException) {throw new IOException("Completion seal storage is unavailable.");}
        catch(Exception error) when(error is JsonException or FormatException or InvalidOperationException or ArgumentException or UnauthorizedAccessException or KeyNotFoundException or DocumentRejectedException or CryptographicException)
        {throw Invalid();}
    }

    private async Task<CompletionSealData> PrepareStage(CompletionCandidateData candidate,CompletionSealKind kind,CompletionSealData? executed,CancellationToken ct,
        CompletionTimestampWork? timestampWork)
    {
        var owned=new List<DocumentBlob>(); var commitStarted=false; var committed=false;
        try
        {
            byte[] source; int pages;
            if(kind==CompletionSealKind.Executed) {source=candidate.Packet.Bytes; pages=candidate.Packet.DocumentPages+candidate.Packet.CertificatePages;}
            else {
                if(executed is null)throw Invalid();
                var certificate=renderer.PrepareStandalone(candidate.Evidence,candidate.Packet,executed.Pdf,ct); source=certificate.Bytes; pages=certificate.Pages;
            }
            var sourceHash=SHA256.HashData(source);
            var timestampArtifact=timestampWork is null ? null : await timestamps!.BindArtifactAsync(timestampWork,candidate.Id,kind,sourceHash,
                executed?.Pdf.Sha256,executed?.RecipeSha256,ct);
            var sealedPdf=executed is null ? await engine.SealAsync(source,sourceHash,ct,timestampArtifact) :
                await engine.SealBoundAsync(source,sourceHash,Convert.FromHexString(executed.Pdf.CertificateSha256),ct,timestampArtifact);
            if(!Same(sealedPdf.SourceSha256,sourceHash) || sealedPdf.PageCount!=pages || sealedPdf.SealedAt<candidate.Evidence.PreparedAt)throw Invalid();
            var row=new CompletionSealOutput {
                EnvelopeId=candidate.EnvelopeId,CandidateId=candidate.Id,Kind=kind,SourceObjectId=kind==CompletionSealKind.Executed ? candidate.PdfObjectId : Guid.NewGuid(),
                SourceLength=source.LongLength,SourceSha256=sourceHash,PdfObjectId=Guid.NewGuid(),PdfLength=sealedPdf.Bytes.LongLength,PdfSha256=sealedPdf.Sha256.ToArray(),
                PageCount=sealedPdf.PageCount,EvidenceSha256=candidate.Packet.EvidenceSha256.ToArray(),CandidateRecipeSha256=candidate.RecipeSha256.ToArray(),
                ExecutedSha256=executed?.Pdf.Sha256.ToArray(),RecipeVersion=RecipeVersion,
                MetadataJson=JsonSerializer.Serialize(new Metadata(sealedPdf.Provider,sealedPdf.CertificateSha256,Convert.ToBase64String(sealedPdf.CertificateDer),
                    sealedPdf.SealedAt,sealedPdf.TimestampAt,sealedPdf.TimestampCertificateSha256,sealedPdf.TimestampPolicy))
            };
            row.RecipeSha256=Recipe(row);
            // Independently verify the actual engine result and source before giving it durable ownership.
            _=await Verify(row,source,sealedPdf.Bytes,candidate,executed,ct);
            if(kind==CompletionSealKind.Certificate)await Upload(SourceBlob(row),source,sourceHash,owned,ct);
            await Upload(PdfBlob(row),sealedPdf.Bytes,row.PdfSha256,owned,ct);
            CompletionSealOutput saved;
            try
            {
                await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
                await using var transaction=await db.Database.BeginTransactionAsync(ct);
                await RecheckLocked(candidate,ct);
                await RecheckPredecessor(executed,candidate,ct);
                var existing=await db.CompletionSealOutputs.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==row.EnvelopeId && x.CandidateId==candidate.Id && x.Kind==kind,ct);
                if(existing is not null)saved=existing;
                else
                {
                    if(kind==CompletionSealKind.Certificate && !await db.CompletionSealOutputs.AnyAsync(x=>x.Id==executed!.Id && x.EnvelopeId==row.EnvelopeId && x.CandidateId==candidate.Id && x.Kind==CompletionSealKind.Executed && x.PdfSha256==row.ExecutedSha256,ct))throw new DocumentConflictException();
                    if(scope is not null)await scope.CheckLockedAsync(row.EnvelopeId,ct);
                    db.CompletionSealOutputs.Add(row); await db.SaveChangesAsync(ct);
                    await audit.AppendAsync(row.EnvelopeId,Event(kind),null,null,null,ct,Evidence(row),PartyType.System);
                    await RecheckLocked(candidate,ct); await RecheckPredecessor(executed,candidate,ct);
                    if(scope is not null)await scope.CheckLockedAsync(row.EnvelopeId,ct); saved=row;
                }
                commitStarted=existing is null;
                await transaction.CommitAsync(ct); committed=existing is null;
            }
            catch(Exception error) when(commitStarted && error is not OperationCanceledException && error is not OutOfMemoryException)
            {
                db.ChangeTracker.Clear(); var recovered=(await Rows(row.EnvelopeId,ct)).SingleOrDefault(x=>x.Kind==kind && x.CandidateId==candidate.Id);
                if(recovered is null)throw;
                return await ReadStage(recovered,candidate,executed,ct);
            }
            return await ReadStage(saved,candidate,executed,ct);
        }
        finally {if(!commitStarted && !committed)await Cleanup(owned);}
    }

    private async Task<CompletionSealData> ReadStage(CompletionSealOutput row,CompletionCandidateData candidate,CompletionSealData? executed,CancellationToken ct,PublishedCompletionSource? published=null)
    {
        var proof=await Proof(row,ct);
        var source=row.Kind==CompletionSealKind.Executed ? candidate.Packet.Bytes : await ReadExact(SourceBlob(row),row.SourceLength,row.SourceSha256,ct);
        var bytes=await ReadExact(PdfBlob(row),row.PdfLength,row.PdfSha256,ct);
        var value=await Verify(row,source,bytes,candidate,executed,ct);
        if(proof.Sequence<=candidate.AuditSequence || proof.At<value.SealedAt || executed is not null && proof.Sequence<=executed.AuditSequence)throw Invalid();
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using(var transaction=await db.Database.BeginTransactionAsync(ct))
        {
            await RecheckLocked(candidate,ct,published);
            await RecheckPredecessor(executed,candidate,ct);
            var saved=await db.CompletionSealOutputs.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==row.Id && x.EnvelopeId==row.EnvelopeId,ct);
            if(saved is null || !saved.RowVersion.AsSpan().SequenceEqual(row.RowVersion) || !Same(saved.RecipeSha256,row.RecipeSha256))throw new DocumentConflictException();
            var current=await Proof(saved,ct); if(current.Id!=proof.Id || !Same(current.Hash,proof.Hash))throw new DocumentConflictException();
            await transaction.CommitAsync(ct);
        }
        return new(row.Id,row.PdfObjectId,row.Kind,value,row.RecipeSha256.ToArray(),row.RowVersion.ToArray(),proof.Sequence,proof.Hash.ToArray());
    }

    private async Task<SealedPdf> Verify(CompletionSealOutput row,byte[] source,byte[] bytes,CompletionCandidateData candidate,CompletionSealData? executed,CancellationToken ct)
    {
        if(row.Id==Guid.Empty || row.EnvelopeId!=candidate.EnvelopeId || row.CandidateId!=candidate.Id || !Enum.IsDefined(row.Kind) ||
            row.SourceObjectId==Guid.Empty || row.PdfObjectId==Guid.Empty || row.SourceObjectId==row.PdfObjectId || row.SourceLength is <16 or >MaximumBytes ||
            row.PdfLength is <16 or >MaximumBytes || row.PageCount is <1 or >200 || row.RecipeVersion!=RecipeVersion ||
            row.MetadataJson.Length>131072 || Encoding.UTF8.GetByteCount(row.MetadataJson)>131072 || !Same(row.RecipeSha256,Recipe(row)) ||
            !Same(row.CandidateRecipeSha256,candidate.RecipeSha256) || !Same(row.EvidenceSha256,candidate.Packet.EvidenceSha256) ||
            source.LongLength!=row.SourceLength || bytes.LongLength!=row.PdfLength || !Same(SHA256.HashData(source),row.SourceSha256) || !Same(SHA256.HashData(bytes),row.PdfSha256))throw Invalid();
        if(row.Kind==CompletionSealKind.Executed ? executed is not null || row.ExecutedSha256 is not null || row.SourceObjectId!=candidate.PdfObjectId || !Same(row.SourceSha256,candidate.Packet.Sha256) :
            executed is null || row.SourceObjectId==candidate.PdfObjectId || !Same(row.ExecutedSha256,executed.Pdf.Sha256))throw Invalid();
        var metadata=JsonSerializer.Deserialize<Metadata>(row.MetadataJson) ?? throw Invalid();
        if(string.IsNullOrWhiteSpace(metadata.Provider) || metadata.Provider.Length>100 || metadata.CertificateDer is not {Length:>0 and <=87384} ||
            !Hash(metadata.CertificateSha256) || !Hash(metadata.TimestampCertificateSha256) || string.IsNullOrWhiteSpace(metadata.TimestampPolicy) || metadata.TimestampPolicy.Length>128 ||
            metadata.SealedAt<candidate.Evidence.PreparedAt || metadata.SealedAt>time.GetUtcNow() || metadata.TimestampAt==default ||
            executed is not null && (metadata.CertificateSha256!=executed.Pdf.CertificateSha256 || metadata.SealedAt<executed.Pdf.SealedAt))throw Invalid();
        var der=Convert.FromBase64String(metadata.CertificateDer); if(der.Length is <1 or >65536 || Hex(SHA256.HashData(der))!=metadata.CertificateSha256)throw Invalid();
        using var certificate=X509CertificateLoader.LoadCertificate(der); if(certificate.HasPrivateKey)throw Invalid();
        var inspected=await verifier.VerifyAsync(bytes,certificate,metadata.SealedAt,ct);
        if(inspected.PageCount!=row.PageCount || inspected.Timestamp.At!=metadata.TimestampAt || inspected.Timestamp.CertificateSha256!=metadata.TimestampCertificateSha256 ||
            inspected.Timestamp.Policy!=metadata.TimestampPolicy)throw Invalid();
        IReadOnlyList<PageGeometry> geometry;
        lock(SenderPdfRenderer.RenderGate) {
            ct.ThrowIfCancellationRequested(); using var discarded=new MemoryStream();
            geometry=new PdfValidation(new() {MaximumBytes=MaximumBytes,MaximumPages=200}).Rewrite(new MemoryStream(source,false),new BoundedDocumentStream(discarded,MaximumBytes));
        }
        if(!SenderPdfRenderer.GeometryMatches(geometry,inspected.Geometry) || row.Kind==CompletionSealKind.Executed && row.PageCount!=candidate.Packet.DocumentPages+candidate.Packet.CertificatePages ||
            row.Kind==CompletionSealKind.Certificate && row.PageCount>64)throw Invalid();
        return new(bytes,row.PdfSha256.ToArray(),row.SourceSha256.ToArray(),row.PageCount,metadata.Provider,metadata.CertificateSha256,
            metadata.SealedAt,metadata.TimestampAt,metadata.TimestampCertificateSha256,metadata.TimestampPolicy) {CertificateDer=der};
    }

    private async Task<CompletionSealOutput[]> Rows(Guid envelopeId,CancellationToken ct)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([MetadataJson]))),0) AS [Value] FROM [CompletionSealOutputs] WHERE [EnvelopeId]={envelopeId}").SingleAsync(ct);
        if(size>524288)throw Invalid();
        var rows=await db.CompletionSealOutputs.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId).Take(3).ToArrayAsync(ct);
        if(rows.Length>2)throw Invalid(); return rows;
    }
    private async Task RecheckLocked(CompletionCandidateData candidate,CancellationToken ct,PublishedCompletionSource? published=null)
    {
        await collector.RecheckLockedAsync(candidate.EnvelopeId,candidate.FrozenStateSha256,ct,candidate.AuditSequence,candidate.AuditAnchor,published);
        var saved=await db.CompletionCandidates.AsNoTracking().Where(x=>x.Id==candidate.Id && x.EnvelopeId==candidate.EnvelopeId)
            .Select(x=>new {x.RecipeSha256,x.RowVersion,x.PdfObjectId,x.PdfSha256,x.EvidenceSha256}).SingleOrDefaultAsync(ct);
        if(saved is null || saved.PdfObjectId!=candidate.PdfObjectId || !saved.RowVersion.AsSpan().SequenceEqual(candidate.RowVersion) ||
            !Same(saved.RecipeSha256,candidate.RecipeSha256) || !Same(saved.PdfSha256,candidate.Packet.Sha256) || !Same(saved.EvidenceSha256,candidate.Packet.EvidenceSha256))throw new DocumentConflictException();
    }
    private async Task<AuditEvent> Proof(CompletionSealOutput row,CancellationToken ct)
    {
        var events=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==row.EnvelopeId && x.Event==Event(row.Kind)).Take(2).ToArrayAsync(ct);
        if(events.Length!=1 || events[0].ActorType!=PartyType.System || events[0].ActorId is not null || events[0].ActorEmail is not null ||
            events[0].Ip is not null || events[0].UserAgent is not null || !Same(events[0].Hash,AuditHash.Compute(events[0])) || events[0].DataJson!=Evidence(row))throw Invalid();
        return events[0];
    }
    private async Task RecheckPredecessor(CompletionSealData? executed,CompletionCandidateData candidate,CancellationToken ct)
    {
        if(executed is null)return;
        var row=await db.CompletionSealOutputs.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==executed.Id && x.EnvelopeId==candidate.EnvelopeId && x.CandidateId==candidate.Id && x.Kind==CompletionSealKind.Executed,ct);
        if(row is null || !row.RowVersion.AsSpan().SequenceEqual(executed.RowVersion) || !Same(row.RecipeSha256,executed.RecipeSha256) || !Same(row.PdfSha256,executed.Pdf.Sha256))throw new DocumentConflictException();
        var proof=await Proof(row,ct); if(proof.Sequence!=executed.AuditSequence || !Same(proof.Hash,executed.AuditHash))throw new DocumentConflictException();
    }
    private async Task Upload(DocumentBlob blob,byte[] bytes,byte[] hash,List<DocumentBlob> owned,CancellationToken ct)
    {
        try {using var input=new MemoryStream(bytes,false); await blobs.WriteAsync(Capability(blob,AssetOperation.Write),blob,input,input.Length,ct); owned.Add(blob);}
        catch(Exception error) when(error is IOException or Azure.RequestFailedException)
        {ct.ThrowIfCancellationRequested(); _=await ReadExact(blob,bytes.LongLength,hash,ct); owned.Add(blob);}
        _=await ReadExact(blob,bytes.LongLength,hash,ct);
    }
    private async Task<byte[]> ReadExact(DocumentBlob blob,long expectedLength,byte[] hash,CancellationToken ct)
    {
        if(expectedLength is <16 or >MaximumBytes || hash is not {Length:32})throw Invalid();
        using var memory=new MemoryStream(); using var bounded=new BoundedDocumentStream(memory,MaximumBytes);
        var length=await blobs.CopyToAsync(Capability(blob,AssetOperation.Read),blob,bounded,ct);
        if(length!=expectedLength || length!=memory.Length || !Same(hash,SHA256.HashData(memory.GetBuffer().AsSpan(0,checked((int)memory.Length)))))throw Invalid();
        return memory.ToArray();
    }
    private async Task Cleanup(List<DocumentBlob> owned)
    {
        if(owned.Count==0)return; using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(10)); var ct=timeout.Token;
        try
        {
            db.ChangeTracker.Clear(); await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            await using var transaction=await db.Database.BeginTransactionAsync(ct); var envelopeId=owned[0].EnvelopeId;
            _=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={envelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
            foreach(var blob in owned.Distinct())if(!await db.CompletionSealOutputs.AnyAsync(x=>x.EnvelopeId==blob.EnvelopeId && (x.PdfObjectId==blob.ObjectId || x.SourceObjectId==blob.ObjectId),ct))
                await blobs.DeleteAsync(Capability(blob,AssetOperation.Delete),blob,ct);
            await transaction.CommitAsync(ct);
        }
        catch(Exception error) when(error is not OutOfMemoryException) { /* Possibly owned bytes remain private for privileged envelope retention. */ }
    }
    private static byte[] Recipe(CompletionSealOutput row)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
        row.Id,row.EnvelopeId,row.CandidateId,row.Kind,row.SourceObjectId,row.SourceLength,row.SourceSha256,row.PdfObjectId,row.PdfLength,row.PdfSha256,
        row.PageCount,row.EvidenceSha256,row.CandidateRecipeSha256,row.ExecutedSha256,row.RecipeVersion,metadataSha256=SHA256.HashData(Encoding.UTF8.GetBytes(row.MetadataJson))
    }));
    private static string Evidence(CompletionSealOutput row)=>JsonSerializer.Serialize(new {
        outputId=row.Id,row.CandidateId,row.Kind,row.SourceObjectId,row.SourceLength,sourceSha256=Hex(row.SourceSha256),row.PdfObjectId,row.PdfLength,
        pdfSha256=Hex(row.PdfSha256),row.PageCount,evidenceSha256=Hex(row.EvidenceSha256),candidateRecipeSha256=Hex(row.CandidateRecipeSha256),
        executedSha256=row.ExecutedSha256 is null ? null : Hex(row.ExecutedSha256),metadataSha256=Hex(SHA256.HashData(Encoding.UTF8.GetBytes(row.MetadataJson))),
        row.RecipeVersion,recipeSha256=Hex(row.RecipeSha256),serverEvidence="verified_private_completion_seal_not_final_publication"
    });
    private static string Event(CompletionSealKind kind)=>kind==CompletionSealKind.Executed ? "completion_executed_sealed" : "completion_certificate_sealed";
    private static DocumentBlob PdfBlob(CompletionSealOutput row)=>new(row.EnvelopeId,row.Kind==CompletionSealKind.Executed ? DocumentBlobKind.CompletionExecutedSeal : DocumentBlobKind.CompletionCertificateSeal,row.PdfObjectId);
    private static DocumentBlob SourceBlob(CompletionSealOutput row)=>row.Kind==CompletionSealKind.Certificate ? new(row.EnvelopeId,DocumentBlobKind.CompletionCertificateSource,row.SourceObjectId) : throw Invalid();
    private ClaimsPrincipal Capability(DocumentBlob blob,AssetOperation operation)=>CompletionSealCapability.Create(blob,operation,time);
    private static bool Same(byte[]? a,byte[]? b)=>CompletionEvidenceValidation.Same(a,b);
    private static string Hex(byte[] bytes)=>Convert.ToHexStringLower(bytes);
    private static bool Hash(string? value)=>value is {Length:64} && value.All(Uri.IsHexDigit);
    private static InvalidDataException Invalid()=>new("The immutable completion seal could not be verified.");
}
