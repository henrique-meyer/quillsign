using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Completion;

public sealed record PublishedCompletion(Guid EnvelopeId,DateTimeOffset CompletedAt,FinalStoredDocument Executed,
    FinalStoredDocument Certificate,byte[] ExecutedBytes,byte[] CertificateBytes)
{
    public Guid PublicationId {get;init;}
    public byte[] PublicationRecipeSha256 {get;init;}=[];
    public byte[] PublicationRowVersion {get;init;}=[];
}

// Callers separately authorize public access. Notification intent joins the publication transaction.
public sealed class CompletionPublication(QuillSignDbContext db,CompletionCandidates candidates,CompletionSealOutputs seals,
    CompletionEvidenceCollector collector,ICompletionFinalStore final,AuditWriter audit,TimeProvider time,
    CompletionPublicationOptions options,IHostEnvironment environment,CompletionCommitScope? scope=null,Func<CompletionNotificationJobs>? notifications=null)
{
    public const string Version="completion-publication-v1";
    private sealed record Documents(FinalStoredDocument Executed,FinalStoredDocument Certificate);

    public async Task<PublishedCompletion?> PublishAsync(Guid id,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(id==Guid.Empty)return null;
        if(await Result(id,ct) is not null)return await ReadAsync(id,ct);
        var candidate=await candidates.ReadAsync(id,ct); if(candidate is null)return await ReadAsync(id,ct);
        var pair=await seals.ReadAsync(id,ct); if(pair is null)return null;
        var intent=await PrepareIntent(candidate,pair,ct); if(intent is null)return await ReadAsync(id,ct);
        var retention=new FinalRetention(intent.RetentionDays,intent.DevelopmentWriteOnce);
        // Require coverage from this attempt through its selected interval, not merely intent creation.
        var until=retention.RequiredUntil(time.GetUtcNow());
        var executed=await Upload(intent,FinalDocumentKind.Executed,pair.Executed.Pdf.Bytes,pair.Executed.Pdf.Sha256,until,ct);
        var certificate=await Upload(intent,FinalDocumentKind.Certificate,pair.Certificate.Pdf.Bytes,pair.Certificate.Pdf.Sha256,until,ct);
        var commitStarted=false;Guid[] notificationIds=[];
        try
        {
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            await using var transaction=await db.Database.BeginTransactionAsync(ct);
            var envelope=await Locked(id,ct); var existing=await Result(id,ct);
            if(existing is null)
            {
                await CheckIntent(intent,candidate,pair,envelope,ct);
                var at=time.GetUtcNow(); var required=retention.RequiredUntil(at);
                CheckDocument(executed,intent,FinalDocumentKind.Executed,pair.Executed.Pdf.Bytes.LongLength,pair.Executed.Pdf.Sha256,required,false);
                CheckDocument(certificate,intent,FinalDocumentKind.Certificate,pair.Certificate.Pdf.Bytes.LongLength,pair.Certificate.Pdf.Sha256,required,false);
                var sequence=(await db.AuditEvents.Where(x=>x.EnvelopeId==id).MaxAsync(x=>(long?)x.Sequence,ct) ?? 0)+1;
                if(sequence is <1 or >512)throw Invalid();
                // Only publication-owned envelope fields change. Signer Finish times remain untouched.
                if(scope is not null)await scope.CheckLockedAsync(id,ct);
                Apply(envelope!,intent,pair,at); db.Update(envelope!); await db.SaveChangesAsync(ct);
                var result=new CompletionPublicationResult {EnvelopeId=id,IntentId=intent.Id,CompletedAt=at,AuditSequence=sequence,
                    FinalDocumentsJson=JsonSerializer.Serialize(new Documents(executed,certificate)),
                    AfterEnvelopeSha256=PublishedCompletionSource.Digest(envelope!),IntentRecipeSha256=intent.RecipeSha256.ToArray()};
                result.RecipeSha256=Recipe(result); db.CompletionPublicationResults.Add(result); await db.SaveChangesAsync(ct);
                await audit.AppendAsync(id,"completed",null,null,null,ct,Evidence(result),PartyType.System);
                if(notifications is not null)notificationIds=await notifications().PrepareLockedAsync(id,ct);
                if(scope is not null)await scope.CheckLockedAsync(id,ct);
                commitStarted=true;
            }
            await transaction.CommitAsync(ct);
        }
        catch(Exception error) when(commitStarted && error is not OperationCanceledException && error is not OutOfMemoryException)
        {
            db.ChangeTracker.Clear(); if(await Result(id,ct) is null)throw;
            if(notifications is not null)await notifications().PublishAsync(notificationIds,ct);
            return await ReadAsync(id,ct);
        }
        // No cleanup authority exists here, including rollback, cancellation or uncertain commit.
        if(notifications is not null)await notifications().PublishAsync(notificationIds,ct);
        return await ReadAsync(id,ct);
    }

    public async Task<PublishedCompletion?> ReadAsync(Guid id,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(id==Guid.Empty)return null;
        try
        {
            var result=await Result(id,ct); if(result is null)return null;
            var intent=await Intent(id,ct) ?? throw Invalid();
            var context=await PublishedSource(intent,result,ct);
            var pair=await seals.ReadPublishedAsync(id,context,ct) ?? throw Invalid();
            var candidate=await candidates.ReadPublishedAsync(id,context,ct) ?? throw Invalid();
            if(intent.StageBindingsJson!=Bindings(candidate,pair))throw Invalid();
            var documents=JsonSerializer.Deserialize<Documents>(result.FinalDocumentsJson) ?? throw Invalid();
            var until=new FinalRetention(intent.RetentionDays,intent.DevelopmentWriteOnce).RequiredUntil(result.CompletedAt);
            CheckDocument(documents.Executed,intent,FinalDocumentKind.Executed,pair.Executed.Pdf.Bytes.LongLength,pair.Executed.Pdf.Sha256,until,true);
            CheckDocument(documents.Certificate,intent,FinalDocumentKind.Certificate,pair.Certificate.Pdf.Bytes.LongLength,pair.Certificate.Pdf.Sha256,until,true);
            var expected=Before(intent); Apply(expected,intent,pair,result.CompletedAt);
            var current=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id,ct); expected.RowVersion=current.RowVersion;
            if(!Same(PublishedCompletionSource.Digest(expected),result.AfterEnvelopeSha256))throw Invalid();
            var executed=await Download(documents.Executed,intent,ct); var certificate=await Download(documents.Certificate,intent,ct);
            if(!executed.AsSpan().SequenceEqual(pair.Executed.Pdf.Bytes) || !certificate.AsSpan().SequenceEqual(pair.Certificate.Pdf.Bytes))throw Invalid();
            await using(var transaction=await db.Database.BeginTransactionAsync(ct))
            {
                _=await Locked(id,ct); _=await PublishedSource(intent,result,ct);
                await Recheck(candidate,pair,ct,context);
                await transaction.CommitAsync(ct);
            }
            return new(id,result.CompletedAt,documents.Executed,documents.Certificate,executed,certificate) {
                PublicationId=result.Id,PublicationRecipeSha256=result.RecipeSha256.ToArray(),PublicationRowVersion=result.RowVersion.ToArray()};
        }
        catch(Azure.RequestFailedException) {throw new IOException("Final completion storage is unavailable.");}
        catch(Exception error) when(error is JsonException or FormatException or InvalidOperationException or ArgumentException or UnauthorizedAccessException or KeyNotFoundException or DocumentConflictException)
        {throw Invalid();}
    }

    private async Task<CompletionPublicationIntent?> PrepareIntent(CompletionCandidateData candidate,CompletionSealPair pair,CancellationToken ct)
    {
        var commitStarted=false;
        try
        {
            await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
            await using var transaction=await db.Database.BeginTransactionAsync(ct); var envelope=await Locked(candidate.EnvelopeId,ct);
            if(await Result(candidate.EnvelopeId,ct) is not null) {await transaction.CommitAsync(ct); return null;}
            if(envelope is null)return null;
            var saved=await Intent(candidate.EnvelopeId,ct);
            if(saved is not null) {await CheckIntent(saved,candidate,pair,envelope,ct); await transaction.CommitAsync(ct); return saved;}
            await Recheck(candidate,pair,ct);
            if(envelope.Status!=EnvelopeStatus.Sent || envelope.CompletedAt is not null || envelope.FinalBlob is not null || envelope.FinalSha256 is not null ||
                envelope.CertificateBlob is not null || envelope.CertificateSha256 is not null || envelope.SealProvider is not null || envelope.SealCertThumbprint is not null)throw Invalid();
            var retention=options.Select(envelope,environment);
            var row=new CompletionPublicationIntent {EnvelopeId=candidate.EnvelopeId,CandidateId=candidate.Id,
                ExecutedOutputId=pair.Executed.Id,CertificateOutputId=pair.Certificate.Id,BeforeEnvelopeJson=JsonSerializer.Serialize(envelope),
                StageBindingsJson=Bindings(candidate,pair),RetentionDays=retention.Days,DevelopmentWriteOnce=retention.DevelopmentWriteOnce,PreparedAt=time.GetUtcNow()};
            row.RecipeSha256=Recipe(row); Validate(row);
            if(scope is not null)await scope.CheckLockedAsync(row.EnvelopeId,ct);
            db.CompletionPublicationIntents.Add(row); await db.SaveChangesAsync(ct);
            await audit.AppendAsync(row.EnvelopeId,"completion_publication_prepared",null,null,null,ct,Evidence(row),PartyType.System);
            await Recheck(candidate,pair,ct); if(scope is not null)await scope.CheckLockedAsync(row.EnvelopeId,ct); commitStarted=true; await transaction.CommitAsync(ct); return row;
        }
        catch(Exception error) when(commitStarted && error is not OperationCanceledException && error is not OutOfMemoryException)
        {db.ChangeTracker.Clear(); var recovered=await Intent(candidate.EnvelopeId,ct); if(recovered is null)throw; return await PrepareIntent(candidate,pair,ct);}
    }
    private async Task CheckIntent(CompletionPublicationIntent row,CompletionCandidateData candidate,CompletionSealPair pair,Envelope? envelope,CancellationToken ct)
    {
        Validate(row); var saved=await Intent(row.EnvelopeId,ct);
        if(envelope is null || saved is null || saved.Id!=row.Id || !saved.RowVersion.AsSpan().SequenceEqual(row.RowVersion) || !Same(saved.RecipeSha256,row.RecipeSha256) ||
            row.CandidateId!=candidate.Id || row.ExecutedOutputId!=pair.Executed.Id || row.CertificateOutputId!=pair.Certificate.Id ||
            row.StageBindingsJson!=Bindings(candidate,pair) || JsonSerializer.Serialize(envelope)!=row.BeforeEnvelopeJson)throw new DocumentConflictException();
        // An explicit development exception cannot survive a move to a hosted runtime or ordinary envelope.
        if(row.DevelopmentWriteOnce && (!environment.IsDevelopment() || !Before(row).IsDemo || !options.AllowDevelopmentWriteOnce))throw Invalid();
        _=await Proof(row.EnvelopeId,"completion_publication_prepared",Evidence(row),ct); await Recheck(candidate,pair,ct);
    }
    private async Task Recheck(CompletionCandidateData candidate,CompletionSealPair pair,CancellationToken ct,PublishedCompletionSource? published=null)
    {
        await collector.RecheckLockedAsync(candidate.EnvelopeId,candidate.FrozenStateSha256,ct,candidate.AuditSequence,candidate.AuditAnchor,published);
        var saved=await db.CompletionCandidates.AsNoTracking().SingleAsync(x=>x.Id==candidate.Id && x.EnvelopeId==candidate.EnvelopeId,ct);
        if(!saved.RowVersion.AsSpan().SequenceEqual(candidate.RowVersion) || !Same(saved.RecipeSha256,candidate.RecipeSha256))throw new DocumentConflictException();
        foreach(var output in new[]{pair.Executed,pair.Certificate})
        {
            var stage=await db.CompletionSealOutputs.AsNoTracking().SingleAsync(x=>x.Id==output.Id && x.EnvelopeId==candidate.EnvelopeId && x.CandidateId==candidate.Id,ct);
            var proof=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==candidate.EnvelopeId && x.Sequence==output.AuditSequence,ct);
            if(!stage.RowVersion.AsSpan().SequenceEqual(output.RowVersion) || !Same(stage.RecipeSha256,output.RecipeSha256) || !Same(stage.PdfSha256,output.Pdf.Sha256) || !Same(proof.Hash,output.AuditHash))throw new DocumentConflictException();
        }
    }
    private async Task<PublishedCompletionSource> PublishedSource(CompletionPublicationIntent intent,CompletionPublicationResult result,CancellationToken ct)
    {
        Validate(intent);
        var currentIntent=await Intent(intent.EnvelopeId,ct); var currentResult=await Result(intent.EnvelopeId,ct);
        if(currentIntent is null || currentResult is null || currentIntent.Id!=intent.Id || currentResult.Id!=result.Id ||
            !currentIntent.RowVersion.AsSpan().SequenceEqual(intent.RowVersion) || !currentResult.RowVersion.AsSpan().SequenceEqual(result.RowVersion) ||
            !Same(currentIntent.RecipeSha256,intent.RecipeSha256) || !Same(currentResult.RecipeSha256,result.RecipeSha256) ||
            result.EnvelopeId!=intent.EnvelopeId || result.IntentId!=intent.Id || result.CompletedAt<intent.PreparedAt || result.CompletedAt>time.GetUtcNow() ||
            result.AuditSequence is <1 or >512 || result.FinalDocumentsJson.Length>16384 || !Same(result.IntentRecipeSha256,intent.RecipeSha256) || !Same(result.RecipeSha256,Recipe(result)))throw Invalid();
        var prepared=await Proof(intent.EnvelopeId,"completion_publication_prepared",Evidence(intent),ct);
        var completed=await Proof(intent.EnvelopeId,"completed",Evidence(result),ct);
        if(prepared.At<intent.PreparedAt || prepared.Sequence>=completed.Sequence || completed.Sequence!=result.AuditSequence || completed.At<result.CompletedAt)throw Invalid();
        var context=new PublishedCompletionSource(intent.BeforeEnvelopeJson,result.AfterEnvelopeSha256.ToArray(),result.AuditSequence);
        _=context.Project(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==intent.EnvelopeId,ct)); return context;
    }
    private async Task<AuditEvent> Proof(Guid id,string kind,string json,CancellationToken ct)
    {
        var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={id} AND [Event]={kind}").SingleAsync(ct);
        if(size>65536)throw Invalid();
        var rows=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==id && x.Event==kind).Take(2).ToArrayAsync(ct);
        if(rows.Length!=1 || rows[0].ActorType!=PartyType.System || rows[0].ActorId is not null || rows[0].ActorEmail is not null || rows[0].Ip is not null ||
            rows[0].UserAgent is not null || rows[0].DataJson!=json || !Same(rows[0].Hash,AuditHash.Compute(rows[0])))throw Invalid(); return rows[0];
    }
    private async Task<FinalStoredDocument> Upload(CompletionPublicationIntent intent,FinalDocumentKind kind,byte[] bytes,byte[] hash,DateTimeOffset? until,CancellationToken ct)
    {
        var target=new FinalDocument(intent.EnvelopeId,kind,kind==FinalDocumentKind.Executed ? intent.ExecutedObjectId : intent.CertificateObjectId);
        var authority=CompletionFinalCapability.Write(target,bytes.LongLength,hash,until,intent.DevelopmentWriteOnce,time);
        using var input=new MemoryStream(bytes,false); var receipt=await final.WriteAsync(authority,target,input,bytes.LongLength,hash,until,ct);
        CheckDocument(receipt,intent,kind,bytes.LongLength,hash,until,false);
        var read=await Download(receipt,intent,ct); if(!read.AsSpan().SequenceEqual(bytes))throw Invalid(); return receipt;
    }
    private async Task<byte[]> Download(FinalStoredDocument reference,CompletionPublicationIntent intent,CancellationToken ct)
    {
        using var output=new MemoryStream(); using var bounded=new BoundedDocumentStream(output,64*1024*1024);
        await final.ReadAsync(CompletionFinalCapability.Read(reference,time),reference,bounded,ct);
        if(output.Length!=reference.Length || !Same(SHA256.HashData(output.GetBuffer().AsSpan(0,checked((int)output.Length))),reference.Sha256))throw Invalid(); return output.ToArray();
    }
    private void CheckDocument(FinalStoredDocument value,CompletionPublicationIntent intent,FinalDocumentKind kind,long length,byte[] hash,DateTimeOffset? until,bool historical)
    {
        if(value.Document!=new FinalDocument(intent.EnvelopeId,kind,kind==FinalDocumentKind.Executed ? intent.ExecutedObjectId : intent.CertificateObjectId) ||
            value.Length!=length || !Same(value.Sha256,hash) || !Enum.IsDefined(value.Protection) || value.ETag.Length is <1 or >256 || value.VersionId.Length>256 ||
            value.CreatedAt==default || value.CreatedAt>time.GetUtcNow().AddMinutes(1) || value.Protection!=FinalProtection.LockedTime && value.ProtectedUntil is not null || value.Protection!=FinalProtection.DevelopmentWriteOnce && string.IsNullOrEmpty(value.VersionId) ||
            value.Protection==FinalProtection.DevelopmentWriteOnce && (!intent.DevelopmentWriteOnce || !Before(intent).IsDemo || !environment.IsDevelopment() || !options.AllowDevelopmentWriteOnce) ||
            value.Protection==FinalProtection.LockedTime && (until is null || value.ProtectedUntil<until || value.ProtectedUntil is null) ||
            !historical && value.Protection==FinalProtection.LockedTime && value.ProtectedUntil<=time.GetUtcNow())throw Invalid();
    }
    private static void Apply(Envelope envelope,CompletionPublicationIntent intent,CompletionSealPair pair,DateTimeOffset at)
    {
        envelope.Status=EnvelopeStatus.Completed; envelope.CompletedAt=at; envelope.FinalBlob=intent.ExecutedObjectId.ToString("N"); envelope.FinalSha256=pair.Executed.Pdf.Sha256.ToArray();
        envelope.CertificateBlob=intent.CertificateObjectId.ToString("N"); envelope.CertificateSha256=pair.Certificate.Pdf.Sha256.ToArray(); envelope.SealProvider=pair.Executed.Pdf.Provider;
        using var leaf=X509CertificateLoader.LoadCertificate(pair.Executed.Pdf.CertificateDer); envelope.SealCertThumbprint=leaf.Thumbprint;
        envelope.PurgeAfter=new FinalRetention(intent.RetentionDays,intent.DevelopmentWriteOnce).RequiredUntil(at);
    }
    private void Validate(CompletionPublicationIntent row)
    {
        if(row.Id==Guid.Empty || row.EnvelopeId==Guid.Empty || row.CandidateId==Guid.Empty || row.ExecutedOutputId==Guid.Empty || row.CertificateOutputId==Guid.Empty ||
            row.ExecutedObjectId==Guid.Empty || row.CertificateObjectId==Guid.Empty || row.ExecutedObjectId==row.CertificateObjectId || row.RetentionDays is <0 or >36500 ||
            row.BeforeEnvelopeJson.Length>262144 || row.StageBindingsJson.Length>16384 || row.PreparedAt==default || row.PreparedAt>time.GetUtcNow() || !Same(row.RecipeSha256,Recipe(row)))throw Invalid();
        var before=Before(row); if(before.Id!=row.EnvelopeId || before.Status!=EnvelopeStatus.Sent || before.RowVersion.Length!=8 || before.IsDemo && row.RetentionDays==0)throw Invalid();
    }
    private async Task<CompletionPublicationIntent?> Intent(Guid id,CancellationToken ct)
    {
        await Bounds(id,true,ct); return await db.CompletionPublicationIntents.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==id,ct);
    }
    private async Task<CompletionPublicationResult?> Result(Guid id,CancellationToken ct)
    {
        await Bounds(id,false,ct); return await db.CompletionPublicationResults.AsNoTracking().SingleOrDefaultAsync(x=>x.EnvelopeId==id,ct);
    }
    private async Task Bounds(Guid id,bool intent,CancellationToken ct)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        var size=intent ? await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([BeforeEnvelopeJson]))+DATALENGTH([StageBindingsJson])),0) AS [Value] FROM [CompletionPublicationIntents] WHERE [EnvelopeId]={id}").SingleAsync(ct) :
            await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([FinalDocumentsJson]))),0) AS [Value] FROM [CompletionPublicationResults] WHERE [EnvelopeId]={id}").SingleAsync(ct);
        if(size>(intent ? 557056 : 32768))throw Invalid();
    }
    private Task<Envelope?> Locked(Guid id,CancellationToken ct)=>db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
    private static Envelope Before(CompletionPublicationIntent row)=>JsonSerializer.Deserialize<Envelope>(row.BeforeEnvelopeJson) ?? throw Invalid();
    private static string Bindings(CompletionCandidateData candidate,CompletionSealPair pair)=>JsonSerializer.Serialize(new {candidate.Id,candidate.EnvelopeId,candidate.RecipeSha256,candidate.RowVersion,
        candidate.FrozenStateSha256,candidate.AuditSequence,candidate.AuditAnchor,outputs=new[]{pair.Executed,pair.Certificate}.Select(x=>new {x.Id,x.PdfObjectId,x.Kind,x.RecipeSha256,x.RowVersion,x.AuditSequence,x.AuditHash,x.Pdf.Sha256})});
    internal static byte[] Recipe(CompletionPublicationIntent row)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {Version,row.Id,row.EnvelopeId,row.CandidateId,row.ExecutedOutputId,row.CertificateOutputId,
        row.ExecutedObjectId,row.CertificateObjectId,beforeSha256=SHA256.HashData(Encoding.UTF8.GetBytes(row.BeforeEnvelopeJson)),stagesSha256=SHA256.HashData(Encoding.UTF8.GetBytes(row.StageBindingsJson)),row.RetentionDays,row.DevelopmentWriteOnce,row.PreparedAt}));
    internal static byte[] Recipe(CompletionPublicationResult row)=>SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {Version,row.Id,row.EnvelopeId,row.IntentId,row.CompletedAt,row.AfterEnvelopeSha256,
        row.IntentRecipeSha256,row.AuditSequence,documentsSha256=SHA256.HashData(Encoding.UTF8.GetBytes(row.FinalDocumentsJson))}));
    internal static string Evidence(CompletionPublicationIntent row)=>JsonSerializer.Serialize(new {Version,intentId=row.Id,row.CandidateId,row.ExecutedOutputId,row.CertificateOutputId,row.ExecutedObjectId,row.CertificateObjectId,
        row.RetentionDays,row.DevelopmentWriteOnce,row.PreparedAt,recipeSha256=Convert.ToHexStringLower(row.RecipeSha256),serverEvidence="stable_final_targets_reserved_before_upload"});
    internal static string Evidence(CompletionPublicationResult row)=>JsonSerializer.Serialize(new {Version,publicationId=row.Id,row.IntentId,row.CompletedAt,row.AuditSequence,
        recipeSha256=Convert.ToHexStringLower(row.RecipeSha256),serverEvidence="exact_verified_pair_published_with_selected_retention"});
    private static bool Same(byte[]? a,byte[]? b)=>CompletionEvidenceValidation.Same(a,b);
    private static InvalidDataException Invalid()=>new("The immutable final publication could not be verified.");
}
