using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
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
    internal bool UsesContext(QuillSignDbContext value)=>ReferenceEquals(db,value)&&candidates.UsesContext(value)&&seals.UsesContext(value)&&collector.UsesContext(value);
    public const string Version="completion-publication-v1";
    private sealed record Documents(FinalStoredDocument Executed,FinalStoredDocument Certificate);
    internal void DemandAdmittedComposition()
    {
        var jobs=notifications?.Invoke();
        if(jobs is null||!jobs.Enabled||!jobs.UsesContext(db))throw new InvalidOperationException("Admitted completion requires its exact durable notification preparation.");
    }

    public async Task<PublishedCompletion?> PublishAsync(Guid id,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested(); if(id==Guid.Empty)return null;
        if(await Result(id,ct) is not null)return await ReadAsync(id,ct);
        var initial=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        if(initial is not null && await UploadPolicy(initial,ct) is { } uploaded && time.GetUtcNow()>=uploaded.DeleteAfter)
            throw new CompletionPublicationUnavailableException("The document retention deadline has passed.");
        var candidate=await candidates.ReadAsync(id,ct); if(candidate is null)return await ReadAsync(id,ct);
        var pair=await seals.ReadAsync(id,ct); if(pair is null)return null;
        var intent=await PrepareIntent(candidate,pair,ct); if(intent is null)return await ReadAsync(id,ct);
        // Require coverage from this attempt through its selected interval, not merely intent creation.
        CompletionRetentionBinding.CanPublish(intent,time.GetUtcNow());
        var until=CompletionRetentionBinding.RequiredUntil(intent,time.GetUtcNow());
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
                var at=time.GetUtcNow();CompletionRetentionBinding.CanPublish(intent,at);var required=CompletionRetentionBinding.RequiredUntil(intent,at);
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
                await ProductionRecordRetentionAccess.AnchorLockedIfEnrolledAsync(db,id,time,ct);
                if(notifications is not null)notificationIds=await notifications().PrepareLockedAsync(id,ct);
                if(scope is not null)await scope.CheckLockedAsync(id,ct);
                CompletionRetentionBinding.CanPublish(intent,time.GetUtcNow());
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
        =>await ReadCore(id,ct,false);
    internal Task<PublishedCompletion?> ReadLockedAsync(Guid id,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A caller-owned completion transaction is required.");
        return ReadCore(id,ct,true);
    }
    private async Task<PublishedCompletion?> ReadCore(Guid id,CancellationToken ct,bool locked)
    {
        ct.ThrowIfCancellationRequested(); if(id==Guid.Empty)return null;
        try
        {
            var result=await Result(id,ct); if(result is null)return null;
            var intent=await Intent(id,ct) ?? throw Invalid();
            var context=await PublishedSource(intent,result,ct);
            var pair=(locked ? await seals.ReadLockedAsync(id,ct,context) : await seals.ReadPublishedAsync(id,context,ct)) ?? throw Invalid();
            var candidate=(locked ? await candidates.ReadLockedAsync(id,ct,context) : await candidates.ReadPublishedAsync(id,context,ct)) ?? throw Invalid();
            if(intent.StageBindingsJson!=await BoundStages(candidate,pair,Before(intent),ct))throw Invalid();
            var documents=JsonSerializer.Deserialize<Documents>(result.FinalDocumentsJson) ?? throw Invalid();
            var until=CompletionRetentionBinding.RequiredUntil(intent,result.CompletedAt);
            CheckDocument(documents.Executed,intent,FinalDocumentKind.Executed,pair.Executed.Pdf.Bytes.LongLength,pair.Executed.Pdf.Sha256,until,true);
            CheckDocument(documents.Certificate,intent,FinalDocumentKind.Certificate,pair.Certificate.Pdf.Bytes.LongLength,pair.Certificate.Pdf.Sha256,until,true);
            var expected=Before(intent); Apply(expected,intent,pair,result.CompletedAt);
            var current=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id,ct); expected.RowVersion=current.RowVersion;
            if(!Same(PublishedCompletionSource.Digest(expected),result.AfterEnvelopeSha256))throw Invalid();
            var deadline=await ProductionReadDeadline(current,intent,ct);
            var executed=await Download(documents.Executed,intent,ct,deadline); var certificate=await Download(documents.Certificate,intent,ct,deadline);
            if(!executed.AsSpan().SequenceEqual(pair.Executed.Pdf.Bytes) || !certificate.AsSpan().SequenceEqual(pair.Certificate.Pdf.Bytes))throw Invalid();
            await using(var transaction=locked ? null : await db.Database.BeginTransactionAsync(ct))
            {
                _=await Locked(id,ct); _=await PublishedSource(intent,result,ct);
                if(await ProductionReadDeadline(current,intent,ct)!=deadline)throw Invalid();
                await Recheck(candidate,pair,ct,context);
                if(transaction is not null)await transaction.CommitAsync(ct);
            }
            DocumentRetentionAccess.Check(deadline,time);
            return new(id,result.CompletedAt,documents.Executed,documents.Certificate,executed,certificate) {
                PublicationId=result.Id,PublicationRecipeSha256=result.RecipeSha256.ToArray(),PublicationRowVersion=result.RowVersion.ToArray()};
        }
        catch(Azure.RequestFailedException) {throw new IOException("Final completion storage is unavailable.");}
        catch(Exception error) when(error is JsonException or FormatException or InvalidOperationException or ArgumentException or UnauthorizedAccessException or KeyNotFoundException or DocumentConflictException)
        {throw Invalid();}
    }

    internal async Task<CompletionPublicationIntent?> ReadIntentLockedAsync(CompletionCandidateData candidate,CompletionSealPair pair,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A caller-owned completion transaction is required.");
        var row=await Intent(candidate.EnvelopeId,ct);if(row is null)return null;
        await CheckIntent(row,candidate,pair,await Locked(row.EnvelopeId,ct),ct);return row;
    }
    internal async Task<CompletionPublicationIntent> CreateIntentLockedAsync(CompletionCandidateData candidate,CompletionSealPair pair,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw new InvalidOperationException("A clean caller-owned completion transaction is required.");
        var envelope=await Locked(candidate.EnvelopeId,ct)??throw Invalid();
        if(await Intent(envelope.Id,ct) is not null||await Result(envelope.Id,ct) is not null)throw Invalid();
        await Recheck(candidate,pair,ct);
        if(envelope.Status!=EnvelopeStatus.Sent||envelope.CompletedAt is not null||envelope.FinalBlob is not null||envelope.FinalSha256 is not null||
            envelope.CertificateBlob is not null||envelope.CertificateSha256 is not null||envelope.SealProvider is not null||envelope.SealCertThumbprint is not null)throw Invalid();
        var upload=await UploadPolicy(envelope,ct);var production=await ProductionRecordRetentionAccess.EnrollmentAsync(db,envelope,time,ct);
        if(production is not null&&upload is not null)throw Invalid();
        var retention=production is not null?new FinalRetention(production.Snapshot.Policy.CompletedDays,false):
            upload is null?options.Select(envelope,environment):new FinalRetention(upload.Days,options.AllowDevelopmentWriteOnce&&environment.IsDevelopment()&&envelope.IsDemo);
        var row=new CompletionPublicationIntent{EnvelopeId=envelope.Id,CandidateId=candidate.Id,ExecutedOutputId=pair.Executed.Id,CertificateOutputId=pair.Certificate.Id,
            BeforeEnvelopeJson=JsonSerializer.Serialize(envelope),StageBindingsJson=production is null?CompletionRetentionBinding.Bind(Bindings(candidate,pair),upload):
                ProductionCompletionRetentionBinding.Bind(Bindings(candidate,pair),production),RetentionDays=retention.Days,DevelopmentWriteOnce=retention.DevelopmentWriteOnce,PreparedAt=time.GetUtcNow()};
        row.RecipeSha256=Recipe(row);Validate(row);CompletionRetentionBinding.CanPublish(row,time.GetUtcNow());return row;
    }
    internal async Task InsertIntentLockedAsync(CompletionPublicationIntent row,CompletionCandidateData candidate,CompletionSealPair pair,DateTimeOffset recordedAt,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges()||recordedAt.Offset!=TimeSpan.Zero||recordedAt<row.PreparedAt||recordedAt>time.GetUtcNow())throw Invalid();
        var envelope=await Locked(row.EnvelopeId,ct);Validate(row);
        if(envelope is null||row.BeforeEnvelopeJson!=JsonSerializer.Serialize(envelope)||row.StageBindingsJson!=await BoundStages(candidate,pair,envelope,ct)||
            row.CandidateId!=candidate.Id||row.ExecutedOutputId!=pair.Executed.Id||row.CertificateOutputId!=pair.Certificate.Id||await Intent(row.EnvelopeId,ct) is not null)throw Invalid();
        await Recheck(candidate,pair,ct);if(scope is not null)await scope.CheckLockedAsync(row.EnvelopeId,ct);
        db.CompletionPublicationIntents.Add(row);await db.SaveChangesAsync(ct);
        await new AuditWriter(db,new CompletionRecordedTime(recordedAt)).AppendAsync(row.EnvelopeId,"completion_publication_prepared",null,null,null,ct,Evidence(row),PartyType.System);
        await Recheck(candidate,pair,ct);if(scope is not null)await scope.CheckLockedAsync(row.EnvelopeId,ct);CompletionRetentionBinding.CanPublish(row,time.GetUtcNow());
    }
    internal async Task<CompletionPublicationTransition> CreateResultLockedAsync(CompletionPublicationIntent intent,CompletionCandidateData candidate,
        CompletionSealPair pair,CompletionPublicationFiles files,DateTimeOffset recordedAt,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw new InvalidOperationException("A clean caller-owned completion transaction is required.");
        var envelope=await Locked(intent.EnvelopeId,ct)??throw Invalid();if(await Result(envelope.Id,ct) is not null)throw Invalid();
        await CheckIntent(intent,candidate,pair,envelope,ct);
        var at=recordedAt;if(files.ResultId==Guid.Empty||at.Offset!=TimeSpan.Zero||at<intent.PreparedAt||at>time.GetUtcNow())throw Invalid();
        CompletionRetentionBinding.CanPublish(intent,time.GetUtcNow());var required=CompletionRetentionBinding.RequiredUntil(intent,at);
        CheckDocument(files.Executed,intent,FinalDocumentKind.Executed,pair.Executed.Pdf.Bytes.LongLength,pair.Executed.Pdf.Sha256,required,false);
        CheckDocument(files.Certificate,intent,FinalDocumentKind.Certificate,pair.Certificate.Pdf.Bytes.LongLength,pair.Certificate.Pdf.Sha256,required,false);
        var sequence=(await db.AuditEvents.Where(x=>x.EnvelopeId==envelope.Id).MaxAsync(x=>(long?)x.Sequence,ct)??0)+1;if(sequence is <1 or >512)throw Invalid();
        var completed=JsonSerializer.Deserialize<Envelope>(JsonSerializer.Serialize(envelope))??throw Invalid();Apply(completed,intent,pair,at);
        var result=new CompletionPublicationResult{Id=files.ResultId,EnvelopeId=envelope.Id,IntentId=intent.Id,CompletedAt=at,AuditSequence=sequence,
            FinalDocumentsJson=JsonSerializer.Serialize(new Documents(files.Executed,files.Certificate)),IntentRecipeSha256=intent.RecipeSha256.ToArray()};
        // These hashes depend on the actual SQL-generated completed rowversion;
        // the pre-SQL semantic plan binds their exact producer relation instead.
        var roster=notifications is null?[]:await CompletionNotificationJobs.FreezeRosterLockedAsync(db,envelope.Id,ct);
        return new(intent,candidate,pair,files,envelope,completed,result,at,roster);
    }
    internal async Task<Guid[]> InsertResultLockedAsync(CompletionPublicationTransition transition,
        Func<Guid,DateTimeOffset,CancellationToken,Task> demandHint,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges()||transition.RecordedAt.Offset!=TimeSpan.Zero||transition.RecordedAt>time.GetUtcNow())throw Invalid();
        var id=transition.Result.EnvelopeId;var envelope=await Locked(id,ct);var intent=transition.Intent;
        if(envelope is null||JsonSerializer.Serialize(envelope)!=JsonSerializer.Serialize(transition.Before)||
            transition.Result.Id!=transition.Files.ResultId||transition.Result.CompletedAt!=transition.RecordedAt||transition.Result.AfterEnvelopeSha256.Length!=0||transition.Result.RecipeSha256.Length!=0||await Result(id,ct) is not null)throw Invalid();
        if(transition.Result.AuditSequence!=(await db.AuditEvents.Where(x=>x.EnvelopeId==id).MaxAsync(x=>(long?)x.Sequence,ct)??0)+1)throw Invalid();
        await CheckIntent(intent,transition.Candidate,transition.Pair,envelope,ct);
        var currentRoster=notifications is null?[]:await CompletionNotificationJobs.FreezeRosterLockedAsync(db,id,ct);
        if(!currentRoster.SequenceEqual(transition.Notifications))throw Invalid();
        var projected=JsonSerializer.Deserialize<Envelope>(JsonSerializer.Serialize(envelope))??throw Invalid();Apply(projected,intent,transition.Pair,transition.RecordedAt);
        if(JsonSerializer.Serialize(projected)!=JsonSerializer.Serialize(transition.Completed)||
            transition.Result.FinalDocumentsJson!=JsonSerializer.Serialize(new Documents(transition.Files.Executed,transition.Files.Certificate))||
            transition.Result.IntentId!=intent.Id||!Same(transition.Result.IntentRecipeSha256,intent.RecipeSha256))throw Invalid();
        var required=CompletionRetentionBinding.RequiredUntil(intent,transition.RecordedAt);
        CheckDocument(transition.Files.Executed,intent,FinalDocumentKind.Executed,transition.Pair.Executed.Pdf.Bytes.LongLength,transition.Pair.Executed.Pdf.Sha256,required,false);
        CheckDocument(transition.Files.Certificate,intent,FinalDocumentKind.Certificate,transition.Pair.Certificate.Pdf.Bytes.LongLength,transition.Pair.Certificate.Pdf.Sha256,required,false);
        if(scope is not null)await scope.CheckLockedAsync(id,ct);
        db.Update(transition.Completed);await db.SaveChangesAsync(ct);
        var result=transition.Result;result.AfterEnvelopeSha256=PublishedCompletionSource.Digest(transition.Completed);result.RecipeSha256=Recipe(result);
        db.CompletionPublicationResults.Add(result);await db.SaveChangesAsync(ct);
        var recorded=new CompletionRecordedTime(transition.RecordedAt);
        await new AuditWriter(db,recorded).AppendAsync(id,"completed",null,null,null,ct,Evidence(result),PartyType.System);
        await ProductionRecordRetentionAccess.AnchorLockedIfEnrolledAsync(db,id,recorded,ct);
        var ids=notifications is null?[]:await notifications().PrepareLockedAsync(id,ct,demandHint,transition.RecordedAt);
        if(scope is not null)await scope.CheckLockedAsync(id,ct);CompletionRetentionBinding.CanPublish(intent,time.GetUtcNow());return ids;
    }
    internal Task PublishNotificationsAsync(IEnumerable<Guid> ids,CancellationToken ct)=>notifications is null?Task.CompletedTask:notifications().PublishAsync(ids,ct);

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
            var upload=await UploadPolicy(envelope,ct);
            var production=await ProductionRecordRetentionAccess.EnrollmentAsync(db,envelope,time,ct);
            if(production is not null && upload is not null)throw Invalid();
            var retention=production is not null ? new FinalRetention(production.Snapshot.Policy.CompletedDays,false) :
                upload is null ? options.Select(envelope,environment) : new FinalRetention(upload.Days,options.AllowDevelopmentWriteOnce && environment.IsDevelopment() && envelope.IsDemo);
            var row=new CompletionPublicationIntent {EnvelopeId=candidate.EnvelopeId,CandidateId=candidate.Id,
                ExecutedOutputId=pair.Executed.Id,CertificateOutputId=pair.Certificate.Id,BeforeEnvelopeJson=JsonSerializer.Serialize(envelope),
                StageBindingsJson=production is null ? CompletionRetentionBinding.Bind(Bindings(candidate,pair),upload) :
                    ProductionCompletionRetentionBinding.Bind(Bindings(candidate,pair),production),RetentionDays=retention.Days,DevelopmentWriteOnce=retention.DevelopmentWriteOnce,PreparedAt=time.GetUtcNow()};
            row.RecipeSha256=Recipe(row); Validate(row);CompletionRetentionBinding.CanPublish(row,time.GetUtcNow());
            if(scope is not null)await scope.CheckLockedAsync(row.EnvelopeId,ct);
            db.CompletionPublicationIntents.Add(row); await db.SaveChangesAsync(ct);
            await audit.AppendAsync(row.EnvelopeId,"completion_publication_prepared",null,null,null,ct,Evidence(row),PartyType.System);
            await Recheck(candidate,pair,ct); if(scope is not null)await scope.CheckLockedAsync(row.EnvelopeId,ct);CompletionRetentionBinding.CanPublish(row,time.GetUtcNow());commitStarted=true; await transaction.CommitAsync(ct); return row;
        }
        catch(Exception error) when(commitStarted && error is not OperationCanceledException && error is not OutOfMemoryException)
        {db.ChangeTracker.Clear(); var recovered=await Intent(candidate.EnvelopeId,ct); if(recovered is null)throw; return await PrepareIntent(candidate,pair,ct);}
    }
    private async Task CheckIntent(CompletionPublicationIntent row,CompletionCandidateData candidate,CompletionSealPair pair,Envelope? envelope,CancellationToken ct)
    {
        Validate(row); var saved=await Intent(row.EnvelopeId,ct);
        if(envelope is null || saved is null || saved.Id!=row.Id || !saved.RowVersion.AsSpan().SequenceEqual(row.RowVersion) || !Same(saved.RecipeSha256,row.RecipeSha256) ||
            row.CandidateId!=candidate.Id || row.ExecutedOutputId!=pair.Executed.Id || row.CertificateOutputId!=pair.Certificate.Id ||
            row.StageBindingsJson!=await BoundStages(candidate,pair,envelope,ct) || JsonSerializer.Serialize(envelope)!=row.BeforeEnvelopeJson)throw new DocumentConflictException();
        // An explicit development exception cannot survive a move to a hosted runtime or ordinary envelope.
        if(row.DevelopmentWriteOnce && (!environment.IsDevelopment() || !Before(row).IsDemo || !options.AllowDevelopmentWriteOnce))throw Invalid();
        CompletionRetentionBinding.CanPublish(row,time.GetUtcNow());
        _=await Proof(row.EnvelopeId,"completion_publication_prepared",Evidence(row),ct); await Recheck(candidate,pair,ct);CompletionRetentionBinding.CanPublish(row,time.GetUtcNow());
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
        if(CompletionRetentionBinding.FixedUntil(intent) is DateTimeOffset deadline && result.CompletedAt>=deadline)throw Invalid();
        if(!CompletionRetentionBinding.Matches(intent,await UploadPolicy(Before(intent),ct)))throw Invalid();
        if(!ProductionCompletionRetentionBinding.Matches(intent,await ProductionRecordRetentionAccess.EnrollmentAsync(db,Before(intent),time,ct)))throw Invalid();
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
        CompletionRetentionBinding.CanPublish(intent,time.GetUtcNow());
        var authority=CompletionRetentionBinding.FixedUntil(intent) is DateTimeOffset fixedUntil
            ? CompletionFinalCapability.WriteFixed(target,bytes.LongLength,hash,fixedUntil,intent.DevelopmentWriteOnce,time)
            : CompletionFinalCapability.Write(target,bytes.LongLength,hash,until,intent.DevelopmentWriteOnce,time);
        using var input=new MemoryStream(bytes,false); var receipt=await final.WriteAsync(authority,target,input,bytes.LongLength,hash,until,ct);
        CompletionRetentionBinding.CanPublish(intent,time.GetUtcNow());
        CheckDocument(receipt,intent,kind,bytes.LongLength,hash,until,false);
        var read=await Download(receipt,intent,ct);CompletionRetentionBinding.CanPublish(intent,time.GetUtcNow());if(!read.AsSpan().SequenceEqual(bytes))throw Invalid(); return receipt;
    }
    private async Task<DateTimeOffset?> ProductionReadDeadline(Envelope envelope,CompletionPublicationIntent intent,CancellationToken ct)
    {
        if(ProductionCompletionRetentionBinding.Read(intent) is null)return null;
        await using var owned=db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var retained=await ProductionRecordRetentionAccess.ReadLockedAsync(db,envelope,time,ct);
        if(retained.Kind!=ProductionEnrollmentKind.Enrolled || retained.Stage!=ProductionRecordStage.Completed)throw Invalid();
        DocumentRetentionAccess.Check(retained.Deadline,time);
        if(owned is not null)await owned.RollbackAsync(ct);
        return retained.Deadline;
    }
    private async Task<byte[]> Download(FinalStoredDocument reference,CompletionPublicationIntent intent,CancellationToken ct,DateTimeOffset? accessUntil=null)
    {
        using var output=new MemoryStream(); using var bounded=new BoundedDocumentStream(output,64*1024*1024);
        var authority=CompletionRetentionBinding.FixedUntil(intent) is DateTimeOffset until
            ? CompletionFinalCapability.ReadFixed(reference,until,time) : CompletionFinalCapability.ReadBounded(reference,time,accessUntil);
        await final.ReadAsync(authority,reference,bounded,ct);
        if(output.Length!=reference.Length || !Same(SHA256.HashData(output.GetBuffer().AsSpan(0,checked((int)output.Length))),reference.Sha256))throw Invalid(); return output.ToArray();
    }
    private void CheckDocument(FinalStoredDocument value,CompletionPublicationIntent intent,FinalDocumentKind kind,long length,byte[] hash,DateTimeOffset? until,bool historical)
    {
        if(CompletionRetentionBinding.FixedUntil(intent) is DateTimeOffset deadline &&
            (value.Protection==FinalProtection.LegalHold || value.Protection==FinalProtection.LockedTime && value.ProtectedUntil!=deadline))throw Invalid();
        if(value.Document!=new FinalDocument(intent.EnvelopeId,kind,kind==FinalDocumentKind.Executed ? intent.ExecutedObjectId : intent.CertificateObjectId) ||
            value.Length!=length || !Same(value.Sha256,hash) || !Enum.IsDefined(value.Protection) || value.ETag.Length is <1 or >256 || value.VersionId.Length>256 ||
            value.CreatedAt==default || value.CreatedAt>time.GetUtcNow().AddMinutes(1) || value.Protection!=FinalProtection.LockedTime && value.ProtectedUntil is not null || value.Protection!=FinalProtection.DevelopmentWriteOnce && string.IsNullOrEmpty(value.VersionId) ||
            value.Protection==FinalProtection.DevelopmentWriteOnce && (!intent.DevelopmentWriteOnce || !Before(intent).IsDemo || !environment.IsDevelopment() || !options.AllowDevelopmentWriteOnce) ||
            value.Protection==FinalProtection.LockedTime && (until is null || value.ProtectedUntil<until || value.ProtectedUntil is null) ||
            !historical && value.Protection==FinalProtection.LockedTime && value.ProtectedUntil<=time.GetUtcNow())throw Invalid();
    }
    internal static void Apply(Envelope envelope,CompletionPublicationIntent intent,CompletionSealPair pair,DateTimeOffset at)
    {
        envelope.Status=EnvelopeStatus.Completed; envelope.CompletedAt=at; envelope.FinalBlob=intent.ExecutedObjectId.ToString("N"); envelope.FinalSha256=pair.Executed.Pdf.Sha256.ToArray();
        envelope.CertificateBlob=intent.CertificateObjectId.ToString("N"); envelope.CertificateSha256=pair.Certificate.Pdf.Sha256.ToArray(); envelope.SealProvider=pair.Executed.Pdf.Provider;
        using var leaf=X509CertificateLoader.LoadCertificate(pair.Executed.Pdf.CertificateDer); envelope.SealCertThumbprint=leaf.Thumbprint;
        envelope.PurgeAfter=CompletionRetentionBinding.RequiredUntil(intent,at);
    }
    private void Validate(CompletionPublicationIntent row)
    {
        if(row.Id==Guid.Empty || row.EnvelopeId==Guid.Empty || row.CandidateId==Guid.Empty || row.ExecutedOutputId==Guid.Empty || row.CertificateOutputId==Guid.Empty ||
            row.ExecutedObjectId==Guid.Empty || row.CertificateObjectId==Guid.Empty || row.ExecutedObjectId==row.CertificateObjectId || row.RetentionDays is <0 or >36500 ||
            row.BeforeEnvelopeJson.Length>262144 || row.StageBindingsJson.Length>16384 || row.PreparedAt==default || row.PreparedAt>time.GetUtcNow() || !Same(row.RecipeSha256,Recipe(row)))throw Invalid();
        var before=Before(row); if(before.Id!=row.EnvelopeId || before.Status!=EnvelopeStatus.Sent || before.RowVersion.Length!=8 || before.IsDemo && row.RetentionDays==0)throw Invalid();
        if(CompletionRetentionBinding.FixedUntil(row) is DateTimeOffset deadline && (!before.IsDemo || row.PreparedAt>=deadline))throw Invalid();
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
    private Task<DocumentRetentionSnapshot?> UploadPolicy(Envelope envelope,CancellationToken ct)=>new UploadRetention(db,new(),time).ReadAsync(envelope,ct);
    private async Task<string> BoundStages(CompletionCandidateData candidate,CompletionSealPair pair,Envelope envelope,CancellationToken ct)
    {
        var production=await ProductionRecordRetentionAccess.EnrollmentAsync(db,envelope,time,ct);
        return production is null ? CompletionRetentionBinding.Bind(Bindings(candidate,pair),await UploadPolicy(envelope,ct)) :
            ProductionCompletionRetentionBinding.Bind(Bindings(candidate,pair),production);
    }
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
