using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using PdfSharp.Pdf.IO;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Sealing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Completion;

// Explicit trusted composition only. It does not register or enable Sealing.
// Runtime owns SQL; this adapter owns the original protected inputs, immutable
// effects and actual engine/storage results under the same caller transaction.
internal sealed class ProductionCompletionEffects(ProductionRecordOperationAdmission operations,IDataProtectionProvider keys,
    IProductionCompletionObjectStore store,PlatformPdfSeal engine):IProductionCompletionEffects
{
    private ProductionRecordOperationAdmission Operations=>operations;
    private IDataProtectionProvider Keys=>keys;
    public async Task<CompletionOwnedRowPlan> CandidateLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,
        CompletionCandidate row,PreparedCompletionPacket packet,CancellationToken ct)
    {
        var cut=await Cut(db,scope,ct);var targets=Targets(CompletionSlot.Candidate,new CompletionEffectTarget(CompletionEffect.CandidatePdf,row.PdfObjectId));
        var context=await operations.CreateCompletionContextLockedAsync(db,scope,CompletionSlot.Candidate,targets,
            ProductionCompletionInputRows.Selectors(row,cut),operations.Clock.GetUtcNow(),ct);
        var input=ProductionCompletionInput.OwnCandidate(keys,scope.RecordId,context,row,packet,context.RecordedAt,cut);
        await Open(db,scope,input,ct);await WriteInput(db,scope,input,ct);
        await WriteObject(db,scope,context,CompletionEffect.CandidatePdf,new(new(scope.RecordId,DocumentBlobKind.CompletionCandidate,row.PdfObjectId),
            row.PdfLength,Hex(row.PdfSha256)),packet.Bytes,ct);
        return CompletionOwnedRowPlan.FromInput(keys,input);
    }
    public async Task<CompletionOwnedSeal> SealLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionCandidateData candidate,
        CompletionSealKind kind,CompletionSealTargets targets,byte[] source,CompletionSealData? executed,CancellationToken ct)
    {
        var ownedSource=source.ToArray();var boundary=new SealBoundary(this,db,scope,candidate,kind,targets,ownedSource,executed);
        var hash=SHA256.HashData(ownedSource);
        var pdf=executed is null?await engine.SealAdmittedAsync(ownedSource,hash,boundary,ct):
            await engine.SealBoundAdmittedAsync(ownedSource,hash,Convert.FromHexString(executed.Pdf.CertificateSha256),boundary,ct);
        var original=boundary.Original??throw Invalid();var context=original.Verified.Context;
        var row=CompletionSealOutputs.CreateOwned(candidate,kind,targets,ownedSource,pdf,executed);
        var input=ProductionCompletionInput.OwnSealResult(keys,original.Verified,row,pdf,context.RecordedAt);
        await WriteObject(db,scope,context,kind==CompletionSealKind.Executed?CompletionEffect.ExecutedPdf:CompletionEffect.CertificatePdf,
            new(new(scope.RecordId,kind==CompletionSealKind.Executed?DocumentBlobKind.CompletionExecutedSeal:DocumentBlobKind.CompletionCertificateSeal,row.PdfObjectId),row.PdfLength,Hex(row.PdfSha256)),pdf.Bytes,ct);
        await WriteInput(db,scope,input,ct);return new(row,pdf,CompletionOwnedRowPlan.FromInput(keys,input));
    }
    public async Task<CompletionOwnedRowPlan> IntentLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionPublicationIntent row,CancellationToken ct)
    {
        var cut=await Cut(db,scope,ct);var context=await operations.CreateCompletionContextLockedAsync(db,scope,CompletionSlot.PublicationIntent,
            Targets(CompletionSlot.PublicationIntent),ProductionCompletionInputRows.Selectors(row,cut),operations.Clock.GetUtcNow(),ct);
        var input=ProductionCompletionInput.OwnIntent(keys,scope.RecordId,context,row,context.RecordedAt,cut);
        await Open(db,scope,input,ct);await WriteInput(db,scope,input,ct);return CompletionOwnedRowPlan.FromInput(keys,input);
    }
    public async Task<CompletionPublicationFiles> PublicationLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,
        CompletionPublicationIntent intent,CompletionSealPair pair,DateTimeOffset recordedAt,DateTimeOffset? until,CancellationToken ct)
    {
        if(until!=CompletionRetentionBinding.RequiredUntil(intent,recordedAt)||recordedAt.Ticks%TimeSpan.TicksPerSecond!=0)throw Invalid();
        var original=await ReadInput(db,scope,CompletionSlot.PublicationIntent,CompletionInputKind.PublicationIntentPlan,ct);
        if(original.Body.Intent is not {} saved||saved.RowVersion is not {Length:0}||intent.RowVersion is not {Length:8})throw Invalid();
        // The protected plan precedes SQL insertion. Only SQL's generated
        // rowversion may resolve afterward; every semantic column remains exact.
        // Never mutate the original authenticated body to compare it.
        var comparable=JsonSerializer.Deserialize<CompletionPublicationIntent>(JsonSerializer.Serialize(saved))??throw Invalid();
        comparable.RowVersion=intent.RowVersion.ToArray();
        if(JsonSerializer.Serialize(comparable)!=JsonSerializer.Serialize(intent))throw Invalid();
        var resultId=Guid.NewGuid();var cut=await Cut(db,scope,ct);
        var before=JsonSerializer.Deserialize<Envelope>(intent.BeforeEnvelopeJson)??throw Invalid();
        var members=await CompletionNotificationJobs.FreezeRosterLockedAsync(db,scope.RecordId,ct);
        var targets=Targets(CompletionSlot.PublicationResult,new(CompletionEffect.PublicationExecutedFinal,intent.ExecutedObjectId),
            new(CompletionEffect.PublicationCertificateFinal,intent.CertificateObjectId));
        var context=await operations.CreateCompletionContextLockedAsync(db,scope,CompletionSlot.PublicationResult,targets,
            ProductionCompletionInputRows.ResultSelectors(before,resultId,members,cut),recordedAt,ct);
        var verified=VerifiedCompletionSlotContext.FromPublicationIntent(original,context,resultId,members);
        await operations.PreflightCompletionInputLockedAsync(db,scope,verified,ct);
        await operations.PrepareCompletionSlotLockedAsync(db,scope,verified,ct);
        var a=await WriteFinal(db,scope,context,CompletionEffect.PublicationExecutedFinal,new(scope.RecordId,FinalDocumentKind.Executed,intent.ExecutedObjectId),pair.Executed.Pdf.Bytes,until,ct);
        var b=await WriteFinal(db,scope,context,CompletionEffect.PublicationCertificateFinal,new(scope.RecordId,FinalDocumentKind.Certificate,intent.CertificateObjectId),pair.Certificate.Pdf.Bytes,until,ct);
        return new(resultId,a,b);
    }
    public async Task<CompletionOwnedRowPlan> ResultLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CompletionPublicationTransition transition,CancellationToken ct)
    {
        var saved=await operations.ReadCompletionRecoveryLockedAsync(db,scope,ct);
        var context=saved.Slots?.GetValueOrDefault(CompletionSlot.PublicationResult)?.Context??throw Invalid();
        if(context.RecordedAt!=transition.RecordedAt||transition.Result.Id!=transition.Files.ResultId)throw Invalid();
        var input=ProductionCompletionInput.OwnResult(keys,scope.RecordId,context,transition,await Cut(db,scope,ct));
        await WriteInput(db,scope,input,ct);return CompletionOwnedRowPlan.FromInput(keys,input);
    }

    private async Task Open(QuillSignDbContext db,ProductionRecordOperation scope,ProductionCompletionInput input,CancellationToken ct)
    {
        await operations.PreflightCompletionInputLockedAsync(db,scope,input.Verified,ct);
        await operations.PrepareCompletionSlotLockedAsync(db,scope,VerifiedCompletionSlotContext.FromInput(input.Verified),ct);
    }
    private async Task WriteInput(QuillSignDbContext db,ProductionRecordOperation scope,ProductionCompletionInput input,CancellationToken ct)
    {
        var state=await operations.ReadCompletionRecoveryLockedAsync(db,scope,ct);
        var sizes=state.Slots!.Values.SelectMany(x=>x.Started.Values).Where(x=>InputEffect(x.Effect)).Select(x=>x.Length).Append(input.Descriptor.Length);
        ProductionCompletionInputCodec.DemandAggregate(sizes);
        using var stream=input.Open();using var memory=new MemoryStream(checked((int)input.Descriptor.Length));stream.CopyTo(memory);
        await WriteObject(db,scope,input.Verified.Context,ProductionCompletionInputCodec.Effect(input.Verified.Kind),input.Descriptor,memory.ToArray(),ct);
    }
    private async Task<ProductionCompletionStored> WriteObject(QuillSignDbContext db,ProductionRecordOperation scope,HoldWitnessCompletionContext context,
        CompletionEffect effect,ProductionRecordWriteDescriptor descriptor,byte[] bytes,CancellationToken ct)
        =>await Write(db,scope,context,ProductionCompletionStoragePlan.Own(scope,context,effect,descriptor,bytes),ct);
    private async Task<FinalStoredDocument> WriteFinal(QuillSignDbContext db,ProductionRecordOperation scope,HoldWitnessCompletionContext context,
        CompletionEffect effect,FinalDocument target,byte[] bytes,DateTimeOffset? until,CancellationToken ct)
        =>(await Write(db,scope,context,ProductionCompletionStoragePlan.OwnFinal(scope,context,effect,target,bytes,until),ct)).Final??throw Invalid();
    private async Task<ProductionCompletionStored> Write(QuillSignDbContext db,ProductionRecordOperation scope,HoldWitnessCompletionContext context,
        ProductionCompletionStoragePlan plan,CancellationToken ct)
    {
        var permit=await operations.BeginCompletionEffectLockedAsync(db,scope,context.Slot,plan.Effect,ct);
        var fence=new WriteFence(operations,db,permit);var actual=await store.WriteAsync(plan,fence,ct);
        await operations.RecordCompletionEffectLockedAsync(db,permit,VerifiedCompletionEffectReceipt.FromStored(plan.Effect,actual),ct);return actual;
    }
    private async Task<VerifiedCompletionInput> ReadInput(QuillSignDbContext db,ProductionRecordOperation scope,CompletionSlot slot,CompletionInputKind kind,CancellationToken ct)
    {
        var state=await operations.ReadCompletionRecoveryLockedAsync(db,scope,ct);var old=state.Slots?.GetValueOrDefault(slot)??throw Invalid();
        var effect=old.Receipts.GetValueOrDefault(ProductionCompletionInputCodec.Effect(kind))??throw Invalid();var stored=effect.Stored??throw Invalid();
        var plan=ProductionCompletionStoragePlan.ReadObject(scope,old.Context,effect.Effect,stored.Item);
        var bytes=await store.ReadInputAsync(plan,new(stored,null),new ReadFence(operations,db,scope),ct);
        return ProductionCompletionInputCodec.OpenVerified(keys,scope.RecordId,old.Context,kind,stored.Item,bytes);
    }
    private static async Task<CompletionInputAuditCut> Cut(QuillSignDbContext db,ProductionRecordOperation scope,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null||db.ChangeTracker.HasChanges())throw Invalid();
        var audit=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==scope.RecordId).OrderByDescending(x=>x.Sequence).FirstAsync(ct);
        if(audit.Sequence is <1 or >512||audit.Hash is not {Length:32})throw Invalid();return new(audit.Sequence,Hex(audit.Hash));
    }
    private static CompletionEffectTarget[] Targets(CompletionSlot slot,params CompletionEffectTarget[] fixedTargets)
        =>ProductionCompletionProtocol.Effects(slot).Select(effect=>fixedTargets.SingleOrDefault(x=>x.Effect==effect)??
            new CompletionEffectTarget(effect,ProductionCompletionProtocol.Tsa(effect)?Guid.Empty:Guid.NewGuid())).ToArray();
    private static bool InputEffect(CompletionEffect e)=>e is not (CompletionEffect.CandidatePdf or CompletionEffect.ExecutedPdf or CompletionEffect.CertificateSource or
        CompletionEffect.CertificatePdf or CompletionEffect.PublicationExecutedFinal or CompletionEffect.PublicationCertificateFinal or CompletionEffect.ExecutedTsa or CompletionEffect.CertificateTsa);
    private static string Hex(byte[] value)=>Convert.ToHexStringLower(value);
    private static InvalidDataException Invalid()=>ProductionCompletionInputCodec.Invalid();

    private sealed class WriteFence(ProductionRecordOperationAdmission operations,QuillSignDbContext db,ProductionCompletionEffectPermit permit):IProductionCompletionStorageFence
    {
        public Task DemandAsync(CancellationToken ct)=>operations.DemandCompletionEffectLockedAsync(db,permit,ct);
        public Task ConsumeMutationAsync(string sha,CancellationToken ct)=>operations.ConsumeCompletionEffectRequestLockedAsync(db,permit,sha,ct);
        public Task AcknowledgeMutationAsync(string sha,CancellationToken ct)=>operations.AcknowledgeCompletionEffectRequestLockedAsync(db,permit,sha,ct);
    }
    private sealed class ReadFence(ProductionRecordOperationAdmission operations,QuillSignDbContext db,ProductionRecordOperation scope):IProductionCompletionStorageFence
    {
        public Task DemandAsync(CancellationToken ct)=>operations.DemandCompletionProgressLockedAsync(db,scope,ct);
        public Task ConsumeMutationAsync(string sha,CancellationToken ct)=>throw Invalid();
        public Task AcknowledgeMutationAsync(string sha,CancellationToken ct)=>throw Invalid();
    }
    private sealed class SealBoundary(ProductionCompletionEffects owner,QuillSignDbContext db,ProductionRecordOperation scope,
        CompletionCandidateData candidate,CompletionSealKind kind,CompletionSealTargets targets,byte[] source,CompletionSealData? executed):IProductionSealBoundary
    {
        private int prepared;internal ProductionCompletionInput? Original;
        private ProductionCompletionEffectPermit? activeTimestamp;
        public Task DemandAsync(CancellationToken ct)=>activeTimestamp is {} permit?
            owner.Operations.DemandCompletionEffectLockedAsync(db,permit,ct):owner.Operations.DemandCompletionProgressLockedAsync(db,scope,ct);
        internal void TimestampRecorded(ProductionCompletionEffectPermit permit)
        {
            if(!ReferenceEquals(activeTimestamp,permit))throw Invalid();
            activeTimestamp=null;
        }
        public async Task PrepareIdentityAsync(ProductionSealIdentity identity,CancellationToken ct)
        {
            if(Interlocked.Exchange(ref prepared,1)!=0||identity.SourceSha256!=Hex(SHA256.HashData(source)))throw Invalid();
            var slot=kind==CompletionSealKind.Executed?CompletionSlot.ExecutedSeal:CompletionSlot.CertificateSeal;
            var fixedTargets=kind==CompletionSealKind.Executed?new[]{new CompletionEffectTarget(CompletionEffect.ExecutedPdf,targets.PdfObjectId)}:
                [new CompletionEffectTarget(CompletionEffect.CertificateSource,targets.SourceObjectId),new(CompletionEffect.CertificatePdf,targets.PdfObjectId)];
            int pages;lock(SenderPdfRenderer.RenderGate){using var pdf=PdfReader.Open(new MemoryStream(source,false),PdfDocumentOpenMode.Import);pages=pdf.PageCount;}
            var cut=await Cut(db,scope,ct);var facts=new CompletionSealInputContext(candidate.Id,Hex(candidate.RecipeSha256),targets.SourceObjectId,source.LongLength,
                identity.SourceSha256,targets.RowId,targets.PdfObjectId,pages,identity.Provider,Convert.FromBase64String(identity.CertificateDer),identity.CertificateSha256,
                identity.SealedAt,executed is null?null:Hex(executed.Pdf.Sha256),executed is null?null:Hex(executed.RecipeSha256));
            var context=await owner.Operations.CreateCompletionContextLockedAsync(db,scope,slot,Targets(slot,fixedTargets),
                ProductionCompletionInputRows.Selectors(facts,cut),identity.SealedAt,ct);
            Original=ProductionCompletionInput.OwnSealContext(owner.Keys,scope.RecordId,context,facts,context.RecordedAt,cut);
            await owner.Open(db,scope,Original,ct);await owner.WriteInput(db,scope,Original,ct);
            if(kind==CompletionSealKind.Certificate)await owner.WriteObject(db,scope,context,CompletionEffect.CertificateSource,
                new(new(scope.RecordId,DocumentBlobKind.CompletionCertificateSource,targets.SourceObjectId),source.LongLength,identity.SourceSha256),source,ct);
        }
        public async Task<IProductionTimestampPermit> BeginTimestampAsync(ProductionTimestampRequest request,CancellationToken ct)
        {
            if(activeTimestamp is not null)throw Invalid();
            var original=Original??throw Invalid();if(request.StartedAt!=original.Verified.Body.SealContext!.SigningAt)throw Invalid();
            var bytes=Convert.FromBase64String(request.Encoded);if(Hex(SHA256.HashData(bytes))!=request.Sha256)throw Invalid();
            var input=ProductionCompletionInput.OwnTimestampRequest(owner.Keys,original.Verified,bytes,request.AuthoritySha256,request.StartedAt);
            await owner.WriteInput(db,scope,input,ct);var context=original.Verified.Context;
            var e=kind==CompletionSealKind.Executed?CompletionEffect.ExecutedTsa:CompletionEffect.CertificateTsa;
            var digest=ProductionCompletionProtocol.Digest(new{Version="completion-tsa-post-v1",Context=ProductionCompletionProtocol.Digest(context),request.AuthoritySha256,request.Sha256,request.StartedAt});
            var effect=new CompletionEffectDescriptor(e,Guid.Empty,bytes.LongLength,request.Sha256,1,[digest]);
            var permit=await owner.Operations.BeginCompletionEffectLockedAsync(db,scope,context.Slot,effect,ct);
            activeTimestamp=permit;
            return new TimestampPermit(owner,this,db,scope,input,request,effect,permit,digest);
        }
    }
    private sealed class TimestampPermit(ProductionCompletionEffects owner,SealBoundary boundary,QuillSignDbContext db,ProductionRecordOperation scope,
        ProductionCompletionInput input,ProductionTimestampRequest original,CompletionEffectDescriptor effect,ProductionCompletionEffectPermit permit,string requestSha):IProductionTimestampPermit
    {
        private int sent,recorded;
        public async Task DemandSendAsync(ProductionTimestampRequest request,CancellationToken ct)
        {if(request!=original||Interlocked.Exchange(ref sent,1)!=0)throw Invalid();await owner.Operations.ConsumeCompletionEffectRequestLockedAsync(db,permit,requestSha,ct);}
        public async Task RecordVerifiedAsync(ProductionTimestampRequest request,ProductionTimestampResponse response,CancellationToken ct)
        {
            if(request!=original||Volatile.Read(ref sent)!=1||Interlocked.Exchange(ref recorded,1)!=0)throw Invalid();
            var raw=Convert.FromBase64String(response.Encoded);var token=Convert.FromBase64String(response.Token);
            if(Hex(SHA256.HashData(raw))!=response.Sha256||Hex(SHA256.HashData(token))!=response.TokenSha256)throw Invalid();
            var result=ProductionCompletionInput.OwnTimestampResponse(owner.Keys,input.Verified,raw,new(token,response.At,response.CertificateSha256,response.Policy));
            await owner.Operations.AcknowledgeCompletionEffectRequestLockedAsync(db,permit,requestSha,ct);
            await owner.Operations.RecordCompletionEffectLockedAsync(db,permit,VerifiedCompletionEffectReceipt.FromTimestamp(effect,request,response),ct);
            boundary.TimestampRecorded(permit);
            await owner.WriteInput(db,scope,result,ct);
        }
    }
}

