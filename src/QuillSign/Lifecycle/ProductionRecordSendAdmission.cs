using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Private opt-in Send composition. Validation/rendering precede reservation;
// exact provider and SQL effects then remain owned through their acknowledgement.
internal sealed class ProductionRecordSendAdmission(ProductionRecordOperationAdmission operations,IProductionRecordSendStore store)
{
    internal static void DemandStandalone(QuillSignDbContext db)
    {
        if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())
            throw new InvalidDataException("Send admission requires a clean standalone caller.");
    }
    private static string Reference(string publicId,byte[] reviewed)=>publicId+":"+Convert.ToBase64String(reviewed);
    internal async Task<ProductionRecordOperation?> BeginLockedAsync(QuillSignDbContext db,Guid id,string publicId,byte[] reviewed,CancellationToken ct)
    {
        if(await operations.IsUnenrolledDemoAsync(db,id,ct))return null;
        return await operations.BeginLockedAsync(db,id,Guid.NewGuid(),"sender/send",Reference(publicId,reviewed),ct);
    }
    internal Task PrepareAsync(QuillSignDbContext db,ProductionRecordOperation scope,ProductionRecordWriteDescriptor source,
        ProductionRecordWriteDescriptor target,CancellationToken ct)=>operations.PrepareSendWriteLockedAsync(db,scope,source,target,ct);
    internal async Task WriteAsync(QuillSignDbContext db,ProductionRecordOperation scope,ClaimsPrincipal sender,
        ProductionRecordWriteDescriptor item,Stream source,CancellationToken ct)
    {
        var mayWrite=await operations.BeginSendWriteLockedAsync(db,scope,item,ct);
        var saved=await operations.ReadSendWriteReceiptLockedAsync(db,scope,item,ct);
        var receipt=await store.WriteAsync(scope,sender,item,source,mayWrite,saved,
            token=>operations.DemandSendWriteLockedAsync(db,scope,item,token),ct);
        await operations.RecordSendWriteLockedAsync(db,scope,receipt,ct);
    }
    internal async Task DemandHintAsync(QuillSignDbContext db,ProductionRecordOperation scope,Guid id,DateTimeOffset due,CancellationToken ct)
    {
        await operations.DemandSendProgressLockedAsync(db,scope,ct);
        var row=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct)??throw Invalid();
        if(row.EnvelopeId!=scope.RecordId||row.Status!=WorkStatus.Queued||row.Attempts!=0||row.LeaseOwner is not null||
            row.LeaseExpiresAt is not null||row.AvailableAt!=due||row.Kind is not (WorkKind.Email or WorkKind.Expiry or WorkKind.Reminder))throw Invalid();
        if(row.Kind==WorkKind.Email)
        {
            var mail=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct)??throw Invalid();
            if(row.PayloadJson!="{}"||mail.EnvelopeId!=scope.RecordId||mail.Template!="signer-invitation"||mail.AvailableAt!=due||
                mail.Status!=EmailStatus.Queued||mail.Attempts!=0||mail.SubmissionStartedAt is not null||mail.Provider is not null||mail.ProviderMessageId is not null)throw Invalid();
        }
        if(row.Kind==WorkKind.Expiry)
        {
            var parent=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==scope.RecordId,ct);
            if(id!=SigningExpiryJobs.WorkId(scope.RecordId)||!SigningExpiryJobs.Matches(parent,row)||due!=parent.ExpiresAt)throw Invalid();
        }
        await operations.DemandSendProgressLockedAsync(db,scope,ct);
    }
    internal Task PrepareOutcomeLockedAsync(QuillSignDbContext db,ProductionRecordOperation scope,CancellationToken ct)
        =>operations.PrepareOutcomeLockedAsync(db,scope,ct);
    internal Task CompleteAsync(ProductionRecordOperation scope,SentDraft result,CancellationToken ct)
        =>operations.CompleteAsync(scope,Receipt(scope,result),ct);
    internal async Task ReconcileAsync(Guid recordId,string publicId,byte[] reviewed,SentDraft result,CancellationToken ct)
    {
        var scope=await operations.ReadSendOutcomeAsync(recordId,Reference(publicId,reviewed),ct);
        if(scope is not null)await CompleteAsync(scope,result,ct);
    }
    private static string Receipt(ProductionRecordOperation scope,SentDraft result)
        =>Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            Version="production-send-committed-v1",scope.RecordId,scope.OperationId,result.InvitationWorkId,result.DocumentHash,result.DisclosureHash,
            ReminderPolicySha256=result.Reminders?.Sha256,result.ReminderSchedulingVersion
        })));
    private static InvalidDataException Invalid()=>new("The exact Send wakeup and original operation could not be verified.");
}
