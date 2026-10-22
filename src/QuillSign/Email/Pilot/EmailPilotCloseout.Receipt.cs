using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

// Factual, private observations. Reservation counts are consumed attempts,
// including unknown outcomes; they are never claims of delivery or authority.
public sealed record EmailPilotCloseoutCommittedReceipt(
    string Version,DateTimeOffset ObservedAt,Guid AuthorizationId,string CapabilitySha256,string ManifestSha256,
    bool ProtectedManifestPresent,DateTimeOffset CreatedAt,DateTimeOffset Until,DateTimeOffset DeleteAfter,
    Guid[] OriginalParentIds,DateTimeOffset ActualOriginalParentDeleteAfterMinimum,Guid[] OriginalWorkIds,
    int OriginalApplication,int OriginalSimulator,int OriginalTimestamp,long OriginalEncodedBytes,
    int NewApplication,int NewSimulator,int NewTimestamp,long NewEncodedBytes,int StepBoundCount,int OperationCount,
    string OperationsSha256,string OriginalMailSha256,string OriginalWorkSha256,string OriginalAccountingSha256,string HeaderFactsSha256,
    bool OriginalPairsPreserved,string ApplicationSha256);

public sealed partial class EmailPilotCloseout
{
    internal const string CommittedReceiptVersion="closeout-committed-accounting-receipt-v1";
    private EmailPilotCloseoutConfiguration ReceiptConfiguration()
    {
        if(email.Enabled||!work.Enabled||ReceiptPilotOptions is not {Enabled:false}||Now.Offset!=TimeSpan.Zero)throw Invalid();
        var c=options.CaptureReceiptConfiguration();if(c.StartsAt>Now||c.Until<=Now)throw Invalid();return c;
    }
    internal async Task<EmailPilotCloseoutCommittedReceipt> ReadCommittedReceiptLockedAsync(QuillSignDbContext db,Guid authorization,CancellationToken ct)
    {
        var cfg=ReceiptConfiguration();if(cfg.AuthorizationId!=authorization)throw Invalid();_=HostedCloseoutReceiptState.Transaction(db);
        void Demand(){if(Hash(ReceiptConfiguration())!=Hash(cfg))throw Invalid();}
        Demand();var saved=await ReadSnapshotLockedAsync(db,cfg,ct)??throw Invalid();Demand();
        var known=await db.EmailPilotRuns.AsNoTracking().Select(x=>x.Id).Take(9).ToArrayAsync(ct);Demand();
        if(!known.ToHashSet().SetEquals(cfg.AccountingParents)||await db.EmailPilotCloseouts.CountAsync(ct)!=1)throw Invalid();Demand();
        var parents=saved.ReceiptParents.ToArray();
        if(parents.Length!=5||!parents.Select(x=>x.Manifest.RunId).ToHashSet().SetEquals(cfg.AccountingParents))throw Invalid();
        var original=parents.SelectMany(x=>x.Reservations).ToArray();
        if(original.Length!=20||original.Count(x=>x.Kind==EmailPilotAttemptKind.Application)!=12||
            original.Count(x=>x.Kind==EmailPilotAttemptKind.Simulator)!=4||original.Count(x=>x.Kind==EmailPilotAttemptKind.Timestamp)!=4||
            original.Sum(x=>(long)x.EncodedBytes)!=27918)throw Invalid();
        var receipts=await Operations(db,saved,ct);Demand();
        var header=await db.EmailPilotCloseouts.AsNoTracking().SingleAsync(x=>x.Id==authorization,ct);Demand();
        var operations=await HostedCloseoutReceiptState.OperationsAsync(db,authorization,ct);Demand();
        if(operations.Length!=receipts.Length)throw Invalid();
        var ids=cfg.CompletionWork.Concat(cfg.VoidWork).OrderBy(x=>x.ToString("N"),StringComparer.Ordinal).ToArray();
        var stored=await HostedCloseoutReceiptState.OriginalsAsync(db,ids,ct);Demand();
        var accounting=await HostedCloseoutReceiptState.OriginalAccountingAsync(db,cfg.AccountingParents.ToArray(),ct);Demand();
        var minimum=parents.Min(x=>x.DeleteAfter);
        if(header.ProtectedManifest is null||header.DeleteAfter!=minimum)throw Invalid();
        var result=new EmailPilotCloseoutCommittedReceipt(CommittedReceiptVersion,Now,header.Id,
            Convert.ToHexStringLower(header.CapabilitySha256),Convert.ToHexStringLower(header.ManifestSha256),true,
            header.CreatedAt,header.Until,header.DeleteAfter,cfg.AccountingParents.OrderBy(x=>x.ToString("N"),StringComparer.Ordinal).ToArray(),minimum,ids,
            12,4,4,27918,receipts.Count(x=>x.Kind==1),0,0,receipts.Where(x=>x.Kind==1).Sum(x=>(long)x.EncodedBytes),
            receipts.Count(x=>x.Kind==0),receipts.Length,HostedCloseoutReceiptState.OperationsHash(operations),stored.Mail,stored.Work,
            accounting,HostedCloseoutReceiptState.HeaderHash(header),true,HostedCloseoutStateVerificationCommand.ApplicationHash());
        if(Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(result))>16384)throw Invalid();
        Demand();return result;
    }
}
