using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Operator;

public sealed record OperatorHoldView(string HoldId,string State);
public sealed record ProductionOperatorDeletionView(string State,bool RecordedSqlRemoved,bool RecordedActiveDataCleaned,string? EligibleAt);
public sealed record ProductionOperatorView(string RecordId,string Stage,string? PolicyVersion,string? Deadline,long? Revision,bool Frozen,
    bool Pending,bool FreshProtection,int? ArchivedObjects,IReadOnlyList<OperatorHoldView>? Holds,ProductionOperatorDeletionView? Deletion=null);
public sealed record ProductionOperatorReview(string Confirmation,string Operation,string HoldId,string Purpose);
public sealed record ProductionOperatorDeletionReview(string Confirmation,string RecordId,string Commitment,string Purpose);
public interface IProductionOperatorActions
{
    bool DeletionEnabled=>false;
    Task<ProductionOperatorView> StatusAsync(HttpContext context,Guid recordId,bool inspect,CancellationToken ct);
    Task<ProductionOperatorReview> ReviewAsync(HttpContext context,Guid recordId,string operation,Guid? holdId,string purpose,string reason,string reference,CancellationToken ct);
    Task<string> ExecuteAsync(HttpContext context,string confirmation,CancellationToken ct);
    Task<byte[]> ExportAsync(HttpContext context,Guid recordId,string purpose,CancellationToken ct);
    Task<ProductionOperatorDeletionReview> ReviewDeletionAsync(HttpContext context,Guid recordId,string purpose,CancellationToken ct)
        =>Task.FromException<ProductionOperatorDeletionReview>(ProductionOperatorAuthority.Denied());
    Task<string> ExecuteDeletionAsync(HttpContext context,string confirmation,CancellationToken ct)
        =>Task.FromException<string>(ProductionOperatorAuthority.Denied());
}
internal sealed class ProductionOperatorActions(ProductionOperatorOptions options,ProductionOperatorBrowser browser,
    ProductionHoldCoordinator coordinator,Func<QuillSignDbContext> open,IDataProtectionProvider keys,TimeProvider time,
    IProductionHoldArchiveInspectionStore inspection,Func<ProductionDeletionCoordinator>? deletion=null,
    ProductionDeletionOptions? deletionOptions=null):IProductionOperatorActions
{
    public bool DeletionEnabled=>deletionOptions?.Enabled==true&&deletion is not null;
    public async Task<ProductionOperatorView> StatusAsync(HttpContext context,Guid recordId,bool inspect,CancellationToken ct)
    {
        var session=await browser.RequireAsync(context,ProductionOperatorPermission.Status);
        if(DeletionEnabled)
        {
            var recorded=await deletion!().ReadRecordedStatusAsync(recordId,ct);
            if(recorded.DeletionId is not null)
            {
                session.Authority.Demand(options.Policy(),ProductionOperatorPermission.Status,time);
                await Audit(recordId,"deletion-recorded-status","recorded deletion state; no fresh provider or SQL absence observation",recorded.Sequence,recorded.HeadHash,null,session.Authority,ct);
                SameDeletion(recorded,await deletion().ReadRecordedStatusAsync(recordId,ct));session.Authority.Demand(options.Policy(),ProductionOperatorPermission.Status,time);
                return new(recordId.ToString("N"),"Deletion lifecycle",null,null,null,true,!recorded.ActiveDataCleaned,false,null,null,
                    new(recorded.State,recorded.SqlRemoved,recorded.ActiveDataCleaned,recorded.EligibleAt?.ToString("O")));
            }
        }
        var before=await coordinator.ReadVerifiedAsync(recordId,ct);
        await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);
        var e=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==recordId,ct)??throw ProductionOperatorAuthority.Denied();
        var retained=await ProductionRecordRetentionAccess.ReadLockedAsync(db,e,time,ct);
        if(retained.Kind!=ProductionEnrollmentKind.Enrolled)throw ProductionOperatorAuthority.Denied();
        var controls=await new ProductionHoldControls(db,keys,time).ReadLockedAsync(recordId,ct);await tx.RollbackAsync(ct);await tx.DisposeAsync();
        var after=await coordinator.ReadVerifiedAsync(recordId,ct);if(before.HeadHash!=after.HeadHash)throw new InvalidDataException("Private state changed.");
        var fresh=false;if(inspect){_=await coordinator.InspectActiveProtectionAsync(session.Authority,options.Policy(),recordId,inspection,ct);fresh=true;}
        session.Authority.Demand(options.Policy(),ProductionOperatorPermission.Status,time);await Audit(recordId,"status",inspect?"explicit protection inspection":"exact record status",before,session.Authority,ct);
        if((await coordinator.ReadVerifiedAsync(recordId,ct)).HeadHash!=before.HeadHash)throw new InvalidDataException("Private state changed.");
        session.Authority.Demand(options.Policy(),ProductionOperatorPermission.Status,time);
        return new(recordId.ToString("N"),retained.Stage!.ToString()!,retained.Enrollment!.Snapshot.Policy.Version,retained.Deadline?.ToString("O")??"No finite policy deadline",
            before.RequestRevision,before.Frozen,before.Unacknowledged is not null||before.OutstandingOperation is not null,fresh,controls.Items.Count,
            before.Holds.Values.Select(h=>new OperatorHoldView(h.Placement.HoldId.ToString("N"),h.Released?"Released":h.Release is not null?"Release pending":h.Effective?"Preserved (stored receipt)":"Preservation pending")).ToArray());
    }
    public async Task<ProductionOperatorReview> ReviewAsync(HttpContext context,Guid recordId,string operation,Guid? holdId,string purpose,string reason,string reference,CancellationToken ct)
    {
        var op=operation=="Place"?ProductionHoldOperation.Place:operation=="Release"?ProductionHoldOperation.Release:throw ProductionOperatorAuthority.Denied();
        var session=await browser.RequireAsync(context,op==ProductionHoldOperation.Place?ProductionOperatorPermission.PlaceHold:ProductionOperatorPermission.ReleaseHold);
        var selected=browser.Selected(context,session.Ticket);if(selected!=recordId)throw ProductionOperatorAuthority.Denied();
        var state=await coordinator.ReadVerifiedAsync(recordId,ct);var id=op==ProductionHoldOperation.Place?Guid.NewGuid():holdId??throw ProductionOperatorAuthority.Denied();
        if(op==ProductionHoldOperation.Release&&(!state.Holds.TryGetValue(id,out var existing)||!existing.Effective||existing.Release is not null||existing.Released))throw ProductionOperatorAuthority.Denied();
        var command=new ProductionHoldCommand(Guid.NewGuid(),recordId,id,state.RequestRevision,op,purpose,reason,reference);_=command.Digest();
        return new(browser.Confirm(session.Ticket,command,state.HeadHash),operation,id.ToString("N"),purpose);
    }
    public async Task<string> ExecuteAsync(HttpContext context,string confirmation,CancellationToken ct)
    {
        var ticket=(await context.AuthenticateAsync(ProductionOperatorAuthority.CookieScheme)).Ticket??throw ProductionOperatorAuthority.Denied();
        var value=browser.Open(ticket,confirmation);var session=await browser.RequireAsync(context,value.Command.Permission);
        if(browser.Selected(context,ticket)!=value.Command.RecordId)throw ProductionOperatorAuthority.Denied();
        var current=await coordinator.ReadVerifiedAsync(value.Command.RecordId,ct);if(current.HeadHash!=value.WitnessHead)throw new InvalidDataException("Private state changed.");
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(ct);var remaining=session.Authority.ExpiresAt-time.GetUtcNow();if(remaining<=TimeSpan.Zero)throw ProductionOperatorAuthority.Denied();stop.CancelAfter(remaining);
        var state=await coordinator.SubmitAsync(session.Authority,options.Policy(),value.Command,stop.Token);
        if(state.OutstandingOperation is not null||state.Unacknowledged is not null)return "Command recorded; preservation or release remains pending.";
        session.Authority.Demand(options.Policy(),value.Command.Permission,time);
        state=value.Command.Operation==ProductionHoldOperation.Place?await coordinator.PreserveAsync(value.Command.RecordId,value.Command.HoldId,Plan(value.Command.CommandId),stop.Token):
            await coordinator.ReleaseAsync(value.Command.RecordId,value.Command.HoldId,stop.Token);
        session.Authority.Demand(options.Policy(),value.Command.Permission,time);
        var hold=state.Holds[value.Command.HoldId];return hold.Released?"Exact hold release reconciled.":hold.Effective?"Complete preservation recorded. Use explicit inspection for current provider protection.":"Command recorded; preservation remains pending.";
    }
    public async Task<byte[]> ExportAsync(HttpContext context,Guid recordId,string purpose,CancellationToken ct)
    {
        if(!ProductionOperatorAuthority.Text(purpose,256))throw ProductionOperatorAuthority.Denied();var session=await browser.RequireAsync(context,ProductionOperatorPermission.ReadEvidence);
        if(browser.Selected(context,session.Ticket)!=recordId)throw ProductionOperatorAuthority.Denied();var state=await coordinator.ReadVerifiedAsync(recordId,ct);
        await using var db=open();await using var tx=await db.Database.BeginTransactionAsync(ct);var controls=await new ProductionHoldControls(db,keys,time).ReadLockedAsync(recordId,ct);
        var plans=controls.Plans.Values.Select(p=>{
            var body=ProductionHoldBundlePlan.OpenVerified(p,keys,time);return new{p.HoldId,p.PlanId,body.Snapshot.Objects,body.Snapshot.Bytes,
                Tables=body.Snapshot.Sql.Tables.Select(t=>new{t.Table,t.Rows,t.Sha256}),Inventory=body.Items.Select(i=>new{i.Kind,i.Length,i.Sha256})};}).ToArray();
        await tx.RollbackAsync(ct);await tx.DisposeAsync();var after=await coordinator.ReadVerifiedAsync(recordId,ct);if(after.HeadHash!=state.HeadHash)throw new InvalidDataException("Private state changed.");
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new{Version="private-operator-evidence-inventory-v1",RecordId=recordId,Purpose=purpose,ObservedAt=time.GetUtcNow(),state.RequestRevision,
            Meaning="Authenticated inventory and historical preservation receipts; no fresh provider protection or deletion authority.",
            Holds=state.Holds.Values.Select(h=>new{h.Placement.HoldId,h.Placement.Purpose,h.Placement.Reason,h.Placement.Reference,h.Effective,h.Released,ReleasePending=h.Release is not null&&!h.Released}),Plans=plans});
        if(bytes.Length>4*1024*1024)throw new InvalidDataException("Private export exceeds its bound.");
        await Audit(recordId,"evidence-inventory-export",purpose,state,session.Authority,ct);
        if((await coordinator.ReadVerifiedAsync(recordId,ct)).HeadHash!=state.HeadHash)throw new InvalidDataException("Private state changed.");
        session.Authority.Demand(options.Policy(),ProductionOperatorPermission.ReadEvidence,time);return bytes;
    }
    public async Task<ProductionOperatorDeletionReview> ReviewDeletionAsync(HttpContext context,Guid recordId,string purpose,CancellationToken ct)
    {
        var backend=Deletion();if(!ProductionOperatorAuthority.Text(purpose,256)||!ProductionOperatorAuthority.Text(deletionOptions!.CompletedCommitmentStatement,2048))throw ProductionOperatorAuthority.Denied();
        var session=await browser.RequireAsync(context,ProductionOperatorPermission.AuthorizeDeletion);
        if(browser.Selected(context,session.Ticket)!=recordId)throw ProductionOperatorAuthority.Denied();
        var before=await backend.ReadRecordedStatusAsync(recordId,ct);if(before.DeletionId is not Guid id||before.SqlRemoved||before.ActiveDataCleaned)throw ProductionOperatorAuthority.Denied();
        var facts=await backend.CompletedFactsAsync(recordId,ct);SameDeletion(before,await backend.ReadRecordedStatusAsync(recordId,ct));
        session.Authority.Demand(options.Policy(),ProductionOperatorPermission.AuthorizeDeletion,time);
        await Audit(recordId,"completed-copy-authorization-review",purpose,before.Sequence,before.HeadHash,null,session.Authority,ct);
        SameDeletion(before,await backend.ReadRecordedStatusAsync(recordId,ct));session.Authority.Demand(options.Policy(),ProductionOperatorPermission.AuthorizeDeletion,time);
        var proof=browser.ConfirmDeletion(session.Ticket,recordId,id,before.Sequence,before.HeadHash!,facts,deletionOptions.CompletedCommitmentStatement,purpose);
        return new(proof,recordId.ToString("N"),deletionOptions.CompletedCommitmentStatement,purpose);
    }
    public async Task<string> ExecuteDeletionAsync(HttpContext context,string confirmation,CancellationToken ct)
    {
        var backend=Deletion();var ticket=(await context.AuthenticateAsync(ProductionOperatorAuthority.CookieScheme)).Ticket??throw ProductionOperatorAuthority.Denied();
        var value=browser.OpenDeletion(ticket,confirmation);var session=await browser.RequireAsync(context,ProductionOperatorPermission.AuthorizeDeletion);
        if(session.Authority.Issuer!=value.Issuer||session.Authority.Subject!=value.Subject||ProductionOperatorBrowser.Session(session.Ticket)!=value.Session||
            session.Ticket.Properties.IssuedUtc!=value.TicketIssuedAt||session.Ticket.Properties.ExpiresUtc!=value.TicketExpiresAt)throw ProductionOperatorAuthority.Denied();
        if(browser.Selected(context,ticket)!=value.RecordId||deletionOptions!.CompletedCommitmentStatement!=value.Commitment)throw ProductionOperatorAuthority.Denied();
        var current=await backend.ReadRecordedStatusAsync(value.RecordId,ct);
        if(current.DeletionId!=value.DeletionId||current.Sequence!=value.Sequence||current.HeadHash!=value.WitnessHead||current.SqlRemoved||current.ActiveDataCleaned)throw new InvalidDataException("Private deletion state changed.");
        var facts=await backend.CompletedFactsAsync(value.RecordId,ct);
        if(facts.PublicationId!=value.PublicationId||facts.PublicationSha256!=value.PublicationSha256||facts.FinalReceiptsSha256!=value.FinalReceiptsSha256)throw new InvalidDataException("The reviewed completed packet changed.");
        SameDeletion(current,await backend.ReadRecordedStatusAsync(value.RecordId,ct));
        var remaining=value.Until-time.GetUtcNow();if(remaining<=TimeSpan.Zero)throw ProductionOperatorAuthority.Denied();
        using var deadline=new CancellationTokenSource(remaining,time);using var stop=CancellationTokenSource.CreateLinkedTokenSource(ct,deadline.Token);
        // Attenuate the already authenticated dedicated ticket; this creates no
        // cookie or new authentication and cannot extend its original lifetime.
        var bounded=new AuthenticationProperties(new Dictionary<string,string?>(session.Ticket.Properties.Items)){ExpiresUtc=value.Until,AllowRefresh=false,IsPersistent=false};
        var authority=ProductionOperatorAuthority.FromValidatedTicket(new(session.Ticket.Principal,bounded,ProductionOperatorAuthority.CookieScheme),options.Policy(),ProductionOperatorPermission.AuthorizeDeletion,time);
        await backend.AuthorizeCompletedAsync(authority,options.Policy(),value.RecordId,value.AuthorizationId,value.WitnessHead,value.Commitment,value.Purpose,value.CreatedAt,stop.Token);
        authority.Demand(options.Policy(),ProductionOperatorPermission.AuthorizeDeletion,time);
        await backend.WakeAsync(value.RecordId,stop.Token);authority.Demand(options.Policy(),ProductionOperatorPermission.AuthorizeDeletion,time);
        return "The exact completed-copy statement was recorded. Inspect recorded cleanup status; this statement is not independent proof of copy possession or legal adequacy.";
    }
    private ProductionDeletionCoordinator Deletion()=>DeletionEnabled?deletion!():throw ProductionOperatorAuthority.Denied();
    private static void SameDeletion(ProductionDeletionStatus a,ProductionDeletionStatus b)
    {if(a.RecordId!=b.RecordId||a.DeletionId!=b.DeletionId||a.Sequence!=b.Sequence||a.HeadHash!=b.HeadHash||a.SqlRemoved!=b.SqlRemoved||a.ActiveDataCleaned!=b.ActiveDataCleaned||a.EligibleAt!=b.EligibleAt)throw new InvalidDataException("Private deletion state changed.");}
    private async Task Audit(Guid recordId,string action,string purpose,HoldWitnessState state,ProductionOperatorAuthority authority,CancellationToken ct)
        =>await Audit(recordId,action,purpose,state.Sequence,state.HeadHash,state.RequestRevision,authority,ct);
    private async Task Audit(Guid recordId,string action,string purpose,long sequence,string? head,long? revision,ProductionOperatorAuthority authority,CancellationToken ct)
    {
        await using var db=open();var id=Guid.NewGuid();var at=time.GetUtcNow();var bytes=JsonSerializer.SerializeToUtf8Bytes(new{Version="production-operator-access-v1",Id=id,At=at,RecordId=recordId,
            Action=action,Purpose=purpose,authority.Issuer,authority.Subject,Sequence=sequence,HeadHash=head,RequestRevision=revision});
        if(bytes.Length>4096||at.Offset!=TimeSpan.Zero)throw ProductionOperatorAuthority.Denied();var cipher=keys.CreateProtector("production-operator-access-v1").Protect(Convert.ToBase64String(bytes));
        if(cipher.Length>8192)throw ProductionOperatorAuthority.Denied();db.Add(new ProductionOperatorAccessReceipt{Id=id,At=at,PayloadSha256=SHA256.HashData(bytes),ProtectedReceipt=cipher});
        await db.SaveChangesAsync(ct);CryptographicOperations.ZeroMemory(bytes);
    }
    private static Guid Plan(Guid command)=>new(SHA256.HashData(command.ToByteArray().Concat("operator-plan-v1"u8.ToArray()).ToArray()).AsSpan(0,16));
}
