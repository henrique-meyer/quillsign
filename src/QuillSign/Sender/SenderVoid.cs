using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;
using QuillSign.Documents;
using QuillSign.Lifecycle;

namespace QuillSign.Sender;

public static class SenderVoidStatement
{
    public const string Version="sender-void-v1";
    public const string Text="I want to void this signing request and stop further signing. Records of earlier actions will be retained.";
    public static string Sha256=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(Text)));
}

public enum SenderVoidOutcome { Voided,AlreadyVoided,InvalidContext,InvalidConfirmation,Conflict,Closed }
public sealed record SenderVoidRecord(string PublicId,DateTimeOffset VoidedAt,string? Reason);
public sealed record SenderVoidResult(SenderVoidOutcome Outcome,SenderVoidRecord? Action=null);

// The caller
// supplies the original named sender ticket's expiry, never an expiry from a form.
public sealed class SenderVoid(QuillSignDbContext db,SignerCheckpointState checkpoints,AuditWriter audit,TimeProvider time,
    Func<VoidNotificationJobs>? notifications=null,QuillSign.Email.Pilot.EmailPilotReadBounds? pilotBounds=null)
{
    private readonly SenderVoidState state=new(db,checkpoints,time,pilotBounds);
    internal ProductionTerminalMutationAdmission? HoldAdmission {get;init;}

    public async Task<SenderVoidResult> VoidAsync(ClaimsPrincipal sender,string publicId,DateTimeOffset senderTicketExpiresAt,
        byte[]? reviewedVersion,bool confirmed,string? statementVersion,string? reason,string? ip,string? userAgent,CancellationToken ct=default)
    {
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Sender void requires a clean standalone unit of work.");
        var identity=SendDraftWorkflow.Identity(sender,publicId);
        if(identity is null || !Guid.TryParseExact(publicId,"N",out var parsed) || parsed==Guid.Empty || senderTicketExpiresAt<=time.GetUtcNow())return new(SenderVoidOutcome.InvalidContext);
        if(reviewedVersion is not {Length:8})return new(SenderVoidOutcome.Conflict);
        if(!confirmed || statementVersion!=SenderVoidStatement.Version || !SenderVoidState.Reason(reason,out var normalized))return new(SenderVoidOutcome.InvalidConfirmation);
        // Copy caller-owned mutable input before the first await.
        var version=Convert.ToBase64String(reviewedVersion.ToArray());
        db.ChangeTracker.Clear();
        try {var result=await Core(identity.Value.Id,identity.Value.Email,publicId,senderTicketExpiresAt,version,normalized,ip,userAgent,ct);db.ChangeTracker.Clear();return result;}
        catch(Exception error)when(HoldAdmission is not null&&error is InvalidDataException or UnauthorizedAccessException or CryptographicException)
        {db.ChangeTracker.Clear();return new(SenderVoidOutcome.InvalidContext);}
        catch {db.ChangeTracker.Clear();throw;}
    }

    private async Task<SenderVoidResult> Core(Guid id,string email,string publicId,DateTimeOffset until,string version,string? reason,string? ip,string? ua,CancellationToken ct)
    {
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var envelope=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(envelope is null || envelope.PublicId!=publicId || envelope.SenderEmail!=email || envelope.SenderVerifiedAt is null || until<=time.GetUtcNow())return new(SenderVoidOutcome.InvalidContext);
        var deadline=await SenderPreparationRetention.ReadAsync(db,envelope,time,ct,pilotBounds);
        if(envelope.Status==EnvelopeStatus.Voided) {
            var recorded=await Recorded(envelope,version,reason,ct);if(recorded is null)return new(SenderVoidOutcome.Conflict);
            if(HoldAdmission is not null)await HoldAdmission.DemandReadLockedAsync(db,id,until,ct);
            if(until<=time.GetUtcNow())return new(SenderVoidOutcome.InvalidContext);
            DocumentRetentionAccess.Check(deadline,time);
            await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,tx,ct);return new(SenderVoidOutcome.AlreadyVoided,recorded);
        }
        if(envelope.Status!=EnvelopeStatus.Sent || envelope.ExpiresAt<=time.GetUtcNow())return new(SenderVoidOutcome.Closed);
        if(Convert.ToBase64String(envelope.RowVersion)!=version)return new(SenderVoidOutcome.Conflict);
        var source=await state.SourceLockedAsync(envelope,ct);
        if(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==id && x.Event=="voided",ct))throw Invalid();
        var at=time.GetUtcNow();if(until<=at)return new(SenderVoidOutcome.InvalidContext);
        if(envelope.ExpiresAt<=at)return new(SenderVoidOutcome.Closed);
        ProductionRecordOperation? operation=null;
        if(HoldAdmission is not null)
        {
            try{operation=await HoldAdmission.BeginLockedAsync(db,id,"void",version,ct);}
            catch(Exception error)when(error is InvalidDataException or UnauthorizedAccessException or CryptographicException){return new(SenderVoidOutcome.InvalidContext);}
            if(until<=time.GetUtcNow()||envelope.ExpiresAt<=time.GetUtcNow())return new(SenderVoidOutcome.Closed);
        }
        var changed=await db.Envelopes.Where(x=>x.Id==id && x.Status==EnvelopeStatus.Sent && x.RowVersion==envelope.RowVersion)
            .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided),ct);
        if(changed!=1)return new(SenderVoidOutcome.Conflict);
        await audit.AppendAsync(id,"voided",email,ip,ua,ct,JsonSerializer.Serialize(SenderVoidState.Bind(envelope,source,version,reason,at)),PartyType.Sender);
        envelope.Status=EnvelopeStatus.Voided;
        var result=await Recorded(envelope,version,reason,ct)??throw Invalid();
        await QuillSign.Lifecycle.ProductionRecordRetentionAccess.AnchorLockedIfEnrolledAsync(db,id,time,ct);
        var producer=notifications?.Invoke();
        var jobs=producer is null ? [] : await producer.PrepareLockedAsync(id,ct);
        if(until<=time.GetUtcNow())return new(SenderVoidOutcome.InvalidContext);
        DocumentRetentionAccess.Check(deadline,time);
        if(envelope.ExpiresAt<=time.GetUtcNow())return new(SenderVoidOutcome.Closed);
        if(operation is not null)
        {
            await HoldAdmission!.PrepareOutcomeLockedAsync(db,operation,ct);
            if(until<=time.GetUtcNow()||envelope.ExpiresAt<=time.GetUtcNow())return new(SenderVoidOutcome.Closed);
        }
        // A lost acknowledgement propagates. A later explicit saved-state read/repeat
        // can verify the existing action; it cannot create a second void record.
        await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,tx,ct);await tx.DisposeAsync();
        if(operation is not null)await HoldAdmission!.CompleteAsync(operation,"voided",ct);
        if(producer is not null)await producer.PublishAsync(jobs,ct);
        return new(SenderVoidOutcome.Voided,result);
    }

    private async Task<SenderVoidRecord?> Recorded(Envelope envelope,string version,string? reason,CancellationToken ct)
    {
        var scope=await state.ReadLockedAsync(envelope.Id,ct)??throw Invalid();
        return scope.Evidence.ReviewedVersion==version && scope.Evidence.Reason==reason ? scope.Action : null;
    }
    private static InvalidDataException Invalid()=>SenderVoidState.Invalid();
}
