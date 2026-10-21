using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

internal sealed record EmailPilotCloseoutLookupToken(bool Known,bool Allowed,Guid RequestId=default,Guid RecordId=default,DateTimeOffset Until=default,DateTimeOffset IssuedAt=default);
internal sealed record EmailPilotCloseoutLookupBinding(Guid RequestId,Guid PublicationId,string PublicationRecipeSha256,string RequestSha256,
    string WorkSha256,string RetentionSha256,DateTimeOffset RequestedAt,DateTimeOffset Deadline);

// One selected-record lookup under the new purpose. The ordinary lookup paths
// reject its durable System/PartyId marker even if this service is disabled.
public sealed class EmailPilotCloseoutLookup(QuillSignDbContext db,Func<EmailPilotCloseout> closeout,CompletionAccessState completion,
    LookupDeliveryProtection payloads,LookupContactRetention retention,LookupDeliveryOptions limits,DocumentLookupOptions lookupOptions,
    DocumentLookupProtection links,Func<LookupEmailTemplate> template,Func<EmailPilotCloseoutSender> sender,Func<IWorkSignals> signals,TimeProvider time)
{
    private DateTimeOffset Now=>time.GetUtcNow();
    private static InvalidDataException Invalid()=>new("The closeout lookup could not be verified.");
    internal static Guid RequestId(Guid authorization)=>new(SHA256.HashData(Encoding.ASCII.GetBytes("pilot-closeout-lookup-v1:"+authorization.ToString("N"))).AsSpan(0,16));
    private void Clean(){if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())throw new InvalidOperationException("Closeout lookup requires a clean standalone context.");}
    internal async Task<bool> IsKnownWorkAsync(Guid id,CancellationToken ct)
    {
        var row=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        if(row?.Template!=LookupDeliveryProtection.Template)return false;
        try{return payloads.Read(row).CloseoutId is not null;}catch(Exception e)when(e is InvalidDataException or CryptographicException or JsonException){return false;}
    }
    public async Task<bool> RequestAsync(Guid authorizationId,string? ip,CancellationToken ct=default)
    {
        Clean();limits.Validate();lookupOptions.Validate();var ipHash=LookupDeliveryProtection.IpHash(ip);
        var snapshot=await closeout().ReadAsync(ct)??throw Invalid();if(snapshot.AuthorizationId!=authorizationId)throw Invalid();
        var prepared=await completion.PrepareAsync(snapshot.CompletionRecord,ct)??throw Invalid();Guid id;DateTimeOffset cleanup;bool publish;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        try {
            await using(var tx=await db.Database.BeginTransactionAsync(ct)) {
                var current=await closeout().ReadLockedAsync(db,ct)??throw Invalid();if(current.AuthorizationId!=authorizationId)throw Invalid();
                await completion.RecheckLockedAsync(prepared.Saved,ct);
                var existing=await closeout().ReadStepLockedAsync(db,current,EmailPilotCloseoutStep.Lookup,ct);
                id=RequestId(authorizationId);
                if(existing is {} saved) {
                    if(saved!=id)throw Invalid();var read=await ReadLockedAsync(current,id,ct);cleanup=read.Policy.DeleteAfter;
                    var item=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
                    publish=item.Status==WorkStatus.Queued && item.Attempts==0 && item.LeaseOwner is null && item.LeaseExpiresAt is null &&
                        read.Mail.Status==EmailStatus.Queued && read.Mail.Attempts==0 && read.Mail.SubmissionStartedAt is null && read.Mail.Provider is null && read.Mail.ProviderMessageId is null;
                } else {
                    await LookupDeliveryRules.LockAsync(db,ct);var now=Now;
                    var envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==current.CompletionRecord,ct);
                    var originalRetention=await SenderPreparationRetention.ReadAsync(db,envelope,time,ct);
                    var deadline=new[]{current.Until,prepared.Saved.PurgeAfter??DateTimeOffset.MaxValue,originalRetention??DateTimeOffset.MaxValue}.Min();
                    if(deadline<=now || prepared.Until<=now || !retention.Configured ||
                        await db.EmailOutbox.AnyAsync(x=>x.Id==id,ct) || await db.WorkItems.AnyAsync(x=>x.Id==id,ct) ||
                        await db.Suppressions.AnyAsync(x=>x.Email==current.Mailboxes.Sender,ct) ||
                        !await LookupDeliveryRules.WithinCapsAsync(db,limits,payloads,current.Mailboxes.Sender,ipHash,now,false,ct))throw Invalid();
                    var p=new LookupMailPayload("lookup-mail-v1",id,current.Mailboxes.Sender,ipHash,now,deadline,null,CloseoutId:authorizationId);
                    var mail=new EmailOutbox {Id=id,To=p.Email,Template=LookupDeliveryProtection.Template,PayloadJson=payloads.Protect(p),AvailableAt=now};
                    db.EmailOutbox.Add(mail);db.WorkItems.Add(new(){Id=id,Kind=WorkKind.Email,AvailableAt=now,PayloadJson=JsonSerializer.Serialize(new{emailId=id})});
                    await db.SaveChangesAsync(ct);var policy=await retention.EnrollLockedAsync(mail,false,ct);cleanup=policy.DeleteAfter;
                    p=p with {Deadline=new[]{deadline,LookupContactRetention.DispatchDeadline(p,limits,policy)}.Min()};
                    if(p.Deadline<=Now)throw Invalid();mail.PayloadJson=payloads.Protect(p);await db.SaveChangesAsync(ct);
                    await closeout().BindNewWorkLockedAsync(db,current,EmailPilotCloseoutStep.Lookup,id,ct);await signals().PutHintAsync(id,now,ct);publish=true;
                }
                if(current.Until<=Now || prepared.Until<=Now)throw Invalid();await tx.CommitAsync(ct);
            }
        }catch {db.ChangeTracker.Clear();throw;}
        await retention.PublishAsync(id,cleanup,ct);
        if((await closeout().ReadAsync(ct))?.AuthorizationId!=authorizationId)throw Invalid();
        if(!publish)return true;
        try {await signals().PublishAsync(id,TimeSpan.Zero,ct);return true;}
        catch(Exception e)when(e is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException){return false;}
    }
    private async Task<(EmailOutbox Mail,LookupMailPayload Payload,LookupContactRetentionSnapshot Policy)> ReadLockedAsync(EmailPilotCloseoutSnapshot snapshot,Guid id,CancellationToken ct)
    {
        if(await closeout().ReadStepLockedAsync(db,snapshot,EmailPilotCloseoutStep.Lookup,ct)!=id)throw Invalid();
        var read=await ReadUnboundLockedAsync(snapshot,id,ct);
        var binding=await closeout().ReadLookupBindingLockedAsync(db,snapshot,ct)??throw Invalid();
        if(binding!=await BindingLockedAsync(snapshot,read.Mail,read.Payload,read.Policy,ct))throw Invalid();return read;
    }
    internal async Task<EmailPilotCloseoutLookupBinding> CaptureBindingLockedAsync(QuillSignDbContext current,EmailPilotCloseoutSnapshot snapshot,Guid id,CancellationToken ct)
    {
        if(!ReferenceEquals(current,db))throw Invalid();var read=await ReadUnboundLockedAsync(snapshot,id,ct);
        var work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id,ct);
        if(read.Payload.Issued is not null || read.Mail.Status!=EmailStatus.Queued || read.Mail.Attempts!=0 || read.Mail.SubmissionStartedAt is not null ||
            read.Mail.Provider is not null || read.Mail.ProviderMessageId is not null || work.Status!=WorkStatus.Queued || work.Attempts!=0 ||
            work.LeaseOwner is not null || work.LeaseExpiresAt is not null || read.Payload.RequestedAt<snapshot.Manifest.CreatedAt)throw Invalid();
        return await BindingLockedAsync(snapshot,read.Mail,read.Payload,read.Policy,ct);
    }
    private async Task<EmailPilotCloseoutLookupBinding> BindingLockedAsync(EmailPilotCloseoutSnapshot snapshot,EmailOutbox mail,LookupMailPayload p,LookupContactRetentionSnapshot policy,CancellationToken ct)
    {
        var publication=await CompletionDownloadState.ReadAsync(db,snapshot.CompletionRecord,time,ct)??throw Invalid();
        var work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==mail.Id,ct);
        return new(mail.Id,publication.Id,Convert.ToHexStringLower(publication.Recipe),EmailPilotLookupRules.OriginalRequestSha256(p),
            EmailPilotLookupRules.Hash(work.PayloadJson),LookupContactRetention.Digest(policy),p.RequestedAt,p.Deadline);
    }
    private async Task<(EmailOutbox Mail,LookupMailPayload Payload,LookupContactRetentionSnapshot Policy)> ReadUnboundLockedAsync(EmailPilotCloseoutSnapshot snapshot,Guid id,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null || snapshot.Until<=Now || id!=RequestId(snapshot.AuthorizationId))throw Invalid();
        var mail=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct)??throw Invalid();var p=payloads.Read(mail);
        var work=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct)??throw Invalid();var policy=await retention.ReadAsync(mail,ct);
        if(p.CloseoutId!=snapshot.AuthorizationId || p.PilotRunId is not null || p.Email!=snapshot.Mailboxes.Sender || p.Deadline>snapshot.Until ||
            p.Deadline<=Now || p.RequestedAt>Now || work.Kind!=WorkKind.Email || work.EnvelopeId is not null ||
            work.PayloadJson!=JsonSerializer.Serialize(new{emailId=id}) || LookupContactRetention.DispatchDeadline(p,limits,policy)<=Now)throw Invalid();
        var publication=await CompletionDownloadState.ReadAsync(db,snapshot.CompletionRecord,time,ct)??throw Invalid();
        await completion.RecheckLockedAsync(publication,ct);var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==snapshot.CompletionRecord,ct);
        var until=await SenderPreparationRetention.ReadAsync(db,e,time,ct);
        if(publication.PurgeAfter<p.Deadline || until<p.Deadline || until<=Now || snapshot.Until<=Now)throw Invalid();
        return(mail,p,policy);
    }
    private async Task<EmailPilotCloseoutSnapshot> CurrentLockedAsync(Guid? authorization,CancellationToken ct)
    {var s=await closeout().ReadLockedAsync(db,ct)??throw Invalid();if(s.AuthorizationId!=authorization || s.Until<=Now)throw Invalid();return s;}
    private async Task<EmailOutbox> OwnedLockedAsync(WorkLease lease,DateTimeOffset? intent,CancellationToken ct)
    {
        var w=await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        var row=await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(lease.Kind!=WorkKind.Email || lease.Attempt!=1 || lease.Until<=Now || w is null || w.Kind!=WorkKind.Email || w.EnvelopeId is not null ||
            w.Status!=WorkStatus.Leased || w.LeaseOwner!=lease.Owner || w.LeaseExpiresAt!=lease.Until || w.Attempts!=lease.Attempt ||
            row is null || row.Status!=EmailStatus.Queued || row.Attempts!=(intent is null?0:lease.Attempt) || row.SubmissionStartedAt!=intent ||
            row.Provider is not null || row.ProviderMessageId is not null)throw Invalid();return row;
    }
    internal async Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)
    {
        Clean();limits.Validate();lookupOptions.Validate();LookupMailPayload original;LookupIssuedToken issued;DateTimeOffset at;string intentPayload;OutgoingEmail outgoing;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        try {
            await using(var tx=await db.Database.BeginTransactionAsync(ct)) {
                var initial=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==lease.Id,ct)??throw Invalid();original=payloads.Read(initial);
                var s=await CurrentLockedAsync(original.CloseoutId,ct);await ReadLockedAsync(s,lease.Id,ct);await LookupDeliveryRules.LockAsync(db,ct);
                var mail=await OwnedLockedAsync(lease,null,ct);if(mail.PayloadJson!=initial.PayloadJson || original.Issued is not null ||
                    await db.Suppressions.AnyAsync(x=>x.Email==original.Email,ct) ||
                    !await LookupDeliveryRules.WithinCapsAsync(db,limits,payloads,original.Email,original.IpHash,Now,true,ct))throw Invalid();
                at=Now;var until=new[]{at.AddMinutes(lookupOptions.LinkMinutes),original.Deadline,s.Until,lease.Until}.Min();if(until<=at)throw Invalid();
                var raw=WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
                var token=new AuthToken {Purpose=TokenPurpose.Lookup,PartyType=PartyType.System,PartyId=lease.Id,Email="",TokenSha256=SHA256.HashData(Encoding.UTF8.GetBytes(raw)),ExpiresAt=until};
                db.AuthTokens.Add(token);await db.SaveChangesAsync(ct);issued=new(token.Id,Convert.ToBase64String(token.RowVersion),Convert.ToHexStringLower(token.TokenSha256),until);
                var link=new DocumentLookupLink(token.Id,links.Link(new LookupIssuance(token.Id,issued.Revision,raw,original.Email,at,until)),until);
                outgoing=await template().RenderAsync(original.Email,link,ct);if(outgoing.EnvelopeId is not null || outgoing.To!=original.Email || outgoing.Attachments is {Count:>0})throw Invalid();
                intentPayload=payloads.Protect(original with {Issued=issued});
                var changed=await db.EmailOutbox.Where(x=>x.Id==lease.Id && x.SubmissionStartedAt==null && x.Status==EmailStatus.Queued && x.Attempts==0)
                    .ExecuteUpdateAsync(x=>x.SetProperty(v=>v.PayloadJson,intentPayload).SetProperty(v=>v.SubmissionStartedAt,at).SetProperty(v=>v.Attempts,lease.Attempt),ct);
                if(changed!=1 || lease.Until<=Now || issued.ExpiresAt<=Now || s.Until<=Now)throw Invalid();await tx.CommitAsync(ct);
            }
        }catch(Exception e)when(e is InvalidDataException or CryptographicException or JsonException or EmailDisabledException){db.ChangeTracker.Clear();return new(WorkOutcome.Failed,"closeout-lookup-unavailable");}
        // No known-unsent reset/retry. A saved intent or an unknown provider
        // result permanently closes this once-only step and remains counted.
        if(lease.Until<=Now || issued.ExpiresAt<=Now)throw Invalid();
        var delivered=await sender().SendAsync(lease,outgoing,ct);
        if(delivered.Provider is not {Length:>0 and <=128} || delivered.MessageId is not {Length:>0 and <=512})throw Invalid();
        await using(var tx=await db.Database.BeginTransactionAsync(ct)) {
            var s=await CurrentLockedAsync(original.CloseoutId,ct);await ReadLockedAsync(s,lease.Id,ct);var mail=await OwnedLockedAsync(lease,at,ct);
            if(mail.PayloadJson!=intentPayload || issued.ExpiresAt<=Now)throw Invalid();
            await db.EmailOutbox.Where(x=>x.Id==lease.Id && x.PayloadJson==intentPayload && x.SubmissionStartedAt==at)
                .ExecuteUpdateAsync(x=>x.SetProperty(v=>v.Provider,delivered.Provider).SetProperty(v=>v.ProviderMessageId,delivered.MessageId).SetProperty(v=>v.Status,EmailStatus.Sent),ct);
            if(s.Until<=Now || lease.Until<=Now)throw Invalid();await tx.CommitAsync(ct);
        }
        return new(WorkOutcome.Completed);
    }
    internal async Task<EmailPilotCloseoutLookupToken> TokenAsync(Guid id,string email,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is not null)return await TokenLockedAsync(id,email,ct);
        Clean();await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);EmailPilotCloseoutLookupToken result;
        await using(var tx=await db.Database.BeginTransactionAsync(ct)){result=await TokenLockedAsync(id,email,ct);await tx.CommitAsync(ct);}
        return result.Allowed && result.Until<=Now?new(true,false):result;
    }
    private async Task<EmailPilotCloseoutLookupToken> TokenLockedAsync(Guid id,string email,CancellationToken ct)
    {
        var token=await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        if(token is null || token.Purpose!=TokenPurpose.Lookup || token.PartyType!=PartyType.System || token.PartyId is null)return new(false,true);
        try {
            var s=await closeout().ReadLockedAsync(db,ct)??throw Invalid();var request=token.PartyId.Value;var read=await ReadLockedAsync(s,request,ct);
            var p=read.Payload;var issued=p.Issued??throw Invalid();var at=read.Mail.SubmissionStartedAt??throw Invalid();
            if(email!=p.Email || token.EnvelopeId is not null || token.Email!="" || token.EmailPilotLookupRequestId is not null || token.Ip is not null ||
                token.DocumentId is not null || token.DocumentSha256 is not null || token.DisclosureSha256 is not null || token.SignerContactRevisionId is not null ||
                token.CompletionPublicationId is not null || token.CompletionRecipeSha256 is not null || token.CompletionPartySha256 is not null ||
                issued.Id!=id || token.ExpiresAt!=issued.ExpiresAt || token.ExpiresAt>p.Deadline || at<p.RequestedAt || at>Now ||
                Convert.ToHexStringLower(token.TokenSha256)!=issued.Sha256 || token.RowVersion.Length!=8 ||
                token.UsedAt is null && (token.ExpiresAt<=Now || Convert.ToBase64String(token.RowVersion)!=issued.Revision) ||
                token.UsedAt is {} used && (used<at || used>=token.ExpiresAt || used>Now))throw Invalid();
            return new(true,true,request,s.CompletionRecord,new[]{s.Until,p.Deadline}.Min(),at);
        }catch(Exception e)when(e is InvalidDataException or CryptographicException or JsonException or EmailDisabledException){return new(true,false);}
    }
}
