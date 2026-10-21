using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed class EmailPilotCloseoutSender(EmailOptions email,Func<EmailPilotCloseout> closeout,Func<QuillSignDbContext> database,
    Func<EmailPilotSesSettings,IPreparedEmailTransport> transport,TimeProvider time)
{
    public async Task<EmailDelivery> SendAsync(WorkLease lease,OutgoingEmail message,CancellationToken ct=default)
    {
        var authority=closeout();if(!authority.Available||email.Enabled||email.Provider!="Ses"||lease is null||message is null||
            email.Ses is null||email.FromEmail!=EmailAddress.Normalize(email.FromEmail)||email.Ses.Region is not {Length:>=5 and <=40}||email.Ses.ConfigurationSet is not {Length:>=1 and <=64})throw new EmailPilotTransportRefusedException();
        var settings=new EmailPilotSesSettings(email.FromEmail,email.FromName,email.Ses.Region,email.Ses.ConfigurationSet);
        var scope=await authority.ReadWorkAsync(lease,ct)??throw new EmailPilotTransportRefusedException();
        await Ready(scope,ct);var prepared=await PreparedRawMime.PrepareAsync(message,settings.FromEmail,settings.FromName,ct);
        await authority.DemandWorkAsync(scope,ct);await authority.ReservePreparedAsync(scope,prepared,ct);
        await Ready(scope,ct);await authority.DemandWorkAsync(scope,ct);
        using var bounded=CancellationTokenSource.CreateLinkedTokenSource(ct);var remaining=scope.Until-time.GetUtcNow();if(remaining<=TimeSpan.Zero)throw new EmailPilotTransportRefusedException();bounded.CancelAfter(remaining);
        var client=transport(settings);await Ready(scope,bounded.Token);await authority.DemandWorkAsync(scope,bounded.Token);
        if(settings!=new EmailPilotSesSettings(email.FromEmail,email.FromName,email.Ses.Region,email.Ses.ConfigurationSet))throw new EmailPilotTransportRefusedException();
        bounded.Token.ThrowIfCancellationRequested();return await client.SendAsync(prepared,bounded.Token);
    }
    private async Task Ready(EmailPilotCloseoutWorkScope scope,CancellationToken ct)
    {
        var row=await database().EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==scope.Lease.Id,ct);
        if(row.Status!=EmailStatus.Queued||row.Attempts!=1||row.SubmissionStartedAt is not {} at||at.Offset!=TimeSpan.Zero||at>time.GetUtcNow()||at>=scope.CloseoutUntil||
            row.Provider is not null||row.ProviderMessageId is not null||row.To!=scope.Recipient||scope.Until<=time.GetUtcNow())throw new EmailPilotTransportRefusedException();
        if(await database().Suppressions.AnyAsync(x=>x.Email==row.To,ct))throw new RecipientSuppressedException();
    }
}
