using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

// Not IEmailSender. It cannot submit application mail and consumes the same
// immutable MIME artifact it reserves, through the already guarded raw adapter.
public sealed class EmailPilotSimulatorSender(EmailPilotOptions options,EmailOptions email,WorkOptions work,
    Func<EmailPilotSimulatorAuthority> authority,Func<EmailPilotLedger> ledger,Func<QuillSignDbContext> database,
    Func<EmailPilotSesSettings,IPreparedEmailTransport> transport,TimeProvider time)
{
    public async Task<EmailDelivery> SendAsync(WorkLease lease,CancellationToken ct=default)
    {
        ct.ThrowIfCancellationRequested();var settings=Settings();if(settings is null)throw new EmailPilotTransportRefusedException();
        var verifier=authority();var scope=await verifier.ReadAsync(lease,ct);if(scope is null)throw new EmailPilotTransportRefusedException();
        await Ready(scope,ct);
        var prepared=await PreparedRawMime.PrepareAsync(EmailPilotSimulator.Message(scope.Kind),settings.FromEmail,settings.FromName,ct);
        if(prepared.EnvelopeId is not null || prepared.Recipient!=EmailPilotSimulator.Target(scope.Kind) || prepared.ByteCount is <1 or >EmailPilotLimits.MessageBytes)
            throw new EmailPilotTransportRefusedException();
        await Current(scope,settings,ct);
        var request=new EmailPilotReservation(Identity("reservation",lease),null,Identity("operation",lease),EmailPilotAttemptKind.Simulator,
            EmailPilotRole.Simulator,prepared.ByteCount,Convert.ToHexStringLower(prepared.Sha256));
        if(await ledger().ReserveAsync(request,null,ct)!=EmailPilotReservationOutcome.Reserved)throw new EmailPilotTransportRefusedException();
        await Ready(scope,ct);await Current(scope,settings,ct);ct.ThrowIfCancellationRequested();
        using var bounded=CancellationTokenSource.CreateLinkedTokenSource(ct);
        var remaining=scope.Until-time.GetUtcNow();if(remaining<=TimeSpan.Zero)throw new EmailPilotTransportRefusedException();
        bounded.CancelAfter(remaining);
        var provider=transport(settings);
        await Ready(scope,bounded.Token);await Current(scope,settings,bounded.Token);bounded.Token.ThrowIfCancellationRequested();
        return await provider.SendAsync(prepared,bounded.Token);
    }
    private async Task Ready(EmailPilotSimulatorScope scope,CancellationToken ct)
    {
        var row=await database().EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==scope.Lease.Id,ct);
        if(row is null || row.EnvelopeId is not null || row.Status!=EmailStatus.Queued || row.To!=EmailPilotSimulator.Target(scope.Kind) ||
            row.SubmissionStartedAt is not {} at || at.Offset!=TimeSpan.Zero || at<scope.AdmittedAt || at>=scope.RunExpiresAt || at>time.GetUtcNow() || row.Attempts!=scope.Lease.Attempt ||
            row.Provider is not null || row.ProviderMessageId is not null)throw new EmailPilotTransportRefusedException();
    }
    private async Task Current(EmailPilotSimulatorScope scope,EmailPilotSesSettings settings,CancellationToken ct)
    {
        if(Settings()!=settings || scope.Until<=time.GetUtcNow() || !await authority().StillCurrentAsync(scope,ct) ||
            Settings()!=settings || scope.Until<=time.GetUtcNow())throw new EmailPilotTransportRefusedException();
    }
    private EmailPilotSesSettings? Settings()
    {
        if(!options.Enabled || email.Enabled || !work.Enabled || email.Provider!="Ses" || email.FromName is null || email.Ses is null ||
            email.Ses.Region is not {Length:>=5 and <=40} region || !region.All(c=>char.IsAsciiLetterLower(c)||char.IsAsciiDigit(c)||c=='-') ||
            email.Ses.ConfigurationSet is not {Length:>=1 and <=64} set || !set.All(c=>char.IsAsciiLetterOrDigit(c)||c is '_' or '-'))return null;
        try{if(email.FromEmail!=EmailAddress.Normalize(email.FromEmail))return null;}catch(ArgumentException){return null;}
        return new(email.FromEmail,email.FromName,region,set);
    }
    private static Guid Identity(string purpose,WorkLease lease)=>new(SHA256.HashData(Encoding.ASCII.GetBytes(
        $"quillsign-pilot-simulator-v1:{purpose}:{lease.Id:N}:{lease.Attempt}")).AsSpan(0,16));
}
