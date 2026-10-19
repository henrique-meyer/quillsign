using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public enum EmailPilotSimulatorKind { Success = 1, Bounce = 2, Complaint = 3 }
public sealed record EmailPilotSimulatorResult(Guid WorkId, bool Recovered, bool WakeupPublished = false);
internal sealed record EmailPilotSimulatorPayload(string Version, Guid RunId, Guid WorkId, EmailPilotSimulatorKind Kind, DateTimeOffset CreatedAt);

// Public AWS protocol fixtures, never an operator-supplied or personal mailbox:
// https://docs.aws.amazon.com/ses/latest/dg/send-an-email-from-console.html
internal static class EmailPilotSimulator
{
    internal const string Template = "pilot-ses-simulator-v1";
    internal const string Version = "ses-simulator-v1";
    internal static string Target(EmailPilotSimulatorKind kind) => (kind switch {
        EmailPilotSimulatorKind.Success => "success", EmailPilotSimulatorKind.Bounce => "bounce",
        EmailPilotSimulatorKind.Complaint => "complaint", _ => throw EmailPilotProtection.Invalid()
    }) + "@simulator.amazonses.com";
    internal static Guid Identity(Guid run, EmailPilotSimulatorKind kind) => new(SHA256.HashData(
        Encoding.ASCII.GetBytes($"quillsign:{Version}:{run:N}:{(int)kind}")).AsSpan(0,16));
    internal static bool Capability(string capability, EmailPilotAdmissionOptions admission)
    {
        if (!EmailPilotCanonical.Hash(admission.CapabilitySha256)) return false;
        try { return CryptographicOperations.FixedTimeEquals(EmailPilotCanonical.Capability(capability), Convert.FromHexString(admission.CapabilitySha256)); }
        catch (ArgumentException) { return false; }
    }
    internal static EmailPilotSimulatorPayload Read(EmailPilotProtection protection, EmailPilotManifest run, WorkItem item, EmailOutbox email)
    {
        var payload = protection.Read<EmailPilotSimulatorPayload>(run.RunId, "simulator-email:"+item.Id.ToString("N"), Unwrap(email.PayloadJson), 4096);
        var work = protection.Read<EmailPilotSimulatorPayload>(run.RunId, "simulator-work:"+item.Id.ToString("N"), Unwrap(item.PayloadJson), 4096);
        if (payload != work || payload.Version != Version || payload.RunId != run.RunId || !Enum.IsDefined(payload.Kind) ||
            payload.WorkId != item.Id || item.Id != email.Id || item.Id != Identity(run.RunId,payload.Kind) ||
            item.Kind != WorkKind.Email || item.EnvelopeId is not null || email.EnvelopeId is not null ||
            email.Template != Template || email.To != Target(payload.Kind) || email.AttachmentsJson != "[]" ||
            payload.CreatedAt.Offset != TimeSpan.Zero || payload.CreatedAt < run.CreatedAt || payload.CreatedAt >= run.ExpiresAt ||
            email.AvailableAt != payload.CreatedAt || item.AvailableAt < payload.CreatedAt || item.AvailableAt >= run.ExpiresAt)
            throw EmailPilotProtection.Invalid();
        return payload;
    }
    internal static string Wrap(string value)=>JsonSerializer.Serialize(new ProtectedWorkPayload(value));
    private static string Unwrap(string value)
    {
        if(value.Length>4096)throw EmailPilotProtection.Invalid();
        try{return JsonSerializer.Deserialize<ProtectedWorkPayload>(value)?.Protected??throw EmailPilotProtection.Invalid();}
        catch(JsonException){throw EmailPilotProtection.Invalid();}
    }
    internal static OutgoingEmail Message(EmailPilotSimulatorKind kind) => new(Target(kind), "QuillSign feedback test: "+kind,
        "Synthetic QuillSign email feedback test. No document or personal information is included.",
        "<p>Synthetic QuillSign email feedback test. No document or personal information is included.</p>");
}

public sealed class EmailPilotSimulatorAdmission(EmailPilotOptions options, EmailOptions email, WorkOptions work,
    EmailPilotAdmissionOptions admission, Func<EmailPilotLedger> ledger, Func<IWorkSignals> signals)
{
    public async Task<EmailPilotSimulatorResult?> RequestAsync(string capability, EmailPilotSimulatorKind kind, CancellationToken ct = default)
    {
        if (!options.Enabled || email.Enabled || !work.Enabled || !Enum.IsDefined(kind) || !EmailPilotSimulator.Capability(capability,admission)) return null;
        var store = ledger();
        await store.CreateAsync(capability,ct);
        var result = await store.AdmitSimulatorAsync(capability,kind,signals(),()=>work.Enabled && EmailPilotSimulator.Capability(capability,admission),ct);
        if (result is null || !options.Enabled || email.Enabled || !work.Enabled || !EmailPilotSimulator.Capability(capability,admission)) return null;
        // Publication is a wakeup only. Lost acknowledgement recovers the same
        // deterministic committed item, never a second simulator submission.
        try { await signals().PublishAsync(result.WorkId,TimeSpan.Zero,ct); return result with { WakeupPublished = true }; }
        catch (Exception e) when (e is IOException or HttpRequestException or OperationCanceledException or Azure.RequestFailedException) { return result; }
    }
}

public sealed partial class EmailPilotLedger
{
    internal async Task<EmailPilotSimulatorResult?> AdmitSimulatorAsync(string capability, EmailPilotSimulatorKind kind, IWorkSignals signals, Func<bool> current, CancellationToken ct)
    {
        if (!Enabled || !Enum.IsDefined(kind)) return null;
        var db=database(); await Open(db,ct); await using var tx=await db.Database.BeginTransactionAsync(ct); await Lock(db,RunId,ct);
        var run=await Manifest(db,RunId,true,ct);
        if(run is null || !MatchesCapability(run,EmailPilotCanonical.Capability(capability)))return null;
        var id=EmailPilotSimulator.Identity(run.RunId,kind);
        var saved=await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        var outbox=await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==id,ct);
        var recovered=saved is not null || outbox is not null;
        if(recovered) {
            if(saved is null || outbox is null)throw EmailPilotProtection.Invalid();
            EmailPilotSimulator.Read(protection(),run,saved,outbox);
        } else {
            if(await db.Suppressions.AnyAsync(x=>x.Email==EmailPilotSimulator.Target(kind),ct))return null;
            var at=Now;
            var payload=new EmailPilotSimulatorPayload(EmailPilotSimulator.Version,run.RunId,id,kind,at);
            db.EmailOutbox.Add(new(){Id=id,To=EmailPilotSimulator.Target(kind),Template=EmailPilotSimulator.Template,AvailableAt=at,
                PayloadJson=EmailPilotSimulator.Wrap(protection().Protect(run.RunId,"simulator-email:"+id.ToString("N"),payload))});
            db.WorkItems.Add(new(){Id=id,Kind=WorkKind.Email,AvailableAt=at,
                PayloadJson=EmailPilotSimulator.Wrap(protection().Protect(run.RunId,"simulator-work:"+id.ToString("N"),payload))});
            await db.SaveChangesAsync(ct);await signals.PutHintAsync(id,at,ct);
        }
        EnsureLive(run);if(!current())throw EmailPilotProtection.Invalid();
        await tx.CommitAsync(ct);EnsureLive(run);if(!current())throw EmailPilotProtection.Invalid();
        return new(id,recovered);
    }

    internal async Task<T?> ReadSimulatorAsync<T>(Func<QuillSignDbContext,EmailPilotManifest,EmailPilotProtection,Task<T?>> read,
        QuillSignDbContext? locked, CancellationToken ct) where T:class
    {
        if(!Enabled)return null;
        var db=locked??database();
        if(locked is null)await Open(db,ct);
        else if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("A simulator intent requires a transaction.");
        var run=await Manifest(db,RunId,true,ct);if(run is null)return null;
        var result=await read(db,run,protection());EnsureLive(run);return result;
    }
}
