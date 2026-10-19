using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

// No endpoint or transport consumes this foundation yet. A reservation is a
// nonrefunded accounting event, not a reusable permission to invoke a provider.
public sealed partial class EmailPilotLedger(EmailPilotOptions options, EmailOptions email, Func<QuillSignDbContext> database,
    Func<EmailPilotProtection> protection, TimeProvider time)
{
    private bool Enabled => options.Enabled && !email.Enabled;
    private Guid RunId { get { options.Validate(); return Guid.ParseExact(options.RunId, "N"); } }
    private DateTimeOffset Now => time.GetUtcNow().ToUniversalTime();

    public async Task<EmailPilotManifest> CreateAsync(string capability, CancellationToken ct = default)
    {
        if (!Enabled) throw new EmailDisabledException();
        var id = RunId; var capabilityHash = EmailPilotCanonical.Capability(capability); var db = database();
        await Open(db, ct); await using var tx = await db.Database.BeginTransactionAsync(ct); await Lock(db, id, ct);
        var existing = await Manifest(db, id, false, ct);
        if (existing is not null)
        {
            if (existing.ExpiresAt <= Now || !MatchesCapability(existing, capabilityHash)) throw EmailPilotProtection.Invalid();
            await tx.CommitAsync(ct); return existing;
        }
        var now = Now;
        var value = new EmailPilotManifest(EmailPilotLimits.Version, id, now, now.AddMinutes(60), Convert.ToHexStringLower(capabilityHash), options.Mailboxes with { });
        db.EmailPilotRuns.Add(new() { Id = id, CreatedAt = value.CreatedAt, ExpiresAt = value.ExpiresAt,
            ManifestSha256 = EmailPilotCanonical.Hash(value), CapabilitySha256 = capabilityHash });
        db.EmailPilotSecrets.Add(new() { RunId = id, ProtectedManifest = protection().Protect(id, "manifest", value), DeleteAfter = now.AddDays(7) });
        await db.SaveChangesAsync(ct); EnsureLive(value); await tx.CommitAsync(ct); return value;
    }

    public async Task<bool> EnrollAsync(string capability, Guid envelopeId, EmailPilotScenario scenario, CancellationToken ct = default)
    {
        if (!Enabled || envelopeId == Guid.Empty || !Enum.IsDefined(scenario)) return false;
        var id = RunId; var capabilityHash = EmailPilotCanonical.Capability(capability); var db = database();
        await Open(db, ct); await using var tx = await db.Database.BeginTransactionAsync(ct); await Lock(db, id, ct);
        var run = await Manifest(db, id, true, ct); if (run is null || !MatchesCapability(run, capabilityHash)) return false;
        var enrolled = await Enrollments(db, run, ct);
        if (enrolled.SingleOrDefault(x => x.SubjectEnvelopeId == envelopeId) is { } saved)
            return saved.Scenario == scenario;
        if (enrolled.Count == 3 || enrolled.Any(x => x.Scenario == scenario) ||
            await db.EmailPilotEnrollments.AnyAsync(x => x.SubjectEnvelopeId == envelopeId, ct)) return false;
        var owner = await db.Envelopes.AsNoTracking().Where(x => x.Id == envelopeId).Select(x => new { x.SenderEmail, x.IsDemo, x.Status }).SingleOrDefaultAsync(ct);
        if (owner is null || !owner.IsDemo || owner.Status != EnvelopeStatus.Draft || owner.SenderEmail != run.Mailboxes.Sender) return false;
        var value = new EmailPilotEnrollment(id, envelopeId, scenario, Now);
        db.EmailPilotEnrollments.Add(new() { RunId = id, SubjectEnvelopeId = envelopeId, Scenario = scenario, EnrolledAt = value.EnrolledAt,
            ProtectedBinding = protection().Protect(id, "enrollment", value) });
        await db.SaveChangesAsync(ct); EnsureLive(run); await tx.CommitAsync(ct); return true;
    }

    public async Task<EmailPilotReservationOutcome> ReserveAsync(EmailPilotReservation request, string? recipient, CancellationToken ct = default)
    {
        if (!Enabled || !Shape(request)) return EmailPilotReservationOutcome.Refused;
        var id = RunId; var db = database(); await Open(db, ct);
        await using var tx = await db.Database.BeginTransactionAsync(ct); await Lock(db, id, ct);
        var run = await Manifest(db, id, true, ct); if (run is null) return EmailPilotReservationOutcome.Refused;
        var enrolled = await Enrollments(db, run, ct);
        if (request.SubjectEnvelopeId is { } envelopeId)
        {
            if (!enrolled.Any(x => x.SubjectEnvelopeId == envelopeId) || !await db.Envelopes.AnyAsync(x => x.Id == envelopeId && x.IsDemo && x.SenderEmail == run.Mailboxes.Sender, ct))
                return EmailPilotReservationOutcome.Refused;
        }
        if (request.Kind == EmailPilotAttemptKind.Application && (recipient != run.Mailboxes.Address(request.Role) || recipient is null)) return EmailPilotReservationOutcome.Refused;
        // Simulator addresses and exact work/lease/source authority are enforced
        // by the later provider gate. This layer accounts only typed reservations.
        if (request.Kind != EmailPilotAttemptKind.Application && recipient is not null) return EmailPilotReservationOutcome.Refused;
        var saved = await Reservations(db, run, ct);
        if (saved.SingleOrDefault(x => x.Id == request.Id) is { } prior)
            return Equivalent(prior, request) ? EmailPilotReservationOutcome.AlreadyConsumed : EmailPilotReservationOutcome.Refused;
        if (saved.Any(x => x.Kind == request.Kind && x.OperationId == request.OperationId && x.Role == request.Role))
            return EmailPilotReservationOutcome.Refused;
        if (await db.EmailPilotReservations.AnyAsync(x => x.Id == request.Id, ct)) return EmailPilotReservationOutcome.Refused;
        var budget = Budget(saved);
        if (request.Kind switch {
            EmailPilotAttemptKind.Application => budget.ApplicationAttempts >= EmailPilotLimits.ApplicationAttempts,
            EmailPilotAttemptKind.Simulator => budget.SimulatorAttempts >= EmailPilotLimits.SimulatorAttempts,
            _ => budget.TimestampAttempts >= EmailPilotLimits.TimestampAttempts
        } || budget.EncodedBytes + request.EncodedBytes > EmailPilotLimits.AggregateBytes) return EmailPilotReservationOutcome.Refused;
        var value = new EmailPilotAttempt(request.Id, id, request.SubjectEnvelopeId, request.OperationId, request.Kind, request.Role,
            request.EncodedBytes, request.RequestSha256, Now);
        db.EmailPilotReservations.Add(new() { Id = value.Id, RunId = id, SubjectEnvelopeId = value.SubjectEnvelopeId, OperationId = value.OperationId,
            Kind = value.Kind, Role = value.Role, EncodedBytes = value.EncodedBytes, RequestSha256 = Convert.FromHexString(value.RequestSha256), ReservedAt = value.ReservedAt,
            ProtectedReceipt = protection().Protect(id, "reservation", value) });
        await db.SaveChangesAsync(ct); EnsureLive(run); await tx.CommitAsync(ct); return EmailPilotReservationOutcome.Reserved;
    }

    public async Task<EmailPilotBudget?> ReadBudgetAsync(CancellationToken ct = default)
    {
        if (!Enabled) return null;
        var id = RunId; var db = database(); await Open(db, ct);
        var run = await Manifest(db, id, false, ct); return run is null ? null : Budget(await Reservations(db, run, ct));
    }

    private async Task<EmailPilotManifest?> Manifest(QuillSignDbContext db, Guid id, bool live, CancellationToken ct, bool configured = true)
    {
        if (id == Guid.Empty || configured && id != RunId) throw EmailPilotProtection.Invalid();
        var row = await db.EmailPilotRuns.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return null;
        var secret = await db.EmailPilotSecrets.AsNoTracking().SingleOrDefaultAsync(x => x.RunId == id, ct) ?? throw EmailPilotProtection.Invalid();
        if (secret.DeleteAfter <= Now) throw EmailPilotProtection.Invalid();
        var value = protection().Read<EmailPilotManifest>(id, "manifest", secret.ProtectedManifest, 16384);
        if (value is null || value.Version != EmailPilotLimits.Version || value.RunId != id || value.CreatedAt.Offset != TimeSpan.Zero || value.ExpiresAt.Offset != TimeSpan.Zero ||
            value.CreatedAt != row.CreatedAt || value.ExpiresAt != row.ExpiresAt || value.ExpiresAt != value.CreatedAt.AddMinutes(60) || value.CreatedAt > Now ||
            secret.DeleteAfter != value.CreatedAt.AddDays(7) || secret.DeleteAfter.Offset != TimeSpan.Zero ||
            value.Mailboxes is null || !value.Mailboxes.Valid() || configured && value.Mailboxes != options.Mailboxes || !EmailPilotCanonical.Hash(value.CapabilitySha256) ||
            !CryptographicOperations.FixedTimeEquals(EmailPilotCanonical.Hash(value), row.ManifestSha256) ||
            !CryptographicOperations.FixedTimeEquals(Convert.FromHexString(value.CapabilitySha256), row.CapabilitySha256)) throw EmailPilotProtection.Invalid();
        if (live && value.ExpiresAt <= Now) return null;
        return value;
    }

    private async Task<List<EmailPilotEnrollment>> Enrollments(QuillSignDbContext db, EmailPilotManifest run, CancellationToken ct)
    {
        var rows = await db.EmailPilotEnrollments.AsNoTracking().Where(x => x.RunId == run.RunId).Take(4).ToListAsync(ct);
        if (rows.Count > 3) throw EmailPilotProtection.Invalid();
        return rows.Select(x => {
            var value = protection().Read<EmailPilotEnrollment>(run.RunId, "enrollment", x.ProtectedBinding, 2048);
            if (value is null || value.RunId != x.RunId || value.SubjectEnvelopeId != x.SubjectEnvelopeId || value.Scenario != x.Scenario || value.EnrolledAt != x.EnrolledAt ||
                value.SubjectEnvelopeId == Guid.Empty || !Enum.IsDefined(value.Scenario) || value.EnrolledAt.Offset != TimeSpan.Zero ||
                value.EnrolledAt < run.CreatedAt || value.EnrolledAt >= run.ExpiresAt || value.EnrolledAt > Now ||
                value.Verification is { } v && (v.WorkId == Guid.Empty || !EmailPilotCanonical.Hash(v.DraftSha256) ||
                    !EmailPilotCanonical.Hash(v.EmailPayloadSha256) || !EmailPilotCanonical.Hash(v.WorkPayloadSha256))) throw EmailPilotProtection.Invalid();
            return value;
        }).ToList();
    }

    private async Task<List<EmailPilotAttempt>> Reservations(QuillSignDbContext db, EmailPilotManifest run, CancellationToken ct)
    {
        var rows = await db.EmailPilotReservations.AsNoTracking().Where(x => x.RunId == run.RunId).Take(35).ToListAsync(ct);
        if (rows.Count > 34) throw EmailPilotProtection.Invalid();
        var result = rows.Select(x => {
            var value = protection().Read<EmailPilotAttempt>(run.RunId, "reservation", x.ProtectedReceipt, 4096);
            if (value is null || value != new EmailPilotAttempt(x.Id, x.RunId, x.SubjectEnvelopeId, x.OperationId, x.Kind, x.Role, x.EncodedBytes, Convert.ToHexStringLower(x.RequestSha256), x.ReservedAt) ||
                !Shape(new(value.Id, value.SubjectEnvelopeId, value.OperationId, value.Kind, value.Role, value.EncodedBytes, value.RequestSha256)) ||
                value.ReservedAt.Offset != TimeSpan.Zero || value.ReservedAt < run.CreatedAt || value.ReservedAt >= run.ExpiresAt || value.ReservedAt > Now) throw EmailPilotProtection.Invalid();
            return value;
        }).ToList();
        var total = Budget(result);
        if (total.ApplicationAttempts > 20 || total.SimulatorAttempts > 10 || total.TimestampAttempts > 4 || total.EncodedBytes > EmailPilotLimits.AggregateBytes)
            throw EmailPilotProtection.Invalid();
        return result;
    }

    private static bool Shape(EmailPilotReservation r) => r is not null && r.Id != Guid.Empty && r.OperationId != Guid.Empty &&
        EmailPilotCanonical.Hash(r.RequestSha256) && r.SubjectEnvelopeId != Guid.Empty && (r.Kind switch {
            EmailPilotAttemptKind.Application => r.SubjectEnvelopeId is not null && r.Role is EmailPilotRole.Sender or EmailPilotRole.FirstSigner or EmailPilotRole.SecondSigner or EmailPilotRole.Recipient && r.EncodedBytes is > 0 and <= EmailPilotLimits.MessageBytes,
            EmailPilotAttemptKind.Simulator => r.SubjectEnvelopeId is null && r.Role == EmailPilotRole.Simulator && r.EncodedBytes is > 0 and <= EmailPilotLimits.MessageBytes,
            EmailPilotAttemptKind.Timestamp => r.SubjectEnvelopeId is not null && r.Role == EmailPilotRole.None && r.EncodedBytes == 0,
            _ => false
        });
    private static bool Equivalent(EmailPilotAttempt p, EmailPilotReservation r) => p.SubjectEnvelopeId == r.SubjectEnvelopeId && p.OperationId == r.OperationId && p.Kind == r.Kind &&
        p.Role == r.Role && p.EncodedBytes == r.EncodedBytes && p.RequestSha256 == r.RequestSha256;
    private static EmailPilotBudget Budget(IEnumerable<EmailPilotAttempt> rows) => new(rows.Count(x => x.Kind == EmailPilotAttemptKind.Application),
        rows.Count(x => x.Kind == EmailPilotAttemptKind.Simulator), rows.Count(x => x.Kind == EmailPilotAttemptKind.Timestamp), rows.Sum(x => (long)x.EncodedBytes));
    private static bool MatchesCapability(EmailPilotManifest run, byte[] hash) => CryptographicOperations.FixedTimeEquals(Convert.FromHexString(run.CapabilitySha256), hash);
    private void EnsureLive(EmailPilotManifest run) { if (!Enabled || run.RunId != RunId || run.Mailboxes != options.Mailboxes || run.ExpiresAt <= Now) throw EmailPilotProtection.Invalid(); }
    private static async Task Open(QuillSignDbContext db, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is not null) throw new InvalidOperationException("Pilot ledger operations require an explicit isolated transaction.");
        if (db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Pilot accounting cannot discard another operation's pending changes.");
        db.ChangeTracker.Clear(); await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
    }
    private static Task Lock(QuillSignDbContext db, Guid id, CancellationToken ct) => db.Database.ExecuteSqlInterpolatedAsync($"""
        DECLARE @result int;
        EXEC @result=sys.sp_getapplock @Resource={"email-pilot:" + id.ToString("N")},@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000;
        IF @result<0 THROW 50002,'Pilot accounting is temporarily busy.',1;
        """, ct);
}
