using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed record EmailPilotSecretPreparation(Guid WorkId, bool Recovered, bool WakeupPublished);

// Contains no contact text, capability, encrypted manifest or provider authority.
public sealed class EmailPilotSecretJobs(QuillSignDbContext db, Func<IWorkSignals> signals, TimeProvider time)
{
    internal const string Version = "email-pilot-secret-purge-v1";
    internal sealed record Binding(Guid RunId, DateTimeOffset CreatedAt, DateTimeOffset DeleteAfter, string ManifestSha256);
    public static Guid WorkId(Guid runId) => new(SHA256.HashData(Encoding.ASCII.GetBytes(Version + ":" + runId.ToString("N")))[..16]);
    internal static string Payload(Binding b) => JsonSerializer.Serialize(new { version = Version, runId = b.RunId,
        createdAt = b.CreatedAt, deleteAfter = b.DeleteAfter, manifestSha256 = b.ManifestSha256 });
    internal static bool IsPayload(string json)
    {
        if (json.Length > 1024) return false;
        try { using var d = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            return d.RootElement.TryGetProperty("version", out var v) && v.GetString() == Version; }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { return false; }
    }
    internal static Binding ReadPayload(string json)
    {
        try {
            if (json.Length > 1024) throw Invalid();
            using var d = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 }); var p = d.RootElement;
            var b = new Binding(p.GetProperty("runId").GetGuid(), p.GetProperty("createdAt").GetDateTimeOffset(),
                p.GetProperty("deleteAfter").GetDateTimeOffset(), p.GetProperty("manifestSha256").GetString()!);
            if (b.RunId == Guid.Empty || b.CreatedAt.Offset != TimeSpan.Zero || b.DeleteAfter.Offset != TimeSpan.Zero ||
                b.DeleteAfter != b.CreatedAt.AddDays(7) || !EmailPilotCanonical.Hash(b.ManifestSha256) || json != Payload(b)) throw Invalid();
            return b;
        } catch (Exception e) when (e is JsonException or KeyNotFoundException or FormatException or InvalidOperationException or ArgumentOutOfRangeException) { throw Invalid(); }
    }
    internal static async Task LockAsync(QuillSignDbContext db, Guid runId, CancellationToken ct)
    {
        var resource = "email-pilot:" + runId.ToString("N");
        await db.Database.ExecuteSqlInterpolatedAsync($"DECLARE @r int; EXEC @r=sys.sp_getapplock @Resource={resource},@LockMode='Exclusive',@LockOwner='Transaction',@LockTimeout=5000; IF @r<0 THROW 51000,'Pilot cleanup lock unavailable.',1;", ct);
    }
    internal static async Task CheckRunAsync(QuillSignDbContext db, Binding binding, CancellationToken ct)
    {
        var row = await db.EmailPilotRuns.AsNoTracking().SingleOrDefaultAsync(x => x.Id == binding.RunId, ct) ?? throw Invalid();
        if (row.CreatedAt != binding.CreatedAt || row.CreatedAt.Offset != TimeSpan.Zero || row.ExpiresAt.Offset != TimeSpan.Zero ||
            row.ExpiresAt != row.CreatedAt.AddMinutes(60) || Convert.ToHexStringLower(row.ManifestSha256) != binding.ManifestSha256) throw Invalid();
        var secretDue = await db.EmailPilotSecrets.AsNoTracking().Where(x => x.RunId == binding.RunId).Select(x => (DateTimeOffset?)x.DeleteAfter).SingleOrDefaultAsync(ct);
        if (secretDue is not null && (secretDue.Value.Offset != TimeSpan.Zero || secretDue != binding.DeleteAfter)) throw Invalid();
    }
    internal static void CheckWork(WorkItem row, Binding b)
    {
        if (row.Id != WorkId(b.RunId) || row.EnvelopeId is not null || row.Kind != WorkKind.Purge || row.PayloadJson != Payload(b) ||
            row.Attempts < 0 || row.AvailableAt.Offset != TimeSpan.Zero || row.AvailableAt < b.DeleteAfter ||
            (row.Attempts == 0 && row.AvailableAt != b.DeleteAfter) || !Enum.IsDefined(row.Status) ||
            (row.Status == WorkStatus.Leased ? row.LeaseOwner is null || row.LeaseOwner == Guid.Empty || row.LeaseExpiresAt is null || row.LeaseExpiresAt.Value.Offset != TimeSpan.Zero || row.LeaseExpiresAt <= row.AvailableAt :
                row.LeaseOwner is not null || row.LeaseExpiresAt is not null)) throw Invalid();
    }
    public async Task<EmailPilotSecretPreparation> PrepareAsync(EmailPilotManifest run, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(run);
        if (run.Version != EmailPilotLimits.Version || run.RunId == Guid.Empty || run.CreatedAt.Offset != TimeSpan.Zero ||
            run.ExpiresAt != run.CreatedAt.AddMinutes(60) || run.ExpiresAt.Offset != TimeSpan.Zero || run.Mailboxes is null ||
            !run.Mailboxes.Valid() || !EmailPilotCanonical.Hash(run.CapabilitySha256)) throw Invalid();
        if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Pilot cleanup preparation requires a clean standalone unit of work.");
        var b = new Binding(run.RunId, run.CreatedAt, run.CreatedAt.AddDays(7), Convert.ToHexStringLower(EmailPilotCanonical.Hash(run)));
        var id = WorkId(run.RunId); bool recovered, terminal; DateTimeOffset due;
        try {
            await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
            await using (var tx = await db.Database.BeginTransactionAsync(ct)) {
                await LockAsync(db, run.RunId, ct); await CheckRunAsync(db, b, ct);
                var row = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").SingleOrDefaultAsync(ct);
                recovered = row is not null;
                if (row is null) { row = new() { Id = id, Kind = WorkKind.Purge, AvailableAt = b.DeleteAfter, PayloadJson = Payload(b) }; db.WorkItems.Add(row); }
                CheckWork(row, b); terminal = row.Status == WorkStatus.Completed;
                if (row.Status == WorkStatus.Failed || (terminal && await db.EmailPilotSecrets.AnyAsync(x => x.RunId == b.RunId, ct))) throw Invalid();
                due = row.Status == WorkStatus.Leased && row.LeaseExpiresAt > row.AvailableAt ? row.LeaseExpiresAt.Value : row.AvailableAt;
                await db.SaveChangesAsync(ct);
                if (!terminal) await signals().PutHintAsync(id, due, ct);
                await tx.CommitAsync(ct);
            }
        } finally { db.ChangeTracker.Clear(); }
        if (terminal) return new(id, recovered, false);
        try { await signals().PublishAsync(id, TimeSpan.FromSeconds(Math.Clamp((due - time.GetUtcNow()).TotalSeconds, 0, 7 * 24 * 60 * 60)), ct); return new(id, recovered, true); }
        catch (Exception e) when (e is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { return new(id, recovered, false); }
    }
    internal static InvalidDataException Invalid() => new("The pilot secret cleanup scope could not be verified.");
}
