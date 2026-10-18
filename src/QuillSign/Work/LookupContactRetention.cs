using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Work;

public sealed class LookupContactRetentionOptions
{
    // Reuses the operator's demo policy; no independent/default retention promise.
    public int? Days { get; set; }
    internal void Validate()
    {
        if (Days is < 1 or > 36500) throw new InvalidOperationException("Configure Demo:PurgeAfterDays between 1 and 36500 or leave it unset.");
    }
}

public sealed class LookupContactRetention(QuillSignDbContext db, LookupContactRetentionOptions options,
    LookupDeliveryProtection protection, Func<IWorkSignals> signals, TimeProvider time)
{
    public const string Version = "lookup-contact-retention-v1";
    internal const string PurgeVersion = "lookup-contact-purge-v1";
    internal sealed record Binding(Guid RequestId, string Sha256, DateTimeOffset DeleteAfter);
    public bool Configured { get { options.Validate(); return options.Days is not null; } }
    public static Guid WorkId(Guid request) => new(SHA256.HashData(Encoding.UTF8.GetBytes("lookup-contact-purge-work-v1:" + request.ToString("N")))[..16]);
    internal static string Digest(LookupContactRetentionSnapshot row) => Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
        row.RequestId, row.PolicyVersion, row.Days, row.StartedAt, row.DeleteAfter })));
    internal static string Payload(LookupContactRetentionSnapshot row) => Payload(new Binding(row.RequestId, Digest(row), row.DeleteAfter));
    private static string Payload(Binding b) => JsonSerializer.Serialize(new { version = PurgeVersion, requestId = b.RequestId, retentionSha256 = b.Sha256, deleteAfter = b.DeleteAfter });
    internal static Binding ReadPayload(string json)
    {
        try {
            if (json.Length > 1024) throw Invalid();
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 }); var p = doc.RootElement;
            var b = new Binding(p.GetProperty("requestId").GetGuid(), p.GetProperty("retentionSha256").GetString()!, p.GetProperty("deleteAfter").GetDateTimeOffset());
            if (b.RequestId == Guid.Empty || !LookupDeliveryProtection.Hash(b.Sha256) || b.DeleteAfter.Offset != TimeSpan.Zero ||
                b.DeleteAfter.Ticks % TimeSpan.TicksPerSecond != 0 || json != Payload(b)) throw Invalid();
            return b;
        } catch (Exception e) when (e is JsonException or KeyNotFoundException or FormatException or InvalidOperationException) { throw Invalid(); }
    }
    internal static bool IsPayload(string json)
    {
        if (json.Length > 1024) return false;
        try { using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 }); return doc.RootElement.TryGetProperty("version", out var v) && v.GetString() == PurgeVersion; }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { return false; }
    }
    internal static void Check(LookupContactRetentionSnapshot row, EmailOutbox email)
    {
        if (row.RequestId != email.Id || email.EnvelopeId is not null || email.Template != LookupDeliveryProtection.Template || email.AttachmentsJson != "[]" ||
            row.PolicyVersion != Version || row.Days is < 1 or > 36500 || row.StartedAt.Offset != TimeSpan.Zero || row.DeleteAfter.Offset != TimeSpan.Zero ||
            row.StartedAt.Ticks % TimeSpan.TicksPerSecond != 0 || row.DeleteAfter != row.StartedAt.AddDays(row.Days) ||
            email.AvailableAt.Offset != TimeSpan.Zero || email.AvailableAt < row.StartedAt || email.AvailableAt >= row.StartedAt.AddSeconds(1)) throw Invalid();
    }
    internal async Task<LookupContactRetentionSnapshot> ReadAsync(EmailOutbox email, CancellationToken ct)
    {
        var row = await db.LookupContactRetentionSnapshots.AsNoTracking().SingleOrDefaultAsync(x => x.RequestId == email.Id, ct) ?? throw Invalid();
        Check(row, email);
        var job = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == WorkId(email.Id), ct) ?? throw Invalid();
        if (job.Kind != WorkKind.Purge || job.EnvelopeId is not null || job.PayloadJson != Payload(row) || job.AvailableAt < row.DeleteAfter ||
            job.Status is not (WorkStatus.Queued or WorkStatus.Leased)) throw Invalid();
        return row;
    }
    // Callers hold the shared lookup application lock and the email-work/outbox locks.
    internal async Task<LookupContactRetentionSnapshot> EnrollLockedAsync(EmailOutbox email, bool resume, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw Invalid();
        var row = await db.LookupContactRetentionSnapshots.AsNoTracking().SingleOrDefaultAsync(x => x.RequestId == email.Id, ct);
        if (row is null) {
            if (!Configured) throw new InvalidOperationException("Configure the demo retention window before lookup admission.");
            var original = protection.Read(email).RequestedAt;
            var started = DateTimeOffset.FromUnixTimeSeconds(original.ToUnixTimeSeconds());
            if (options.Days == 1 && email.SubmissionStartedAt >= new DateTimeOffset(started.UtcDateTime.Date.AddDays(1), TimeSpan.Zero))
                throw new InvalidDataException("A one-day legacy policy would erase current delivery counters.");
            row = new() { RequestId = email.Id, PolicyVersion = Version, Days = options.Days!.Value, StartedAt = started, DeleteAfter = started.AddDays(options.Days.Value) };
            db.LookupContactRetentionSnapshots.Add(row);
        }
        Check(row, email);
        var id = WorkId(email.Id);
        var job = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={id}").SingleOrDefaultAsync(ct);
        if (job is null) db.WorkItems.Add(new() { Id = id, Kind = WorkKind.Purge, PayloadJson = Payload(row), AvailableAt = row.DeleteAfter });
        else {
            if (job.Kind != WorkKind.Purge || job.EnvelopeId is not null || job.PayloadJson != Payload(row) || job.AvailableAt < row.DeleteAfter || job.Status == WorkStatus.Completed) throw Invalid();
            if (job.Status == WorkStatus.Failed) {
                if (!resume || job.LastError is not ("unsupported-work-kind" or "attempts-exhausted")) throw Invalid();
                job.Status = WorkStatus.Queued; job.LastError = null; job.LeaseOwner = null; job.LeaseExpiresAt = null;
            }
        }
        await db.SaveChangesAsync(ct);
        var due = job is { Status: WorkStatus.Leased, LeaseExpiresAt: { } until } && until > job.AvailableAt ? until : job?.AvailableAt ?? row.DeleteAfter;
        await signals().PutHintAsync(id, due, ct); return row;
    }
    internal async Task PublishAsync(Guid request, DateTimeOffset due, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is not null) throw Invalid();
        try { await signals().PublishAsync(WorkId(request), TimeSpan.FromSeconds(Math.Clamp((due - time.GetUtcNow()).TotalSeconds, 0, 7 * 24 * 60 * 60)), ct); }
        catch (Exception e) when (e is RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { }
    }
    public async Task<Guid?> ResumeAsync(Guid request, CancellationToken ct = default)
    {
        if (request == Guid.Empty) return null;
        if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Lookup retention resume requires a clean standalone unit of work.");
        LookupContactRetentionSnapshot policy;
        try {
            await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
            await using (var tx = await db.Database.BeginTransactionAsync(ct)) {
                await LookupDeliveryRules.LockAsync(db, ct);
                var work = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={request}").AsNoTracking().SingleOrDefaultAsync(ct);
                var email = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={request}").AsNoTracking().SingleOrDefaultAsync(ct);
                if (email is null) return null;
                if (work is null || work.Kind != WorkKind.Email || work.EnvelopeId is not null || work.PayloadJson != JsonSerializer.Serialize(new { emailId = request }) ||
                    work.Status == WorkStatus.Leased && work.LeaseExpiresAt > time.GetUtcNow()) throw Invalid();
                // Legacy enrollment must first verify the protected original request.
                if (!await db.LookupContactRetentionSnapshots.AnyAsync(x => x.RequestId == request, ct)) _ = protection.Read(email);
                policy = await EnrollLockedAsync(email, true, ct); await tx.CommitAsync(ct);
            }
            await PublishAsync(request, policy.DeleteAfter, ct); return WorkId(request);
        } finally { db.ChangeTracker.Clear(); }
    }
    internal static DateTimeOffset DispatchDeadline(LookupMailPayload request, LookupDeliveryOptions limits, LookupContactRetentionSnapshot policy)
    {
        var end = new[] { request.Deadline, request.RequestedAt.AddHours(limits.RequestHours), policy.DeleteAfter }.Min();
        // Retain admission/delivery counters through their complete UTC day, even
        // for a one-day policy. Never extend private retention to keep counters.
        return policy.Days == 1 ? new[] { end, new DateTimeOffset(policy.StartedAt.UtcDateTime.Date.AddDays(1), TimeSpan.Zero) }.Min() : end;
    }
    private static InvalidDataException Invalid() => new("The saved lookup contact retention scope could not be verified.");
}
