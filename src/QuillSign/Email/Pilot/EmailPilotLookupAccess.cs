using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotLookupAccess(Func<QuillSignDbContext> database, Func<EmailPilotProtection> protection,
    Func<EmailPilotEnvelopeAccess> cohorts, Func<EmailPilotLedger> ledger, EmailPilotAdmissionOptions admission, WorkOptions work,
    Func<LookupDeliveryProtection> payloads, Func<LookupContactRetention> retention, LookupDeliveryOptions limits,
    Func<CompletionAccessState> completions, TimeProvider time)
{
    private DateTimeOffset Now => time.GetUtcNow().ToUniversalTime();
    internal bool Live(EmailPilotManifest manifest) => ledger().EnvelopeCohortLive(manifest, admission, work);
    internal static bool SourceError(Exception e) => e is InvalidDataException or CryptographicException or JsonException or ArgumentException or EmailDisabledException;

    internal async Task<bool> IsKnownWorkAsync(Guid id, CancellationToken ct)
    {
        var db = database();
        if (await db.EmailPilotLookupRequests.AsNoTracking().AnyAsync(x => x.RequestId == id, ct)) return true;
        var row = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row?.Template != LookupDeliveryProtection.Template) return false;
        try { return payloads().Read(row).PilotRunId is not null; }
        catch (Exception e) when (SourceError(e)) { return false; } // The ordinary payload verifier also cannot submit this row.
    }

    internal EmailPilotLookupRequestBinding Decode(EmailPilotLookupRequestRecord row)
    {
        var value = protection().Read<EmailPilotLookupRequestBinding>(row.RunId, "lookup-request", row.ProtectedBinding, 4096);
        if (!EmailPilotLookupRules.Shape(value) || value != EmailPilotLookupRules.Binding(row)) throw EmailPilotProtection.Invalid();
        return value;
    }
    internal EmailPilotLookupTokenBinding Decode(EmailPilotLookupTokenRecord row)
    {
        var value = protection().Read<EmailPilotLookupTokenBinding>(row.RunId, "lookup-token", row.ProtectedBinding, 4096);
        if (!EmailPilotLookupRules.Shape(value) || value != EmailPilotLookupRules.Binding(row)) throw EmailPilotProtection.Invalid();
        return value;
    }

    // This metadata read does not grant storage access. Admission and the normal
    // list/download path independently verify the actual immutable final pair.
    internal async Task<(EmailPilotManifest Run, DownloadPublication Publication, EmailOutbox Email, LookupMailPayload Payload)>
        ReadRequestLockedAsync(EmailPilotLookupRequestBinding saved, CancellationToken ct)
    {
        var db = database();
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Pilot lookup reads require their parent transaction.");
        var cohort = await cohorts().RequireSendRosterLockedAsync(new() { Id = saved.SubjectEnvelopeId }, ct);
        if (!cohort.Allowed || cohort.Scenario != EmailPilotScenario.Completion || cohort.RunId != saved.RunId || cohort.Manifest is not { } run ||
            saved.RequestedAt < run.CreatedAt || saved.RequestedAt > Now || saved.ExpiresAt > run.ExpiresAt || saved.ExpiresAt <= Now) throw EmailPilotProtection.Invalid();
        var email = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == saved.RequestId, ct) ?? throw EmailPilotProtection.Invalid();
        var p = payloads().Read(email);
        var item = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == saved.RequestId, ct) ?? throw EmailPilotProtection.Invalid();
        var policy = await retention().ReadAsync(email, ct);
        if (p.PilotRunId != saved.RunId || p.Email != run.Mailboxes.Sender || p.RequestedAt != saved.RequestedAt || p.Deadline != saved.ExpiresAt ||
            EmailPilotLookupRules.OriginalRequestSha256(p) != saved.RequestSha256 || LookupContactRetention.Digest(policy) != saved.RetentionSha256 ||
            LookupContactRetention.DispatchDeadline(p, limits, policy) <= Now || item.Kind != WorkKind.Email || item.EnvelopeId is not null ||
            item.AvailableAt < p.RequestedAt || item.PayloadJson != JsonSerializer.Serialize(new { emailId = saved.RequestId }) ||
            EmailPilotLookupRules.Hash(item.PayloadJson) != saved.WorkSha256) throw EmailPilotProtection.Invalid();
        var publication = await CompletionDownloadState.ReadAsync(db, saved.SubjectEnvelopeId, time, ct) ?? throw EmailPilotProtection.Invalid();
        if (publication.Id != saved.PublicationId || Convert.ToHexStringLower(publication.Recipe) != saved.PublicationRecipeSha256 ||
            publication.PurgeAfter < saved.ExpiresAt || publication.PurgeAfter <= Now)
            throw EmailPilotProtection.Invalid();
        await completions().RecheckLockedAsync(publication, ct);
        var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == saved.SubjectEnvelopeId, ct);
        var deadline = await SenderPreparationRetention.ReadAsync(db, envelope, time, ct);
        if (deadline < saved.ExpiresAt || deadline <= Now || !Live(run)) throw EmailPilotProtection.Invalid();
        return (run, publication, email, p);
    }

    internal async Task<EmailPilotLookupWorkScope?> ReadWorkAsync(WorkLease lease, bool submitted, CancellationToken ct)
    {
        if (lease is null || lease.Id == Guid.Empty || lease.Owner == Guid.Empty || lease.Kind != WorkKind.Email || lease.Attempt is < 1 or > 10 ||
            lease.Until.Offset != TimeSpan.Zero || lease.Until <= Now) return null;
        var db = database();
        if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Pilot lookup authority needs a clean standalone context.");
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        var record = await db.EmailPilotLookupRequests.AsNoTracking().SingleOrDefaultAsync(x => x.RequestId == lease.Id, ct);
        if (record is null) return null;
        try
        {
            var saved = Decode(record);
            EmailPilotLookupWorkScope scope;
            await using (var tx = await db.Database.BeginTransactionAsync(ct))
            {
                var current = await ReadRequestLockedAsync(saved, ct); // completion parent first
                await LookupDeliveryRules.LockAsync(db, ct);
                var item = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
                var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
                var p = payloads().Read(row);
                if (item.EnvelopeId is not null || item.Kind != WorkKind.Email || item.Status != WorkStatus.Leased || item.LeaseOwner != lease.Owner ||
                    item.Attempts != lease.Attempt || item.LeaseExpiresAt != lease.Until || item.LeaseExpiresAt <= Now || item.AvailableAt > Now ||
                    row.Status != EmailStatus.Queued || row.Provider is not null || row.ProviderMessageId is not null ||
                    row.PayloadJson != current.Email.PayloadJson || (row.SubmissionStartedAt is not null) != submitted ||
                    submitted && (row.Attempts != lease.Attempt || row.SubmissionStartedAt > Now || p.Issued is null) || !submitted && p.Issued is not null)
                    throw EmailPilotProtection.Invalid();
                if (submitted) await VerifyIssuedLockedAsync(saved, p.Issued!, lease.Attempt, ct);
                var until = new[] { saved.ExpiresAt, current.Run.ExpiresAt, lease.Until }.Min();
                scope = new(saved, current.Run, lease, current.Publication,
                    Convert.ToHexStringLower(EmailPilotCanonical.Hash(new { saved, Work = item.PayloadJson, Email = row.PayloadJson, row.To, row.SubmissionStartedAt, row.Attempts })), until);
                if (!Live(current.Run) || until <= Now) throw EmailPilotProtection.Invalid();
                await tx.CommitAsync(ct);
            }
            return Live(scope.Manifest) && scope.Until > Now ? scope : null;
        }
        catch (Exception e) when (SourceError(e)) { return null; }
    }

    internal async Task<bool> StillCurrentAsync(EmailPilotLookupWorkScope scope, CancellationToken ct)
    {
        if (!Live(scope.Manifest) || scope.Until <= Now) return false;
        var current = await ReadWorkAsync(scope.Lease, true, ct);
        return current is not null && current.Request == scope.Request && current.SourceSha256 == scope.SourceSha256 && current.Until == scope.Until;
    }

    internal async Task DemandBeforeIssueLockedAsync(EmailPilotLookupWorkScope scope, CancellationToken ct)
    {
        var db = database();
        if (db.Database.CurrentTransaction is null || !Live(scope.Manifest) || scope.Until <= Now) throw EmailPilotProtection.Invalid();
        var current = await ReadRequestLockedAsync(scope.Request, ct);
        await LookupDeliveryRules.LockAsync(db, ct);
        var lease = scope.Lease;
        var item = await db.WorkItems.FromSqlInterpolated($"SELECT * FROM [WorkItems] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
        var row = await db.EmailOutbox.FromSqlInterpolated($"SELECT * FROM [EmailOutbox] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={lease.Id}").AsNoTracking().SingleAsync(ct);
        var p = payloads().Read(row);
        var hash = Convert.ToHexStringLower(EmailPilotCanonical.Hash(new { saved = scope.Request, Work = item.PayloadJson,
            Email = row.PayloadJson, row.To, row.SubmissionStartedAt, row.Attempts }));
        if (item.Kind != WorkKind.Email || item.EnvelopeId is not null || item.Status != WorkStatus.Leased || item.LeaseOwner != lease.Owner ||
            item.Attempts != lease.Attempt || item.LeaseExpiresAt != lease.Until || item.AvailableAt > Now ||
            row.Status != EmailStatus.Queued || row.Provider is not null || row.ProviderMessageId is not null || row.SubmissionStartedAt is not null ||
            p.Issued is not null || row.PayloadJson != current.Email.PayloadJson || hash != scope.SourceSha256 || !Live(current.Run) || scope.Until <= Now)
            throw EmailPilotProtection.Invalid();
    }
}
