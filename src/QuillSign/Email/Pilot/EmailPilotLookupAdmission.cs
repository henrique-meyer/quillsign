using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

// No public endpoint calls this source component. Only an explicit authenticated
// operator POST may nominate the already-approved manifest Sender for lookup.
public sealed class EmailPilotLookupAdmission(EmailPilotOptions options, EmailOptions email, WorkOptions work,
    EmailPilotAdmissionOptions admission, Func<QuillSignDbContext> database, Func<EmailPilotLedger> ledger,
    Func<EmailPilotEnvelopeAccess> cohorts, Func<CompletionAccessState> completions, Func<DocumentLookupRequests> requests,
    Func<EmailPilotLookupAccess> access, Func<EmailPilotProtection> protection, Func<LookupContactRetention> retention,
    Func<IWorkSignals> signals, TimeProvider time)
{
    private sealed record Committed(Guid RequestId, bool Recovered, bool Publish, DateTimeOffset CleanupDue);
    private bool Enabled => options.Enabled && !email.Enabled && work.Enabled;
    private DateTimeOffset Now => time.GetUtcNow().ToUniversalTime();

    public async Task<EmailPilotLookupAdmissionResult?> RequestAsync(string capability, string? serverIp, CancellationToken ct = default)
    {
        // Match configured operator authority before SQL, storage, key ring or
        // ordinary lookup dependency resolution. Never accept caller recipients.
        if (!Enabled || !EmailPilotCanonical.Hash(admission.CapabilitySha256)) return null;
        byte[] supplied;
        try { supplied = EmailPilotCanonical.Capability(capability); }
        catch (ArgumentException) { return null; }
        if (!CryptographicOperations.FixedTimeEquals(supplied, Convert.FromHexString(admission.CapabilitySha256))) return null;
        var selected = await ledger().LookupCompletionAsync(capability, ct); if (selected is null) return null;
        var cohort = await cohorts().ReadAsync(selected.SubjectEnvelopeId, ct);
        if (!cohort.Allowed || cohort.Scenario != EmailPilotScenario.Completion || cohort.RunId != selected.RunId) return null;
        // The normal verifier reads both exact immutable finals. This is not an
        // invented completion state or a mailbox-verification bypass.
        var prepared = await completions().PrepareAsync(selected.SubjectEnvelopeId, ct); if (prepared is null) return null;
        var saved = await ledger().AdmitLookupAsync<Committed>(capability, async (db, run, enrolled) => {
            if (!ReferenceEquals(db, database()) || enrolled.SubjectEnvelopeId != prepared.Saved.EnvelopeId || run.RunId != selected.RunId)
                throw EmailPilotProtection.Invalid();
            await completions().RecheckLockedAsync(prepared.Saved, ct);
            var currentCohort = await cohorts().RequireSendRosterLockedAsync(new() { Id = enrolled.SubjectEnvelopeId }, ct);
            if (!currentCohort.Allowed || currentCohort.RunId != run.RunId || currentCohort.Scenario != EmailPilotScenario.Completion) return null;
            var existing = await db.EmailPilotLookupRequests.AsNoTracking().SingleOrDefaultAsync(x => x.RunId == run.RunId, ct);
            if (existing is not null)
            {
                var binding = access().Decode(existing);
                var current = await access().ReadRequestLockedAsync(binding, ct);
                if (current.Payload.Issued is { } issued && !(await access().TokenLockedAsync(issued.Id, run.Mailboxes.Sender, ct)).Allowed)
                    throw EmailPilotProtection.Invalid();
                var row = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == binding.RequestId, ct);
                var policy = await retention().ReadAsync(current.Email, ct);
                if (prepared.Until <= Now || !ledger().EnvelopeCohortLive(run, admission, work)) throw EmailPilotProtection.Invalid();
                return new(binding.RequestId, true, row.Status == WorkStatus.Queued && current.Email.Status == EmailStatus.Queued, policy.DeleteAfter);
            }
            var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == enrolled.SubjectEnvelopeId, ct);
            var documentDeadline = await SenderPreparationRetention.ReadAsync(db, envelope, time, ct);
            var deadline = new[] { run.ExpiresAt, prepared.Saved.PurgeAfter ?? DateTimeOffset.MaxValue, documentDeadline ?? DateTimeOffset.MaxValue }.Min();
            if (deadline <= Now || prepared.Until <= Now) return null;
            var scope = new EmailPilotLookupAdmissionScope(db, run, deadline);
            var request = await requests().PreparePilotLockedAsync(scope, serverIp, ct); if (request is null) return null;
            var item = await db.WorkItems.AsNoTracking().SingleAsync(x => x.Id == scope.RequestId, ct);
            var value = new EmailPilotLookupRequestBinding(EmailPilotLookupRules.Version, run.RunId, scope.RequestId, enrolled.SubjectEnvelopeId,
                prepared.Saved.Id, Convert.ToHexStringLower(prepared.Saved.Recipe), EmailPilotLookupRules.OriginalRequestSha256(request.Payload),
                EmailPilotLookupRules.Hash(item.PayloadJson), LookupContactRetention.Digest(request.Retention), request.Payload.RequestedAt, request.Payload.Deadline);
            if (!EmailPilotLookupRules.Shape(value) || !Enabled || prepared.Until <= Now || !ledger().EnvelopeCohortLive(run, admission, work)) throw EmailPilotProtection.Invalid();
            db.EmailPilotLookupRequests.Add(new() { RunId = value.RunId, RequestId = value.RequestId, SubjectEnvelopeId = value.SubjectEnvelopeId,
                PublicationId = value.PublicationId, PublicationRecipeSha256 = Convert.FromHexString(value.PublicationRecipeSha256),
                RequestSha256 = Convert.FromHexString(value.RequestSha256), WorkSha256 = Convert.FromHexString(value.WorkSha256),
                RetentionSha256 = Convert.FromHexString(value.RetentionSha256), RequestedAt = value.RequestedAt, ExpiresAt = value.ExpiresAt,
                ProtectedBinding = protection().Protect(run.RunId, "lookup-request", value) });
            await db.SaveChangesAsync(ct);
            await access().ReadRequestLockedAsync(value, ct);
            if (prepared.Until <= Now || !ledger().EnvelopeCohortLive(run, admission, work)) throw EmailPilotProtection.Invalid();
            return new(value.RequestId, false, true, request.Retention.DeleteAfter);
        }, ct);
        if (saved is null) return null;
        var published = !saved.Publish;
        if (saved.Publish)
        {
            try { await signals().PublishAsync(saved.RequestId, TimeSpan.Zero, ct); published = true; }
            catch (Exception e) when (e is Azure.RequestFailedException or IOException or HttpRequestException or OperationCanceledException) { }
        }
        await retention().PublishAsync(saved.RequestId, saved.CleanupDue, ct);
        return new(saved.RequestId, saved.Recovered, published);
    }
}
