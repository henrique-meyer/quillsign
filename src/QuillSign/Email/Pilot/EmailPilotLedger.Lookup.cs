using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotLedger
{
    internal async Task<EmailPilotEnrollment?> LookupCompletionAsync(string capability, CancellationToken ct)
    {
        if (!Enabled) return null;
        var db = database(); await Open(db, ct);
        var run = await Manifest(db, RunId, true, ct);
        if (run is null || !MatchesCapability(run, EmailPilotCanonical.Capability(capability))) return null;
        var saved = (await Enrollments(db, run, ct)).SingleOrDefault(x => x.Scenario == EmailPilotScenario.Completion);
        EnsureLive(run); return saved?.Verification is null ? null : saved;
    }

    internal async Task<T?> AdmitLookupAsync<T>(string capability,
        Func<QuillSignDbContext, EmailPilotManifest, EmailPilotEnrollment, Task<T?>> prepare, CancellationToken ct) where T : class
    {
        if (!Enabled) return null;
        var db = database(); await Open(db, ct); var committed = false;
        try
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct); await Lock(db, RunId, ct);
            var run = await Manifest(db, RunId, true, ct);
            if (run is null || !MatchesCapability(run, EmailPilotCanonical.Capability(capability))) return null;
            var saved = (await Enrollments(db, run, ct)).SingleOrDefault(x => x.Scenario == EmailPilotScenario.Completion);
            if (saved?.Verification is null) return null;
            var result = await prepare(db, run, saved);
            if (result is null) return null;
            EnsureLive(run); await tx.CommitAsync(ct); committed = true; return result;
        }
        finally { if (!committed) db.ChangeTracker.Clear(); }
    }
}
