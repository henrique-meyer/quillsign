using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

internal sealed record EmailPilotHistoricalState(EmailPilotManifest Manifest, EmailPilotEnrollment[] Enrollments,
    EmailPilotAttempt[] Reservations, DateTimeOffset DeleteAfter, string Sha256);

public sealed partial class EmailPilotLedger
{
    // Historical facts only. Never calls EnsureLive or creates an old-run scope.
    internal async Task<EmailPilotHistoricalState> ReadHistoricalLockedAsync(QuillSignDbContext db, Guid id, CancellationToken ct)
    {
        if (!ReferenceEquals(db, database()) || db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges()) throw EmailPilotProtection.Invalid();
        var manifest = await Manifest(db, id, false, ct, configured: false) ?? throw EmailPilotProtection.Invalid();
        var enrollments = (await Enrollments(db, manifest, ct)).OrderBy(x => x.SubjectEnvelopeId).ToArray();
        var reservations = (await Reservations(db, manifest, ct)).OrderBy(x => x.Id).ToArray();
        var secret = await db.EmailPilotSecrets.AsNoTracking().SingleAsync(x => x.RunId == id, ct);
        var hash = Convert.ToHexStringLower(EmailPilotCanonical.Hash(new { manifest, enrollments, reservations, secret.DeleteAfter }));
        return new(manifest, enrollments, reservations, secret.DeleteAfter, hash);
    }
}
