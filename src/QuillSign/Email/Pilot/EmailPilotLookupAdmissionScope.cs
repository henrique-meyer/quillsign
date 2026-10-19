using QuillSign.Data;

namespace QuillSign.Email.Pilot;

// Internal, one-use, exact-context authority for the normal lookup request
// writer. It supplies only the configured manifest Sender, never caller email.
internal sealed class EmailPilotLookupAdmissionScope(QuillSignDbContext database, EmailPilotManifest manifest, DateTimeOffset deadline)
{
    private bool used;
    internal Guid RunId => manifest.RunId;
    internal Guid RequestId => EmailPilotLookupRules.RequestId(manifest.RunId);
    internal string Sender => manifest.Mailboxes.Sender;
    internal DateTimeOffset Deadline => deadline;
    internal void Demand(QuillSignDbContext db, DateTimeOffset now)
    {
        if (used || !ReferenceEquals(db, database) || db.Database.CurrentTransaction is null || deadline <= now || deadline > manifest.ExpiresAt ||
            manifest.CreatedAt > now || manifest.ExpiresAt <= now) throw new EmailDisabledException();
        used = true;
    }
}
