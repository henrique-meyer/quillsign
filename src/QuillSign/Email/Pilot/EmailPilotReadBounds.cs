using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public sealed class EmailPilotAccessUnavailableException():Exception("This restricted test access is unavailable or has ended.");

// Adds an access deadline after the caller's ordinary envelope/party check.
// It does not change the saved retention policy, authenticate a browser or grant
// storage/provider authority. Every read revalidates the persisted cohort.
public sealed class EmailPilotReadBounds(Func<QuillSignDbContext> database,Func<EmailPilotEnvelopeAccess> access,TimeProvider time)
{
    private DateTimeOffset? earliest;
    // Identifiers to revalidate, never cached permission or decoded authority.
    private readonly HashSet<Guid> observed=[];
    // Error presentation only; never used to permit a read or skip validation.
    internal bool HasExpiredSnapshot=>earliest<=time.GetUtcNow();
    public async Task<DateTimeOffset?> ReadAsync(Envelope envelope,CancellationToken ct)
    {
        var db=database();
        var cohort=db.Database.CurrentTransaction is null ? await access().ReadAsync(envelope.Id,ct) : await access().ReadLockedAsync(envelope,ct);
        if(!cohort.EnvelopeExists || cohort.IsEnrolled && (!cohort.Allowed || cohort.RunExpiresAt is null || cohort.RunExpiresAt<=time.GetUtcNow()))
            throw new EmailPilotAccessUnavailableException();
        observed.Add(envelope.Id);
        if(!cohort.IsEnrolled)return null;
        earliest=earliest is null || cohort.RunExpiresAt<earliest ? cohort.RunExpiresAt : earliest;
        return cohort.RunExpiresAt;
    }

    private async Task RecheckAsync(CancellationToken ct)
    {
        foreach(var id in observed.ToArray())await ReadAsync(new(){Id=id},ct);
    }

    // A successful commit is not permission to return a stale grant. Dispose the
    // committed transaction before the fresh standalone cohort read. Unknown or
    // denied acknowledgement exposes no browser proof; persisted work stays put.
    internal static async Task CommitAsync(EmailPilotReadBounds? bounds,IDbContextTransaction transaction,CancellationToken ct)
    {
        if(bounds is null){await transaction.CommitAsync(ct);return;}
        await bounds.RecheckAsync(ct);
        await transaction.CommitAsync(ct);
        await transaction.DisposeAsync();
        await bounds.RecheckAsync(ct);
    }

    internal static DateTimeOffset? Earlier(DateTimeOffset? retention,DateTimeOffset? access)=>
        access is null ? retention : retention is null || access<retention ? access : retention;
}
