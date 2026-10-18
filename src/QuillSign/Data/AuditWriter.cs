using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

public sealed class AuditWriter(QuillSignDbContext db, TimeProvider time)
{
    public async Task AppendAsync(Guid envelopeId, string eventName, string? email, string? ip, string? userAgent, CancellationToken cancellationToken,
        string dataJson = "{}",PartyType actorType = PartyType.Sender,Guid? actorId = null)
        => await AppendCoreAsync(envelopeId, eventName, email, ip, userAgent, cancellationToken, dataJson, actorType, actorId, null);

    // Internal admission code binds immutable evidence and its audit event to
    // one server-clock sample. This is never supplied from a browser request.
    internal Task AppendAtAsync(Guid envelopeId, string eventName, string? email, string? ip, string? userAgent, CancellationToken cancellationToken,
        string dataJson, DateTimeOffset recordedAt)
    {
        if (recordedAt.Offset != TimeSpan.Zero || recordedAt > time.GetUtcNow()) throw new ArgumentException("Use an elapsed server UTC timestamp.");
        return AppendCoreAsync(envelopeId, eventName, email, ip, userAgent, cancellationToken, dataJson, PartyType.Sender, null, recordedAt);
    }
    private async Task AppendCoreAsync(Guid envelopeId, string eventName, string? email, string? ip, string? userAgent, CancellationToken cancellationToken,
        string dataJson, PartyType actorType, Guid? actorId, DateTimeOffset? recordedAt)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Audit appends require a transaction.");
        // Every appender takes this same envelope lock before assigning a sequence.
        _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {envelopeId}")
            .AsNoTracking().SingleAsync(cancellationToken);
        var previous = await db.AuditEvents.Where(x => x.EnvelopeId == envelopeId).OrderByDescending(x => x.Sequence)
            .FirstOrDefaultAsync(cancellationToken);
        var entry = new AuditEvent
        {
            EnvelopeId = envelopeId, Sequence = (previous?.Sequence ?? 0) + 1, PrevHash = previous?.Hash,
            At = recordedAt ?? time.GetUtcNow(), ActorType = actorType,ActorId = actorId,ActorEmail = email, Event = eventName,
            Ip = ip, UserAgent = userAgent is { Length: > 2048 } ? userAgent[..2048] : userAgent, DataJson = dataJson
        };
        entry.Hash = AuditHash.Compute(entry);
        db.AuditEvents.Add(entry);
        await db.SaveChangesAsync(cancellationToken);
    }
}
