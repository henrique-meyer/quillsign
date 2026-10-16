using Microsoft.EntityFrameworkCore;

namespace QuillSign.Data;

public sealed class AuditWriter(QuillSignDbContext db, TimeProvider time)
{
    public async Task AppendAsync(Guid envelopeId, string eventName, string email, string? ip, string? userAgent, CancellationToken cancellationToken, string dataJson = "{}")
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
            At = time.GetUtcNow(), ActorType = PartyType.Sender, ActorEmail = email, Event = eventName,
            Ip = ip, UserAgent = userAgent is { Length: > 2048 } ? userAgent[..2048] : userAgent, DataJson = dataJson
        };
        entry.Hash = AuditHash.Compute(entry);
        db.AuditEvents.Add(entry);
        await db.SaveChangesAsync(cancellationToken);
    }
}
