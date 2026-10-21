using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

internal enum ProductionEnrollmentKind { MissingRecord, Demo, Unenrolled, Enrolled }
internal sealed record ProductionEnrollmentRead(ProductionEnrollmentKind Kind, VerifiedProductionRetention? Enrollment = null);
internal sealed record VerifiedProductionRetention(ProductionRetentionSnapshot Snapshot, DateTimeOffset OriginalCreatedAt,
    DateTimeOffset EnrolledAt, long AuditSequence, string AuditHash);
internal sealed record VerifiedProductionTerminal(EnvelopeStatus Status, DateTimeOffset OriginalAt, DateTimeOffset ClockAt,
    long SourceAuditSequence, string SourceAuditHash);

// Internal metadata backend. Callers own the transaction/commit and ordinary
// participant authorization. This service issues no storage, hold, access or purge authority.
internal sealed class ProductionRetentionLedger(QuillSignDbContext db, AuditWriter audit, TimeProvider time)
{
    internal const string EnrollmentEvent = "production_retention_enrolled", TerminalEvent = "production_retention_anchored";

    internal async Task<VerifiedProductionRetention> PrepareNewLockedAsync(Envelope envelope,
        ProductionRetentionPolicyOptions options, CancellationToken ct = default)
    {
        RequireTransaction();
        // A replay recovers by reading the original saved record. It cannot manufacture
        // a new creation event for a loaded historical record, even an empty old draft.
        if (db.Entry(envelope).State != EntityState.Added || db.ChangeTracker.Entries().Any(x =>
            x.State is EntityState.Added or EntityState.Modified or EntityState.Deleted && !ReferenceEquals(x.Entity, envelope)))
            throw new InvalidOperationException("Capture production policy with only the newly added envelope in its creation transaction.");
        var at = time.GetUtcNow();
        if (envelope.Id == Guid.Empty || envelope.IsDemo || envelope.Status != EnvelopeStatus.Draft ||
            envelope.CreatedAt == default || envelope.CreatedAt.Offset != TimeSpan.Zero || envelope.CreatedAt > at ||
            envelope.PublicId is not { Length: 32 } || !Guid.TryParseExact(envelope.PublicId, "N", out _) ||
            envelope.SenderEmail is not { Length: > 0 and <= 320 } || envelope.RowVersion.Length != 0 ||
            envelope.SenderVerifiedAt is not null || envelope.SentAt is not null || envelope.CompletedAt is not null ||
            envelope.PurgeAfter is not null || envelope.PdfBlob is not null || envelope.OriginalBlob is not null ||
            envelope.PreviewConfirmedAt is not null || envelope.PageCount is not null || envelope.PageSizesJson is not null ||
            envelope.SentPdfBlob is not null || envelope.FinalBlob is not null || envelope.CertificateBlob is not null ||
            envelope.CurrentFinishId is not null || envelope.CurrentCopyVersion != 0 || envelope.ErsdSha256 is not null)
            throw Invalid();
        var exists = await LockAsync(envelope.Id, ct);
        if (exists is not null || await db.AuditEvents.AnyAsync(x => x.EnvelopeId == envelope.Id, ct)) throw Invalid();
        var snapshot = ProductionRetentionPolicyContract.Freeze(envelope.Id, Seconds(envelope.CreatedAt), options);
        foreach (var days in new[] { snapshot.Policy.AbandonedDraftDays, snapshot.Policy.ExpiredDays, snapshot.Policy.DeclinedDays,
            snapshot.Policy.VoidedDays, snapshot.Policy.CompletedDays }) _ = ProductionRetentionPolicyContract.AddDays(envelope.CreatedAt, days);
        var row = new ProductionRetentionPolicyRecord
        {
            EnvelopeId = envelope.Id, OriginalCreatedAt = envelope.CreatedAt, EnrolledAt = at,
            PolicyJson = ProductionRetentionPolicyContract.Serialize(snapshot), PolicySha256 = ProductionRetentionPolicyContract.Digest(snapshot),
            OriginSha256 = Origin(envelope)
        };
        await db.SaveChangesAsync(ct);
        await audit.AppendAsync(envelope.Id, EnrollmentEvent, null, null, null, ct, EnrollmentJson(row), PartyType.System);
        var proof = await db.AuditEvents.AsNoTracking().SingleAsync(x => x.EnvelopeId == envelope.Id && x.Event == EnrollmentEvent, ct);
        row.AuditSequence = proof.Sequence; row.AuditHash = proof.Hash.ToArray();
        db.ProductionRetentionPolicies.Add(row);
        await db.SaveChangesAsync(ct);
        return (await ReadLockedAsync(envelope.Id, ct)).Enrollment ?? throw Invalid();
    }

    internal async Task<ProductionEnrollmentRead> ReadLockedAsync(Guid id, CancellationToken ct = default)
    {
        RequireTransaction();
        var envelope = await LockAsync(id, ct);
        if (envelope is null) return new(ProductionEnrollmentKind.MissingRecord);
        var row = await db.ProductionRetentionPolicies.AsNoTracking().SingleOrDefaultAsync(x => x.EnvelopeId == id, ct);
        if (row is null)
        {
            if (await db.AuditEvents.AnyAsync(x => x.EnvelopeId == id && (x.Event == EnrollmentEvent || x.Event == TerminalEvent), ct) ||
                await db.ProductionRetentionTerminals.AnyAsync(x => x.EnvelopeId == id, ct)) throw Invalid();
            return new(envelope.IsDemo ? ProductionEnrollmentKind.Demo : ProductionEnrollmentKind.Unenrolled);
        }
        var snapshot = ProductionRetentionPolicyContract.Read(row.PolicyJson, row.PolicySha256);
        if (envelope.IsDemo || snapshot.RecordId != id || snapshot.CreatedAt != Seconds(envelope.CreatedAt) ||
            row.OriginalCreatedAt != envelope.CreatedAt || envelope.CreatedAt.Offset != TimeSpan.Zero ||
            row.EnrolledAt.Offset != TimeSpan.Zero || row.EnrolledAt < envelope.CreatedAt || row.EnrolledAt > time.GetUtcNow() ||
            !Same(row.OriginSha256, Origin(envelope)) || row.AuditSequence != 1) throw Invalid();
        if (await db.AuditEvents.Where(x => x.EnvelopeId == id && x.Event == EnrollmentEvent).Take(2).CountAsync(ct) != 1) throw Invalid();
        var chain = await ChainAsync(id, ct, 1);
        var events = chain.Where(x => x.Event == EnrollmentEvent).ToArray();
        if (events.Length != 1 || events[0].Sequence != row.AuditSequence || !Same(events[0].Hash, row.AuditHash) ||
            !SystemEvent(events[0]) || events[0].At < row.EnrolledAt || events[0].DataJson != EnrollmentJson(row)) throw Invalid();
        return new(ProductionEnrollmentKind.Enrolled, new(snapshot, row.OriginalCreatedAt, row.EnrolledAt, row.AuditSequence, Hex(row.AuditHash)));
    }

    internal async Task<VerifiedProductionTerminal> CaptureTerminalLockedAsync(Guid id, CancellationToken ct = default)
    {
        RequireTransaction();
        var enrolled = (await ReadLockedAsync(id, ct)).Enrollment ?? throw Invalid();
        var envelope = await LockAsync(id, ct) ?? throw Invalid();
        var existing = await db.ProductionRetentionTerminals.AsNoTracking().SingleOrDefaultAsync(x => x.EnvelopeId == id, ct);
        var chain = await ChainAsync(id, ct, existing?.AuditSequence);
        var source = await ProductionRetentionTerminalSource.ReadAsync(db, envelope, chain, time, ct) ?? throw Invalid();
        await VerifyTerminalUniquenessAsync(id, existing is null ? 0 : 1, ct);
        if (existing is not null) return VerifyTerminal(existing, enrolled, envelope, source, chain);
        if (chain.Length >= 512 || chain.Any(x => x.Event == TerminalEvent)) throw Invalid();
        var row = new ProductionRetentionTerminalRecord
        {
            EnvelopeId = id, Status = envelope.Status, PolicySha256 = ProductionRetentionPolicyContract.Digest(enrolled.Snapshot),
            OriginalAt = source.At, ClockAt = Seconds(source.At), RecordedAt = time.GetUtcNow(),
            SourceAuditSequence = source.Event.Sequence, SourceAuditHash = source.Event.Hash.ToArray()
        };
        _ = Decision(enrolled, new(row.Status, row.OriginalAt, row.ClockAt, row.SourceAuditSequence, Hex(row.SourceAuditHash)), time.GetUtcNow());
        await audit.AppendAsync(id, TerminalEvent, null, null, null, ct, TerminalJson(row), PartyType.System);
        var proof = await db.AuditEvents.AsNoTracking().SingleAsync(x => x.EnvelopeId == id && x.Event == TerminalEvent, ct);
        row.AuditSequence = proof.Sequence; row.AuditHash = proof.Hash.ToArray();
        db.ProductionRetentionTerminals.Add(row); await db.SaveChangesAsync(ct);
        return VerifyTerminal(row, enrolled, envelope, source, await ChainAsync(id, ct));
    }

    internal async Task<VerifiedProductionTerminal?> ReadTerminalLockedAsync(Guid id, CancellationToken ct = default)
    {
        RequireTransaction();
        var enrolled = (await ReadLockedAsync(id, ct)).Enrollment ?? throw Invalid();
        var envelope = await LockAsync(id, ct) ?? throw Invalid();
        var row = await db.ProductionRetentionTerminals.AsNoTracking().SingleOrDefaultAsync(x => x.EnvelopeId == id, ct);
        if (row is null)
        {
            if (await db.AuditEvents.AnyAsync(x => x.EnvelopeId == id && x.Event == TerminalEvent, ct)) throw Invalid();
            return null;
        }
        await VerifyTerminalUniquenessAsync(id, 1, ct);
        var chain = await ChainAsync(id, ct, row.AuditSequence);
        var source = await ProductionRetentionTerminalSource.ReadAsync(db, envelope, chain, time, ct) ?? throw Invalid();
        return VerifyTerminal(row, enrolled, envelope, source, chain);
    }

    // Exact elapsed durations are retained alongside second-normalized policy clocks.
    // A later storage adapter may round protection up, never shorten the exact interval.
    internal static DateTimeOffset? ExactEligibleAt(VerifiedProductionRetention enrolled, VerifiedProductionTerminal terminal)
    {
        var decision = Decision(enrolled, terminal, DateTimeOffset.MaxValue.ToUniversalTime());
        if (decision.Disposition == ProductionRetentionDisposition.Indefinite) return null;
        var exact = terminal.OriginalAt;
        var days = checked((int)(decision.EligibleAt!.Value - decision.StartedAt!.Value).TotalDays);
        return ProductionRetentionPolicyContract.AddDays(exact, days);
    }

    private VerifiedProductionTerminal VerifyTerminal(ProductionRetentionTerminalRecord row, VerifiedProductionRetention enrolled,
        Envelope envelope, (AuditEvent Event, DateTimeOffset At) source, AuditEvent[] chain)
    {
        var events = chain.Where(x => x.Event == TerminalEvent).ToArray();
        if (row.Status != envelope.Status || row.PolicySha256 != ProductionRetentionPolicyContract.Digest(enrolled.Snapshot) ||
            row.OriginalAt != source.At || row.OriginalAt.Offset != TimeSpan.Zero || row.ClockAt != Seconds(source.At) ||
            row.RecordedAt.Offset != TimeSpan.Zero || row.RecordedAt < source.Event.At || row.RecordedAt > time.GetUtcNow() ||
            row.SourceAuditSequence != source.Event.Sequence || !Same(row.SourceAuditHash, source.Event.Hash) ||
            events.Length != 1 || events[0].Sequence != row.AuditSequence || row.AuditSequence <= row.SourceAuditSequence ||
            !Same(row.AuditHash, events[0].Hash) || !SystemEvent(events[0]) || events[0].At < row.RecordedAt ||
            events[0].DataJson != TerminalJson(row)) throw Invalid();
        var result = new VerifiedProductionTerminal(row.Status, row.OriginalAt, row.ClockAt, row.SourceAuditSequence, Hex(row.SourceAuditHash));
        _ = Decision(enrolled, result, time.GetUtcNow());
        _ = ExactEligibleAt(enrolled, result);
        return result;
    }

    private static ProductionRetentionDecision Decision(VerifiedProductionRetention enrolled, VerifiedProductionTerminal? terminal, DateTimeOffset now) =>
        ProductionRetentionDecision.Evaluate(enrolled.Snapshot, terminal?.Status switch
        {
            null => ProductionRecordStage.Draft,
            EnvelopeStatus.Completed => ProductionRecordStage.Completed, EnvelopeStatus.Expired => ProductionRecordStage.Expired,
            EnvelopeStatus.Declined => ProductionRecordStage.Declined, EnvelopeStatus.Voided => ProductionRecordStage.Voided,
            _ => throw Invalid()
        }, now, terminal?.ClockAt);

    private async Task<Envelope?> LockAsync(Guid id, CancellationToken ct) => await db.Envelopes
        .FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
    private async Task VerifyTerminalUniquenessAsync(Guid id, int anchors, CancellationToken ct)
    {
        // Only historical provenance is materialized. Still reject a second terminal or
        // anchor anywhere in the later operational tail instead of silently truncating it.
        if (await db.AuditEvents.Where(x => x.EnvelopeId == id && x.Event == TerminalEvent).Take(2).CountAsync(ct) != anchors ||
            await db.AuditEvents.Where(x => x.EnvelopeId == id &&
                (x.Event == "completed" || x.Event == "voided" || x.Event == "declined" || x.Event == "expired")).Take(2).CountAsync(ct) != 1)
            throw Invalid();
    }

    private async Task<AuditEvent[]> ChainAsync(Guid id, CancellationToken ct, long? through = null)
    {
        if (through is < 1 or > 512) throw Invalid();
        var size = through is { } last
            ? await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={id} AND [Sequence]<={last}").SingleAsync(ct)
            : await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={id}").SingleAsync(ct);
        if (size > 16 * 1024 * 1024) throw Invalid();
        var query = db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == id);
        if (through is { } end) query = query.Where(x => x.Sequence <= end);
        var rows = await query.OrderBy(x => x.Sequence).Take(513).ToArrayAsync(ct);
        if (rows.Length is < 1 or > 512 || through is { } expected && rows.Length != expected) throw Invalid();
        byte[]? previous = null; DateTimeOffset? at = null;
        foreach (var row in rows)
        {
            if (row.Sequence < 1 || row.Sequence > rows.Length || rows[row.Sequence - 1] != row || row.At.Offset != TimeSpan.Zero ||
                row.At < at || row.At > time.GetUtcNow() || !Enum.IsDefined(row.ActorType) ||
                (previous is null ? row.PrevHash is not null : !Same(previous, row.PrevHash))) throw Invalid();
            try { if (!Same(row.Hash, AuditHash.Compute(row))) throw Invalid(); }
            catch (Exception error) when (error is JsonException or ArgumentException) { throw new InvalidDataException("Production retention audit evidence is invalid.", error); }
            previous = row.Hash; at = row.At;
        }
        return rows;
    }

    private static byte[] Origin(Envelope e) => SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { e.Id, e.PublicId, e.SenderEmail, e.CreatedAt, e.IsDemo }));
    private static string EnrollmentJson(ProductionRetentionPolicyRecord r) => JsonSerializer.Serialize(new
        { version = "production-retention-enrollment-v1", r.EnvelopeId, r.OriginalCreatedAt, r.EnrolledAt, r.PolicySha256, originSha256 = Hex(r.OriginSha256) });
    internal static string TerminalJson(ProductionRetentionTerminalRecord r) => JsonSerializer.Serialize(new
        { version = "production-retention-terminal-v1", r.EnvelopeId, r.Status, r.PolicySha256, r.OriginalAt, r.ClockAt, r.RecordedAt, r.SourceAuditSequence, sourceAuditHash = Hex(r.SourceAuditHash) });
    private static bool SystemEvent(AuditEvent e) => e.ActorType == PartyType.System && e.ActorId is null && e.ActorEmail is null && e.Ip is null && e.UserAgent is null;
    internal static DateTimeOffset Seconds(DateTimeOffset at) => DateTimeOffset.FromUnixTimeSeconds(at.ToUnixTimeSeconds());
    internal static bool Same(byte[]? a, byte[]? b) => a is { Length: 32 } && b is { Length: 32 } && CryptographicOperations.FixedTimeEquals(a, b);
    internal static string Hex(byte[] a) => Convert.ToHexStringLower(a);
    private void RequireTransaction() { if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Production retention requires its parent's transaction."); }
    internal static InvalidDataException Invalid() => new("The saved production retention provenance could not be verified.");
}
