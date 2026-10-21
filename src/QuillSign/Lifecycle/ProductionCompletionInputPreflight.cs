using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

internal sealed partial class ProductionRecordOperationAdmission
{
    internal async Task PreflightCompletionInputLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        VerifiedCompletionInput input, CancellationToken ct = default)
    {
        if (input.RecordId != scope.RecordId || input.Context.OperationId != scope.OperationId) throw Invalid();
        var sql = await CompletionPreflightSql(db, scope, input.Context, ct);
        using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        ProductionCompletionSqlBudget.Demand(sql.PlaintextBytes, input.Body, plain.RootElement);
    }
    // Publication's actual version receipts do not exist before its final writes.
    // Its original authenticated intent and fixed context still permit an early
    // conservative SQL-budget check; this grants no provider or mutation permit.
    internal async Task PreflightCompletionInputLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        VerifiedCompletionSlotContext context, CancellationToken ct = default)
    {
        if (context.RecordId != scope.RecordId || context.Context.OperationId != scope.OperationId) throw Invalid();
        var sql = await CompletionPreflightSql(db, scope, context.Context, ct);
        using var plain = ProductionHoldSqlInventory.OpenAcknowledgementVerified(sql, keys);
        ProductionCompletionSqlBudget.Demand(sql.PlaintextBytes, context.Context.Slot, plain.RootElement);
    }
    private async Task<ProductionHoldSqlSnapshot> CompletionPreflightSql(QuillSignDbContext db, ProductionRecordOperation scope,
        HoldWitnessCompletionContext context, CancellationToken ct)
    {
        var state = await DemandCompletionHeadLocked(db, scope, ct); var predecessor = CompletionAcknowledged(Completion(scope, state));
        if (predecessor.Sequence != context.PredecessorSequence || predecessor.ContentSha256 != context.PredecessorContentSha256 ||
            predecessor.SqlStateSha256 != context.PredecessorSqlStateSha256) throw Invalid();
        return await DemandCompletionExactLocked(db, scope, state, predecessor, ct);
    }
}

internal static class ProductionCompletionSqlBudget
{
    internal const long MaximumBytes = 16 * 1024 * 1024;
    // Existing producer bounds: two seal metadata rows (including escaped DER),
    // the <=262144-character before-envelope/<=16384-character stage binding,
    // exact final-reference/result/terminal/audit rows, and <=8192 protected mail.
    // These are conservative size reserves, not new retention/provider policy.
    private const long SealRow = 512 * 1024, IntentRow = 768 * 1024, ResultRows = 128 * 1024;
    private const long NotificationRows = 40 * 1024, Framing = 64 * 1024;
    private static readonly JsonSerializerOptions Sql = new() { Converters = { new JsonStringEnumConverter() } };
    internal static void Demand(long currentBytes, CompletionInputV1 body, JsonElement sql)
    {
        long known = body.Kind switch {
            CompletionInputKind.CandidatePlan => Measure(body.Candidate!),
            CompletionInputKind.ExecutedResult or CompletionInputKind.CertificateResult => Measure(body.SealResult!),
            CompletionInputKind.PublicationIntentPlan => Measure(body.Intent!),
            CompletionInputKind.PublicationResultPlan => Measure(body.Publication!.Result) + 1024,
            _ => 0 };
        var future = Reserve(body.Context.Slot, Members(sql));
        // The exact known row replaces its conservative slot reserve. Never
        // subtract rows already in the captured SQL or a guessed refund.
        if (body.Kind is CompletionInputKind.ExecutedResult or CompletionInputKind.CertificateResult) future -= SealRow;
        if (body.Kind == CompletionInputKind.PublicationIntentPlan) future -= IntentRow;
        DemandTotal(currentBytes, known, future);
    }
    internal static void Demand(long currentBytes, CompletionSlot slot, JsonElement sql)
        => DemandTotal(currentBytes, 0, Reserve(slot, Members(sql)));
    private static long Reserve(CompletionSlot slot, int members) => checked(Framing + NotificationRows * members + ResultRows + (slot switch {
        CompletionSlot.Candidate => 2 * SealRow + IntentRow,
        CompletionSlot.ExecutedSeal => 2 * SealRow + IntentRow,
        CompletionSlot.CertificateSeal => SealRow + IntentRow,
        CompletionSlot.PublicationIntent => IntentRow,
        CompletionSlot.PublicationResult => 0,
        _ => throw ProductionCompletionInputCodec.Invalid() }));
    private static void DemandTotal(long current, long known, long future)
    {
        if (current is < 1 or > MaximumBytes || known < 0 || future < 0 || known > MaximumBytes - current || future > MaximumBytes - current - known)
            throw ProductionCompletionInputCodec.Invalid();
    }
    private static int Members(JsonElement sql)
    {
        JsonElement Table(string name) => sql.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == name).GetProperty("Rows");
        var envelope = Table("Envelopes").EnumerateArray().Single();
        var count = Table("Signers").EnumerateArray().Select(x => x.GetProperty("Email").GetString()!)
            .Concat(Table("Recipients").EnumerateArray().Select(x => x.GetProperty("Email").GetString()!))
            .Prepend(envelope.GetProperty("SenderEmail").GetString()!).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        return count is >= 1 and <= 201 ? count : throw ProductionCompletionInputCodec.Invalid();
    }
    private static long Measure<T>(T value)
    {
        using var counter = new CountingStream(); using var writer = new Utf8JsonWriter(counter);
        JsonSerializer.Serialize(writer, value, Sql); writer.Flush(); return counter.Length;
    }
    private sealed class CountingStream : Stream
    {
        private long size;
        public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
        public override long Length => size; public override long Position { get => size; set => throw new NotSupportedException(); }
        public override void Write(ReadOnlySpan<byte> buffer) { if (buffer.Length > MaximumBytes - size) throw ProductionCompletionInputCodec.Invalid(); size += buffer.Length; }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
