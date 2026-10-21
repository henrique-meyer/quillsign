using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRecordUploadWritesTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("before-plan")][InlineData("before-first-intent")][InlineData("after-first-intent")]
    public async Task Every_upload_boundary_preserves_the_authenticated_original_Draft_deadline(string phase)
    {
        var run = await Run.Create(fixture); var original = await run.Retention();
        run.Record.Clock.Now = original.Deadline.AddTicks(-1);
        if (phase != "before-plan") await run.Plan();
        if (phase == "after-first-intent")
        {
            Assert.True(await run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
            await run.Gate.DemandUploadWriteAsync(run.Scope, run.Original);
        }
        run.Record.Clock.Now = original.Deadline;
        if (phase == "before-plan") await Assert.ThrowsAsync<DocumentRetentionExpiredException>(run.Plan);
        else
        {
            await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.BeginUploadWriteAsync(run.Scope, run.Normalized));
            await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.ReadUploadWriteReceiptAsync(run.Scope, run.Original));
            if (phase == "before-first-intent")
                await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
            else
            {
                // These are the uploader's subsequent stage/commit and readback
                // boundaries after a first attempt; expiry cannot erase it.
                await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.DemandUploadWriteAsync(run.Scope, run.Original));
                await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.RecordUploadWriteAsync(run.Scope, Run.Receipt(run.Original)));
            }
        }
        var state = await run.Record.Journal().ReadAsync(run.Record.Id);
        Assert.Empty(state.Outcomes!); Assert.Empty(state.SettledOperations); Assert.Equal(run.Scope.OperationId, state.OutstandingOperation);
        if (phase == "before-plan") Assert.Empty(state.UploadWrites!);
        else
        {
            var plan = state.UploadWrites![run.Scope.OperationId]; Assert.Empty(plan.Receipts);
            Assert.Equal(phase == "after-first-intent" ? 1 : 0, plan.Begun.Count);
        }
        Assert.Equal(original, await run.Retention());
    }

    [Fact]
    public async Task Exact_two_objects_drain_pending_hold_then_only_the_bound_saved_SQL_can_complete()
    {
        var run = await Run.Create(fixture); await run.Plan(); await run.Write(run.Original);
        var command = Place(run.Record.Id); await run.Record.Journal().IntentAsync(Authority(run.Record.Clock, command.Permission), Operators, command, Guid.NewGuid());
        await run.Write(run.Normalized); Assert.False(await run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
        var prior = await run.Record.Journal().ReadAsync(run.Record.Id); Assert.Equal(2, prior.UploadWrites![run.Scope.OperationId].Receipts.Count);
        await run.Save(); var done = await run.Gate.CompleteAsync(run.Scope, Hash);
        Assert.Equal(Hash, done.SettledOperations[run.Scope.OperationId]); Assert.Equal(command, done.Unacknowledged); Assert.Null(done.OutstandingOperation);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandUploadWriteAsync(run.Scope, run.Original));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginUploadWriteAsync(run.Scope, run.Normalized));
    }

    [Theory]
    [InlineData("zero")][InlineData("large")][InlineData("hash")][InlineData("foreign")][InlineData("wrong-kind")][InlineData("same-object")]
    public async Task Missing_or_foreign_unbounded_or_changed_plan_never_creates_write_authority(string fault)
    {
        var run = await Run.Create(fixture); var original = run.Original; var normalized = run.Normalized;
        if (fault == "zero") original = original with { Length = 0 };
        if (fault == "large") original = original with { Length = ProductionRecordUploadWriteContract.MaximumBytes + 1 };
        if (fault == "hash") original = original with { Sha256 = new('A', 64) };
        if (fault == "foreign") original = original with { Blob = original.Blob with { EnvelopeId = Guid.NewGuid() } };
        if (fault == "wrong-kind") original = original with { Blob = original.Blob with { Kind = DocumentBlobKind.Preview } };
        if (fault == "same-object") normalized = normalized with { Blob = normalized.Blob with { ObjectId = original.Blob.ObjectId } };
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareUploadWritesAsync(run.Scope, original, normalized));
        Assert.Empty((await run.Record.Journal().ReadAsync(run.Record.Id)).UploadWrites!);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
    }

    [Theory]
    [InlineData("plan")][InlineData("demand")][InlineData("receipt")]
    public async Task Every_provider_boundary_rejects_changed_original_full_SQL_not_only_its_unchanged_request_head(string phase)
    {
        var run = await Run.Create(fixture);
        if (phase != "plan") { await run.Plan(); Assert.True(await run.Gate.BeginUploadWriteAsync(run.Scope, run.Original)); }
        await run.Record.Edit("Unadmitted business state or restored older SQL");
        if (phase == "plan") await Assert.ThrowsAsync<InvalidDataException>(run.Plan);
        if (phase == "demand") await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandUploadWriteAsync(run.Scope, run.Original));
        if (phase == "receipt") await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.RecordUploadWriteAsync(run.Scope, Run.Receipt(run.Original)));
        var state = await run.Record.Journal().ReadAsync(run.Record.Id); Assert.Equal(0, state.RequestRevision); Assert.Equal(run.Scope.OperationId, state.OutstandingOperation);
        Assert.Empty(state.Outcomes!);
    }

    [Theory]
    [InlineData("none")][InlineData("begun")][InlineData("one-receipt")]
    public async Task A_write_plan_never_uses_unchanged_SQL_as_absence_or_cancellation_settlement(string phase)
    {
        var run = await Run.Create(fixture); await run.Plan();
        if (phase == "begun") Assert.True(await run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
        if (phase == "one-receipt") await run.Write(run.Original);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(run.Scope, Hash));
        var state = await run.Record.Journal().ReadAsync(run.Record.Id); Assert.Equal(run.Scope.OperationId, state.OutstandingOperation);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Record.Journal().PrepareOperationOutcomeAsync(run.Record.Id,
            state.Operations![run.Scope.OperationId], run.Scope.ContentSha256, run.Scope.SqlStateSha256, Guid.NewGuid()));
        Assert.Empty((await run.Record.Journal().ReadAsync(run.Record.Id)).Outcomes!);
    }

    [Theory]
    [InlineData("version")][InlineData("etag")][InlineData("item")][InlineData("foreign")][InlineData("not-started")]
    public async Task Only_exact_begun_member_receipts_are_accepted_and_saved_receipts_are_immutable(string fault)
    {
        var run = await Run.Create(fixture); await run.Plan();
        if (fault != "not-started") Assert.True(await run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
        var receipt = Run.Receipt(run.Original);
        if (fault == "version") receipt = receipt with { VersionId = "*" };
        if (fault == "etag") receipt = receipt with { ETag = new('x', 257) };
        if (fault == "item") receipt = receipt with { Item = run.Original with { Length = run.Original.Length + 1 } };
        if (fault == "foreign") receipt = receipt with { Item = run.Original with { Blob = run.Original.Blob with { ObjectId = Guid.NewGuid() } } };
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.RecordUploadWriteAsync(run.Scope, receipt));
        Assert.Null(await run.Gate.ReadUploadWriteReceiptAsync(run.Scope, run.Original));
        if (fault == "not-started") Assert.True(await run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
        receipt = Run.Receipt(run.Original); await run.Gate.RecordUploadWriteAsync(run.Scope, receipt);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.RecordUploadWriteAsync(run.Scope, receipt with { VersionId = "different-version" }));
        Assert.Equal(receipt, await run.Gate.ReadUploadWriteReceiptAsync(run.Scope, run.Original));
    }

    [Theory]
    [InlineData("plan")][InlineData("begin")][InlineData("receipt")]
    public async Task Lost_external_acknowledgement_and_restart_never_grant_a_second_write(string phase)
    {
        var run = await Run.Create(fixture);
        if (phase == "plan")
        {
            run.Record.Store.LostAck = true; await Assert.ThrowsAsync<IOException>(run.Plan);
            var bytes = run.Record.Store.Rows[^1].ProtectedPayload.ToArray(); await run.Plan(); Assert.Equal(bytes, run.Record.Store.Rows[^1].ProtectedPayload);
        }
        else await run.Plan();
        if (phase == "begin")
        {
            run.Record.Store.LostAck = true; await Assert.ThrowsAsync<IOException>(() => run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
            Assert.False(await run.Record.Gate().BeginUploadWriteAsync(run.Scope, run.Original));
        }
        else Assert.True(await run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
        if (phase == "receipt")
        {
            run.Record.Store.LostAck = true; await Assert.ThrowsAsync<IOException>(() => run.Gate.RecordUploadWriteAsync(run.Scope, Run.Receipt(run.Original)));
            var bytes = run.Record.Store.Rows[^1].ProtectedPayload.ToArray();
            await run.Record.Gate().RecordUploadWriteAsync(run.Scope, Run.Receipt(run.Original)); Assert.Equal(bytes, run.Record.Store.Rows[^1].ProtectedPayload);
        }
        Assert.False(await run.Record.Gate().BeginUploadWriteAsync(run.Scope, run.Original));
        Assert.Single((await run.Record.Journal().ReadAsync(run.Record.Id)).UploadWrites![run.Scope.OperationId].Begun);
    }

    [Fact]
    public async Task Concurrent_started_intents_return_true_at_most_once_and_only_for_the_first_new_intent()
    {
        var run = await Run.Create(fixture); await run.Plan();
        async Task<bool?> Attempt()
        { try { return await run.Record.Gate().BeginUploadWriteAsync(run.Scope, run.Original); } catch (IOException) { return null; } }
        var results = await Task.WhenAll(Attempt(), Attempt()); Assert.Single(results, x => x == true);
        Assert.False(await run.Gate.BeginUploadWriteAsync(run.Scope, run.Original));
        Assert.Single((await run.Record.Journal().ReadAsync(run.Record.Id)).UploadWrites![run.Scope.OperationId].Begun);
    }

    [Theory]
    [InlineData("original-id")][InlineData("normalized-id")][InlineData("original-hash")][InlineData("normalized-hash")]
    public async Task Final_SQL_outcome_must_bind_both_exact_planned_targets_and_hashes(string fault)
    {
        var run = await Run.Create(fixture); await run.Plan(); await run.Write(run.Original); await run.Write(run.Normalized);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Save(fault));
        Assert.Empty((await run.Record.Journal().ReadAsync(run.Record.Id)).Outcomes!);
        await run.Save(); await run.Gate.CompleteAsync(run.Scope, Hash);
    }

    [Theory]
    [InlineData("future-field")][InlineData("future-version")][InlineData("changed-kind")]
    public async Task Fully_reprotected_and_rehashed_plan_with_unknown_or_foreign_shape_fails_closed(string fault)
    {
        var run = await Run.Create(fixture); await run.Plan(); var row = run.Record.Store.Rows[^1];
        var protector = run.Record.Keys.CreateProtector(ProductionHoldWitnessJournal.Version, Installation, run.Record.Id.ToString("N"));
        var node = JsonNode.Parse(protector.Unprotect(row.ProtectedPayload))!;
        if (fault == "future-field") node["UploadOriginal"]!["FutureReference"] = Guid.NewGuid();
        if (fault == "future-version") node["UploadWriteVersion"] = "unknown-upload-version";
        if (fault == "changed-kind") node["UploadOriginal"]!["Blob"]!["Kind"] = (int)DocumentBlobKind.Preview;
        var bytes = protector.Protect(JsonSerializer.SerializeToUtf8Bytes(node));
        run.Record.Store.Rows[^1] = row with { ProtectedPayload = bytes, Length = bytes.Length, Sha256 = ProductionHoldWitnessJournal.Digest(bytes) };
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Record.Journal().ReadAsync(run.Record.Id));
    }

    [Fact]
    public async Task Exact_plan_replay_and_fork_refusal_preserve_original_bytes_and_missing_plan_has_no_authority()
    {
        var run = await Run.Create(fixture);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandUploadWriteAsync(run.Scope, run.Original));
        await run.Plan(); var bytes = run.Record.Store.Rows[^1].ProtectedPayload.ToArray(); await run.Plan(); Assert.Equal(bytes, run.Record.Store.Rows[^1].ProtectedPayload);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareUploadWritesAsync(run.Scope, run.Original with { Sha256 = new('d', 64) }, run.Normalized));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginUploadWriteAsync(run.Scope with { Reference = "foreign-reference" }, run.Original));
        Assert.Empty((await run.Record.Journal().ReadAsync(run.Record.Id)).UploadWrites![run.Scope.OperationId].Begun);
    }

    private sealed class Run(SqlDatabaseFixture fixture, ProductionRecordOperationAdmissionTests.Run record)
    {
        internal readonly ProductionRecordOperationAdmissionTests.Run Record = record;
        internal readonly ProductionRecordOperationAdmission Gate = record.Gate();
        internal ProductionRecordOperation Scope = null!;
        internal ProductionRecordWriteDescriptor Original = null!, Normalized = null!;
        internal static async Task<Run> Create(SqlDatabaseFixture fixture)
        {
            // Kernel-only synthetic SQL protocol proof; participant authentication
            // and actual uploader/provider integration are tested by the caller.
            var run = new Run(fixture, await ProductionRecordOperationAdmissionTests.Run.Create(fixture, work: false));
            await run.Gate.InitializeAsync(run.Record.Id); run.Scope = await run.Gate.BeginAsync(run.Record.Id, Guid.NewGuid(), ProductionRecordUploadWriteContract.Kind, "synthetic-upload");
            run.Original = new(new(run.Record.Id, DocumentBlobKind.Original, Guid.NewGuid()), 37, new('b', 64));
            run.Normalized = new(new(run.Record.Id, DocumentBlobKind.Normalized, Guid.NewGuid()), 53, new('c', 64)); return run;
        }
        internal Task Plan() => Gate.PrepareUploadWritesAsync(Scope, Original, Normalized);
        internal async Task<(DateTimeOffset Deadline, string Policy, DateTimeOffset Created)> Retention()
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var row = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == Record.Id);
            var saved = await ProductionRecordRetentionAccess.ReadLockedAsync(db, row, Record.Clock);
            Assert.Equal(ProductionEnrollmentKind.Enrolled, saved.Kind); Assert.Equal(ProductionRecordStage.Draft, saved.Stage);
            Assert.NotNull(saved.Deadline); Assert.NotNull(saved.Enrollment);
            var result = (saved.Deadline.Value, JsonSerializer.Serialize(saved.Enrollment.Snapshot), saved.Enrollment.OriginalCreatedAt);
            await tx.RollbackAsync(); return result;
        }
        internal static ProductionRecordWriteReceipt Receipt(ProductionRecordWriteDescriptor item) => new(item, "synthetic-version-" + item.Blob.ObjectId.ToString("N"), "\"synthetic-etag\"");
        internal async Task Write(ProductionRecordWriteDescriptor item)
        {
            Assert.True(await Gate.BeginUploadWriteAsync(Scope, item)); await Gate.DemandUploadWriteAsync(Scope, item);
            await Gate.RecordUploadWriteAsync(Scope, Receipt(item)); Assert.Equal(Receipt(item), await Gate.ReadUploadWriteReceiptAsync(Scope, item));
        }
        internal async Task Save(string? fault = null)
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var row = await db.Envelopes.SingleAsync(x => x.Id == Record.Id);
            row.OriginalBlob = (fault == "original-id" ? Guid.NewGuid() : Original.Blob.ObjectId).ToString("N");
            row.PdfBlob = (fault == "normalized-id" ? Guid.NewGuid() : Normalized.Blob.ObjectId).ToString("N");
            row.OriginalSha256 = Convert.FromHexString(fault == "original-hash" ? new('d', 64) : Original.Sha256);
            row.PdfSha256 = Convert.FromHexString(fault == "normalized-hash" ? new('e', 64) : Normalized.Sha256);
            row.OriginalMime = "application/pdf"; await db.SaveChangesAsync();
            await Gate.PrepareOutcomeLockedAsync(db, Scope); await tx.CommitAsync();
        }
    }
}
