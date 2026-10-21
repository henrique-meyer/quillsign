using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRecordSendWritesTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Caller_owned_reservation_exact_single_write_and_SQL_outcome_drain_a_pending_hold()
    {
        var run = await Run.Create(fixture); await run.Locked(async db => {
            await run.Plan(db); Assert.True(await run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            var place = Place(run.Record.Id); await run.Record.Journal().IntentAsync(Authority(run.Record.Clock, place.Permission), Operators, place, Guid.NewGuid());
            await run.Gate.DemandSendWriteLockedAsync(db, run.Scope, run.Target); await run.Gate.RecordSendWriteLockedAsync(db, run.Scope, run.Receipt);
            Assert.False(await run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            Assert.Equal(run.Receipt, await run.Gate.ReadSendWriteReceiptLockedAsync(db, run.Scope, run.Target));
            await run.Save(db); await run.Gate.DemandSendProgressLockedAsync(db, run.Scope); await run.Gate.PrepareOutcomeLockedAsync(db, run.Scope);
        }, commit: true);
        var state = await run.Gate.CompleteAsync(run.Scope, Hash); Assert.Null(state.OutstandingOperation); Assert.NotNull(state.Unacknowledged);
        Assert.Equal(Hash, state.SettledOperations[run.Scope.OperationId]); Assert.Single(state.SendWrites!);
    }

    [Theory]
    [InlineData("no-transaction")][InlineData("dirty")][InlineData("changed-business")][InlineData("held")]
    public async Task BeginLocked_requires_exact_clean_current_baseline_and_never_creates_a_new_R0(string fault)
    {
        var run = await Run.Create(fixture, begin: false);
        if (fault == "changed-business") await run.Record.Edit("Unadmitted SQL or older restored state");
        if (fault == "held") { var p = Place(run.Record.Id); await run.Record.Journal().IntentAsync(Authority(run.Record.Clock, p.Permission), Operators, p, Guid.NewGuid()); }
        await using var db = fixture.Open(); await using var tx = fault == "no-transaction" ? null : await db.Database.BeginTransactionAsync();
        if (fault == "dirty") db.Add(new Envelope { SenderEmail = "synthetic-foreign@example.invalid" });
        var before = await run.Record.Journal().ReadAsync(run.Record.Id);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginLockedAsync(db, run.Record.Id, Guid.NewGuid(), ProductionRecordSendWriteContract.Kind, "send"));
        Assert.Equal(before.HeadHash, (await run.Record.Journal().ReadAsync(run.Record.Id)).HeadHash);
    }

    [Theory]
    [InlineData("source-hash")][InlineData("source-id")][InlineData("source-kind")][InlineData("foreign")][InlineData("same-id")][InlineData("length")]
    public async Task Plan_requires_exact_confirmed_owned_source_and_distinct_bounded_target(string fault)
    {
        var run = await Run.Create(fixture); var source = run.Source; var target = run.Target;
        if (fault == "source-hash") source = source with { Sha256 = new('d', 64) };
        if (fault == "source-id") source = source with { Blob = source.Blob with { ObjectId = Guid.NewGuid() } };
        if (fault == "source-kind") source = source with { Blob = source.Blob with { Kind = DocumentBlobKind.Original } };
        if (fault == "foreign") target = target with { Blob = target.Blob with { EnvelopeId = Guid.NewGuid() } };
        if (fault == "same-id") target = target with { Blob = source.Blob };
        if (fault == "length") target = target with { Length = ProductionRecordUploadWriteContract.MaximumBytes + 1 };
        await run.Locked(db => Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareSendWriteLockedAsync(db, run.Scope, source, target)));
        Assert.Empty((await run.Record.Journal().ReadAsync(run.Record.Id)).SendWrites!);
    }

    [Theory]
    [InlineData("no-plan")][InlineData("not-begun")][InlineData("no-receipt")][InlineData("wrong-receipt")]
    public async Task Missing_or_wrong_write_proof_has_no_outcome_or_unchanged_cancellation_path(string fault)
    {
        var run = await Run.Create(fixture); await run.Locked(async db => {
            if (fault != "no-plan") await run.Plan(db);
            if (fault is "no-receipt" or "wrong-receipt") Assert.True(await run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            if (fault == "wrong-receipt") await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.RecordSendWriteLockedAsync(db, run.Scope,
                run.Receipt with { Item = run.Target with { Sha256 = new('d', 64) } }));
            await run.Save(db); await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, run.Scope));
        });
        if (fault == "no-plan")
        {
            // No provider plan/intent ever existed, and SQL rolled back to the
            // exact original baseline: only that known unchanged result is safe.
            Assert.Equal(Hash, (await run.Gate.CompleteAsync(run.Scope, Hash)).SettledOperations[run.Scope.OperationId]); return;
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(run.Scope, Hash));
        var state = await run.Record.Journal().ReadAsync(run.Record.Id); Assert.False(state.Outcomes!.ContainsKey(run.Scope.OperationId)); Assert.Equal(run.Scope.OperationId, state.OutstandingOperation);
    }

    [Theory]
    [InlineData("source-id")][InlineData("source-hash")][InlineData("target-id")][InlineData("target-hash")][InlineData("status")][InlineData("sent-deadline")]
    public async Task Final_outcome_binds_original_source_exact_target_Sent_state_and_original_deadline(string fault)
    {
        var run = await Run.Create(fixture); await run.Locked(async db => {
            await run.Plan(db); await run.Write(db); await run.Save(db, fault);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, run.Scope));
        });
        Assert.False((await run.Record.Journal().ReadAsync(run.Record.Id)).Outcomes!.ContainsKey(run.Scope.OperationId));
    }

    [Theory]
    [InlineData("plan")][InlineData("begin")][InlineData("demand")][InlineData("progress")]
    public async Task Saved_original_Draft_deadline_blocks_every_later_boundary_without_renewal(string phase)
    {
        var run = await Run.Create(fixture); var originalDeadline = run.Deadline;
        await run.Locked(async db => {
            run.Record.Clock.Now = run.Deadline.AddTicks(-1);
            if (phase != "plan") await run.Plan(db);
            if (phase == "demand") Assert.True(await run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            if (phase == "progress") { await run.Write(db); await run.Save(db); }
            run.Record.Clock.Now = run.Deadline;
            if (phase == "plan") await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Plan(db));
            if (phase == "begin") await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            if (phase == "demand")
            {
                await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.DemandSendWriteLockedAsync(db, run.Scope, run.Target));
                await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.RecordSendWriteLockedAsync(db, run.Scope, run.Receipt));
            }
            if (phase == "progress") await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.DemandSendProgressLockedAsync(db, run.Scope));
        });
        var state = await run.Record.Journal().ReadAsync(run.Record.Id);
        Assert.False(state.Outcomes!.ContainsKey(run.Scope.OperationId)); Assert.False(state.SettledOperations.ContainsKey(run.Scope.OperationId));
        await using var check = fixture.Open(); await using var tx = await check.Database.BeginTransactionAsync();
        var row = await check.Envelopes.AsNoTracking().SingleAsync(x => x.Id == run.Record.Id);
        Assert.Equal(originalDeadline, (await ProductionRecordRetentionAccess.ReadLockedAsync(check, row, run.Record.Clock)).Deadline);
    }

    [Theory]
    [InlineData("plan")][InlineData("begin")][InlineData("receipt")]
    public async Task Lost_external_acknowledgements_replay_original_bytes_and_never_authorize_a_second_write(string phase)
    {
        var run = await Run.Create(fixture); await run.Locked(async db => {
            if (phase == "plan") { run.Record.Store.LostAck = true; await Assert.ThrowsAsync<IOException>(() => run.Plan(db)); }
            else await run.Plan(db);
            await run.Plan(db); var originalBytes = run.Record.Store.Rows[^1].ProtectedPayload.ToArray(); await run.Plan(db); Assert.Equal(originalBytes, run.Record.Store.Rows[^1].ProtectedPayload);
            if (phase == "begin") { run.Record.Store.LostAck = true; await Assert.ThrowsAsync<IOException>(() => run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target)); }
            else Assert.True(await run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            Assert.False(await run.Record.Gate().BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            if (phase == "receipt") { run.Record.Store.LostAck = true; await Assert.ThrowsAsync<IOException>(() => run.Gate.RecordSendWriteLockedAsync(db, run.Scope, run.Receipt)); }
            await run.Record.Gate().RecordSendWriteLockedAsync(db, run.Scope, run.Receipt);
            Assert.Equal(run.Receipt, await run.Gate.ReadSendWriteReceiptLockedAsync(db, run.Scope, run.Target));
        });
    }

    [Theory]
    [InlineData("version")][InlineData("future-property")][InlineData("target-kind")][InlineData("deadline")]
    public async Task Reprotected_rehashed_unknown_or_foreign_Send_event_shape_is_rejected(string fault)
    {
        var run = await Run.Create(fixture); await run.Locked(db => run.Plan(db)); var row = run.Record.Store.Rows[^1];
        var protector = run.Record.Keys.CreateProtector(ProductionHoldWitnessJournal.Version, Installation, run.Record.Id.ToString("N"));
        var node = JsonNode.Parse(protector.Unprotect(row.ProtectedPayload))!;
        if (fault == "version") node["SendWriteVersion"] = "future-version";
        if (fault == "future-property") node["SendTarget"]!["FutureReference"] = Guid.NewGuid();
        if (fault == "target-kind") node["SendTarget"]!["Blob"]!["Kind"] = (int)DocumentBlobKind.Original;
        if (fault == "deadline") node["SendDeadline"] = run.Record.Clock.Now.ToString("O");
        var bytes = protector.Protect(JsonSerializer.SerializeToUtf8Bytes(node));
        run.Record.Store.Rows[^1] = row with { ProtectedPayload = bytes, Length = bytes.Length, Sha256 = ProductionHoldWitnessJournal.Digest(bytes) };
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Record.Journal().ReadAsync(run.Record.Id));
    }

    [Fact]
    public async Task Changed_SQL_before_blob_IO_fails_but_same_scope_progress_after_its_SQL_is_permitted()
    {
        var run = await Run.Create(fixture); await run.Locked(async db => {
            await run.Plan(db); await run.Write(db); await run.Save(db);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandSendWriteLockedAsync(db, run.Scope, run.Target));
            await run.Gate.DemandSendProgressLockedAsync(db, run.Scope);
            await run.Gate.PrepareOutcomeLockedAsync(db, run.Scope);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandSendProgressLockedAsync(db, run.Scope));
        }, commit: true);
        await run.Gate.CompleteAsync(run.Scope, Hash);
    }

    [Fact]
    public async Task ReadSendOutcome_is_receipt_only_exact_reference_and_never_restarts_unsealed_work()
    {
        var run = await Run.Create(fixture);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ReadSendOutcomeAsync(run.Record.Id, run.Scope.Reference));
        await run.Locked(async db => { await run.Plan(db); await run.Write(db); await run.Save(db); await run.Gate.PrepareOutcomeLockedAsync(db, run.Scope); }, commit: true);
        Assert.Equal(run.Scope, await run.Record.Gate().ReadSendOutcomeAsync(run.Record.Id, run.Scope.Reference));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.ReadSendOutcomeAsync(run.Record.Id, "wrong-reference"));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.DemandAsync(run.Scope));
        await run.Gate.CompleteAsync(run.Scope, Hash); Assert.Null(await run.Gate.ReadSendOutcomeAsync(run.Record.Id, run.Scope.Reference));
    }

    [Fact]
    public async Task Reprotected_later_deadline_cannot_replace_the_original_authenticated_policy_deadline()
    {
        var run = await Run.Create(fixture); await run.Locked(db => run.Plan(db)); var row = run.Record.Store.Rows[^1];
        var protector = run.Record.Keys.CreateProtector(ProductionHoldWitnessJournal.Version, Installation, run.Record.Id.ToString("N"));
        var savedEvent = JsonSerializer.Deserialize<HoldWitnessEvent>(protector.Unprotect(row.ProtectedPayload))!;
        var bytes = protector.Protect(JsonSerializer.SerializeToUtf8Bytes(savedEvent with {
            SendDeadline = run.Deadline.AddDays(1), SendDraftDeadline = run.Deadline.AddDays(1) }));
        run.Record.Store.Rows[^1] = row with { ProtectedPayload = bytes, Length = bytes.Length, Sha256 = ProductionHoldWitnessJournal.Digest(bytes) };
        Assert.Equal(run.Deadline.AddDays(1), (await run.Record.Journal().ReadAsync(run.Record.Id)).SendWrites![run.Scope.OperationId].Deadline);
        await run.Locked(db => Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target)));
        var saved = (await run.Record.Journal().ReadAsync(run.Record.Id)).SendWrites![run.Scope.OperationId]; Assert.False(saved.Begun); Assert.Null(saved.Receipt);
    }

    [Theory]
    [InlineData("plan")][InlineData("begin")][InlineData("stage")][InlineData("hint")]
    public async Task Earlier_original_requested_signing_deadline_also_blocks_every_provider_and_hint_boundary(string phase)
    {
        var run = await Run.Create(fixture, requested: TimeSpan.FromMinutes(5));
        Assert.True(run.Deadline < run.DraftDeadline);
        await run.Locked(async db => {
            run.Record.Clock.Now = run.Deadline.AddTicks(-1);
            if (phase != "plan") await run.Plan(db);
            if (phase == "stage") Assert.True(await run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            if (phase == "hint") { await run.Write(db); await run.Save(db); }
            run.Record.Clock.Now = run.Deadline;
            if (phase == "plan") await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Plan(db));
            if (phase == "begin") await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.BeginSendWriteLockedAsync(db, run.Scope, run.Target));
            if (phase == "stage")
            {
                await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.DemandSendWriteLockedAsync(db, run.Scope, run.Target));
                await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.RecordSendWriteLockedAsync(db, run.Scope, run.Receipt));
            }
            if (phase == "hint") await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.DemandSendProgressLockedAsync(db, run.Scope));
        });
        var state = await run.Record.Journal().ReadAsync(run.Record.Id); Assert.False(state.Outcomes!.ContainsKey(run.Scope.OperationId));
        Assert.False(state.SettledOperations.ContainsKey(run.Scope.OperationId));
        if (phase != "plan")
        {
            var plan = state.SendWrites![run.Scope.OperationId]; Assert.Equal(run.Deadline, plan.SigningDeadline);
            Assert.Equal(run.DraftDeadline, plan.DraftDeadline); Assert.Equal(run.Deadline, plan.Deadline);
            if (phase != "hint") Assert.Null(plan.Receipt);
        }
        await using var check = fixture.Open(); Assert.Equal(run.Deadline, await check.Envelopes.Where(x => x.Id == run.Record.Id).Select(x => x.ExpiresAt).SingleAsync());
    }

    private sealed class Run(SqlDatabaseFixture fixture, ProductionRecordOperationAdmissionTests.Run record)
    {
        internal readonly ProductionRecordOperationAdmissionTests.Run Record = record;
        internal readonly ProductionRecordOperationAdmission Gate = record.Gate();
        internal ProductionRecordOperation Scope = null!;
        internal ProductionRecordWriteDescriptor Source = null!, Target = null!;
        internal DateTimeOffset Deadline, DraftDeadline;
        internal ProductionRecordWriteReceipt Receipt => new(Target, "synthetic-send-version", "\"synthetic-send-etag\"");
        internal static async Task<Run> Create(SqlDatabaseFixture fixture, bool begin = true, TimeSpan? requested = null)
        {
            // Explicit kernel fixture bootstrap, not a production upload/Send
            // authentication or a claim of native provider byte verification.
            var run = new Run(fixture, await ProductionRecordOperationAdmissionTests.Run.Create(fixture, work: false));
            run.Source = new(new(run.Record.Id, DocumentBlobKind.Normalized, Guid.NewGuid()), 37, new('b', 64));
            run.Target = new(new(run.Record.Id, DocumentBlobKind.Normalized, Guid.NewGuid()), 53, new('c', 64));
            await run.Gate.InitializeAsync(run.Record.Id); var bootstrap = await run.Gate.BeginAsync(run.Record.Id, Guid.NewGuid(), "synthetic/bootstrap", "confirmed-source");
            await run.Locked(async db => {
                var row = await db.Envelopes.SingleAsync(x => x.Id == run.Record.Id); row.PdfBlob = run.Source.Blob.ObjectId.ToString("N");
                row.PdfSha256 = Convert.FromHexString(run.Source.Sha256); row.SenderVerifiedAt = row.PreviewConfirmedAt = run.Record.Clock.Now;
                row.ExpiresAt = requested is null ? null : run.Record.Clock.Now.Add(requested.Value);
                await db.SaveChangesAsync(); await run.Gate.PrepareOutcomeLockedAsync(db, bootstrap);
            }, commit: true);
            await run.Gate.CompleteAsync(bootstrap, Hash);
            await run.Locked(async db => {
                var row = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == run.Record.Id);
                run.DraftDeadline = (await ProductionRecordRetentionAccess.ReadLockedAsync(db, row, run.Record.Clock)).Deadline!.Value;
                run.Deadline = ProductionRecordSendWriteContract.Earlier(run.DraftDeadline, row.ExpiresAt);
                if (begin) run.Scope = await run.Gate.BeginLockedAsync(db, run.Record.Id, Guid.NewGuid(), ProductionRecordSendWriteContract.Kind, "send");
            }); return run;
        }
        internal Task Plan(QuillSignDbContext db) => Gate.PrepareSendWriteLockedAsync(db, Scope, Source, Target);
        internal async Task Locked(Func<QuillSignDbContext, Task> action, bool commit = false)
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            await action(db); if (commit) await tx.CommitAsync(); else await tx.RollbackAsync();
        }
        internal async Task Write(QuillSignDbContext db)
        {
            Assert.True(await Gate.BeginSendWriteLockedAsync(db, Scope, Target)); await Gate.DemandSendWriteLockedAsync(db, Scope, Target);
            await Gate.RecordSendWriteLockedAsync(db, Scope, Receipt);
        }
        internal async Task Save(QuillSignDbContext db, string? fault = null)
        {
            var row = await db.Envelopes.SingleAsync(x => x.Id == Record.Id); row.Status = fault == "status" ? EnvelopeStatus.Draft : EnvelopeStatus.Sent;
            row.SentAt = fault == "sent-deadline" ? Deadline : Record.Clock.Now;
            row.SentPdfBlob = (fault == "target-id" ? Guid.NewGuid() : Target.Blob.ObjectId).ToString("N");
            row.SentPdfSha256 = Convert.FromHexString(fault == "target-hash" ? new('d', 64) : Target.Sha256);
            if (fault == "source-id") row.PdfBlob = Guid.NewGuid().ToString("N");
            if (fault == "source-hash") row.PdfSha256 = new byte[32];
            await db.SaveChangesAsync();
        }
    }
}
