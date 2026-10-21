using System.Security.Claims;
using System.Data.Common;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionPreviewConfirmationAdmissionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Pending_hold_blocks_confirmation_before_file_access_but_original_readonly_PDF_remains_readable()
    {
        await using var test = await Prepared.Create(fixture);
        var command = Place(test.Run.Id);
        await test.Run.Coordinator.SubmitAsync(Authority(test.Run.Time, command.Permission), Operators, command);
        await using var db = fixture.Open(); var before = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == test.Run.Id);
        var events = await db.AuditEvents.CountAsync(x => x.EnvelopeId == test.Run.Id); var copies = test.Blobs.Copies;
        Assert.False(await test.Workflow(db).ConfirmAsync(test.Sender, before.PublicId, before.RowVersion, before.PdfBlob!, true, null, null, default));
        Assert.Equal(copies, test.Blobs.Copies);
        var after = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == before.Id);
        Assert.Null(after.PreviewConfirmedAt); Assert.Equal(before.RowVersion, after.RowVersion);
        Assert.Equal(events, await db.AuditEvents.CountAsync(x => x.EnvelopeId == before.Id));
        await using var read = await test.Workflow(db).ReadAsync(test.Sender, before.PublicId, before.PdfBlob!, default);
        Assert.NotNull(read); Assert.Equal(before.PdfSha256, await SHA256.HashDataAsync(read));
        Assert.True((await test.Run.Journal.ReadAsync(before.Id)).Frozen);
        Assert.Equal(0, test.Blobs.Deletes);
    }

    [Fact]
    public async Task Actual_confirmation_and_idempotent_current_confirmation_settle_after_SQL_and_keep_one_original_audit()
    {
        await using var test = await Prepared.Create(fixture); await using var db = fixture.Open();
        var before = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == test.Run.Id);
        Assert.True(await test.Workflow(db).ConfirmAsync(test.Sender, before.PublicId, before.RowVersion, before.PdfBlob!, true, null, null, default));
        db.ChangeTracker.Clear(); var after = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == before.Id);
        Assert.Equal(test.Run.Time.Now, after.PreviewConfirmedAt); Assert.NotEqual(before.RowVersion, after.RowVersion);
        Assert.True(await test.Workflow(db).ConfirmAsync(test.Sender, after.PublicId, after.RowVersion, after.PdfBlob!, true, null, null, default));
        Assert.Equal(1, await db.AuditEvents.CountAsync(x => x.EnvelopeId == before.Id && x.Event == "preview_confirmed"));
        Assert.Null((await test.Run.Journal.ReadAsync(before.Id)).OutstandingOperation);
        Assert.False((await test.Run.Coordinator.ReadVerifiedAsync(before.Id)).Frozen);
        Assert.Equal(0, test.Blobs.Deletes);
    }

    [Fact]
    public async Task Unknown_confirmation_commit_retains_reservation_and_never_replays_confirmation_or_extends_authority()
    {
        await using var test = await Prepared.Create(fixture); string connection;
        await using (var source = fixture.Open()) connection = source.Database.GetDbConnection().ConnectionString;
        Envelope before; await using (var source = fixture.Open()) before = await source.Envelopes.AsNoTracking().SingleAsync(x => x.Id == test.Run.Id);
        await using (var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
            await Assert.ThrowsAsync<IOException>(() => test.Workflow(db).ConfirmAsync(test.Sender, before.PublicId, before.RowVersion, before.PdfBlob!, true, null, null, default));
        Assert.NotNull((await test.Run.Journal.ReadAsync(before.Id)).OutstandingOperation);
        await using var readback = fixture.Open(); var after = await readback.Envelopes.AsNoTracking().SingleAsync(x => x.Id == before.Id);
        Assert.NotNull(after.PreviewConfirmedAt);
        Assert.False(await test.Workflow(readback).ConfirmAsync(test.Sender, after.PublicId, after.RowVersion, after.PdfBlob!, true, null, null, default));
        Assert.Equal(1, await readback.AuditEvents.CountAsync(x => x.EnvelopeId == before.Id && x.Event == "preview_confirmed"));
        Assert.NotNull((await test.Run.Journal.ReadAsync(before.Id)).OutstandingOperation);
    }

    [Fact]
    public async Task Changed_owner_between_reservation_and_initial_core_read_cannot_be_acknowledged_as_a_noop()
    {
        await using var test = await Prepared.Create(fixture); Envelope before;
        string connection; await using (var source = fixture.Open())
        { before = await source.Envelopes.AsNoTracking().SingleAsync(x => x.Id == test.Run.Id); connection = source.Database.GetConnectionString()!; }
        var race = new ChangeOwnerBeforeCore(fixture, before.Id);
        await using var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(race).Options);
        await Assert.ThrowsAsync<DocumentConflictException>(() => test.Workflow(db).ConfirmAsync(test.Sender, before.PublicId, before.RowVersion, before.PdfBlob!, true, null, null, default));
        Assert.True(race.Changed); var state = await test.Run.Journal.ReadAsync(before.Id); Assert.NotNull(state.OutstandingOperation);
        Assert.False(state.Outcomes!.ContainsKey(state.OutstandingOperation!.Value));
    }

    [Fact]
    public async Task Restored_earlier_preview_and_audit_after_commit_cannot_replace_the_precommitted_outcome()
    {
        await using var test = await Prepared.Create(fixture); Envelope before; string connection;
        await using (var source = fixture.Open())
        { before = await source.Envelopes.AsNoTracking().SingleAsync(x => x.Id == test.Run.Id); connection = source.Database.GetConnectionString()!; }
        var restore = new RestoreConfirmationAfterCommit(fixture, before.Id);
        await using var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(restore).Options);
        await Assert.ThrowsAsync<InvalidDataException>(() => test.Workflow(db).ConfirmAsync(test.Sender, before.PublicId, before.RowVersion, before.PdfBlob!, true, null, null, default));
        Assert.True(restore.Restored); var state = await test.Run.Journal.ReadAsync(before.Id);
        Assert.NotNull(state.OutstandingOperation); Assert.True(state.Outcomes!.ContainsKey(state.OutstandingOperation!.Value));
        await using var readback = fixture.Open();
        Assert.Null((await readback.Envelopes.SingleAsync(x => x.Id == before.Id)).PreviewConfirmedAt);
        Assert.False(await readback.AuditEvents.AnyAsync(x => x.EnvelopeId == before.Id && x.Event == "preview_confirmed"));
        Assert.True(state.Frozen);
    }

    [Fact]
    public async Task Explicit_matching_confirmation_and_original_version_checks_are_not_bypassed()
    {
        await using var test = await Prepared.Create(fixture); await using var db = fixture.Open();
        var before = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == test.Run.Id); var state = await test.Run.Journal.ReadAsync(before.Id);
        await Assert.ThrowsAsync<DocumentRejectedException>(() => test.Workflow(db).ConfirmAsync(test.Sender, before.PublicId, before.RowVersion, before.PdfBlob!, false, null, null, default));
        Assert.Equal(state.HeadHash, (await test.Run.Journal.ReadAsync(before.Id)).HeadHash);
        await Assert.ThrowsAsync<DocumentConflictException>(() => test.Workflow(db).ConfirmAsync(test.Sender, before.PublicId, new byte[8], before.PdfBlob!, true, null, null, default));
        Assert.Equal(state.HeadHash, (await test.Run.Journal.ReadAsync(before.Id)).HeadHash);
        await Assert.ThrowsAsync<DocumentConflictException>(() => test.Workflow(db).ConfirmAsync(test.Sender, before.PublicId, before.RowVersion, Guid.NewGuid().ToString("N"), true, null, null, default));
        Assert.Equal(state.HeadHash, (await test.Run.Journal.ReadAsync(before.Id)).HeadHash);
        Assert.Null((await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == before.Id)).PreviewConfirmedAt);
    }

    private sealed class LostCommit : DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(System.Data.Common.DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
            => throw new IOException("Synthetic lost preview confirmation commit acknowledgement");
    }
    private sealed class ChangeOwnerBeforeCore(SqlDatabaseFixture fixture, Guid id) : DbCommandInterceptor
    {
        private int reads; internal bool Changed;
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("[SenderVerifiedAt] IS NOT NULL", StringComparison.Ordinal) && ++reads == 2)
            { await using var db = fixture.Open(); await db.Envelopes.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(e => e.SenderVerifiedAt, (DateTimeOffset?)null), cancellationToken); Changed = true; }
            return result;
        }
    }
    private sealed class RestoreConfirmationAfterCommit(SqlDatabaseFixture fixture, Guid id) : DbTransactionInterceptor
    {
        internal bool Restored;
        public override async Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken cancellationToken = default)
        {
            await using var db = fixture.Open(); await using var restore = await db.Database.BeginTransactionAsync(cancellationToken);
            await db.AuditEvents.Where(x => x.EnvelopeId == id && x.Event == "preview_confirmed").ExecuteDeleteAsync(cancellationToken);
            await db.Envelopes.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(e => e.PreviewConfirmedAt, (DateTimeOffset?)null), cancellationToken);
            await restore.CommitAsync(cancellationToken); Restored = true;
        }
    }
    private sealed class SealUploadOutcome(ProductionRecordOperationAdmission operations, ProductionRecordOperation scope) : DbTransactionInterceptor
    {
        public override async ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData,
            InterceptionResult result, CancellationToken cancellationToken = default)
        {
            await operations.PrepareOutcomeLockedAsync((QuillSignDbContext)eventData.Context!, scope, cancellationToken); return result;
        }
    }
    private sealed class MemoryBlobs : IBlobStore
    {
        private readonly Dictionary<DocumentBlob, byte[]> bytes = [];
        internal int Copies, Deletes;
        public async Task WriteAsync(ClaimsPrincipal sender, DocumentBlob blob, Stream source, long length, CancellationToken cancellationToken = default)
        {
            EnvelopeStorageAuthorization.Demand(sender, blob); using var saved = new MemoryStream(); await source.CopyToAsync(saved, cancellationToken);
            Assert.Equal(length, saved.Length); bytes.Add(blob, saved.ToArray());
        }
        public async Task<long> CopyToAsync(ClaimsPrincipal sender, DocumentBlob blob, Stream destination, CancellationToken cancellationToken = default)
        { EnvelopeStorageAuthorization.DemandRead(sender, blob); Copies++; await destination.WriteAsync(bytes[blob], cancellationToken); return bytes[blob].Length; }
        public Task DeleteAsync(ClaimsPrincipal sender, DocumentBlob blob, CancellationToken cancellationToken = default)
        { EnvelopeStorageAuthorization.DemandDelete(sender, blob); Deletes++; bytes.Remove(blob); return Task.CompletedTask; }
    }
    private sealed class Prepared(ProductionRuntimeAdmissionTests.Run run) : IAsyncDisposable
    {
        internal readonly ProductionRuntimeAdmissionTests.Run Run = run;
        internal readonly MemoryBlobs Blobs = new(); internal ClaimsPrincipal Sender = null!;
        internal DocumentWorkflow Workflow(QuillSignDbContext db) => new(db, Blobs, new(new()), new(), new(db, Run.Time), Run.Time,
            NullLogger<DocumentWorkflow>.Instance) { HoldAdmission = new(Run.Admission) };
        internal static async Task<Prepared> Create(SqlDatabaseFixture fixture)
        {
            var run = await ProductionRuntimeAdmissionTests.Run.Create(fixture); var test = new Prepared(run);
            await run.DeliverAndFinish(await run.Claim());
            await using var db = fixture.Open(); var verified = await run.Sender(db).VerifyAsync(run.Token.Token, null, null); Assert.NotNull(verified);
            test.Sender = new(new ClaimsIdentity([new(EnvelopeStorageAuthorization.EnvelopeClaim, run.Id.ToString()), new(ClaimTypes.Email, verified.Email)], EnvelopeStorageAuthorization.SenderScheme));
            var before = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == run.Id);
            // This explicit test scope joins the existing ordinary upload to the
            // witnessed fixture. Upload's runtime long-operation hook is still
            // separate required work; this test makes no installed upload claim.
            var operation = await run.Admission.BeginAsync(run.Id, Guid.NewGuid(), "test/upload", "synthetic-local-PDF");
            var bytes = PdfFixtures.Create(); using var input = new MemoryStream(bytes, false);
            await using var upload = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(db.Database.GetConnectionString())
                .AddInterceptors(new SealUploadOutcome(run.Admission, operation)).Options);
            Assert.True(await test.Workflow(upload).UploadAsync(test.Sender, before.PublicId, before.RowVersion, "synthetic.pdf", input, bytes.Length, null, null, default));
            await run.Admission.CompleteAsync(operation, Convert.ToHexStringLower(SHA256.HashData("synthetic-confirmation-fixture-upload"u8)));
            return test;
        }
        public ValueTask DisposeAsync() => Run.DisposeAsync();
    }
}
