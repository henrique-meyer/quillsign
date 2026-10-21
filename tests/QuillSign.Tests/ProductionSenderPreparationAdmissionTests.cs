using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionSenderPreparationAdmissionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("details")][InlineData("signers")][InlineData("fields")]
    public async Task Exact_effective_hold_blocks_SQL_mutations_and_readonly_getters_remain_readonly_until_exact_release(string action)
    {
        await using var run = await Run.Create(fixture); var hold = await run.Hold(); var before = await run.Snapshot();
        var external = (await run.Journal.ReadAsync(run.Id)).Sequence;
        Assert.Equal(3, await run.Mutate(action)); Assert.Equal(before, await run.Snapshot());
        await using (var db = fixture.Open())
        {
            Assert.NotNull(await run.Details(db).GetAsync(run.Principal, run.PublicId));
            Assert.NotNull(await run.Signers(db).GetAsync(run.Principal, run.PublicId));
            Assert.NotNull(await run.Fields(db).GetAsync(run.Principal, run.PublicId));
        }
        Assert.Equal(external, (await run.Journal.ReadAsync(run.Id)).Sequence);
        await run.Release(hold); Assert.Equal(0, await run.Mutate(action));
        var after = await run.Snapshot(); Assert.NotEqual(before.Version, after.Version); Assert.Equal(before.Audits + 1, after.Audits);
        Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
        Assert.False((await run.Coordinator.ReadVerifiedAsync(run.Id)).Frozen);
    }

    [Theory]
    [InlineData("details")][InlineData("signers")][InlineData("fields")]
    public async Task Invalid_or_stale_known_SQL_noop_settles_without_changing_rows_or_versions(string action)
    {
        await using var run = await Run.Create(fixture); var before = await run.Snapshot();
        Assert.Equal(4, await run.Mutate(action, invalid: true)); Assert.Equal(before, await run.Snapshot());
        Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
        Assert.Equal(3, await run.Mutate(action, version: Convert.ToBase64String(new byte[8]))); Assert.Equal(before, await run.Snapshot());
        var state = await run.Journal.ReadAsync(run.Id); Assert.Null(state.OutstandingOperation);
        Assert.Equal(3, state.SettledOperations.Count); // Synthetic setup plus two known no-op acknowledgements.
        Assert.Equal(0, await run.Mutate(action));
    }

    [Theory]
    [InlineData("details")][InlineData("signers")][InlineData("fields")]
    public async Task Unknown_SQL_commit_acknowledgement_keeps_exact_scope_open_and_never_replays_automatically(string action)
    {
        await using var run = await Run.Create(fixture); var before = await run.Snapshot();
        await using (var db = run.Open(new LostCommit())) await Assert.ThrowsAsync<IOException>(() => run.Mutate(action, supplied: db));
        var after = await run.Snapshot(); Assert.NotEqual(before.Version, after.Version); Assert.Equal(before.Audits + 1, after.Audits);
        var state = await run.Journal.ReadAsync(run.Id); Assert.NotNull(state.OutstandingOperation);
        Assert.Equal("sender/" + action, state.Operations![state.OutstandingOperation!.Value].Kind);
        Assert.Equal(3, await run.Mutate(action)); Assert.Equal(after, await run.Snapshot());
        var command = Place(run.Id); var pending = await run.Coordinator.SubmitAsync(Authority(run.Time, command.Permission), Operators, command);
        Assert.Equal(state.OutstandingOperation, pending.OutstandingOperation); Assert.Equal(command, pending.Unacknowledged);
        await using var check = fixture.Open(); Assert.False(await check.ProductionHoldRequests.AnyAsync(x => x.EnvelopeId == run.Id));
    }

    [Theory]
    [InlineData("details")][InlineData("signers")][InlineData("fields")]
    public async Task Starting_snapshot_is_rechecked_under_parent_lock_before_any_mutation_or_noop_return(string action)
    {
        await using var run = await Run.Create(fixture); var before = await run.Snapshot();
        await using (var db = run.Open(new ChangedStartingRow(run.Id)))
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Mutate(action, supplied: db));
        Assert.Equal(before, await run.Snapshot()); Assert.NotNull((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    [Theory]
    [InlineData("details")][InlineData("signers")][InlineData("fields")]
    public async Task Unauthorized_owner_creates_no_operation_and_demo_or_default_construction_preserves_existing_behavior(string action)
    {
        await using var run = await Run.Create(fixture); var before = await run.Snapshot(); var count = run.External.Rows.Count;
        var foreign = SenderConfiguration.Principal(new VerifiedSender(run.Id, run.PublicId, "foreign@example.invalid"));
        Assert.Equal(1, await run.Mutate(action, principal: foreign)); Assert.Equal(before, await run.Snapshot()); Assert.Equal(count, run.External.Rows.Count);
        await using var demo = await Run.Create(fixture, demo: true);
        Assert.Equal(0, await demo.Mutate(action)); Assert.Empty(demo.External.Rows);
        await using var legacy = await Run.Create(fixture, demo: true);
        Assert.Equal(0, await legacy.Mutate(action, hook: false)); Assert.Empty(legacy.External.Rows);
    }

    [Theory]
    [InlineData("details")][InlineData("signers")][InlineData("fields")]
    public async Task Mutable_demo_flag_cannot_downgrade_enrolled_production_or_bypass_its_external_witness(string action)
    {
        await using var run = await Run.Create(fixture);
        await using (var db = fixture.Open()) await db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.IsDemo, true));
        var before = await run.Snapshot(); var count = run.External.Rows.Count;
        Assert.Equal(3, await run.Mutate(action)); Assert.Equal(before, await run.Snapshot()); Assert.Equal(count, run.External.Rows.Count);
    }

    [Theory]
    [InlineData("details")][InlineData("signers")][InlineData("fields")]
    public async Task Dirty_or_transactional_caller_cannot_flush_foreign_changes_or_create_external_reservation(string action)
    {
        await using var run = await Run.Create(fixture); var before = await run.Snapshot(); var count = run.External.Rows.Count;
        var foreign = new Envelope { SenderEmail = "foreign@example.invalid", Title = "Unrelated unsaved draft" };
        await using (var db = fixture.Open())
        {
            db.Envelopes.Add(foreign);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Mutate(action, supplied: db));
            Assert.Equal(EntityState.Added, db.Entry(foreign).State);
        }
        await using (var db = fixture.Open())
        {
            await using var transaction = await db.Database.BeginTransactionAsync();
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Mutate(action, supplied: db));
            Assert.Same(transaction, db.Database.CurrentTransaction);
        }
        await using var check = fixture.Open(); Assert.False(await check.Envelopes.AnyAsync(x => x.Id == foreign.Id));
        Assert.Equal(before, await run.Snapshot()); Assert.Equal(count, run.External.Rows.Count);
        Assert.Null((await run.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    private sealed class LostCommit : DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData data, CancellationToken ct = default)
            => throw new IOException("Synthetic preparation commit acknowledgement lost");
    }
    private sealed class ChangedStartingRow(Guid id) : DbCommandInterceptor
    {
        private bool changed;
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData data,
            InterceptionResult<DbDataReader> result, CancellationToken ct = default)
        {
            if (!changed && command.Transaction is not null && command.CommandText.Contains("[Envelopes]", StringComparison.Ordinal) && command.CommandText.Contains("UPDLOCK", StringComparison.Ordinal))
            {
                changed = true; await using var edit = command.Connection!.CreateCommand(); edit.Transaction = command.Transaction;
                edit.CommandText = "UPDATE [Envelopes] SET [Message]='Synthetic concurrent unadmitted edit' WHERE [Id]=@id";
                var parameter = edit.CreateParameter(); parameter.ParameterName = "@id"; parameter.Value = id; edit.Parameters.Add(parameter);
                await edit.ExecuteNonQueryAsync(ct);
            }
            return result;
        }
    }
    private sealed record Snapshot(string Version, string? Title, string? Message, int Audits, int Signers, int Recipients, int Fields);
    private sealed class Run : IAsyncDisposable
    {
        private readonly SqlDatabaseFixture fixture; private readonly bool demo;
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider(); internal readonly Clock Time = new(); internal readonly Store External = new();
        private readonly ProductionHoldArchiveReleaseTests.Provider archiveProvider = new(); private readonly Sources sources = new();
        private readonly SourceTransport transport;
        internal readonly ProductionHoldWitnessJournal Journal; internal readonly ProductionRecordOperationAdmission Operations;
        internal readonly ProductionHoldCoordinator Coordinator;
        internal Guid Id; internal string PublicId = "", Email = "", DocumentId = "";
        internal ClaimsPrincipal Principal => SenderConfiguration.Principal(new VerifiedSender(Id, PublicId, Email));
        private ProductionSenderPreparationAdmission Hook => new(Operations);
        private Run(SqlDatabaseFixture fixture, bool demo)
        {
            this.fixture = fixture; this.demo = demo; Journal = new(External, Keys, Time, Installation); Operations = new(fixture.Open, Keys, Time, Journal);
            transport = new(archiveProvider, sources);
            var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03) { Transport = new HttpClientTransport(new HttpClient(transport, false)) };
            options.Retry.MaxRetries = 0; options.Diagnostics.IsLoggingEnabled = false;
            var client = new BlobServiceClient(new Uri("https://storage.example.invalid"), new ProductionHoldArchiveReleaseTests.Credential(), options);
            Coordinator = new(fixture.Open, Keys, Time, Journal, sources, new(client), new(client));
        }
        internal QuillSignDbContext Open(IInterceptor interceptor)
        {
            using var source = fixture.Open();
            return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(interceptor).Options);
        }
        internal DraftDetails Details(QuillSignDbContext db, bool hook = true) => new(db, new(db, Time), new(), Time) { HoldAdmission = hook ? Hook : null };
        internal SignerSetup Signers(QuillSignDbContext db, bool hook = true) => new(db, new(db, Time), new(), Time) { HoldAdmission = hook ? Hook : null };
        internal FieldEditor Fields(QuillSignDbContext db, bool hook = true) => new(db, new(db, Time), new(), Time) { HoldAdmission = hook ? Hook : null };
        internal async Task<int> Mutate(string action, bool invalid = false, string? version = null, QuillSignDbContext? supplied = null, bool hook = true, ClaimsPrincipal? principal = null)
        {
            await using var owned = supplied is null ? fixture.Open() : null; var db = supplied ?? owned!;
            var e = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == Id); var current = version ?? Convert.ToBase64String(e.RowVersion); var user = principal ?? Principal;
            return action switch
            {
                "details" => (int)(await Details(db, hook).ChangeAsync(user, PublicId, new(DetailsChangeKind.SaveDetails, current, Title: invalid ? "" : "Updated synthetic title"), null, null)).Error,
                "signers" => (int)(await Signers(db, hook).ChangeAsync(user, PublicId, new(SignerChangeKind.Save, current, FullName: invalid ? "" : "Synthetic signer", Email: "signer@example.invalid"), null, null)).Error,
                "fields" => (int)(await Fields(db, hook).SaveAsync(user, PublicId, new(current, DocumentId,
                    [new(Guid.NewGuid(), null, invalid ? "Unknown" : "Text", 1, .1m, .1m, .2m, .1m, false, Value: "Synthetic sender value")]), null, null)).Error,
                _ => throw new InvalidOperationException()
            };
        }
        internal async Task<Snapshot> Snapshot()
        {
            await using var db = fixture.Open(); var e = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == Id);
            return new(Convert.ToBase64String(e.RowVersion), e.Title, e.Message, await db.AuditEvents.CountAsync(x => x.EnvelopeId == Id),
                await db.Signers.CountAsync(x => x.EnvelopeId == Id), await db.Recipients.CountAsync(x => x.EnvelopeId == Id), await db.Fields.CountAsync(x => x.EnvelopeId == Id));
        }
        internal async Task<ProductionHoldCommand> Hold()
        { var command = Place(Id); await Coordinator.SubmitAsync(Authority(Time, command.Permission), Operators, command); await Coordinator.PreserveAsync(Id, command.HoldId, Guid.NewGuid()); return command; }
        internal async Task Release(ProductionHoldCommand placement)
        { var command = placement with { CommandId = Guid.NewGuid(), ExpectedRevision = 1, Operation = ProductionHoldOperation.Release }; await Coordinator.SubmitAsync(Authority(Time, command.Permission), Operators, command); await Coordinator.ReleaseAsync(Id, placement.HoldId); }
        internal static async Task<Run> Create(SqlDatabaseFixture fixture, bool demo = false)
        {
            var run = new Run(fixture, demo);
            await using (var db = fixture.Open())
            {
                await using var tx = await db.Database.BeginTransactionAsync();
                var e = new Envelope { SenderEmail = "synthetic-preparation-" + Guid.NewGuid().ToString("N") + "@example.invalid", CreatedAt = run.Time.Now, IsDemo = demo };
                db.Add(e);
                if (!demo) await new ProductionRetentionLedger(db, new(db, run.Time), run.Time).PrepareNewLockedAsync(e, ProductionRetentionLedgerTests.Policy());
                else await db.SaveChangesAsync();
                var audit = new AuditWriter(db, run.Time); await audit.AppendAsync(e.Id, "draft_created", e.SenderEmail, null, null, default); await audit.AppendAsync(e.Id, "sender_verification_requested", e.SenderEmail, null, null, default);
                run.Id = e.Id; run.PublicId = e.PublicId; run.Email = e.SenderEmail; await tx.CommitAsync();
            }
            if (!demo) await run.Operations.InitializeAsync(run.Id);
            var setup = demo ? null : await run.Operations.BeginAsync(run.Id, Guid.NewGuid(), "test/synthetic-sql-fixture", run.PublicId);
            // This fixture installs typed synthetic SQL upload/preview evidence
            // and intercepted bytes only. It is not an actual upload/browser or
            // live immutable-provider validation, and mints no participant link.
            await using (var db = fixture.Open())
            {
                await using var tx = await db.Database.BeginTransactionAsync();
                var e = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={run.Id}").SingleAsync();
                if (setup is not null) await run.Operations.DemandStartingLockedAsync(db, setup);
                var audit = new AuditWriter(db, run.Time); e.SenderVerifiedAt = run.Time.Now;
                db.AuthTokens.Add(new() { EnvelopeId = e.Id, Email = e.SenderEmail, PartyType = PartyType.Sender, Purpose = TokenPurpose.SenderVerify,
                    TokenSha256 = SHA256.HashData(Guid.NewGuid().ToByteArray()), UsedAt = run.Time.Now, ExpiresAt = run.Time.Now.AddHours(1) });
                await audit.AppendAsync(e.Id, "sender_email_verified", e.SenderEmail, null, null, default);
                var original = Guid.NewGuid(); var normalized = Guid.NewGuid(); var digest = SHA256.HashData(ProductionHoldArchiveReleaseTests.Raw);
                e.Title = "synthetic.pdf"; e.OriginalBlob = original.ToString("N"); e.OriginalMime = "application/pdf"; e.OriginalSha256 = digest;
                e.PdfBlob = normalized.ToString("N"); e.PdfSha256 = digest; e.PageCount = 1;
                e.PageSizesJson = JsonSerializer.Serialize(new[] { new PageGeometry(612, 792, 0, 1, [0, 0, 612, 792], [0, 0, 612, 792]) });
                var hash = Convert.ToHexStringLower(digest);
                await audit.AppendAsync(e.Id, "document_uploaded", e.SenderEmail, null, null, default, dataJson: JsonSerializer.Serialize(new { filename = e.Title, originalSha256 = hash,
                    pdfSha256 = hash, pageCount = 1, previousDocument = (string?)null, retentionSha256 = (string?)null }));
                e.PreviewConfirmedAt = run.Time.Now;
                await audit.AppendAsync(e.Id, "preview_confirmed", e.SenderEmail, null, null, default, dataJson: JsonSerializer.Serialize(new { document = e.PdfBlob, pdfSha256 = hash }));
                run.DocumentId = e.PdfBlob; run.sources.Objects.Add(new("originals", $"{e.Id:N}/{original:N}", "synthetic-original-version", "", "\"synthetic-original-tag\"", ProductionHoldArchiveReleaseTests.Raw.Length));
                run.sources.Objects.Add(new("normalized", $"{e.Id:N}/{normalized:N}", "synthetic-normalized-version", "", "\"synthetic-normalized-tag\"", ProductionHoldArchiveReleaseTests.Raw.Length));
                if (setup is not null) await run.Operations.PrepareOutcomeLockedAsync(db, setup);
                await tx.CommitAsync();
            }
            if (setup is not null) await run.Operations.CompleteAsync(setup, Hash); return run;
        }
        public ValueTask DisposeAsync() { transport.Dispose(); archiveProvider.Dispose(); return ValueTask.CompletedTask; }
    }
    private sealed class Sources : IProductionHoldObjectSource
    {
        internal readonly List<HoldObjectAddress> Objects = [];
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct)
            => Task.FromResult(new HoldObjectPage(Objects.Where(x => x.Area == area).ToArray(), null));
        public Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress address, CancellationToken ct)
            => Task.FromResult(Convert.ToHexStringLower(SHA256.HashData(ProductionHoldArchiveReleaseTests.Raw)));
    }
    private sealed class SourceTransport(ProductionHoldArchiveReleaseTests.Provider archive, Sources sources) : HttpMessageHandler
    {
        private readonly HttpMessageInvoker next = new(archive, false);
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path is "/originals" or "/normalized") return Task.FromResult(Reply([]));
            var source = sources.Objects.SingleOrDefault(x => path == "/" + x.Area + "/" + x.Name);
            if (source is null) return next.SendAsync(request, ct);
            Assert.Equal(HttpMethod.Get, request.Method); var query = QueryHelpers.ParseQuery(request.RequestUri.Query);
            Assert.Equal(source.VersionId, query["versionid"].ToString()); Assert.Equal(source.ETag, request.Headers.GetValues("If-Match").Single());
            var result = Reply(ProductionHoldArchiveReleaseTests.Raw); result.Content.Headers.ContentLength = source.Length;
            result.Headers.TryAddWithoutValidation("ETag", source.ETag); result.Headers.TryAddWithoutValidation("x-ms-version-id", source.VersionId); return Task.FromResult(result);
        }
        private static HttpResponseMessage Reply(byte[] bytes)
        { var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }; response.Headers.TryAddWithoutValidation("x-ms-version", "2023-11-03"); return response; }
        protected override void Dispose(bool disposing) { if (disposing) next.Dispose(); base.Dispose(disposing); }
    }
}
