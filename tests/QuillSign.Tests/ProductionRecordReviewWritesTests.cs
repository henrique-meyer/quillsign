using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRecordReviewWritesTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Actual_renderer_original_snapshot_two_SDK_objects_and_only_exact_candidate_audit_SQL_commit()
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); ProductionRecordOperation scope;
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Prepare(db); var plan = (await run.Journal.ReadAsync(scope.RecordId)).ReviewWrites![scope.OperationId].Plan;
            foreach (var item in run.Items)
            {
                using var source = run.Write.Open(item.Blob.Kind); using var bytes = new MemoryStream(); source.CopyTo(bytes); source.Position = 0;
                using var provider = new ProductionSignerReviewTransportTests.Provider(suppliedItem: item, suppliedScope: scope, suppliedIdentity: run.Write.Identity,
                    suppliedClock: run.Record.Time, suppliedBytes: bytes.ToArray());
                var mayWrite = await run.Gate.BeginReviewWriteLockedAsync(db, scope, item); var demands = 0;
                var receipt = await provider.Store.WriteAsync(scope, run.Write.Identity, item, source, mayWrite, null, async ct => {
                    Assert.Same(tx, db.Database.CurrentTransaction); demands++; await run.Gate.DemandReviewWriteLockedAsync(db, scope, item, ct);
                });
                await run.Gate.RecordReviewWriteLockedAsync(db, scope, receipt); Assert.Equal(1, provider.Commits); Assert.True(demands >= provider.Requests.Count * 2);
                Assert.DoesNotContain(provider.Requests, x => x.Method == HttpMethod.Delete);
            }
            await run.Save(db, plan); await run.Gate.PrepareOutcomeLockedAsync(db, scope); await tx.CommitAsync();
        }
        await run.Gate.CompleteAsync(scope, Hash); var state = await run.Journal.ReadAsync(scope.RecordId);
        Assert.Null(state.OutstandingOperation); Assert.Equal(2, state.ReviewWrites![scope.OperationId].Receipts.Count);
        var candidate = await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x => x.Id == run.Write.CandidateId);
        Assert.Equal(run.Write.CandidateRowJson, ProductionRecordReviewWriteContract.Row(candidate)); Assert.Equal(8, candidate.RowVersion.Length);
        var row = await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == run.Delivered.TokenRecord.Id); Assert.Equal(run.Delivered.TokenRecord.ExpiresAt, row.ExpiresAt);
    }
    [Fact]
    public async Task PDF_cannot_begin_before_input_and_lost_input_start_ack_SQL_rollback_never_grants_another_write()
    {
        await using var run = await Ready.Create(fixture); ProductionRecordOperation scope;
        await using (var db = fixture.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Prepare(db); await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginReviewWriteLockedAsync(db, scope, run.Write.Pdf));
            run.Record.External.LostAck = true; await Assert.ThrowsAsync<IOException>(() => run.Gate.BeginReviewWriteLockedAsync(db, scope, run.Write.Input)); await tx.RollbackAsync();
        }
        await using var retry = fixture.Open(); await using var next = await retry.Database.BeginTransactionAsync();
        Assert.False(await run.Gate.BeginReviewWriteLockedAsync(retry, scope, run.Write.Input));
        Assert.Null(await run.Gate.ReadReviewWriteReceiptLockedAsync(retry, scope, run.Write.Input));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginReviewWriteLockedAsync(retry, scope, run.Write.Pdf));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(retry, scope)); Assert.Equal(0, run.Writes);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginLockedAsync(retry, scope.RecordId, Guid.NewGuid(), ProductionRecordReviewWriteContract.Kind, Guid.NewGuid().ToString("N")));
    }
    [Fact]
    public async Task Lost_record_ack_only_recovers_exact_receipt_and_original_review_clock_expiry_stops_second_object()
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var scope = await run.Prepare(db); Assert.True(await run.Gate.BeginReviewWriteLockedAsync(db, scope, run.Write.Input));
        var receipt = new ProductionRecordWriteReceipt(run.Write.Input, "original-input-version", "\"original-input-tag\""); run.Record.External.LostAck = true;
        await Assert.ThrowsAsync<IOException>(() => run.Gate.RecordReviewWriteLockedAsync(db, scope, receipt));
        Assert.False(await run.Gate.BeginReviewWriteLockedAsync(db, scope, run.Write.Input)); Assert.Equal(receipt, await run.Gate.ReadReviewWriteReceiptLockedAsync(db, scope, run.Write.Input));
        await run.Gate.RecordReviewWriteLockedAsync(db, scope, receipt);
        run.Record.Time.Now = run.Write.ExpiresAt;
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(() => run.Gate.BeginReviewWriteLockedAsync(db, scope, run.Write.Pdf));
        Assert.False(await db.SignerReviewCandidates.AnyAsync(x => x.Id == run.Write.CandidateId)); Assert.Equal(scope.OperationId, (await run.Journal.ReadAsync(scope.RecordId)).OutstandingOperation);
    }
    [Theory]
    [InlineData("candidate")][InlineData("extra-row")][InlineData("audit")][InlineData("actor")][InlineData("metadata")][InlineData("other-table")][InlineData("missing-audit")]
    public async Task Complete_pair_cannot_seal_unplanned_candidate_audit_or_business_mutations(string fault)
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var scope = await run.Prepare(db); foreach (var item in run.Items) await run.RecordItem(db, scope, item);
        var plan = (await run.Journal.ReadAsync(scope.RecordId)).ReviewWrites![scope.OperationId].Plan;
        var row = ProductionRecordReviewWriteContract.ReadRow(run.Write.CandidateRowJson);
        if (fault == "candidate") row.SnapshotSha256[0] ^= 1;
        db.Add(row); await db.SaveChangesAsync();
        if (fault == "extra-row") { var extra = ProductionRecordReviewWriteContract.ReadRow(run.Write.CandidateRowJson); extra.Id = Guid.NewGuid(); extra.PdfObjectId = Guid.NewGuid(); db.Add(extra); await db.SaveChangesAsync(); }
        if (fault != "missing-audit") await new AuditWriter(db, run.Record.Time).AppendAsync(scope.RecordId, "signer_review_prepared", run.Write.Identity.Email, null, null, default,
            fault == "audit" ? "{}" : ProductionRecordReviewWriteContract.AuditData(row), fault == "actor" ? PartyType.Sender : PartyType.Signer, run.Write.Identity.SignerId);
        if (fault == "metadata") await db.AuditEvents.Where(x => x.EnvelopeId == scope.RecordId && x.Sequence == plan.AuditSequence + 1).ExecuteUpdateAsync(x => x.SetProperty(a => a.UserAgent, "unexpected metadata"));
        if (fault == "other-table") await db.Envelopes.Where(x => x.Id == scope.RecordId).ExecuteUpdateAsync(x => x.SetProperty(e => e.Title, "unplanned title"));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, scope)); Assert.False((await run.Journal.ReadAsync(scope.RecordId)).Outcomes!.ContainsKey(scope.OperationId));
    }
    [Fact]
    public async Task Review_operation_without_both_members_never_implicitly_settles_and_old_events_keep_original_bytes()
    {
        await using var run = await Ready.Create(fixture); ProductionRecordOperation scope;
        await using (var db = fixture.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Gate.BeginLockedAsync(db, run.Write.Identity.EnvelopeId, run.Write.OperationId, ProductionRecordReviewWriteContract.Kind, run.Write.CandidateId.ToString("N"));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, scope));
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(scope, Hash));
        var old = new HoldWitnessEvent("old", Guid.NewGuid(), 1, Guid.NewGuid(), HoldWitnessKind.Initialized, run.Record.Time.Now, null, null, null, null, null, 0, null, null, null, null, null, null);
        Assert.DoesNotContain("Review", JsonSerializer.Serialize(old)); Assert.Equal(21, (int)HoldWitnessKind.PreviewWriteRecorded);
    }
    [Fact]
    public async Task Pending_hold_can_drain_only_the_exact_original_pair_and_still_prevents_fresh_participant_work()
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); ProductionRecordOperation scope; var hold = Place(run.Write.Identity.EnvelopeId);
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Prepare(db); await run.RecordItem(db, scope, run.Write.Input);
            await run.Journal.IntentAsync(Authority(run.Record.Time, hold.Permission), Operators, hold, Guid.NewGuid());
            await run.RecordItem(db, scope, run.Write.Pdf); var plan = (await run.Journal.ReadAsync(scope.RecordId)).ReviewWrites![scope.OperationId].Plan;
            await run.Save(db, plan); await run.Gate.PrepareOutcomeLockedAsync(db, scope); await tx.CommitAsync();
        }
        await run.Gate.CompleteAsync(scope, Hash); var state = await run.Journal.ReadAsync(scope.RecordId); Assert.Equal(hold, state.Unacknowledged); Assert.Null(state.OutstandingOperation);
        await using var next = await db.Database.BeginTransactionAsync(); await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginLockedAsync(db, scope.RecordId, Guid.NewGuid(), "signer/finish", run.Write.CandidateId.ToString("N")));
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Exact_captured_supersede_reverts_only_its_timestamp_and_original_rowversion_for_baseline_comparison(bool unrelatedChange)
    {
        await using var run = await Ready.Create(fixture); var prior = ProductionRecordReviewWriteContract.ReadRow(run.Write.CandidateRowJson);
        prior.Id = Guid.NewGuid(); prior.PdfObjectId = Guid.NewGuid(); prior.SnapshotSha256[0] ^= 1;
        // Isolated kernel fixture: admit this historical-row setup explicitly.
        // This does not claim its producer graph or sidecar is valid history.
        await using (var seed = fixture.Open())
        {
            ProductionRecordOperation setup;
            await using (var tx = await seed.Database.BeginTransactionAsync())
            {
                setup = await run.Gate.BeginLockedAsync(seed, prior.EnvelopeId, Guid.NewGuid(), "test/review-history", prior.Id.ToString("N"));
                seed.Add(prior); await seed.SaveChangesAsync(); await run.Gate.PrepareOutcomeLockedAsync(seed, setup); await tx.CommitAsync();
            }
            await run.Gate.CompleteAsync(setup, Hash);
        }
        await using var db = fixture.Open(); await using var transaction = await db.Database.BeginTransactionAsync();
        var scope = await run.Prepare(db); var saved = (await run.Journal.ReadAsync(scope.RecordId)).ReviewWrites![scope.OperationId];
        Assert.Equal(prior.Id, Assert.Single(saved.Plan.Superseded).CandidateId);
        // Plan publication may recover byte-identically despite a new immutable-array backing store.
        await run.Gate.PrepareReviewWritesLockedAsync(db, scope, run.Write);
        foreach (var item in run.Items) await run.RecordItem(db, scope, item);
        await db.SignerReviewCandidates.Where(x => x.Id == prior.Id).ExecuteUpdateAsync(x => x.SetProperty(r => r.SupersededAt, run.Write.PreparedAt));
        if (unrelatedChange) await db.SignerReviewCandidates.Where(x => x.Id == prior.Id).ExecuteUpdateAsync(x => x.SetProperty(r => r.PdfLength, prior.PdfLength + 1));
        await run.Save(db, saved.Plan);
        if (unrelatedChange) await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, scope));
        else await run.Gate.PrepareOutcomeLockedAsync(db, scope);
    }
    [Fact]
    public async Task Fresh_positive_private_SQL_scope_reads_only_exact_pinned_input_ciphertext_and_expires_without_new_IO()
    {
        await using var run = await Ready.Create(fixture); HoldWitnessReviewPlan plan;
        await using (var db = fixture.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
        { var scope = await run.Prepare(db); plan = (await run.Journal.ReadAsync(scope.RecordId)).ReviewWrites![scope.OperationId].Plan; }
        await using var privateDb = fixture.Open(); await using var privateTx = await privateDb.Database.BeginTransactionAsync();
        var command = Place(run.Write.Identity.EnvelopeId);
        var request = await new ProductionHoldRequests(privateDb, run.Record.Keys, run.Record.Time).PrepareLockedAsync(Authority(run.Record.Time, command.Permission), Operators, command);
        var snapshot = await new ProductionHoldSqlInventory(privateDb, run.Record.Keys, run.Record.Time).CaptureLockedAsync(command.RecordId, request.Current.Revision, request.Current.FenceHash!);
        var current = ProductionHoldObjectScope.FromVerified(snapshot, run.Record.Keys, run.Record.Time);
        using var input = run.Write.Open(DocumentBlobKind.ReviewInput); using var buffer = new MemoryStream(); input.CopyTo(buffer);
        var operation = new ProductionRecordOperation(run.Write.Identity.EnvelopeId, run.Write.OperationId, ProductionRecordReviewWriteContract.Kind, run.Write.CandidateId.ToString("N"), 0, null, new('a',64), new('b',64), 2);
        using var provider = new ProductionSignerReviewTransportTests.Provider(suppliedItem: run.Write.Input, suppliedScope: operation,
            suppliedIdentity: run.Write.Identity, suppliedClock: run.Record.Time, suppliedBytes: buffer.ToArray());
        var receipt = await provider.Write(true);
        var address = new HoldObjectAddress("normalized", AzureProductionSignerReviewStore.Path(run.Write.Input.Blob), receipt.VersionId, "", receipt.ETag, run.Write.Input.Length);
        var evidence = new HoldObjectEvidence(address, run.Write.Input.Sha256); var read = ProductionReviewInputReadScope.FromHold(current, plan, receipt, evidence);
        var cipher = await provider.Store.ReadAsync(read); Assert.Same(privateTx, privateDb.Database.CurrentTransaction); Assert.Equal(buffer.ToArray(), cipher);
        Assert.Equal(run.Write.CandidateId, ProductionReviewInputCodec.OpenVerified(run.Record.Keys, plan, cipher).CandidateId);
        Assert.Throws<InvalidDataException>(() => ProductionReviewInputReadScope.FromHold(current, plan, receipt, evidence with { Address = address with { VersionId = "foreign" } }));
        var requests = provider.Requests.Count; run.Record.Time.Now = snapshot.CapturedAt.AddMinutes(10);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => provider.Store.ReadAsync(read)); Assert.Equal(requests, provider.Requests.Count);
    }
    [Fact]
    public async Task Actual_owned_database_restore_before_SQL_outcome_cannot_replay_either_external_object_or_settle_newer_receipts()
    {
        var isolated = new SqlDatabaseFixture(); await isolated.InitializeAsync(); string? backup = null;
        try
        {
            await using var run = await Ready.Create(isolated); string connection;
            await using (var db = isolated.Open()) connection = db.Database.GetConnectionString()!;
            var builder = new SqlConnectionStringBuilder(connection); var name = builder.InitialCatalog; Assert.Matches("^QuillSignTests_[a-f0-9]{32}$", name);
            builder.InitialCatalog = "master"; builder.Pooling = false; await using var master = new SqlConnection(builder.ConnectionString); await master.OpenAsync();
            await using var command = master.CreateCommand(); command.CommandTimeout = 120; command.CommandText = "SELECT CONVERT(nvarchar(4000),SERVERPROPERTY('InstanceDefaultBackupPath'))";
            var directory = Assert.IsType<string>(await command.ExecuteScalarAsync()); backup = directory.TrimEnd('\\','/') + (directory.Contains('\\') ? "\\" : "/") + name + "-review.bak";
            command.CommandText = $"BACKUP DATABASE [{name}] TO DISK=@backup WITH COPY_ONLY, INIT"; command.Parameters.AddWithValue("@backup", backup); await command.ExecuteNonQueryAsync();
            ProductionRecordOperation scope;
            await using (var db = isolated.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
            {
                scope = await run.Prepare(db); foreach (var item in run.Items) await run.RecordItem(db, scope, item);
                await run.Save(db, (await run.Journal.ReadAsync(scope.RecordId)).ReviewWrites![scope.OperationId].Plan); await run.Gate.PrepareOutcomeLockedAsync(db, scope); await tx.CommitAsync();
            }
            var before = await run.Journal.ReadAsync(scope.RecordId);
            command.CommandText = $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; RESTORE DATABASE [{name}] FROM DISK=@backup WITH REPLACE; ALTER DATABASE [{name}] SET MULTI_USER";
            await command.ExecuteNonQueryAsync(); using (var pool = new SqlConnection(connection)) SqlConnection.ClearPool(pool);
            var fresh = new ProductionRecordOperationAdmission(isolated.Open, run.Record.Keys, run.Record.Time, run.Journal);
            await Assert.ThrowsAsync<InvalidDataException>(() => fresh.CompleteAsync(scope, Hash));
            await using (var db = isolated.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
            { await Assert.ThrowsAsync<InvalidDataException>(() => fresh.BeginReviewWriteLockedAsync(db, scope, run.Write.Input)); Assert.False(await db.SignerReviewCandidates.AnyAsync(x => x.Id == run.Write.CandidateId)); }
            Assert.Equal(before.HeadHash, (await run.Journal.ReadAsync(scope.RecordId)).HeadHash); Assert.Equal(2, run.Writes);
        }
        finally { await isolated.DisposeAsync(); if (backup is not null && File.Exists(backup)) File.Delete(backup); }
    }
    internal sealed class Ready(ProductionRecordSignaturePreviewWritesTests.Ready preview) : IAsyncDisposable
    {
        internal ProductionInvitationWorkerAdmissionTests.Delivered Delivered => preview.Delivered;
        internal ProductionRuntimeAdmissionTests.Run Record => Delivered.Record;
        internal ProductionRecordOperationAdmission Gate => Record.Admission;
        internal ProductionHoldWitnessJournal Journal => Record.Journal;
        internal ProductionSignerReviewWrite Write = null!;
        internal ProductionRecordWriteDescriptor[] Items => [Write.Input, Write.Pdf]; internal int Writes;
        internal static async Task<Ready> Create(SqlDatabaseFixture fixture)
        {
            var preview = await ProductionRecordSignaturePreviewWritesTests.Ready.Create(fixture); var run = new Ready(preview);
            var blobs = run.Delivered.Ready.Prepared.Blobs; ProductionRecordOperation operation;
            await using (var db = fixture.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
            {
                operation = await preview.Prepare(db);
                foreach (var item in preview.Items) { await preview.Record(db, operation, item); using var stream = preview.Write.Open(item.Blob.Kind); using var bytes = new MemoryStream(); stream.CopyTo(bytes); blobs.Objects.Add(item.Blob, bytes.ToArray()); }
                db.Add(ProductionRecordPreviewWriteContract.ReadRow(preview.Write.PreviewRowJson)); await db.SaveChangesAsync(); await run.Gate.PrepareOutcomeLockedAsync(db, operation); await tx.CommitAsync();
            }
            await run.Gate.CompleteAsync(operation, Hash); var identity = preview.Write.Identity; var principal = SignerAccessConfiguration.Principal(identity);
            await using (var db = fixture.Open())
            {
                var service = new SignatureAdoption(db, ProductionSignerMutationAdmissionTests.Access(run.Delivered, db), blobs, new(run.Record.Keys, run.Record.Time), new(db, run.Record.Time), run.Record.Time) { HoldAdmission = new(run.Gate) };
                var receipt = new SignaturePreviewProtection(run.Record.Keys, run.Record.Time).Create(ProductionRecordPreviewWriteContract.ReadRow(preview.Write.PreviewRowJson), identity);
                Assert.Equal(SignatureAdoptionResult.Adopted, await service.AdoptAsync(principal, identity.PublicId, receipt, true, SignatureAdoptionStatement.Version, null, null));
            }
            await using (var db = fixture.Open())
            {
                var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == identity.EnvelopeId); var signer = await db.Signers.AsNoTracking().SingleAsync(x => x.Id == identity.SignerId);
                var fields = await db.Fields.AsNoTracking().Where(x => x.EnvelopeId == identity.EnvelopeId && x.SignerId == identity.SignerId).OrderBy(x => x.Id).ToArrayAsync();
                var row = await db.SignaturePreviews.AsNoTracking().SingleAsync(x => x.Id == preview.Write.PreviewId); var pages = JsonSerializer.Deserialize<PageGeometry[]>(envelope.PageSizesJson!)!;
                var snapshot = JsonSerializer.Serialize(new { version = "signer-review-v1", identity.EnvelopeId, identity.SignerId, identity.DocumentId, identity.DocumentHash, identity.DisclosureHash,
                    envelope.RowVersion, envelope.PageCount, envelope.PageSizesJson, signer.FullName, signer.ConsentAt, signerVersion = signer.RowVersion, adoptionId = row.Id,
                    row.SignatureSha256, row.InitialsSha256, row.NormalizationVersion, fields });
                var request = new SignerPdfRequest(identity.EnvelopeId, identity.SignerId, signer.FullName, run.Record.Time.Now, row.Id,
                    fields.Select(f => new SignerPdfField(f.Id, f.EnvelopeId, f.SignerId, f.RowVersion, f.Type, f.Page, f.X, f.Y, f.Width, f.Height, f.Required, f.Value, f.FilledAt, f.FilledBy, f.SignatureAdoptionId, f.ImageSha256)).ToArray(),
                    new(row.Id, row.SignatureObjectId, row.InitialsObjectId, preview.Signature.Bytes, preview.Initials.Bytes, row.SignatureSha256, row.InitialsSha256, row.NormalizationVersion));
                var rendered = new SignerPdfRenderer(64 * 1024 * 1024, 200, 200).Render(blobs.Objects[new(identity.EnvelopeId, DocumentBlobKind.Normalized, identity.DocumentId)], Convert.FromHexString(identity.DocumentHash), pages, request);
                var context = (await ProductionSignerMutationAdmissionTests.Access(run.Delivered, db).GetContextAsync(principal, identity.PublicId))!;
                var candidate = new SignerReviewCandidate { EnvelopeId = identity.EnvelopeId, SignerId = identity.SignerId, AdoptionId = row.Id, SourceObjectId = identity.DocumentId, PdfObjectId = Guid.NewGuid(), PdfLength = rendered.Bytes.LongLength,
                    SourceSha256 = rendered.SourceSha256, DisclosureSha256 = Convert.FromHexString(identity.DisclosureHash), SessionSha256 = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity)),
                    SnapshotSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(snapshot)), PdfSha256 = rendered.Sha256, RecipeSha256 = rendered.BindingSha256, RendererVersion = rendered.RendererVersion, SnapshotVersion = "signer-review-v1",
                    PreparedAt = run.Record.Time.Now, ExpiresAt = ProductionRecordReviewWriteContract.Earlier(run.Record.Time.Now.AddMinutes(10), context.AccessExpiresAt), ProspectiveDate = DateOnly.FromDateTime(run.Record.Time.Now.UtcDateTime) };
                var cut = await db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == identity.EnvelopeId).OrderByDescending(x => x.Sequence).FirstAsync();
                run.Write = ProductionSignerReviewWrite.Own(run.Record.Keys, Guid.NewGuid(), Guid.NewGuid(), candidate, identity, context.AccessExpiresAt, snapshot, request, pages, rendered, cut.Id, checked((int)cut.Sequence), cut.Hash);
            }
            return run;
        }
        internal async Task<ProductionRecordOperation> Prepare(QuillSignDbContext db)
        { var scope = await Gate.BeginLockedAsync(db, Write.Identity.EnvelopeId, Write.OperationId, ProductionRecordReviewWriteContract.Kind, Write.CandidateId.ToString("N")); await Gate.PrepareReviewWritesLockedAsync(db, scope, Write); return scope; }
        internal async Task RecordItem(QuillSignDbContext db, ProductionRecordOperation scope, ProductionRecordWriteDescriptor item)
        { Assert.True(await Gate.BeginReviewWriteLockedAsync(db, scope, item)); await Gate.DemandReviewWriteLockedAsync(db, scope, item); Writes++; await Gate.RecordReviewWriteLockedAsync(db, scope, new(item, "version-" + item.Blob.Kind, "\"etag-" + item.Blob.Kind + "\"")); }
        internal async Task Save(QuillSignDbContext db, HoldWitnessReviewPlan plan)
        { var row = ProductionRecordReviewWriteContract.ReadRow(Write.CandidateRowJson); db.Add(row); await db.SaveChangesAsync(); await new AuditWriter(db, Record.Time).AppendAsync(row.EnvelopeId, "signer_review_prepared", Write.Identity.Email, plan.Ip, plan.UserAgent, default, ProductionRecordReviewWriteContract.AuditData(row), PartyType.Signer, row.SignerId); }
        public ValueTask DisposeAsync() => preview.DisposeAsync();
    }
}
