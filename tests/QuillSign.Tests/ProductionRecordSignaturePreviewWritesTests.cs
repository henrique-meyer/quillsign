using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRecordSignaturePreviewWritesTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(SignatureMethod.Typed)][InlineData(SignatureMethod.Drawn)][InlineData(SignatureMethod.Uploaded)]
    public async Task Genuine_consent_two_exact_marks_and_only_the_planned_preview_row_commit_without_renewing_original_clocks(SignatureMethod method)
    {
        await using var run = await Ready.Create(fixture, method); var expires = run.Row.ExpiresAt; var tokenExpires = run.Delivered.TokenRecord.ExpiresAt;
        await using var db = fixture.Open(); ProductionRecordOperation scope;
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Prepare(db); var before = (await run.Journal.ReadAsync(scope.RecordId)).PreviewWrites![scope.OperationId].Plan;
            // The copied row and normalized buffers cannot follow mutable caller arrays.
            run.Row.SignatureSha256[0] ^= 1; run.Row.BaselineSignerVersion[0] ^= 1;
            foreach (var item in run.Items) await run.Record(db, scope, item);
            db.SignaturePreviews.Add(ProductionRecordPreviewWriteContract.ReadRow(run.Write.PreviewRowJson)); await db.SaveChangesAsync();
            await run.Gate.PrepareOutcomeLockedAsync(db, scope); await tx.CommitAsync();
            Assert.Equal(before, (await run.Journal.ReadAsync(scope.RecordId)).PreviewWrites![scope.OperationId].Plan);
        }
        await run.Gate.CompleteAsync(scope, Hash);
        var saved = await db.SignaturePreviews.AsNoTracking().SingleAsync(x => x.Id == run.Write.PreviewId);
        Assert.Equal(run.Write.PreviewRowJson, ProductionRecordPreviewWriteContract.Row(saved)); Assert.Equal(expires, saved.ExpiresAt);
        Assert.Equal(tokenExpires, (await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == run.Delivered.TokenRecord.Id)).ExpiresAt);
        Assert.Null((await run.Journal.ReadAsync(scope.RecordId)).OutstandingOperation); Assert.Equal(2, run.Writes);
    }

    [Fact]
    public async Task Actual_SDK_pair_readback_demands_the_same_native_parent_transaction_at_every_boundary_before_exact_SQL_outcome()
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); ProductionRecordOperation scope;
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Prepare(db);
            foreach (var item in run.Items)
            {
                using var source = run.Write.Open(item.Blob.Kind); using var buffer = new MemoryStream(); await source.CopyToAsync(buffer); source.Position = 0;
                using var provider = new ProductionSignaturePreviewTransportTests.Provider(suppliedItem: item, suppliedScope: scope,
                    suppliedIdentity: run.Write.Identity, suppliedClock: run.Delivered.Record.Time, suppliedBytes: buffer.ToArray());
                var mayWrite = await run.Gate.BeginPreviewWriteLockedAsync(db, scope, item); var demands = 0;
                var receipt = await provider.Store.WriteAsync(scope, run.Write.Identity, item, source, mayWrite, null, async token => {
                    Assert.Same(tx, db.Database.CurrentTransaction); demands++; await run.Gate.DemandPreviewWriteLockedAsync(db, scope, item, token);
                });
                await run.Gate.RecordPreviewWriteLockedAsync(db, scope, receipt);
                Assert.Equal(1, provider.Commits); Assert.True(demands >= provider.Requests.Count * 2);
                Assert.DoesNotContain(provider.Requests, x => x.Method == HttpMethod.Delete);
            }
            db.Add(ProductionRecordPreviewWriteContract.ReadRow(run.Write.PreviewRowJson)); await db.SaveChangesAsync();
            await run.Gate.PrepareOutcomeLockedAsync(db, scope); await tx.CommitAsync();
        }
        await run.Gate.CompleteAsync(scope, Hash); Assert.Null((await run.Journal.ReadAsync(scope.RecordId)).OutstandingOperation);
    }

    [Theory]
    [InlineData(0)][InlineData(1)]
    public async Task Lost_start_ack_and_SQL_rollback_never_authorize_another_write_or_a_new_preview(int member)
    {
        await using var run = await Ready.Create(fixture); ProductionRecordOperation scope;
        await using (var db = fixture.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Prepare(db); if (member == 1) await run.Record(db, scope, run.Write.Signature);
            run.Delivered.Record.External.LostAck = true;
            await Assert.ThrowsAsync<IOException>(() => run.Gate.BeginPreviewWriteLockedAsync(db, scope, run.Items[member]));
            await tx.RollbackAsync();
        }
        await using var retry = fixture.Open(); await using var second = await retry.Database.BeginTransactionAsync();
        Assert.False(await run.Gate.BeginPreviewWriteLockedAsync(retry, scope, run.Items[member]));
        Assert.Null(await run.Gate.ReadPreviewWriteReceiptLockedAsync(retry, scope, run.Items[member]));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(retry, scope));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginLockedAsync(retry, scope.RecordId, Guid.NewGuid(), "signer/preview", Guid.NewGuid().ToString("N")));
        Assert.Equal(member, run.Writes); Assert.False(await retry.SignaturePreviews.AnyAsync(x => x.EnvelopeId == scope.RecordId));
    }

    [Fact]
    public async Task Lost_receipt_ack_recovers_only_the_same_exact_version_with_no_second_write()
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var scope = await run.Prepare(db); var item = run.Write.Signature;
        Assert.True(await run.Gate.BeginPreviewWriteLockedAsync(db, scope, item)); var receipt = new ProductionRecordWriteReceipt(item, "exact-version", "\"exact-tag\"");
        run.Delivered.Record.External.LostAck = true;
        await Assert.ThrowsAsync<IOException>(() => run.Gate.RecordPreviewWriteLockedAsync(db, scope, receipt));
        Assert.False(await run.Gate.BeginPreviewWriteLockedAsync(db, scope, item));
        Assert.Equal(receipt, await run.Gate.ReadPreviewWriteReceiptLockedAsync(db, scope, item));
        await run.Gate.RecordPreviewWriteLockedAsync(db, scope, receipt);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.RecordPreviewWriteLockedAsync(db, scope, receipt with { VersionId = "different" }));
        Assert.Equal(0, run.Writes);
    }

    [Theory]
    [InlineData("expiry")][InlineData("method")][InlineData("used")][InlineData("baseline")][InlineData("signer")][InlineData("extra-preview")][InlineData("other-sql")]
    public async Task Complete_pair_receipts_cannot_acknowledge_changed_preview_or_any_unplanned_business_SQL(string change)
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var scope = await run.Prepare(db); foreach (var item in run.Items) await run.Record(db, scope, item);
        var row = ProductionRecordPreviewWriteContract.ReadRow(run.Write.PreviewRowJson);
        switch (change)
        {
            case "expiry": row.ExpiresAt = row.ExpiresAt.AddTicks(-1); break;
            case "method": row.Method = SignatureMethod.Uploaded; break;
            case "used": row.UsedAt = run.Delivered.Record.Time.Now; break;
            case "baseline": row.BaselineSignerVersion[0] ^= 1; break;
            case "signer": row.TypedName = "Substituted name"; break;
            case "extra-preview": var extra = ProductionRecordPreviewWriteContract.ReadRow(run.Write.PreviewRowJson); extra.Id = Guid.NewGuid(); db.Add(extra); break;
            case "other-sql": await db.Envelopes.Where(x => x.Id == scope.RecordId).ExecuteUpdateAsync(x => x.SetProperty(e => e.Message, "Unplanned business mutation")); break;
        }
        db.Add(row); await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, scope));
        Assert.False((await run.Journal.ReadAsync(scope.RecordId)).Outcomes!.ContainsKey(scope.OperationId));
    }

    [Fact]
    public async Task A_hold_during_the_pair_can_only_drain_the_original_plan_and_does_not_admit_a_new_operation()
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); ProductionRecordOperation scope;
        var hold = Place(run.Write.Identity.EnvelopeId);
        await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Prepare(db); await run.Record(db, scope, run.Write.Signature);
            await run.Journal.IntentAsync(Authority(run.Delivered.Record.Time, hold.Permission), Operators, hold, Guid.NewGuid());
            await run.Record(db, scope, run.Write.Initials); db.Add(ProductionRecordPreviewWriteContract.ReadRow(run.Write.PreviewRowJson));
            await db.SaveChangesAsync(); await run.Gate.PrepareOutcomeLockedAsync(db, scope); await tx.CommitAsync();
        }
        await run.Gate.CompleteAsync(scope, Hash); var state = await run.Journal.ReadAsync(scope.RecordId);
        Assert.Equal(hold, state.Unacknowledged); Assert.Null(state.OutstandingOperation);
        await using var next = await db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.BeginLockedAsync(db, scope.RecordId, Guid.NewGuid(), "signer/preview", Guid.NewGuid().ToString("N")));
    }

    [Theory]
    [InlineData("preview")][InlineData("session")]
    public async Task Original_expiry_after_first_member_keeps_attempted_bytes_reserved_without_a_second_member(string clock)
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var scope = await run.Prepare(db); await run.Record(db, scope, run.Write.Signature);
        run.Delivered.Record.Time.Now = clock == "preview" ? run.Row.ExpiresAt : run.Write.Identity.SessionExpiresAt;
        await Assert.ThrowsAsync<QuillSign.Documents.DocumentRetentionExpiredException>(() => run.Gate.BeginPreviewWriteLockedAsync(db, scope, run.Write.Initials));
        Assert.Equal(1, run.Writes); Assert.Equal(scope.OperationId, (await run.Journal.ReadAsync(scope.RecordId)).OutstandingOperation);
        Assert.False(await db.SignaturePreviews.AnyAsync(x => x.EnvelopeId == scope.RecordId));
    }

    [Fact]
    public async Task New_plan_cannot_replace_the_original_objects_and_original_event_serialization_omits_all_new_null_members()
    {
        await using var run = await Ready.Create(fixture); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var scope = await run.Prepare(db); var row = ProductionRecordPreviewWriteContract.ReadRow(run.Write.PreviewRowJson); row.SignatureObjectId = Guid.NewGuid();
        var replacement = ProductionSignaturePreviewWrite.Own(row, run.Write.Identity, run.Write.AccessExpiresAt, run.Signature, run.Initials);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PreparePreviewWritesLockedAsync(db, scope, replacement));
        var raw = new HoldWitnessEvent("old", Guid.NewGuid(), 1, Guid.NewGuid(), HoldWitnessKind.Initialized, run.Delivered.Record.Time.Now,
            null, null, null, null, null, 0, null, null, null, null, null, null);
        Assert.DoesNotContain("Preview", JsonSerializer.Serialize(raw)); Assert.DoesNotContain("DispatchStart", JsonSerializer.Serialize(raw));
        Assert.Equal(18, (int)HoldWitnessKind.DispatchStarted);
    }

    [Fact]
    public async Task Owning_input_is_bounded_before_serialization_and_never_invents_a_null_retention_policy()
    {
        await using var run = await Ready.Create(fixture);
        SignaturePreview Row() => ProductionRecordPreviewWriteContract.ReadRow(run.Write.PreviewRowJson);
        foreach (var change in new Action<SignaturePreview>[] { x => x.TypedName = new string('x', 201), x => x.TypedName = "a\u200Bb",
            x => x.TypedName = "a\uD800b", x => x.SignatureSha256 = new byte[1024 * 1024], x => x.NormalizationVersion = "future-version" })
        {
            var row = Row(); change(row);
            Assert.Throws<InvalidDataException>(() => ProductionSignaturePreviewWrite.Own(row, run.Write.Identity, run.Write.AccessExpiresAt, run.Signature, run.Initials));
        }
        var clamped = Row(); var access = clamped.CreatedAt.AddMinutes(5); clamped.ExpiresAt = access;
        _ = ProductionSignaturePreviewWrite.Own(clamped, run.Write.Identity, access, run.Signature, run.Initials);
        Assert.Null((await run.Journal.ReadAsync(run.Row.EnvelopeId)).OutstandingOperation);
    }

    [Fact]
    public async Task A_preview_operation_without_its_pair_plan_cannot_seal_or_implicitly_settle_unchanged_SQL()
    {
        await using var run = await Ready.Create(fixture); ProductionRecordOperation scope;
        await using (var db = fixture.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
        {
            scope = await run.Gate.BeginLockedAsync(db, run.Row.EnvelopeId, Guid.NewGuid(), "signer/preview", run.Row.Id.ToString("N"));
            var operation = (await run.Journal.ReadAsync(scope.RecordId)).Operations![scope.OperationId];
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Journal.PrepareOperationOutcomeAsync(scope.RecordId, operation, scope.ContentSha256, scope.SqlStateSha256, Guid.NewGuid()));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.PrepareOutcomeLockedAsync(db, scope));
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate.CompleteAsync(scope, Hash));
    }

    [Fact]
    public async Task Actual_owned_database_restore_before_the_preview_cannot_adopt_the_newer_external_outcome_or_repeat_mark_writes()
    {
        var isolated = new SqlDatabaseFixture(); await isolated.InitializeAsync(); string? backup = null;
        try
        {
            await using var run = await Ready.Create(isolated); string connection;
            await using (var db = isolated.Open()) connection = db.Database.GetConnectionString()!;
            var builder = new SqlConnectionStringBuilder(connection); var name = builder.InitialCatalog;
            Assert.Matches("^QuillSignTests_[a-f0-9]{32}$", name); builder.InitialCatalog = "master"; builder.Pooling = false;
            await using var master = new SqlConnection(builder.ConnectionString); await master.OpenAsync();
            await using var command = master.CreateCommand(); command.CommandTimeout = 120;
            command.CommandText = "SELECT CONVERT(nvarchar(4000),SERVERPROPERTY('InstanceDefaultBackupPath'))";
            var directory = Assert.IsType<string>(await command.ExecuteScalarAsync()); Assert.False(string.IsNullOrWhiteSpace(directory));
            backup = directory.TrimEnd('\\', '/') + (directory.Contains('\\') ? "\\" : "/") + name + "-preview.bak";
            command.CommandText = $"BACKUP DATABASE [{name}] TO DISK=@backup WITH COPY_ONLY, INIT";
            command.Parameters.AddWithValue("@backup", backup); await command.ExecuteNonQueryAsync();
            ProductionRecordOperation scope;
            await using (var db = isolated.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
            {
                scope = await run.Prepare(db); foreach (var item in run.Items) await run.Record(db, scope, item);
                db.Add(ProductionRecordPreviewWriteContract.ReadRow(run.Write.PreviewRowJson)); await db.SaveChangesAsync();
                await run.Gate.PrepareOutcomeLockedAsync(db, scope); await tx.CommitAsync();
            }
            var before = await run.Journal.ReadAsync(scope.RecordId);
            command.CommandText = $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; RESTORE DATABASE [{name}] FROM DISK=@backup WITH REPLACE; ALTER DATABASE [{name}] SET MULTI_USER";
            await command.ExecuteNonQueryAsync(); using (var pooled = new SqlConnection(connection)) SqlConnection.ClearPool(pooled);
            var fresh = new ProductionRecordOperationAdmission(isolated.Open, run.Delivered.Record.Keys, run.Delivered.Record.Time, run.Journal);
            await Assert.ThrowsAsync<InvalidDataException>(() => fresh.CompleteAsync(scope, Hash));
            await using (var db = isolated.Open()) await using (var tx = await db.Database.BeginTransactionAsync())
            {
                await Assert.ThrowsAsync<InvalidDataException>(() => fresh.BeginPreviewWriteLockedAsync(db, scope, run.Write.Signature));
                Assert.False(await db.SignaturePreviews.AnyAsync(x => x.EnvelopeId == scope.RecordId));
            }
            Assert.Equal(before.HeadHash, (await run.Journal.ReadAsync(scope.RecordId)).HeadHash); Assert.Equal(2, run.Writes);
        }
        finally { await isolated.DisposeAsync(); if (backup is not null && File.Exists(backup)) File.Delete(backup); }
    }

    internal sealed class Ready(ProductionInvitationWorkerAdmissionTests.Delivered delivered) : IAsyncDisposable
    {
        internal readonly ProductionInvitationWorkerAdmissionTests.Delivered Delivered = delivered;
        internal ProductionRecordOperationAdmission Gate => Delivered.Record.Admission;
        internal ProductionHoldWitnessJournal Journal => Delivered.Record.Journal;
        internal SignaturePreview Row = null!; internal ProductionSignaturePreviewWrite Write = null!;
        internal NormalizedSignatureImage Signature = null!, Initials = null!;
        internal ProductionRecordWriteDescriptor[] Items => [Write.Signature, Write.Initials]; internal int Writes;
        internal static async Task<Ready> Create(SqlDatabaseFixture fixture, SignatureMethod method = SignatureMethod.Typed)
        {
            var delivered = await ProductionInvitationWorkerAdmissionTests.Delivered.Create(fixture); var run = new Ready(delivered);
            ProductionSignerMutationAdmission Hook() => new(delivered.Record.Admission);
            SignerAccess Access(QuillSignDbContext db) => new(db, new(db, delivered.Record.Time), new(), delivered.Record.Time) { HoldAdmission = Hook() };
            VerifiedSigner identity;
            await using (var db = fixture.Open()) identity = (await Access(db).RedeemAsync(delivered.Token, null, null))!;
            var user = SignerAccessConfiguration.Principal(identity); SignerReadContext context;
            await using (var db = fixture.Open())
            {
                context = (await Access(db).GetContextAsync(user, identity.PublicId))!;
                _ = await new SignerPdfAccess(delivered.Ready.Prepared.Blobs, new()) { HoldAdmission = Hook() }.PrepareAsync(user, context);
                var consent = new SignerConsent(db, Access(db), new(delivered.Record.Keys, delivered.Record.Time), new(db, delivered.Record.Time),
                    new DeclineNotificationWriter(db, () => delivered.Ready.Signals, new() { Enabled = true }, new(delivered.Record.Keys), delivered.Record.Time), delivered.Record.Time) { HoldAdmission = Hook() };
                Assert.Equal(ConsentResult.Accepted, await consent.AcceptAsync(user, identity.PublicId,
                    new SignerReceiptProtection(delivered.Record.Keys, delivered.Record.Time).Create(context), true, true, "preview", null, null));
            }
            await using (var db = fixture.Open())
            {
                context = (await Access(db).GetContextAsync(user, identity.PublicId))!;
                var signer = await db.Signers.AsNoTracking().SingleAsync(x => x.Id == identity.SignerId);
                run.Signature = SignaturePng.Normalize(SignatureAdoptionTests.Mark()); run.Initials = SignaturePng.Normalize(SignatureAdoptionTests.Mark(60));
                run.Row = new() { EnvelopeId = identity.EnvelopeId, SignerId = identity.SignerId, DocumentId = identity.DocumentId,
                    SignatureObjectId = Guid.NewGuid(), InitialsObjectId = Guid.NewGuid(), SignatureSha256 = run.Signature.Sha256, InitialsSha256 = run.Initials.Sha256,
                    SignatureWidth = run.Signature.Width, SignatureHeight = run.Signature.Height, InitialsWidth = run.Initials.Width, InitialsHeight = run.Initials.Height,
                    DocumentSha256 = Convert.FromHexString(identity.DocumentHash), DisclosureSha256 = Convert.FromHexString(identity.DisclosureHash),
                    SessionSha256 = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity)), BaselineSignerVersion = signer.RowVersion, Method = method,
                    TypedName = method == SignatureMethod.Typed ? "Synthetic signer" : null, TypedInitials = method == SignatureMethod.Typed ? "SS" : null,
                    NormalizationVersion = SignaturePng.Version, AdoptionVersion = SignatureAdoptionStatement.Version, CreatedAt = delivered.Record.Time.Now,
                    ExpiresAt = ProductionRecordPreviewWriteContract.Earlier(delivered.Record.Time.Now.AddMinutes(10), context.AccessExpiresAt) };
                run.Write = ProductionSignaturePreviewWrite.Own(run.Row, identity, context.AccessExpiresAt, run.Signature, run.Initials);
            }
            return run;
        }
        internal async Task<ProductionRecordOperation> Prepare(QuillSignDbContext db)
        {
            var scope = await Gate.BeginLockedAsync(db, Row.EnvelopeId, Guid.NewGuid(), "signer/preview", Row.Id.ToString("N"));
            await Gate.PreparePreviewWritesLockedAsync(db, scope, Write); return scope;
        }
        internal async Task Record(QuillSignDbContext db, ProductionRecordOperation scope, ProductionRecordWriteDescriptor item)
        {
            Assert.True(await Gate.BeginPreviewWriteLockedAsync(db, scope, item)); await Gate.DemandPreviewWriteLockedAsync(db, scope, item);
            using var bytes = Write.Open(item.Blob.Kind); using var buffer = new MemoryStream(); await bytes.CopyToAsync(buffer);
            Assert.Equal(item.Sha256, Convert.ToHexStringLower(SHA256.HashData(buffer.ToArray()))); Writes++;
            await Gate.RecordPreviewWriteLockedAsync(db, scope, new(item, "version-" + item.Blob.Kind, "\"etag-" + item.Blob.Kind + "\""));
        }
        public ValueTask DisposeAsync() => Delivered.DisposeAsync();
    }
}
