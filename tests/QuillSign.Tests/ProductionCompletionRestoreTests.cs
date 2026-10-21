using System.Collections.Immutable;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionCompletionRestoreTests
{
    [Theory]
    [InlineData(0)][InlineData(1)][InlineData(2)][InlineData(3)][InlineData(4)][InlineData(5)][InlineData(6)]
    public async Task An_older_actual_whole_database_cannot_ack_any_newer_known_completion_expected_SQL(int targetNumber)
    {
        var target = (CompletionSlot)targetNumber;
        // A separate disposable database is essential: restoring a shared fixture
        // would disturb other tests. No provider or real completion is claimed.
        var fixture = new SqlDatabaseFixture(); await fixture.InitializeAsync(); string? backup = null;
        try
        {
            var run = await ProductionRecordOperationAdmissionTests.Run.Create(fixture);
            await using (var edit = fixture.Open()) await edit.WorkItems.Where(x => x.Id == run.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Kind, WorkKind.Sealing));
            var gate = run.Gate(); await gate.InitializeAsync(run.Id); var id = Guid.NewGuid();
            var scope = await gate.BeginAsync(run.Id, id, "work/3", run.Work.ToString("N") + "/attempt/1");
            await using (var claim = fixture.Open())
            {
                await using var tx = await claim.Database.BeginTransactionAsync(); var row = await claim.WorkItems.AsNoTracking().SingleAsync(x => x.Id == run.Work);
                row.Attempts = 1; row.Status = WorkStatus.Leased; row.LeaseOwner = id; row.LeaseExpiresAt = run.Clock.Now.AddMinutes(5);
                var permit = await gate.BeginCompletionClaimLockedAsync(claim, scope, row);
                await claim.WorkItems.Where(x => x.Id == run.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, row.Status).SetProperty(w => w.Attempts, row.Attempts)
                    .SetProperty(w => w.LeaseOwner, row.LeaseOwner).SetProperty(w => w.LeaseExpiresAt, row.LeaseExpiresAt));
                await gate.PrepareCompletionClaimExpectedLockedAsync(claim, permit); await tx.CommitAsync();
            }
            await gate.AcknowledgeCompletionClaimAsync(scope);
            string connection; await using (var db = fixture.Open()) connection = db.Database.GetConnectionString()!;
            var builder = new SqlConnectionStringBuilder(connection); var name = builder.InitialCatalog;
            Assert.Matches("^QuillSignTests_[a-f0-9]{32}$", name); builder.InitialCatalog = "master"; builder.Pooling = false;
            await using var master = new SqlConnection(builder.ConnectionString); await master.OpenAsync();
            await using var command = master.CreateCommand(); command.CommandTimeout = 120;
            command.CommandText = "SELECT CONVERT(nvarchar(4000),SERVERPROPERTY('InstanceDefaultBackupPath'))";
            var directory = Assert.IsType<string>(await command.ExecuteScalarAsync());
            backup = directory.TrimEnd('\\', '/') + (directory.Contains('\\') ? "\\" : "/") + name + "-completion.bak";
            command.CommandText = $"BACKUP DATABASE [{name}] TO DISK=@backup WITH COPY_ONLY, INIT";
            command.Parameters.AddWithValue("@backup", backup); await command.ExecuteNonQueryAsync();
            for (var number = 0; number <= (int)target; number++)
            {
                var slot = (CompletionSlot)number; var state = await run.Journal().ReadAsync(run.Id); var c = state.Completions![id];
                var previous = slot == CompletionSlot.Candidate ? c.ClaimAcknowledged! : c.Slots![slot - 1].Acknowledged!;
                var original = await Capture(); using var originalSql = ProductionHoldSqlInventory.OpenAcknowledgementVerified(original, run.Keys);
                var context = new HoldWitnessCompletionContext(slot, id, previous.Sequence, previous.SqlStateSha256, previous.ContentSha256, run.Work, 1,
                    c.Claim.Until, c.Claim.PayloadSha256, ProductionCompletionProtocol.Effects(slot).Select(x => new CompletionEffectTarget(x, ProductionCompletionProtocol.Tsa(x) ? Guid.Empty : Guid.NewGuid())).ToImmutableArray(),
                    [], ProductionRecordOperationAdmission.CompletionRemainder(originalSql.RootElement, []), run.Clock.Now);
                await Change(new(CompletionTransitionKind.SlotOpened, slot, Context: context));
                foreach (var item in context.Targets)
                {
                    var descriptor = new CompletionEffectDescriptor(item.Effect, item.TargetId, 20, Hash(item.Effect.ToString()), 1, [Hash("request-" + item.Effect)]);
                    await Change(new(CompletionTransitionKind.EffectStarted, slot, Effect: descriptor));
                    var stored = ProductionCompletionProtocol.Tsa(item.Effect) || ProductionCompletionProtocol.FinalEffect(item.Effect) ? null :
                        new ProductionRecordWriteReceipt(new(new(run.Id, DocumentBlobKind.Normalized, item.TargetId), descriptor.Length, descriptor.Sha256), "synthetic-v", "\"synthetic-e\"");
                    var final = ProductionCompletionProtocol.FinalEffect(item.Effect) ? new FinalStoredDocument(new(run.Id, item.Effect == CompletionEffect.PublicationExecutedFinal ? FinalDocumentKind.Executed : FinalDocumentKind.Certificate, item.TargetId),
                        descriptor.Length, Convert.FromHexString(descriptor.Sha256), "synthetic-final-v", "\"synthetic-final-e\"", FinalProtection.LockedTime, run.Clock.Now.AddDays(1), run.Clock.Now) : null;
                    await Change(new(CompletionTransitionKind.EffectRecorded, slot, Receipt: new(descriptor, Hash("receipt-" + item.Effect), stored, final)));
                }
                // Install a trusted known Expected event via the private journal
                // to isolate ACK/rollback fencing from the separate typed input
                // and provider protocols. This is not an admissible row-plan
                // factory or an assertion that arbitrary Message edits are owned.
                if (slot == target) await run.Edit("Synthetic known SQL newer than the backup");
                var expected = await Capture(); var content = ProductionRecordOperationAdmission.ContentDigest(expected, run.Keys);
                var current = (await run.Journal().ReadAsync(run.Id)).Completions![id].Slots![slot];
                var header = new HoldWitnessCompletionRows(ProductionCompletionProtocol.Digest(context), current.Receipts.Values.FirstOrDefault(x => x.Stored is not null)?.Stored?.Item, Hash("rows"));
                await Change(new(CompletionTransitionKind.RowsPlanned, slot, Rows: header, RemainderSha256: context.RemainderSha256));
                await Change(new(CompletionTransitionKind.SlotExpected, slot, Rows: header, ContentSha256: content, SqlStateSha256: expected.StateSha256, PhysicalTransaction: Guid.NewGuid()));
                if (slot == target) break;
                await Change(new(CompletionTransitionKind.SlotAcknowledged, slot, ContentSha256: content, SqlStateSha256: expected.StateSha256, PhysicalTransaction: Guid.NewGuid()));
                if (slot == CompletionSlot.HandlerReceipt)
                    await run.Journal().PrepareHandlerOutcomeAsync(run.Id, state.Operations![id], content, expected.StateSha256, Guid.NewGuid());
            }
            command.CommandText = $"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; RESTORE DATABASE [{name}] FROM DISK=@backup WITH REPLACE; ALTER DATABASE [{name}] SET MULTI_USER";
            await command.ExecuteNonQueryAsync(); using (var pooled = new SqlConnection(connection)) SqlConnection.ClearPool(pooled);
            var before = run.Store.Rows.Count;
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().AcknowledgeCompletionSlotAsync(scope, target));
            await using (var check = fixture.Open())
            {
                await using var tx = await check.Database.BeginTransactionAsync();
                var replay = await run.Gate().ResumeCompletionLockedAsync(check, run.Id, id, scope.Kind, scope.Reference);
                Assert.Equal(scope, replay); // factual identity, never a provider permit
                await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().ReadCompletionRecoveryLockedAsync(check, scope));
                await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().DemandCompletionProgressLockedAsync(check, scope));
            }
            Assert.Equal(before, run.Store.Rows.Count); Assert.Equal(id, (await run.Journal().ReadAsync(run.Id)).OutstandingOperation);
            Assert.Empty((await run.Journal().ReadAsync(run.Id)).SettledOperations);

            async Task<ProductionHoldSqlSnapshot> Capture()
            {
                await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
                var requests = await new ProductionHoldRequests(db, run.Keys, run.Clock).ReadLockedAsync(run.Id);
                return await new ProductionHoldSqlInventory(db, run.Keys, run.Clock).CaptureAcknowledgementLockedAsync(run.Id, requests.Revision, requests.FenceHash);
            }
            async Task<bool> Change(HoldWitnessCompletionTransition value) => await run.Journal().ChangeCompletionAsync(run.Id, (await run.Journal().ReadAsync(run.Id)).Operations![id], value, Guid.NewGuid());
        }
        finally { await fixture.DisposeAsync(); if (backup is not null && File.Exists(backup)) File.Delete(backup); }
    }
    private static string Hash(string value) => ProductionCompletionProtocol.Digest(value);
}
