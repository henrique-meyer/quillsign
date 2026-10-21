using System.Security.Claims;
using System.Security.Cryptography;
using System.Data.Common;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionHoldSqlInventoryTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private readonly IDataProtectionProvider keys = new EphemeralDataProtectionProvider();
    private readonly Clock clock = new();
    private static ProductionOperatorPolicy Operators => new(true, [new("https://operator.synthetic.invalid", "synthetic-operator",
        new HashSet<ProductionOperatorPermission> { ProductionOperatorPermission.PlaceHold })]);

    [Fact]
    public async Task Snapshot_preserves_owned_scalar_history_and_linked_lookup_retention_without_global_or_other_record_data()
    {
        var (id, request) = await Held(); var (other, _) = await Held();
        await using (var db = fixture.Open())
        {
            var signer = new Signer { EnvelopeId = id, Order = 1, FullName = "Synthetic held signer", Email = "held@example.invalid" };
            var owned = new EmailOutbox { EnvelopeId = id, To = "held@example.invalid", Template = "synthetic", PayloadJson = "{\"owned\":\"Owned private payload\"}" };
            var global = new EmailOutbox { To = "global@example.invalid", Template = "synthetic", PayloadJson = "{\"unrelated\":\"UnrelatedGlobalMarker\"}" };
            db.AddRange(signer, owned, global, new Signer { EnvelopeId = other, Order = 1, FullName = "UnrelatedRecordMarker", Email = "other@example.invalid" },
                new Recipient { EnvelopeId = id, Email = "cc@example.invalid" },
                new DocumentField { EnvelopeId = id, Type = FieldType.Text, Page = 1, X = .1m, Y = .1m, Width = .2m, Height = .1m, Value = "Owned field" },
                new WorkItem { EnvelopeId = id, Kind = WorkKind.Rendering, PayloadJson = "{}" },
                new AuthToken { EnvelopeId = id, TokenSha256 = SHA256.HashData(Guid.NewGuid().ToByteArray()), Email = "held@example.invalid", ExpiresAt = clock.Now.AddMinutes(10) },
                new Suppression { Email = "held@example.invalid", Reason = SuppressionReason.Unsubscribe });
            await db.SaveChangesAsync();
            var revision = new SignerContactRevisionRecord { Id = Guid.NewGuid(), EnvelopeId = id, SignerId = signer.Id, Number = 1,
                ChangedAt = clock.Now, EvidenceJson = "{\"synthetic\":\"Owned contact history\"}", RetirementJson = "{}" };
            db.Add(revision);
            foreach (var outbox in new[] { owned, global }) db.Add(new LookupContactRetentionSnapshot { RequestId = outbox.Id, PolicyVersion = "synthetic-v1",
                Days = 7, StartedAt = clock.Now, DeleteAfter = clock.Now.AddDays(7) });
            await db.SaveChangesAsync();
            db.Add(new SignerContactSession { SessionId = Guid.NewGuid(), EnvelopeId = id, SignerId = signer.Id, RevisionId = revision.Id,
                SessionSha256 = SHA256.HashData(Guid.NewGuid().ToByteArray()), CreatedAt = clock.Now, ExpiresAt = clock.Now.AddHours(1) });
            await db.SaveChangesAsync();
        }
        var snapshot = await Capture(id, request);
        var plain = keys.CreateProtector(ProductionHoldSqlInventory.Version, id.ToString("N")).Unprotect(snapshot.ProtectedPayload);
        Assert.Equal(snapshot.PayloadSha256, Convert.ToHexStringLower(SHA256.HashData(plain)));
        Assert.Equal(snapshot.PlaintextBytes, plain.LongLength);
        var json = System.Text.Encoding.UTF8.GetString(plain); Assert.Contains("Owned private payload", json); Assert.Contains("Owned contact history", json);
        Assert.DoesNotContain("UnrelatedGlobalMarker", json); Assert.DoesNotContain("UnrelatedRecordMarker", json);
        using var document = JsonDocument.Parse(plain);
        Assert.Equal(id, document.RootElement.GetProperty("RecordId").GetGuid());
        var counts = snapshot.Tables.ToDictionary(x => x.Table, x => x.Rows);
        Assert.Equal(22, counts.Count); Assert.Equal(1, counts["Envelopes"]); Assert.Equal(1, counts["Signers"]);
        Assert.Equal(1, counts["LookupContactRetentionSnapshots"]); Assert.Equal(1, counts["EmailOutbox"]);
        Assert.Equal(1, counts["SignerContactSessions"]); Assert.Equal(1, counts["SignerContactRevisions"]);
        Assert.Contains("SignerFinishAcceptances", counts.Keys); Assert.Contains("CompletionPublicationResults", counts.Keys);
        Assert.Contains("CompletionSealOutputs", counts.Keys); Assert.Contains("SignaturePreviews", counts.Keys);
        Assert.DoesNotContain("Suppressions", counts.Keys); Assert.DoesNotContain("EmailPilotSecrets", counts.Keys);
        Assert.Throws<CryptographicException>(() => keys.CreateProtector(ProductionHoldSqlInventory.Version, other.ToString("N")).Unprotect(snapshot.ProtectedPayload));
    }

    [Fact]
    public async Task Content_fingerprint_is_stable_across_capture_time_but_changes_with_scalar_evidence_without_renewing_a_policy()
    {
        var (id, request) = await Held(); var first = await Capture(id, request); clock.Now = clock.Now.AddSeconds(1);
        var next = await Capture(id, request); Assert.Equal(first.StateSha256, next.StateSha256);
        Assert.NotEqual(first.PayloadSha256, next.PayloadSha256); Assert.NotEqual(first.CapturedAt, next.CapturedAt);
        await using var db = fixture.Open(); var originalPolicy = (await db.ProductionRetentionPolicies.SingleAsync(x => x.EnvelopeId == id)).PolicySha256;
        await db.Envelopes.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "New private source evidence"));
        var changed = await Capture(id, request); Assert.NotEqual(first.StateSha256, changed.StateSha256);
        Assert.Equal(originalPolicy, (await db.ProductionRetentionPolicies.AsNoTracking().SingleAsync(x => x.EnvelopeId == id)).PolicySha256);
        Assert.Equal(1, await db.ProductionHoldRequests.CountAsync(x => x.EnvelopeId == id));
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == id).ToArrayAsync());
    }

    [Theory]
    [InlineData("rows")][InlineData("database-bytes")][InlineData("serialized-bytes")]
    public async Task Over_limit_evidence_fails_without_creating_a_receipt_or_modifying_source_rows(string limit)
    {
        var (id, request) = await Held(); var bounds = limit switch
        {
            "rows" => new ProductionHoldSqlLimits(MaximumRows: 1),
            "database-bytes" => new ProductionHoldSqlLimits(MaximumDatabaseBytes: 1),
            _ => new ProductionHoldSqlLimits(MaximumJsonBytes: 4096)
        };
        await Assert.ThrowsAsync<InvalidDataException>(() => Capture(id, request, bounds));
        await using var db = fixture.Open(); Assert.Equal(1, await db.ProductionHoldRequests.CountAsync(x => x.EnvelopeId == id));
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == id).ToArrayAsync());
    }

    [Fact]
    public async Task Wrong_revision_or_fence_cannot_capture_a_snapshot_and_pending_hold_is_not_sufficient_for_another_record()
    {
        var (id, request) = await Held(); var (other, _) = await Held();
        await Assert.ThrowsAsync<DocumentConflictException>(() => Capture(id, request with { Current = request.Current with { Revision = 2 } }));
        await Assert.ThrowsAsync<DocumentConflictException>(() => Capture(id, request with { Current = request.Current with { FenceHash = new string('0', 64) } }));
        await Assert.ThrowsAsync<DocumentConflictException>(() => Capture(other, request));
    }

    [Fact]
    public async Task An_unexpected_pilot_association_is_not_archived_as_a_normal_production_record()
    {
        var (id, request) = await Held();
        await using (var db = fixture.Open())
        {
            var run = new EmailPilotRunRecord { Id = Guid.NewGuid(), CreatedAt = clock.Now, ExpiresAt = clock.Now.AddHours(1),
                ManifestSha256 = new byte[32], CapabilitySha256 = new byte[32] }; db.Add(run); await db.SaveChangesAsync();
            db.Add(new EmailPilotEnrollmentRecord { SubjectEnvelopeId = id, RunId = run.Id, Scenario = EmailPilotScenario.Completion,
                EnrolledAt = clock.Now, ProtectedBinding = "synthetic-unexpected-pilot-binding" }); await db.SaveChangesAsync();
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => Capture(id, request));
    }

    [Fact]
    public async Task Range_locks_keep_a_snapshot_consistent_even_when_another_writer_ignores_the_parent_lock()
    {
        var (id, request) = await Held();
        await using var source = fixture.Open();
        source.Add(new DocumentField { EnvelopeId = id, Type = FieldType.Text, Page = 1, X = .1m, Y = .1m, Width = .2m, Height = .1m, Value = "Before concurrent write" });
        await source.SaveChangesAsync();
        var barrier = new CaptureBarrier(); var started = new WriteStarted();
        await using var captureDb = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(barrier).Options);
        await using var writerDb = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(started).Options);
        await using var transaction = await captureDb.Database.BeginTransactionAsync();
        var capture = new ProductionHoldSqlInventory(captureDb, keys, clock).CaptureLockedAsync(id, request.Current.Revision, request.Current.FenceHash!);
        try
        {
            await barrier.Entered.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var write = writerDb.Fields.Where(x => x.EnvelopeId == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Value, "After concurrent write"));
            await started.Entered.Task.WaitAsync(TimeSpan.FromSeconds(15));
            await Assert.ThrowsAsync<TimeoutException>(() => write.WaitAsync(TimeSpan.FromMilliseconds(500)));
            barrier.Continue.TrySetResult(); var frozen = await capture;
            var plain = keys.CreateProtector(ProductionHoldSqlInventory.Version, id.ToString("N")).Unprotect(frozen.ProtectedPayload);
            Assert.Contains("Before concurrent write", System.Text.Encoding.UTF8.GetString(plain));
            Assert.DoesNotContain("After concurrent write", System.Text.Encoding.UTF8.GetString(plain));
            await transaction.RollbackAsync(); await write.WaitAsync(TimeSpan.FromSeconds(15));
            Assert.NotEqual(frozen.StateSha256, (await Capture(id, request)).StateSha256);
        }
        finally { barrier.Continue.TrySetResult(); }
    }

    private async Task<(Guid, ProductionHoldRequestReceipt)> Held()
    {
        var envelope = new Envelope { SenderEmail = "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid", CreatedAt = clock.Now };
        await using var db = fixture.Open();
        await using (var creation = await db.Database.BeginTransactionAsync())
        {
            db.Add(envelope); await new ProductionRetentionLedger(db, new(db, clock), clock).PrepareNewLockedAsync(envelope, ProductionRetentionLedgerTests.Policy());
            await creation.CommitAsync();
        }
        var command = new ProductionHoldCommand(Guid.NewGuid(), envelope.Id, Guid.NewGuid(), 0, ProductionHoldOperation.Place, "Synthetic purpose", "Synthetic reason", "synthetic-reference");
        var ticket = new AuthenticationTicket(new ClaimsPrincipal(new ClaimsIdentity([new("iss", "https://operator.synthetic.invalid", ClaimValueTypes.String, "https://operator.synthetic.invalid"),
            new("sub", "synthetic-operator", ClaimValueTypes.String, "https://operator.synthetic.invalid")], ProductionOperatorAuthority.OidcScheme)),
            new AuthenticationProperties { IssuedUtc = clock.Now, ExpiresUtc = clock.Now.AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme);
        var authority = ProductionOperatorAuthority.FromValidatedTicket(ticket, Operators, command.Permission, clock);
        await using var tx = await db.Database.BeginTransactionAsync();
        var request = await new ProductionHoldRequests(db, keys, clock).PrepareLockedAsync(authority, Operators, command); await tx.CommitAsync();
        return (envelope.Id, request);
    }
    private async Task<ProductionHoldSqlSnapshot> Capture(Guid id, ProductionHoldRequestReceipt request, ProductionHoldSqlLimits? limits = null)
    {
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var snapshot = await new ProductionHoldSqlInventory(db, keys, clock).CaptureLockedAsync(id, request.Current.Revision, request.Current.FenceHash!, limits);
        Assert.False(db.ChangeTracker.HasChanges()); await tx.RollbackAsync(); return snapshot;
    }
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class CaptureBarrier : DbCommandInterceptor
    {
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Continue = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private bool paused;
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (!paused && command.CommandText.Contains("SELECT * FROM [dbo].[Fields]", StringComparison.Ordinal))
            {
                paused = true; Entered.TrySetResult(); await Continue.Task.WaitAsync(TimeSpan.FromSeconds(20), cancellationToken);
            }
            return result;
        }
    }
    private sealed class WriteStarted : DbCommandInterceptor
    {
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        { Entered.TrySetResult(); return ValueTask.FromResult(result); }
    }
}
