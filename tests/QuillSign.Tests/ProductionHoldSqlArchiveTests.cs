using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionHoldSqlArchiveTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private static readonly byte[] Raw = "Synthetic source object - NO AGREEMENT"u8.ToArray();
    [Fact]
    public async Task Durable_controls_preserve_exact_plan_and_verify_each_provider_item_without_a_snapshot_publication_cycle()
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var control = new ProductionHoldControls(run.Db, run.Keys, run.Time);
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        var saved = await control.SavePlanLockedAsync(plan);
        Assert.Equal(plan.Payload, saved.Payload);
        var body = ProductionHoldBundlePlan.OpenVerified(saved, run.Keys, run.Time);
        foreach (var item in body.Items)
        {
            IProductionHoldArchivePayload cap = item.Kind == "sql"
                ? await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, body.Snapshot.Sql)
                : await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, body.Snapshot, item.Source);
            using var handler = new Handler(run, "lost-ack", cap); var writer = new AzureProductionHoldArchiveWriter(Service(handler));
            var eventId = Guid.NewGuid();
            var receipt = await control.PreserveItemLockedAsync(plan.RecordId, plan.PlanId, item.Path, eventId, writer);
            Assert.Equal(item.Sha256, receipt.Stored.Sha256); Assert.Equal(item.Length, receipt.Stored.Length);
            Assert.Equal(receipt, await control.PreserveItemLockedAsync(plan.RecordId, plan.PlanId, item.Path, eventId, writer));
            Assert.Equal(1, handler.Commits);
            await Assert.ThrowsAsync<DocumentConflictException>(() => control.PreserveItemLockedAsync(plan.RecordId, plan.PlanId, item.Path, Guid.NewGuid(), writer));
        }
        var state = await control.ReadLockedAsync(plan.RecordId); Assert.Equal(4, state.Prefix.Sequence); Assert.Equal(3, state.Items.Count);
        var after = await new ProductionHoldSqlInventory(run.Db, run.Keys, run.Time).CaptureLockedAsync(plan.RecordId, inventory.Revision, inventory.FenceHash);
        Assert.Equal(inventory.SqlStateSha256, after.StateSha256); Assert.NotEqual(inventory.SqlPayloadSha256, after.PayloadSha256);
        Assert.Equal(state.Prefix, after.Control); Assert.DoesNotContain(after.Tables, x => x.Table == "ProductionHoldControls");
        await new ProductionHoldControls(run.Db, run.Keys, run.Time).DemandExtendsLockedAsync(plan.RecordId, inventory.Sql.Control!);
        var repeated = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, plan.PlanId, inventory);
        Assert.Equal(saved.Payload, (await control.SavePlanLockedAsync(repeated)).Payload);
        Assert.Equal(4, (await control.ReadLockedAsync(plan.RecordId)).Prefix.Sequence);
        await run.Commit();
        await using var check = fixture.Open(); await using var tx = await check.Database.BeginTransactionAsync();
        var restarted = await new ProductionHoldControls(check, run.Keys, run.Time).ReadLockedAsync(plan.RecordId);
        Assert.Equal(state.Prefix, restarted.Prefix); Assert.Equal(saved.Payload, restarted.Plans[plan.PlanId].Payload); Assert.Equal(3, restarted.Items.Count);
    }

    [Theory]
    [InlineData("tail")][InlineData("prefix")][InlineData("whole")][InlineData("cipher")][InlineData("payload")][InlineData("metadata")]
    public async Task Captured_control_prefix_and_authenticated_rows_reject_rollback_or_recomputed_unkeyed_tampering(string fault)
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var control = new ProductionHoldControls(run.Db, run.Keys, run.Time);
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        await control.SavePlanLockedAsync(plan);
        var secondCapture = await new ProductionHoldObjectInventory(run.Db, run.Keys, run.Time, new InventorySource(new("originals", $"{plan.RecordId:N}/{Guid.NewGuid():N}", Handler.Version, "", "\"source-etag\"", Raw.Length)))
            .CaptureLockedAsync(plan.RecordId, inventory.Revision, inventory.FenceHash);
        var second = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, Guid.NewGuid(), secondCapture);
        await control.SavePlanLockedAsync(second);
        var captured = (await control.ReadLockedAsync(plan.RecordId)).Prefix;
        if (fault is "tail" or "prefix" or "whole")
        {
            var sequence = fault == "prefix" ? 1L : 2L;
            if (fault == "whole") await run.Db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM [ProductionHoldControls] WHERE [EnvelopeId]={plan.RecordId}");
            else await run.Db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM [ProductionHoldControls] WHERE [EnvelopeId]={plan.RecordId} AND [Sequence]={sequence}");
        }
        else
        {
            var row = await run.Db.ProductionHoldControls.AsNoTracking().SingleAsync(x => x.EventId == second.PlanId);
            if (fault == "cipher") row.ProtectedEvidence = row.ProtectedEvidence[..^1] + (row.ProtectedEvidence[^1] == 'A' ? 'B' : 'A');
            else if (fault == "metadata") row.PlanSha256 = new string('0', 64);
            else { row.PlanPayload![0] ^= 1; row.PayloadSha256 = Convert.ToHexStringLower(SHA256.HashData(row.PlanPayload)); }
            row.Hash = (byte[])typeof(ProductionHoldControls).GetMethod("Hash", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)!.Invoke(null, [row])!;
            await run.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE [ProductionHoldControls] SET [ProtectedEvidence]={row.ProtectedEvidence},[PlanPayload]={row.PlanPayload},[PayloadSha256]={row.PayloadSha256},[PlanSha256]={row.PlanSha256},[Hash]={row.Hash} WHERE [EventId]={row.EventId}");
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => control.DemandExtendsLockedAsync(plan.RecordId, captured));
    }

    [Fact]
    public async Task Control_plan_rollback_and_lost_commit_recovery_preserve_original_bytes_and_clock()
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        await new ProductionHoldControls(run.Db, run.Keys, run.Time).SavePlanLockedAsync(plan); await run.Rollback();
        await using var source = fixture.Open();
        Assert.False(await source.ProductionHoldControls.AnyAsync(x => x.EnvelopeId == plan.RecordId));
        var faults = new ControlLostCommit();
        await using (var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(faults).Options))
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            await new ProductionHoldControls(db, run.Keys, run.Time).SavePlanLockedAsync(plan);
            await Assert.ThrowsAsync<IOException>(() => tx.CommitAsync());
        }
        run.Time.Now = run.Time.Now.AddMinutes(11);
        await using var recover = fixture.Open(); await using var recovery = await recover.Database.BeginTransactionAsync();
        var saved = await new ProductionHoldControls(recover, run.Keys, run.Time).SavePlanLockedAsync(plan);
        Assert.Equal(plan.Payload, saved.Payload); Assert.Single(await recover.ProductionHoldControls.Where(x => x.EnvelopeId == plan.RecordId).ToArrayAsync());
        Assert.Equal(run.Time.Now.AddMinutes(-11), (await recover.ProductionHoldControls.SingleAsync(x => x.EventId == plan.PlanId)).At);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Concurrent_same_or_independent_plans_use_one_parent_chain_and_exact_replay(bool independent)
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var first = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        var second = independent ? await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory) : first;
        await run.Rollback();
        async Task<ProductionHoldProtectedPlan> Save(ProductionHoldProtectedPlan plan)
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var result = await new ProductionHoldControls(db, run.Keys, run.Time).SavePlanLockedAsync(plan); await tx.CommitAsync(); return result;
        }
        var result = await Task.WhenAll(Save(first), Save(second));
        await using var check = fixture.Open(); await using var read = await check.Database.BeginTransactionAsync();
        var state = await new ProductionHoldControls(check, run.Keys, run.Time).ReadLockedAsync(first.RecordId);
        Assert.Equal(independent ? 2 : 1, state.Prefix.Sequence);
        if (!independent) Assert.Equal(result[0].Payload, result[1].Payload);
    }

    [Fact]
    public async Task Controls_reject_missing_transactions_and_tracked_evidence_changes()
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        await new ProductionHoldControls(run.Db, run.Keys, run.Time).SavePlanLockedAsync(plan);
        var row = run.Db.ProductionHoldControls.Local.Single(x => x.EventId == plan.PlanId); row.ProtectedEvidence += "changed";
        await Assert.ThrowsAsync<InvalidOperationException>(() => run.Db.SaveChangesAsync()); run.Db.Entry(row).State = EntityState.Unchanged;
        run.Db.Remove(row); await Assert.ThrowsAsync<InvalidOperationException>(() => run.Db.SaveChangesAsync()); run.Db.Entry(row).State = EntityState.Unchanged;
        await run.Rollback();
        await using var check = fixture.Open();
        await Assert.ThrowsAsync<InvalidOperationException>(() => new ProductionHoldControls(check, run.Keys, run.Time).ReadLockedAsync(plan.RecordId));
    }

    [Fact]
    public async Task Saving_plan_owns_ciphertext_before_SQL_and_returns_a_copy_of_the_persisted_bytes()
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        var exact = plan.Payload.ToArray(); var control = new ProductionHoldControls(run.Db, run.Keys, run.Time);
        var saving = control.SavePlanLockedAsync(plan); plan.Payload[0] ^= 1;
        var saved = await saving; Assert.Equal(exact, saved.Payload); saved.Payload[0] ^= 1;
        Assert.Equal(exact, (await control.ReadLockedAsync(plan.RecordId)).Plans[plan.PlanId].Payload);
    }

    private sealed class ControlLostCommit : Microsoft.EntityFrameworkCore.Diagnostics.DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(System.Data.Common.DbTransaction transaction,
            Microsoft.EntityFrameworkCore.Diagnostics.TransactionEndEventData eventData, CancellationToken ct = default) => throw new IOException("Synthetic lost control commit acknowledgement");
    }

    [Theory]
    [InlineData("denied")][InlineData("unheld")][InlineData("bad-bytes")][InlineData("hold-removed")][InlineData("expire-commit")]
    public async Task Provider_refusal_corruption_removed_protection_and_expiry_never_publish_an_item_receipt(string fault)
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        var control = new ProductionHoldControls(run.Db, run.Keys, run.Time); await control.SavePlanLockedAsync(plan);
        var body = ProductionHoldBundlePlan.OpenVerified(plan, run.Keys, run.Time); var item = Assert.Single(body.Items, x => x.Kind == "sql");
        var cap = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, body.Snapshot.Sql);
        using var handler = new Handler(run, fault, cap);
        var error = await Record.ExceptionAsync(() => control.PreserveItemLockedAsync(plan.RecordId, plan.PlanId, item.Path, Guid.NewGuid(), new(Service(handler))));
        Assert.True(error is InvalidDataException or Azure.RequestFailedException or UnauthorizedAccessException, error?.ToString());
        var state = await control.ReadLockedAsync(plan.RecordId); Assert.Empty(state.Items); Assert.Equal(1, state.Prefix.Sequence);
        Assert.DoesNotContain(handler.Requests, x => x.Method == HttpMethod.Delete || x.Comp is "legalhold" or "immutabilitypolicy");
    }

    [Fact]
    public async Task Receipt_lost_SQL_commit_recovery_rechecks_same_provider_version_without_reupload_or_clock_reset()
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        await new ProductionHoldControls(run.Db, run.Keys, run.Time).SavePlanLockedAsync(plan); await run.Commit();
        var body = ProductionHoldBundlePlan.OpenVerified(plan, run.Keys, run.Time); var item = Assert.Single(body.Items, x => x.Kind == "sql");
        // Use the exact frozen SQL ciphertext, rather than the earlier admission capture.
        await using var source = fixture.Open();
        await using var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(new ControlLostCommit()).Options);
        await using var tx = await db.Database.BeginTransactionAsync();
        var cap = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(db, run.Keys, run.Time, plan.HoldId, body.Snapshot.Sql);
        using var provider = new Handler(run, "lost-ack", cap); var writer = new AzureProductionHoldArchiveWriter(Service(provider)); var eventId = Guid.NewGuid();
        var recorded = await new ProductionHoldControls(db, run.Keys, run.Time).PreserveItemLockedAsync(plan.RecordId, plan.PlanId, item.Path, eventId, writer);
        await Assert.ThrowsAsync<IOException>(() => tx.CommitAsync()); run.Time.Now = run.Time.Now.AddMinutes(11);
        await using var recover = fixture.Open(); await using var recovery = await recover.Database.BeginTransactionAsync();
        var replayed = await new ProductionHoldControls(recover, run.Keys, run.Time).PreserveItemLockedAsync(plan.RecordId, plan.PlanId, item.Path, eventId, writer);
        Assert.Equal(recorded, replayed); Assert.Equal(1, provider.Commits);
        Assert.Equal(run.Time.Now.AddMinutes(-11), (await recover.ProductionHoldControls.SingleAsync(x => x.EventId == eventId)).At);
        Assert.Equal(2, (await new ProductionHoldControls(recover, run.Keys, run.Time).ReadLockedAsync(plan.RecordId)).Prefix.Sequence);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Changed_business_or_pending_release_keeps_historical_control_readable_but_forbids_provider_work(bool release)
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        var control = new ProductionHoldControls(run.Db, run.Keys, run.Time); await control.SavePlanLockedAsync(plan);
        if (release)
        {
            const string issuer = "https://operator.synthetic.invalid"; const string subject = "synthetic-operator";
            var policy = new ProductionOperatorPolicy(true, [new(issuer, subject, new HashSet<ProductionOperatorPermission> { ProductionOperatorPermission.ReleaseHold })]);
            var ticket = new AuthenticationTicket(new(new ClaimsIdentity([new("iss", issuer, ClaimValueTypes.String, issuer), new("sub", subject, ClaimValueTypes.String, issuer)], ProductionOperatorAuthority.OidcScheme)),
                new AuthenticationProperties { IssuedUtc = run.Time.Now, ExpiresUtc = run.Time.Now.AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme);
            var authority = ProductionOperatorAuthority.FromValidatedTicket(ticket, policy, ProductionOperatorPermission.ReleaseHold, run.Time);
            var command = new ProductionHoldCommand(Guid.NewGuid(), plan.RecordId, plan.HoldId, inventory.Revision, ProductionHoldOperation.Release,
                "Synthetic release", "Synthetic private reason", "synthetic-reference");
            Assert.True((await new ProductionHoldRequests(run.Db, run.Keys, run.Time).PrepareLockedAsync(authority, policy, command)).Current.BlocksDeletion);
        }
        else await run.Db.Envelopes.Where(x => x.Id == plan.RecordId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "New business evidence"));
        Assert.Equal(plan.Payload, (await control.ReadLockedAsync(plan.RecordId)).Plans[plan.PlanId].Payload);
        using var handler = new Handler(run, "normal"); var writer = new AzureProductionHoldArchiveWriter(Service(handler));
        var item = ProductionHoldBundlePlan.OpenVerified(plan, run.Keys, run.Time).Items[0];
        await Assert.ThrowsAsync<DocumentConflictException>(() => control.PreserveItemLockedAsync(plan.RecordId, plan.PlanId, item.Path, Guid.NewGuid(), writer));
        await Assert.ThrowsAsync<DocumentConflictException>(() => control.SavePlanLockedAsync(plan));
        Assert.Empty(handler.Requests); Assert.Equal(1, (await control.ReadLockedAsync(plan.RecordId)).Prefix.Sequence);
    }
    [Fact]
    public async Task Frozen_bundle_plan_owns_exact_restart_payload_and_uses_the_same_archive_addresses()
    {
        await using var run = await Run.Create(fixture); var (inventory, source) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        var decoded = ProductionHoldBundlePlan.OpenVerified(plan, run.Keys, run.Time);
        var repeated = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, plan.PlanId, inventory);
        Assert.Equal(plan.Sha256, repeated.Sha256);
        Assert.Equal(3, decoded.Items.Length); Assert.Equal(run.Capability.PlaceCommandId, decoded.PlaceCommandId);
        Assert.Equal(inventory.Sql.ProtectedPayload, decoded.Snapshot.Sql.ProtectedPayload);
        Assert.Equal(inventory.ProtectedManifest, decoded.Snapshot.ProtectedManifest);
        var sql = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, decoded.Snapshot.Sql);
        var manifest = await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, decoded.Snapshot);
        var raw = await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, decoded.Snapshot, source.Address);
        Assert.Equal(sql.Path, Assert.Single(decoded.Items, x => x.Kind == "sql").Path);
        Assert.Equal(manifest.Path, Assert.Single(decoded.Items, x => x.Kind == "manifest").Path);
        Assert.Equal(raw.Path, Assert.Single(decoded.Items, x => x.Kind == "object").Path);
        inventory.ProtectedManifest[0] ^= 1; inventory.Sql.ProtectedPayload[0] ^= 1;
        decoded.Snapshot.ProtectedManifest[0] ^= 1;
        run.Time.Now = run.Time.Now.AddMinutes(11);
        var recovered = ProductionHoldBundlePlan.OpenVerified(plan, run.Keys, run.Time);
        var fresh = await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, plan.HoldId, recovered.Snapshot, source.Address);
        Assert.Equal(raw.Path, fresh.Path); Assert.Equal(raw.Sha256, fresh.Sha256);
        Assert.Equal(plan.PlanId, recovered.PlanId); Assert.Equal(plan.Sha256, Convert.ToHexStringLower(SHA256.HashData(
            run.Keys.CreateProtector(ProductionHoldBundlePlan.Version, plan.RecordId.ToString("N"), plan.PlanId.ToString("N")).Unprotect(plan.Payload))));
    }

    [Theory]
    [InlineData("record")][InlineData("hold")][InlineData("plan")][InlineData("hash")][InlineData("cipher")][InlineData("empty")][InlineData("keys")]
    public async Task Frozen_plan_rejects_foreign_metadata_ciphertext_and_missing_historical_keys(string fault)
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        plan = fault switch {
            "record" => plan with { RecordId = Guid.NewGuid() }, "hold" => plan with { HoldId = Guid.NewGuid() },
            "plan" => plan with { PlanId = Guid.NewGuid() }, "hash" => plan with { Sha256 = new string('0', 64) },
            "empty" => plan with { Payload = [] }, _ => plan };
        if (fault == "cipher") plan.Payload[0] ^= 1;
        var error = Record.Exception(() => ProductionHoldBundlePlan.OpenVerified(plan, fault == "keys" ? new EphemeralDataProtectionProvider() : run.Keys, run.Time));
        Assert.True(error is CryptographicException or InvalidDataException, error?.ToString());
    }

    [Theory]
    [InlineData("path")][InlineData("hash")][InlineData("length")][InlineData("source")][InlineData("kind")][InlineData("missing")][InlineData("placement")]
    public async Task Even_authenticated_plan_items_must_match_the_exact_complete_manifest_and_placement(string fault)
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory);
        var body = ProductionHoldBundlePlan.OpenVerified(plan, run.Keys, run.Time);
        var index = Array.FindIndex(body.Items, x => x.Kind == "object"); var item = body.Items[index];
        body.Items[index] = fault switch {
            "path" => item with { Path = item.Path + "-different" }, "hash" => item with { Sha256 = new string('0', 64) },
            "length" => item with { Length = item.Length + 1 }, "source" => item with { Source = item.Source! with { VersionId = "other-version" } },
            "kind" => item with { Kind = "sql" }, _ => item };
        if (fault == "missing") body = body with { Items = body.Items[..^1] };
        if (fault == "placement") body = body with { PlaceCommandId = Guid.NewGuid() };
        var plain = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(body);
        plan = plan with { Sha256 = Convert.ToHexStringLower(SHA256.HashData(plain)), Payload = run.Keys.CreateProtector(
            ProductionHoldBundlePlan.Version, plan.RecordId.ToString("N"), plan.PlanId.ToString("N")).Protect(plain) };
        Assert.Throws<InvalidDataException>(() => ProductionHoldBundlePlan.OpenVerified(plan, run.Keys, run.Time));
    }

    [Fact]
    public async Task Freeze_never_authorizes_a_stale_business_capture_or_an_empty_plan_identity()
    {
        await using var run = await Run.Create(fixture); var (inventory, _) = await Inventory(run, "version");
        await Assert.ThrowsAsync<InvalidDataException>(() => ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.Empty, inventory));
        await run.Db.Envelopes.Where(x => x.Id == run.Sql.RecordId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "Changed after capture"));
        await Assert.ThrowsAsync<DocumentConflictException>(() => ProductionHoldBundlePlan.FreezeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, Guid.NewGuid(), inventory));
    }

    [Theory]
    [InlineData("manifest")][InlineData("version")][InlineData("snapshot")][InlineData("plain")]
    public async Task Manifest_and_raw_source_archives_bind_the_same_SQL_inventory_and_only_exact_scoped_bytes(string kind)
    {
        await using var run = await Run.Create(fixture); var (inventory, source) = await Inventory(run, kind);
        var cap = await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, inventory,
            kind == "manifest" ? null : source.Address);
        using var handler = new Handler(run, "normal", cap); var store = new AzureProductionHoldBundleArchiveStore(Service(handler));
        var receipt = await store.PreserveAsync(cap);
        Assert.Equal(inventory.ManifestSha256, receipt.ManifestSha256); Assert.Equal(inventory.SqlStateSha256, receipt.SqlStateSha256);
        Assert.Equal(inventory.SqlPayloadSha256, receipt.SqlPayloadSha256); Assert.Equal(cap.Path, receipt.Stored.Path);
        Assert.Equal(kind == "manifest" ? inventory.ProtectedManifest : Raw, handler.Stored);
        Assert.Equal(kind == "manifest" ? 0 : 1, handler.SourceReads); Assert.Equal(1, handler.Commits);
        Assert.Equal(receipt, await store.PreserveAsync(cap)); Assert.Equal(1, handler.Commits); Assert.Equal(kind == "manifest" ? 0 : 1, handler.SourceReads);
        Assert.DoesNotContain(handler.Requests, x => x.Comp is "legalhold" or "immutabilitypolicy" || x.Method == HttpMethod.Delete);
    }
    [Theory]
    [InlineData("source-hash")][InlineData("source-short")][InlineData("source-long")][InlineData("source-version")]
    [InlineData("source-etag")][InlineData("source-missing")][InlineData("source-public")]
    public async Task Missing_changed_partial_or_public_source_never_commits_an_archive(string fault)
    {
        await using var run = await Run.Create(fixture); var (inventory, source) = await Inventory(run, "version");
        var cap = await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, inventory, source.Address);
        using var handler = new Handler(run, fault, cap);
        var error = await Record.ExceptionAsync(() => new AzureProductionHoldBundleArchiveStore(Service(handler)).PreserveAsync(cap));
        Assert.True(error is InvalidDataException or Azure.RequestFailedException, error?.ToString()); Assert.Equal(0, handler.Commits);
    }
    [Theory]
    [InlineData("ciphertext")][InlineData("summary")][InlineData("SQL")][InlineData("unlisted")][InlineData("stale")]
    public async Task Archive_scope_requires_the_authenticated_entire_manifest_and_current_SQL_fence(string fault)
    {
        await using var run = await Run.Create(fixture); var (inventory, source) = await Inventory(run, "version");
        var selection = source.Address;
        switch (fault)
        {
            case "ciphertext": inventory.ProtectedManifest[0] ^= 1; break;
            case "summary": inventory = inventory with { Objects = 2 }; break;
            case "SQL": inventory = inventory with { SqlPayloadSha256 = new string('0', 64) }; break;
            case "unlisted": selection = selection with { VersionId = "different-version" }; break;
            default: await run.Db.Envelopes.Where(x => x.Id == run.Sql.RecordId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "Changed source")); break;
        }
        var error = await Record.ExceptionAsync(() => ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, inventory, selection));
        Assert.True(error is CryptographicException or InvalidDataException or DocumentConflictException, error?.ToString());
    }
    [Fact]
    public async Task Recovered_retained_raw_archive_does_not_require_a_now_missing_source_or_a_new_write()
    {
        await using var run = await Run.Create(fixture); var (inventory, source) = await Inventory(run, "version");
        var cap = await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, inventory, source.Address);
        using var handler = new Handler(run, "lost-ack", cap); var store = new AzureProductionHoldBundleArchiveStore(Service(handler));
        var first = await store.PreserveAsync(cap); run.Time.Now = run.Time.Now.AddMinutes(11); handler.SourceMissing = true;
        var fresh = await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, inventory, source.Address);
        Assert.Equal(first, await store.PreserveAsync(fresh)); Assert.Equal(1, handler.SourceReads); Assert.Equal(1, handler.Commits);
    }
    [Theory]
    [InlineData("source-expire")][InlineData("source-expire-read")]
    public async Task Scope_expiry_while_opening_or_reading_source_cannot_stage_or_commit_any_archive_bytes(string mode)
    {
        await using var run = await Run.Create(fixture); var (inventory, source) = await Inventory(run, "version");
        var cap = await ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, inventory, source.Address);
        using var handler = new Handler(run, mode, cap);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new AzureProductionHoldBundleArchiveStore(Service(handler)).PreserveAsync(cap));
        Assert.Equal(1, handler.SourceReads); Assert.Equal(0, handler.Commits); Assert.DoesNotContain(handler.Requests, x => x.Comp == "block");
    }
    [Fact]
    public async Task Scope_expiry_during_archive_readback_stops_before_another_provider_operation()
    {
        await using var run = await Run.Create(fixture); using var handler = new Handler(run, "archive-expire-read");
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Store(handler).PreserveAsync(run.Capability));
        Assert.Equal(1, handler.Commits); Assert.Equal(1, handler.VersionHeads); Assert.Equal(HttpMethod.Get, handler.Requests[^1].Method);
    }
    [Fact]
    public async Task A_manifest_captured_after_the_current_clock_cannot_issue_a_worker_scope()
    {
        await using var run = await Run.Create(fixture); var (inventory, source) = await Inventory(run, "version");
        run.Time.Now = run.Time.Now.AddMinutes(-1);
        await Assert.ThrowsAsync<InvalidDataException>(() => ProductionHoldBundleArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, inventory, source.Address));
    }
    [Theory]
    [InlineData("normal")][InlineData("lost-ack")][InlineData("race")]
    public async Task Exact_encrypted_SQL_is_created_once_with_own_legal_hold_and_verified_version_bytes(string mode)
    {
        await using var run = await Run.Create(fixture); using var handler = new Handler(run, mode); var store = Store(handler);
        var receipt = await store.PreserveAsync(run.Capability);
        Assert.Equal(run.Sql.RecordId, receipt.RecordId); Assert.Equal(run.Capability.HoldId, receipt.HoldId); Assert.Equal(run.Sql.StateSha256, receipt.SqlStateSha256);
        Assert.Equal(run.Sql.PayloadSha256, receipt.SqlPayloadSha256); Assert.Equal(run.Capability.Path, receipt.Path);
        Assert.StartsWith("production-holds/", receipt.Path); Assert.False(receipt.Path.StartsWith($"{run.Sql.RecordId:N}/", StringComparison.Ordinal));
        Assert.Equal(run.Sql.ProtectedPayload, handler.Stored); Assert.Equal(1, handler.Commits); Assert.Equal(Handler.Version, receipt.VersionId);
        Assert.Equal(receipt, await store.PreserveAsync(run.Capability)); Assert.Equal(1, handler.Commits);
        Assert.True(handler.VersionHeads >= 4); Assert.DoesNotContain(handler.Requests, x => x.Method == HttpMethod.Delete || x.Comp is "legalhold" or "immutabilitypolicy");
        Assert.All(handler.Requests, x => Assert.True(x.Path == "/final" || x.Path == "/final/" + run.Capability.Path));
    }
    [Theory]
    [InlineData("public")][InlineData("versioning-off")][InlineData("denied")][InlineData("unheld")]
    [InlineData("wrong-version")][InlineData("bad-bytes")][InlineData("short")][InlineData("long")][InlineData("hold-removed")]
    public async Task Partial_unknown_or_changed_provider_protection_never_becomes_a_verified_archive(string fault)
    {
        await using var run = await Run.Create(fixture); using var handler = new Handler(run, fault);
        var error = await Record.ExceptionAsync(() => Store(handler).PreserveAsync(run.Capability));
        Assert.True(error is InvalidDataException or Azure.RequestFailedException, error?.ToString());
        Assert.Equal(fault is "public" or "versioning-off" ? 0 : 1, handler.Commits);
        Assert.DoesNotContain(handler.Requests, x => x.Method == HttpMethod.Delete || x.Comp is "legalhold" or "immutabilitypolicy");
    }
    [Fact]
    public async Task Expiry_during_staging_stops_before_immutable_commit_and_does_not_invent_provider_success()
    {
        await using var run = await Run.Create(fixture); using var handler = new Handler(run, "expire-stage");
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Store(handler).PreserveAsync(run.Capability)); Assert.Equal(0, handler.Commits);
    }
    [Fact]
    public async Task Expiry_at_commit_preserves_uncertainty_and_requires_fresh_scope_before_any_followup_IO()
    {
        await using var run = await Run.Create(fixture); using var handler = new Handler(run, "expire-commit"); var store = Store(handler);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.PreserveAsync(run.Capability));
        Assert.Equal("blocklist", handler.Requests[^1].Comp); Assert.Equal(1, handler.Commits); Assert.NotNull(handler.Stored);
        var fresh = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, run.Sql);
        Assert.Equal(run.Capability.Path, (await store.PreserveAsync(fresh)).Path); Assert.Equal(1, handler.Commits);
    }
    [Fact]
    public async Task A_pending_release_cannot_authorize_new_archive_work_or_restore_participant_authority()
    {
        await using var run = await Run.Create(fixture); const string issuer = "https://operator.synthetic.invalid"; const string subject = "synthetic-operator";
        var operators = new ProductionOperatorPolicy(true, [new(issuer, subject, new HashSet<ProductionOperatorPermission> { ProductionOperatorPermission.ReleaseHold })]);
        var ticket = new AuthenticationTicket(new(new ClaimsIdentity([new("iss", issuer, ClaimValueTypes.String, issuer), new("sub", subject, ClaimValueTypes.String, issuer)], ProductionOperatorAuthority.OidcScheme)),
            new AuthenticationProperties { IssuedUtc = run.Time.Now, ExpiresUtc = run.Time.Now.AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme);
        var authority = ProductionOperatorAuthority.FromValidatedTicket(ticket, operators, ProductionOperatorPermission.ReleaseHold, run.Time);
        var command = new ProductionHoldCommand(Guid.NewGuid(), run.Sql.RecordId, run.Capability.HoldId, run.Sql.Revision, ProductionHoldOperation.Release,
            "Synthetic release", "Synthetic private reason", "synthetic-reference");
        var request = await new ProductionHoldRequests(run.Db, run.Keys, run.Time).PrepareLockedAsync(authority, operators, command);
        var sql = await new ProductionHoldSqlInventory(run.Db, run.Keys, run.Time).CaptureLockedAsync(run.Sql.RecordId, request.Current.Revision, request.Current.FenceHash!);
        await Assert.ThrowsAsync<DocumentConflictException>(() => ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, command.HoldId, sql));
        Assert.True(request.Current.BlocksDeletion);
    }
    [Fact]
    public async Task Restart_after_worker_expiry_reauthorizes_same_ciphertext_only_after_current_SQL_and_hold_verification()
    {
        await using var run = await Run.Create(fixture); using var handler = new Handler(run, "lost-ack"); var store = Store(handler);
        var first = await store.PreserveAsync(run.Capability); run.Time.Now = run.Time.Now.AddMinutes(11);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.PreserveAsync(run.Capability));
        var fresh = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, run.Sql);
        Assert.Equal(first, await store.PreserveAsync(fresh)); Assert.Equal(1, handler.Commits);
        await run.Db.Envelopes.Where(x => x.Id == run.Sql.RecordId).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "Changed business source"));
        await Assert.ThrowsAsync<DocumentConflictException>(() => ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, fresh.HoldId, run.Sql));
    }
    [Fact]
    public async Task Wrong_hold_or_fence_and_mutated_ciphertext_cannot_issue_an_archive_scope()
    {
        await using var run = await Run.Create(fixture);
        await Assert.ThrowsAsync<DocumentConflictException>(() => ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, Guid.NewGuid(), run.Sql));
        await Assert.ThrowsAsync<InvalidDataException>(() => ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId,
            run.Sql with { FenceHash = new string('0', 64) }));
        run.Sql.ProtectedPayload[0] ^= 1;
        await Assert.ThrowsAsync<CryptographicException>(() => ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Capability.HoldId, run.Sql));
        // Already issued capability owns its own bounded copy, unaffected by the
        // caller mutating a returned snapshot buffer after authorization.
        using var input = run.Capability.Open(default); Assert.NotEqual(run.Sql.ProtectedPayload[0], input.ReadByte());
    }

    private static AzureProductionHoldSqlArchiveStore Store(Handler handler)
        => new(Service(handler));
    private static BlobServiceClient Service(Handler handler)
    {
        var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03) { Transport = new HttpClientTransport(new HttpClient(handler)) };
        options.Retry.MaxRetries = 0; options.Diagnostics.IsLoggingEnabled = false; options.Diagnostics.IsLoggingContentEnabled = false; options.Diagnostics.IsDistributedTracingEnabled = false;
        return new(new Uri("https://storage.example.invalid"), new Credential(), options);
    }
    private static async Task<(ProductionHoldObjectSnapshot, InventorySource)> Inventory(Run run, string kind)
    {
        var source = new InventorySource(new("originals", $"{run.Sql.RecordId:N}/{Guid.NewGuid():N}", kind is "version" or "manifest" ? Handler.Version : "",
            kind == "snapshot" ? Handler.Version : "", "\"source-etag\"", Raw.Length));
        var inventory = await new ProductionHoldObjectInventory(run.Db, run.Keys, run.Time, source)
            .CaptureLockedAsync(run.Sql.RecordId, run.Sql.Revision, run.Sql.FenceHash);
        return (inventory, source);
    }
    private sealed class InventorySource(HoldObjectAddress address) : IProductionHoldObjectSource
    {
        internal HoldObjectAddress Address => address;
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct)
            => Task.FromResult(new HoldObjectPage(area == address.Area ? [address] : [], null));
        public Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress value, CancellationToken ct)
            => Task.FromResult(Convert.ToHexStringLower(SHA256.HashData(Raw)));
    }
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed class Run : IAsyncDisposable
    {
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider(); internal readonly Clock Time = new();
        internal QuillSignDbContext Db = null!; private IDbContextTransaction transaction = null!;
        internal ProductionHoldSqlSnapshot Sql = null!; internal ProductionHoldSqlArchiveCapability Capability = null!;
        internal Task Commit() => transaction.CommitAsync();
        internal Task Rollback() => transaction.RollbackAsync();
        internal static async Task<Run> Create(SqlDatabaseFixture fixture)
        {
            var run = new Run { Db = fixture.Open() };
            try
            {
                var e = new Envelope { SenderEmail = "synthetic-archive@example.invalid", CreatedAt = run.Time.Now };
                await using (var creation = await run.Db.Database.BeginTransactionAsync())
                {
                    run.Db.Add(e); await new ProductionRetentionLedger(run.Db, new(run.Db, run.Time), run.Time).PrepareNewLockedAsync(e, ProductionRetentionLedgerTests.Policy()); await creation.CommitAsync();
                }
                const string issuer = "https://operator.synthetic.invalid"; const string subject = "synthetic-operator";
                var operators = new ProductionOperatorPolicy(true, [new(issuer, subject, new HashSet<ProductionOperatorPermission> { ProductionOperatorPermission.PlaceHold })]);
                var ticket = new AuthenticationTicket(new(new ClaimsIdentity([new("iss", issuer, ClaimValueTypes.String, issuer), new("sub", subject, ClaimValueTypes.String, issuer)], ProductionOperatorAuthority.OidcScheme)),
                    new AuthenticationProperties { IssuedUtc = run.Time.Now, ExpiresUtc = run.Time.Now.AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme);
                var authority = ProductionOperatorAuthority.FromValidatedTicket(ticket, operators, ProductionOperatorPermission.PlaceHold, run.Time);
                var command = new ProductionHoldCommand(Guid.NewGuid(), e.Id, Guid.NewGuid(), 0, ProductionHoldOperation.Place, "Synthetic archive", "Private synthetic reason", "synthetic-reference");
                await using (var placement = await run.Db.Database.BeginTransactionAsync())
                { await new ProductionHoldRequests(run.Db, run.Keys, run.Time).PrepareLockedAsync(authority, operators, command); await placement.CommitAsync(); }
                run.transaction = await run.Db.Database.BeginTransactionAsync();
                var request = await new ProductionHoldRequests(run.Db, run.Keys, run.Time).ReadLockedAsync(e.Id);
                run.Sql = await new ProductionHoldSqlInventory(run.Db, run.Keys, run.Time).CaptureLockedAsync(e.Id, request.Revision, request.FenceHash!);
                run.Capability = await ProductionHoldSqlArchiveCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, command.HoldId, run.Sql); return run;
            }
            catch { await run.DisposeAsync(); throw; }
        }
        public async ValueTask DisposeAsync() { if (transaction is not null) await transaction.DisposeAsync(); if (Db is not null) await Db.DisposeAsync(); }
    }
    private sealed record Request(HttpMethod Method, string Comp, string Path);
    private sealed class Handler(Run run, string mode, IProductionHoldArchivePayload? selected = null) : HttpMessageHandler
    {
        internal const string Version = "2030-01-01T00:00:00.0000000Z", Tag = "\"synthetic-etag\"";
        private readonly IProductionHoldArchivePayload payload = selected ?? run.Capability;
        internal List<Request> Requests = []; internal byte[]? Stored; internal int Commits, VersionHeads, SourceReads; internal bool SourceMissing;
        private readonly Dictionary<string, byte[]> blocks = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var query = QueryHelpers.ParseQuery(request.RequestUri!.Query); string Q(string name) => query.TryGetValue(name, out var value) ? value.ToString() : "";
            string H(string name) => request.Headers.TryGetValues(name, out var values) ? values.Single() : "";
            var comp = Q("comp"); Requests.Add(new(request.Method, comp, request.RequestUri.AbsolutePath));
            Assert.Equal("storage.example.invalid", request.RequestUri.Host);
            if (Q("restype") == "container")
            {
                Assert.Equal(HttpMethod.Get, request.Method);
                var sourceContainer = request.RequestUri.AbsolutePath != "/final";
                Assert.Equal(sourceContainer ? "/" + payload.Source!.Area : "/final", request.RequestUri.AbsolutePath);
                var result = Reply([]); result.Headers.TryAddWithoutValidation("x-ms-immutable-storage-with-versioning-enabled", mode == "versioning-off" ? "false" : "true");
                if (mode == "public" || sourceContainer && mode == "source-public") result.Headers.TryAddWithoutValidation("x-ms-blob-public-access", "blob"); return result;
            }
            if (payload.Source is { } source && request.RequestUri.AbsolutePath == "/" + source.Area + "/" + source.Name)
            {
                Assert.Equal(HttpMethod.Get, request.Method); Assert.Equal(source.VersionId, Q("versionid")); Assert.Equal(source.Snapshot, Q("snapshot")); Assert.Equal(source.ETag, H("If-Match")); SourceReads++;
                if (SourceMissing || mode == "source-missing") return Error(HttpStatusCode.NotFound, "BlobNotFound");
                var sourceBytes = Raw.ToArray(); if (mode == "source-hash") sourceBytes[0] ^= 1; if (mode == "source-short") sourceBytes = sourceBytes[..^1]; if (mode == "source-long") sourceBytes = sourceBytes.Append((byte)1).ToArray();
                var reply = Reply(sourceBytes);
                if (mode == "source-expire-read") reply.Content = new StreamContent(new ExpiringStream(sourceBytes, () => run.Time.Now = run.Time.Now.AddMinutes(10)));
                reply.Content.Headers.ContentLength = source.Length;
                reply.Headers.TryAddWithoutValidation("ETag", mode == "source-etag" ? "\"changed\"" : source.ETag);
                if (source.VersionId != "") reply.Headers.TryAddWithoutValidation("x-ms-version-id", mode == "source-version" ? "wrong-version" : source.VersionId);
                if (mode == "source-expire") run.Time.Now = run.Time.Now.AddMinutes(10);
                return reply;
            }
            Assert.Equal("/final/" + payload.Path, request.RequestUri.AbsolutePath);
            if (comp == "block")
            {
                Assert.Equal(HttpMethod.Put, request.Method); Assert.Empty(H("x-ms-legal-hold")); Assert.Empty(H("x-ms-immutability-policy-until-date"));
                blocks.Add(Q("blockid"), await request.Content!.ReadAsByteArrayAsync(ct));
                if (mode == "expire-stage") run.Time.Now = run.Time.Now.AddMinutes(10);
                var response = Reply([]); response.StatusCode = HttpStatusCode.Created; return response;
            }
            if (comp == "blocklist")
            {
                Assert.Equal(HttpMethod.Put, request.Method); Assert.Equal("*", H("If-None-Match")); Assert.Equal("true", H("x-ms-legal-hold"));
                Assert.Empty(H("x-ms-immutability-policy-until-date")); Commits++;
                if (mode == "denied") return Error(HttpStatusCode.Forbidden, "AuthorizationPermissionMismatch");
                var order = XDocument.Parse(await request.Content!.ReadAsStringAsync(ct)).Root!.Elements().Select(x => x.Value);
                Stored = order.SelectMany(x => blocks[x]).ToArray();
                if (mode == "expire-commit") run.Time.Now = run.Time.Now.AddMinutes(10);
                if (mode == "lost-ack") return Error(HttpStatusCode.InternalServerError, "SyntheticLostAcknowledgement");
                if (mode == "race") return Error(HttpStatusCode.PreconditionFailed, "ConditionNotMet");
                var response = Reply([]); response.StatusCode = HttpStatusCode.Created; return response;
            }
            if (request.Method == HttpMethod.Head)
            {
                if (Stored is null) return Error(HttpStatusCode.NotFound, "BlobNotFound");
                if (Q("versionid") != "") { Assert.Equal(Version, Q("versionid")); Assert.Equal(Tag, H("If-Match")); VersionHeads++; }
                var result = Reply([]); result.Content.Headers.ContentLength = Stored.Length;
                result.Headers.TryAddWithoutValidation("ETag", Tag); result.Headers.TryAddWithoutValidation("x-ms-version-id", mode == "wrong-version" ? "" : Version);
                result.Headers.TryAddWithoutValidation("x-ms-legal-hold", mode == "unheld" || mode == "hold-removed" && VersionHeads >= 2 ? "false" : "true");
                result.Headers.TryAddWithoutValidation("x-ms-blob-type", "BlockBlob"); return result;
            }
            Assert.Equal(HttpMethod.Get, request.Method); Assert.Equal(Version, Q("versionid")); Assert.Equal(Tag, H("If-Match"));
            var bytes = Stored!.ToArray();
            if (mode == "bad-bytes") bytes[0] ^= 1; if (mode == "short") bytes = bytes[..^1]; if (mode == "long") bytes = bytes.Append((byte)1).ToArray();
            var download = Reply(bytes);
            if (mode == "archive-expire-read") download.Content = new StreamContent(new ExpiringStream(bytes, () => run.Time.Now = run.Time.Now.AddMinutes(10)));
            download.Content.Headers.ContentLength = Stored!.Length;
            download.Headers.TryAddWithoutValidation("ETag", Tag); download.Headers.TryAddWithoutValidation("x-ms-version-id", Version); return download;
        }
        private static HttpResponseMessage Reply(byte[] bytes)
        {
            var result = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
            result.Headers.TryAddWithoutValidation("x-ms-version", "2023-11-03"); result.Headers.TryAddWithoutValidation("x-ms-request-id", "synthetic-no-agreement"); return result;
        }
        private static HttpResponseMessage Error(HttpStatusCode status, string code)
        { var result = Reply(Encoding.UTF8.GetBytes($"<Error><Code>{code}</Code><Message>Synthetic failure</Message></Error>")); result.StatusCode = status; result.Headers.TryAddWithoutValidation("x-ms-error-code", code); return result; }
    }
    private sealed class ExpiringStream(byte[] bytes, Action expire) : MemoryStream(bytes, false)
    {
        private bool expired;
        private void BeforeRead() { if (!expired) { expired = true; expire(); } }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { BeforeRead(); return base.ReadAsync(buffer, ct); }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) { BeforeRead(); return base.ReadAsync(buffer, offset, count, ct); }
    }
    private sealed class Credential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext c, CancellationToken ct) => new("synthetic-no-agreement", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext c, CancellationToken ct) => ValueTask.FromResult(GetToken(c, ct));
    }
}
