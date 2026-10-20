using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldObjectInventoryTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private readonly IDataProtectionProvider keys = new EphemeralDataProtectionProvider();
    private readonly Clock clock = new();
    private static readonly byte[] Content = "Synthetic object bytes - NO AGREEMENT"u8.ToArray();
    private static string Hash => Convert.ToHexStringLower(SHA256.HashData(Content));

    [Fact]
    public async Task Actual_document_upload_preview_and_replacement_bind_history_and_missing_old_bytes_stay_pending()
    {
        var client = new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"), new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
        Assert.True(client.Uri.IsLoopback || client.Uri.Host == "azurite", "Only disposable local storage is allowed.");
        foreach (var area in ProductionHoldObjectScope.Areas) await client.GetBlobContainerClient(area).CreateIfNotExistsAsync(PublicAccessType.None);
        var e = new Envelope { SenderEmail = "document-sender@example.invalid", CreatedAt = clock.Now };
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync(); db.Add(e);
            await new ProductionRetentionLedger(db, new(db, clock), clock).PrepareNewLockedAsync(e, ProductionRetentionLedgerTests.Policy());
            e.SenderVerifiedAt = clock.Now; await db.SaveChangesAsync(); await tx.CommitAsync();
        }
        var sender = QuillSign.Sender.SenderConfiguration.Principal(new(e.Id, e.PublicId, e.SenderEmail));
        var store = new DocumentWorkflowTests.FaultStore(new AzureBlobStore(client, 25 * 1024 * 1024, true));
        async Task<Envelope> State() { await using var db = fixture.Open(); return await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == e.Id); }
        async Task<bool> Upload(byte[] bytes, bool confirm)
        {
            var before = await State(); await using var db = fixture.Open(); var options = new DocumentOptions();
            var work = new DocumentWorkflow(db, store, new(options), options, new(db, clock), clock,
                Microsoft.Extensions.Logging.Abstractions.NullLogger<DocumentWorkflow>.Instance, new());
            if (confirm) return await work.ConfirmAsync(sender, e.PublicId, before.RowVersion, before.PdfBlob!, true, null, null, default);
            using var input = new MemoryStream(bytes); return await work.UploadAsync(sender, e.PublicId, before.RowVersion, "synthetic.pdf", input, bytes.Length, null, null, default);
        }
        try
        {
            Assert.True(await Upload(PdfFixtures.Create(text: "Synthetic first NO AGREEMENT"), false));
            Assert.True(await Upload([], true));
            var request = await Hold(e.Id, clock, keys); ProductionHoldObjectSnapshot snapshot;
            await using (var db = fixture.Open())
            {
                await using var tx = await db.Database.BeginTransactionAsync();
                snapshot = await new ProductionHoldObjectInventory(db, keys, clock, new AzureProductionHoldObjectSource(client))
                    .CaptureLockedAsync(e.Id, request.Current.Revision, request.Current.FenceHash!);
            }
            Assert.Equal(2, ProductionHoldObjectInventory.OpenVerified(snapshot, keys, clock).Length);
            using (var saved = ProductionHoldSqlInventory.OpenVerified(snapshot.Sql, keys))
            {
                var root = JsonNode.Parse(saved.RootElement.GetRawText())!.AsObject();
                var tail = root["Tables"]!.AsArray().Single(x => x!["Table"]!.GetValue<string>() == "AuditEvents")!["Rows"]!.AsArray()
                    .Single(x => x!["Event"]!.GetValue<string>() == "preview_confirmed")!;
                var row = tail.Deserialize<AuditEvent>(new JsonSerializerOptions { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } })!;
                var data = JsonNode.Parse(row.DataJson)!; data["document"] = Guid.NewGuid().ToString("N"); row.DataJson = data.ToJsonString(); row.Hash = AuditHash.Compute(row);
                tail["DataJson"] = row.DataJson; tail["Hash"] = Convert.ToBase64String(row.Hash);
                var substituted = Rebind(snapshot, root, keys);
                using (ProductionHoldSqlInventory.OpenVerified(substituted.Sql, keys)) { }
                Assert.Throws<InvalidDataException>(() => ProductionHoldObjectInventory.OpenVerified(substituted, keys, clock));
            }
            async Task<Guid> AddSigner(string name, string email)
            {
                var state = await State(); await using var db = fixture.Open();
                var result = await new SignerSetup(db, new(db, clock), new(), clock).ChangeAsync(sender, e.PublicId,
                    new(SignerChangeKind.Save, Convert.ToBase64String(state.RowVersion), FullName: name, Email: email), null, null);
                Assert.Equal(SignerSetupError.None, result.Error);
                return (await db.Signers.AsNoTracking().SingleAsync(x => x.EnvelopeId == e.Id && x.Email == email)).Id;
            }
            async Task SaveFields(params FieldInput[] fields)
            {
                var state = await State(); await using var db = fixture.Open();
                var result = await new FieldEditor(db, new(db, clock), new(), clock).SaveAsync(sender, e.PublicId,
                    new(Convert.ToBase64String(state.RowVersion), state.PdfBlob!, fields), null, null);
                Assert.Equal(FieldEditorError.None, result.Error);
            }
            async Task ChangeSigner(Guid signer, SignerChangeKind kind)
            {
                var state = await State(); await using var db = fixture.Open();
                var result = await new SignerSetup(db, new(db, clock), new(), clock).ChangeAsync(sender, e.PublicId,
                    new(kind, Convert.ToBase64String(state.RowVersion), signer), null, null);
                Assert.Equal(SignerSetupError.None, result.Error);
            }
            async Task<Guid> Recipient(Guid? recipient, bool remove, string name, string email)
            {
                var state = await State(); await using var db = fixture.Open();
                var result = await new DraftDetails(db, new(db, clock), new(), clock).ChangeAsync(sender, e.PublicId,
                    new(remove ? DetailsChangeKind.RemoveRecipient : DetailsChangeKind.SaveRecipient, Convert.ToBase64String(state.RowVersion), recipient, Name: name, Email: email), null, null);
                Assert.Equal(DetailsError.None, result.Error);
                return remove ? recipient!.Value : (await db.Recipients.AsNoTracking().SingleAsync(x => x.EnvelopeId == e.Id && x.Email == email)).Id;
            }
            var removed = await AddSigner("Removed synthetic signer", "removed-signing@example.invalid");
            var surviving = await AddSigner("Current synthetic signer", "current-signing@example.invalid");
            var generic = new FieldInput(Guid.NewGuid(), null, "Text", 1, .1m, .2m, .3m, .1m, false, Value: Guid.NewGuid().ToString("N"));
            await SaveFields(new(Guid.NewGuid(), removed, "Signature", 1, .1m, .4m, .3m, .1m, true), generic);
            await SaveFields(generic); await ChangeSigner(removed, SignerChangeKind.Remove);
            var added = await AddSigner("Later synthetic signer", "later-signing@example.invalid"); await ChangeSigner(added, SignerChangeKind.MoveUp);
            var retiredRecipient = await Recipient(null, false, "Retired synthetic recipient", "retired-recipient@example.invalid");
            _ = await Recipient(null, false, "Current synthetic recipient", "current-recipient@example.invalid");
            _ = await Recipient(retiredRecipient, true, "", "");
            await SaveFields(generic, new(Guid.NewGuid(), surviving, "Signature", 1, .1m, .4m, .3m, .1m, true));
            {
                var state = await State(); await using var db = fixture.Open();
                var result = await new DraftDetails(db, new(db, clock), new(), clock).ChangeAsync(sender, e.PublicId,
                    new(DetailsChangeKind.SaveDetails, Convert.ToBase64String(state.RowVersion), Title: "Prepared synthetic title", Message: "Historical synthetic message"), null, null);
                Assert.Equal(DetailsError.None, result.Error);
                Assert.False(await db.Signers.AnyAsync(x => x.Id == removed));
            }
            await using (var prepared = fixture.Open())
            {
                await using var preparedTx = await prepared.Database.BeginTransactionAsync();
                var preserved = await new ProductionHoldObjectInventory(prepared, keys, clock, new AzureProductionHoldObjectSource(client))
                    .CaptureLockedAsync(e.Id, request.Current.Revision, request.Current.FenceHash!);
                Assert.Equal(2, ProductionHoldObjectInventory.OpenVerified(preserved, keys, clock).Length);
            }
            var first = await State();
            Assert.True(await Upload(PdfFixtures.Create(2, text: "Synthetic replacement NO AGREEMENT"), false));
            Assert.True(await Upload([], true));
            // Current workflow cleanup is still outside the future hold fence.
            // Missing old evidence must fail preservation, not be replaced by
            // the newer valid PDF or silently dropped from the audit graph.
            Assert.False((await client.GetBlobContainerClient("originals").GetBlobClient($"{e.Id:N}/{first.OriginalBlob}").ExistsAsync()).Value);
            await using var current = fixture.Open(); await using var currentTx = await current.Database.BeginTransactionAsync();
            await Assert.ThrowsAsync<InvalidDataException>(() => new ProductionHoldObjectInventory(current, keys, clock, new AzureProductionHoldObjectSource(client))
                .CaptureLockedAsync(e.Id, request.Current.Revision, request.Current.FenceHash!));
            var pending = await new ProductionHoldRequests(current, keys, clock).ReadLockedAsync(e.Id);
            Assert.True(pending.BlocksDeletion); Assert.Equal(request.Current.Revision, pending.Revision); Assert.Single(pending.Holds);
            Assert.False(await current.AuthTokens.AnyAsync(x => x.EnvelopeId == e.Id));
        }
        finally { foreach (var blob in store.Created) await store.Inner.DeleteAsync(sender, blob); }
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Full_tail_and_closed_owned_mail_registry_are_checked_in_capture_and_authenticated_replay(bool unknownMail)
    {
        var (id, request, original) = await Held();
        await using (var db = fixture.Open())
        {
            await using var tx = await db.Database.BeginTransactionAsync();
            await new AuditWriter(db, clock).AppendAsync(id, "draft_created", "synthetic-sender@example.invalid", null, null, default);
            await tx.CommitAsync();
        }
        var snapshot = await Capture(id, request, Source(id, original));
        Assert.Single(ProductionHoldObjectInventory.OpenVerified(snapshot, keys, clock));
        using var saved = ProductionHoldSqlInventory.OpenVerified(snapshot.Sql, keys);
        var root = JsonNode.Parse(saved.RootElement.GetRawText())!.AsObject();
        var target = root["Tables"]!.AsArray().Single(x => x!["Table"]!.GetValue<string>() == (unknownMail ? "EmailOutbox" : "AuditEvents"))!;
        if (unknownMail)
        {
            var mail = new EmailOutbox { EnvelopeId = id, To = "synthetic-sender@example.invalid", Template = "future-owned-template", AvailableAt = clock.Now };
            target["Rows"]!.AsArray().Add(JsonSerializer.SerializeToNode(mail, new JsonSerializerOptions { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } }));
            await using var db = fixture.Open(); db.Add(mail); await db.SaveChangesAsync();
        }
        else
        {
            var tail = target["Rows"]!.AsArray().Single(x => x!["Sequence"]!.GetValue<long>() == 2)!;
            // A well-hashed but ambiguous operational tail must not be accepted
            // just because the enrollment prefix remains fully authentic.
            var row = tail.Deserialize<AuditEvent>(new JsonSerializerOptions { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } })!;
            row.DataJson = "{\"x\":1,\"x\":2}"; row.Hash = AuditHash.Compute(row);
            tail["DataJson"] = row.DataJson; tail["Hash"] = Convert.ToBase64String(row.Hash);
            await using var db = fixture.Open();
            await db.AuditEvents.Where(x => x.EnvelopeId == id && x.Sequence == 2).ExecuteUpdateAsync(s => s.SetProperty(x => x.DataJson, row.DataJson).SetProperty(x => x.Hash, row.Hash));
        }
        // Reprotect/recompute every envelope and table digest, proving the new
        // semantic checks run during manifest replay, beyond DP/hash integrity.
        var changed = Rebind(snapshot, root, keys);
        using (var validEnvelope = ProductionHoldSqlInventory.OpenVerified(changed.Sql, keys)) Assert.Equal(id, validEnvelope.RootElement.GetProperty("RecordId").GetGuid());
        Assert.Throws<InvalidDataException>(() => ProductionHoldObjectInventory.OpenVerified(changed, keys, clock));
        await Assert.ThrowsAsync<InvalidDataException>(() => Capture(id, request, Source(id, original)));
        // Neither failed attempt rewrites the original exact capture or mints
        // access authority; this record never needed a participant token.
        Assert.Single(ProductionHoldObjectInventory.OpenVerified(snapshot, keys, clock));
        await using (var db = fixture.Open()) Assert.False(await db.AuthTokens.AnyAsync(x => x.EnvelopeId == id));
    }

    private static ProductionHoldObjectSnapshot Rebind(ProductionHoldObjectSnapshot snapshot, JsonObject root, IDataProtectionProvider keys)
    {
        static string Digest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
        foreach (var table in root["Tables"]!.AsArray())
        {
            table!["Count"] = (long)table["Rows"]!.AsArray().Count;
            table["Sha256"] = Digest(JsonSerializer.SerializeToUtf8Bytes(table["Rows"]));
        }
        using var document = JsonDocument.Parse(root.ToJsonString()); var value = document.RootElement;
        var state = JsonSerializer.SerializeToUtf8Bytes(new { Version = value.GetProperty("Version").GetString(),
            RecordId = snapshot.RecordId, Revision = snapshot.Revision, FenceHash = snapshot.FenceHash,
            PolicySha256 = value.GetProperty("PolicySha256").GetString(), Tables = value.GetProperty("Tables") });
        root["StateSha256"] = Digest(state); var raw = JsonSerializer.SerializeToUtf8Bytes(root);
        var sql = snapshot.Sql with { StateSha256 = Digest(state), PayloadSha256 = Digest(raw), PlaintextBytes = raw.Length,
            ProtectedPayload = keys.CreateProtector(ProductionHoldSqlInventory.Version, snapshot.RecordId.ToString("N")).Protect(raw),
            Tables = root["Tables"]!.AsArray().Select(x => new ProductionHoldSqlTable(x!["Table"]!.GetValue<string>(), x["Count"]!.GetValue<long>(), x["Sha256"]!.GetValue<string>())).ToArray() };
        var protector = keys.CreateProtector(ProductionHoldObjectInventory.Version, snapshot.RecordId.ToString("N"));
        var manifest = JsonNode.Parse(protector.Unprotect(snapshot.ProtectedManifest))!;
        manifest["SqlStateSha256"] = sql.StateSha256; manifest["SqlPayloadSha256"] = sql.PayloadSha256;
        var encoded = JsonSerializer.SerializeToUtf8Bytes(manifest);
        return snapshot with { Sql = sql, SqlStateSha256 = sql.StateSha256, SqlPayloadSha256 = sql.PayloadSha256,
            ManifestSha256 = Digest(encoded), ProtectedManifest = protector.Protect(encoded) };
    }

    [Fact]
    public async Task Protected_invitation_reference_is_required_during_capture_and_authenticated_manifest_replay()
    {
        var (id, request, original) = await Held(); var historical = Guid.NewGuid();
        await using (var db = fixture.Open())
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == id); envelope.ErsdSha256 = SHA256.HashData(Content);
            var signer = new Signer { EnvelopeId = id, FullName = "Synthetic signer", Email = "synthetic-signer@example.invalid", Order = 1 };
            db.Add(signer);
            db.Add(new EmailOutbox { EnvelopeId = id, To = signer.Email, Template = "signer-invitation", AvailableAt = clock.Now,
                PayloadJson = new SignerInvitationProtection(keys).Protect(new(signer.Id, DocumentId: historical, DocumentSha256: Hash, DisclosureSha256: Hash)) });
            await db.SaveChangesAsync();
        }
        var source = Source(id, original); source.Objects.Add(Address(id, "normalized", historical.ToString("N")));
        var snapshot = await Capture(id, request, source);
        Assert.Equal(2, ProductionHoldObjectInventory.OpenVerified(snapshot, keys, clock).Length);
        await Assert.ThrowsAsync<InvalidDataException>(() => Capture(id, request, Source(id, original)));
        // Even a correctly protected/hash-bound manifest cannot omit the old
        // document that exists only inside the protected invitation payload.
        var protector = keys.CreateProtector(ProductionHoldObjectInventory.Version, id.ToString("N"));
        var raw = protector.Unprotect(snapshot.ProtectedManifest);
        try
        {
            var manifest = JsonNode.Parse(raw)!.AsObject();
            manifest["Objects"] = new JsonArray(manifest["Objects"]!.AsArray().Single(x => x!["Address"]!["Area"]!.GetValue<string>() == "originals")!.DeepClone());
            var changed = JsonSerializer.SerializeToUtf8Bytes(manifest);
            var omitted = snapshot with { Objects = 1, Bytes = Content.Length, ProtectedManifest = protector.Protect(changed),
                ManifestSha256 = Convert.ToHexStringLower(SHA256.HashData(changed)) };
            Assert.Throws<InvalidDataException>(() => ProductionHoldObjectInventory.OpenVerified(omitted, keys, clock));
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
    }

    [Fact]
    public async Task Queued_verification_can_be_captured_before_issuance_and_changed_protected_mail_is_not_verified()
    {
        var (id, request, original) = await Held();
        var mail = new EmailOutbox { EnvelopeId = id, To = "synthetic-sender@example.invalid", Template = "sender-verification", AvailableAt = clock.Now,
            PayloadJson = new EmailPayloadProtection(keys).Protect(new(Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(SHA256.HashData(Content)), Guid.NewGuid())) };
        await using (var db = fixture.Open()) { db.Add(mail); await db.SaveChangesAsync(); }
        var snapshot = await Capture(id, request, Source(id, original));
        Assert.Single(ProductionHoldObjectInventory.OpenVerified(snapshot, keys, clock));
        await using (var db = fixture.Open())
            await db.EmailOutbox.Where(x => x.Id == mail.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.PayloadJson, "{}"));
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => Capture(id, request, Source(id, original)));
        Assert.Contains("verification or decline", error.Message);
        // Later corrupt SQL does not rewrite the exact earlier encrypted capture.
        Assert.Single(ProductionHoldObjectInventory.OpenVerified(snapshot, keys, clock));
    }

    [Fact]
    public async Task Actual_captured_invitation_decline_matches_its_protected_SQL_capture_without_renewing_access()
    {
        var storage = new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"));
        Assert.True(storage.Uri.IsLoopback || storage.Uri.Host == "azurite", "Only the disposable local object service is allowed.");
        await using var h = await SendDraftWorkflowTests.Harness.Create(fixture, browser: true, productionRetention: ProductionRetentionLedgerTests.Policy());
        Assert.NotNull(await h.Send()); Assert.True(await h.Once());
        var raw = Regex.Match(h.Sender.Last!.Text, "token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        using var services = h.App.Services.CreateScope();
        var identity = await services.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(raw, null, null);
        Assert.NotNull(identity);
        var principal = SignerAccessConfiguration.Principal(identity);
        var context = await services.ServiceProvider.GetRequiredService<SignerAccess>().GetContextAsync(principal, h.Envelope.PublicId);
        Assert.NotNull(context);
        var pdf = await services.ServiceProvider.GetRequiredService<SignerPdfAccess>().PrepareAsync(principal, context);
        Assert.Equal(identity.DocumentHash, Convert.ToHexStringLower(SHA256.HashData(pdf)));
        var receipt = services.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(context);
        Assert.Equal(ConsentResult.Accepted, await services.ServiceProvider.GetRequiredService<SignerConsent>().AcceptAsync(
            principal, h.Envelope.PublicId, receipt, true, true, "download", null, null));
        Assert.NotNull(await services.ServiceProvider.GetRequiredService<SignerConsent>().DeclineAsync(
            SignerAccessConfiguration.Principal(identity), h.Envelope.PublicId, "Synthetic refusal", null, null));
        var protection = services.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        var request = await Hold(h.Envelope.Id, h.Clock, protection);
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var tokenBefore = await db.AuthTokens.AsNoTracking().SingleAsync(x => x.EnvelopeId == h.Envelope.Id && x.PartyId == identity.SignerId && x.Purpose == TokenPurpose.SignerAccess);
        var snapshot = await new ProductionHoldSqlInventory(db, protection, h.Clock).CaptureLockedAsync(h.Envelope.Id, request.Current.Revision, request.Current.FenceHash!);
        using var sql = ProductionHoldSqlInventory.OpenVerified(snapshot, protection);
        var objects = new List<HoldObjectEvidence> { new(new("normalized", $"{h.Envelope.Id:N}/{identity.DocumentId:N}", "historical", "", "\"etag\"", pdf.LongLength), identity.DocumentHash) };
        ProductionHoldDecisionNotificationReferences.Demand(sql.RootElement, objects, protection);
        ProductionHoldConsentAuditReferences.Demand(sql.RootElement, objects);
        // Reopen the actual authenticated SQL capture again; neither old token
        // nor consent timestamps are renewed by this historical graph reader.
        using (var replay = ProductionHoldSqlInventory.OpenVerified(snapshot, protection))
            ProductionHoldConsentAuditReferences.Demand(replay.RootElement, objects);
        objects.Clear();
        Assert.Throws<InvalidDataException>(() => ProductionHoldDecisionNotificationReferences.Demand(sql.RootElement, objects, protection));
        Assert.Throws<InvalidDataException>(() => ProductionHoldConsentAuditReferences.Demand(sql.RootElement, objects));
        var tokenAfter = await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == tokenBefore.Id);
        Assert.Equal(tokenBefore.ExpiresAt, tokenAfter.ExpiresAt); Assert.Equal(tokenBefore.UsedAt, tokenAfter.UsedAt);
    }

    [Fact]
    public async Task Actual_local_Azurite_private_census_reads_current_and_snapshot_bytes_without_collecting_another_record()
    {
        var service = new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),
            new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
        Assert.True(service.Uri.IsLoopback || service.Uri.Host == "azurite", "Only the disposable local object service is allowed.");
        var (id, request, original) = await Held(); var clients = new List<BlobClient>();
        try
        {
            foreach (var area in ProductionHoldObjectScope.Areas)
                await service.GetBlobContainerClient(area).CreateIfNotExistsAsync(PublicAccessType.None);
            var own = service.GetBlobContainerClient("originals").GetBlobClient($"{id:N}/{original:N}"); clients.Add(own);
            await own.UploadAsync(BinaryData.FromBytes(Content), new BlobUploadOptions { Conditions = new() { IfNoneMatch = ETag.All } });
            await own.CreateSnapshotAsync();
            var unrelated = service.GetBlobContainerClient("originals").GetBlobClient($"{Guid.NewGuid():N}/{Guid.NewGuid():N}"); clients.Add(unrelated);
            await unrelated.UploadAsync(BinaryData.FromString("Unrelated synthetic record - NO AGREEMENT"));
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var result = await new ProductionHoldObjectInventory(db, keys, clock, new AzureProductionHoldObjectSource(service))
                .CaptureLockedAsync(id, request.Current.Revision, request.Current.FenceHash!);
            Assert.Equal(2, result.Objects); Assert.Equal(2 * Content.Length, result.Bytes);
            var manifest = keys.CreateProtector(ProductionHoldObjectInventory.Version, id.ToString("N")).Unprotect(result.ProtectedManifest);
            Assert.DoesNotContain(unrelated.Name, System.Text.Encoding.UTF8.GetString(manifest));
            Assert.True((await unrelated.ExistsAsync()).Value); Assert.True((await own.ExistsAsync()).Value);
        }
        finally
        {
            // Only the exact disposable test objects created above; never a
            // production adapter operation or shared container deletion.
            foreach (var client in clients) await client.DeleteIfExistsAsync(DeleteSnapshotsOption.IncludeSnapshots);
        }
    }

    [Fact]
    public async Task Exact_SQL_and_all_four_object_areas_versions_snapshots_and_replaced_assets_are_bound_in_private_output()
    {
        var (id, request, original) = await Held(); var source = Source(id, original);
        source.Objects.Add(source.Objects[0] with { VersionId = "older-version", ETag = "\"old\"" });
        source.Objects.Add(source.Objects[0] with { VersionId = "", Snapshot = "synthetic-snapshot" });
        source.Objects.Add(Address(id, "normalized", "completion-seals/certificate/" + Guid.NewGuid().ToString("N")));
        source.Objects.Add(Address(id, "previews", Guid.NewGuid().ToString("N")));
        source.Objects.Add(Address(id, "final", "executed/" + Guid.NewGuid().ToString("N")));
        var result = await Capture(id, request, source);
        Assert.Equal(6, result.Objects); Assert.Equal(6 * Content.Length, result.Bytes); Assert.Equal(6, source.Hashes);
        var plain = keys.CreateProtector(ProductionHoldObjectInventory.Version, id.ToString("N")).Unprotect(result.ProtectedManifest);
        Assert.Equal(result.ManifestSha256, Convert.ToHexStringLower(SHA256.HashData(plain)));
        using var json = JsonDocument.Parse(plain); Assert.Equal(id, json.RootElement.GetProperty("RecordId").GetGuid());
        Assert.Equal(result.SqlStateSha256, json.RootElement.GetProperty("SqlStateSha256").GetString());
        Assert.Equal(result.SqlPayloadSha256, json.RootElement.GetProperty("SqlPayloadSha256").GetString());
        using (var sql = ProductionHoldSqlInventory.OpenVerified(result.Sql, keys))
            Assert.Equal(result.SqlStateSha256, sql.RootElement.GetProperty("StateSha256").GetString());
        Assert.Contains("older-version", System.Text.Encoding.UTF8.GetString(plain));
        Assert.DoesNotContain("synthetic-sender", System.Text.Encoding.UTF8.GetString(plain));
        Assert.Equal(8, source.Lists); // both complete censuses, including empty areas
        await using var db = fixture.Open(); Assert.Single(await db.ProductionHoldRequests.Where(x => x.EnvelopeId == id).ToArrayAsync());
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == id).ToArrayAsync());
    }

    [Theory]
    [InlineData("missing")][InlineData("hash")][InlineData("area")]
    public async Task Missing_or_wrong_named_source_is_not_preservation(string fault)
    {
        var (id, request, original) = await Held(); var source = Source(id, original);
        if (fault == "missing") source.Objects.Clear();
        else if (fault == "hash") source.Hash = new string('0', 64);
        else source.Objects[0] = source.Objects[0] with { Area = "normalized" };
        await Assert.ThrowsAsync<InvalidDataException>(() => Capture(id, request, source));
    }

    [Fact]
    public async Task Complete_bounded_pagination_captures_every_page_before_and_after_hashing()
    {
        var (id, request, original) = await Held(); var source = Source(id, original); source.Paginate = true;
        for (var i = 0; i < 150; i++) source.Objects.Add(Address(id, "normalized", Guid.NewGuid().ToString("N")));
        var result = await Capture(id, request, source);
        Assert.Equal(151, result.Objects); Assert.Equal(151, source.Hashes); Assert.Equal(10, source.Lists);
    }

    [Theory]
    [InlineData("added")][InlineData("changed")][InlineData("removed")][InlineData("SQL")]
    public async Task Observed_late_object_or_business_SQL_change_rejects_the_manifest(string fault)
    {
        var (id, request, original) = await Held(); var source = Source(id, original);
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        source.AfterHash = async () =>
        {
            switch (fault)
            {
                case "added": source.Objects.Add(Address(id, "normalized", Guid.NewGuid().ToString("N"))); break;
                case "changed": source.Objects[0] = source.Objects[0] with { ETag = "\"new\"" }; break;
                case "removed": source.Objects.Clear(); break;
                default: await db.Envelopes.Where(x => x.Id == id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "Changed after capture")); break;
            }
        };
        await Assert.ThrowsAsync<DocumentConflictException>(() => new ProductionHoldObjectInventory(db, keys, clock, source)
            .CaptureLockedAsync(id, request.Current.Revision, request.Current.FenceHash!));
    }

    [Theory]
    [InlineData("count")][InlineData("object-bytes")][InlineData("total-bytes")][InlineData("duplicate")]
    [InlineData("escape")][InlineData("traversal")][InlineData("both-selectors")][InlineData("wildcard")][InlineData("weak-etag")][InlineData("cursor-loop")]
    public async Task Bounded_census_rejects_escaped_partial_or_repeating_inventory_before_reading_content(string fault)
    {
        var (id, request, original) = await Held(); var source = Source(id, original); ProductionHoldObjectLimits? limits = null;
        switch (fault)
        {
            case "count": source.Objects.Add(Address(id, "originals", Guid.NewGuid().ToString("N"))); limits = new(MaximumObjects: 1); break;
            case "object-bytes": limits = new(MaximumObjectBytes: Content.Length - 1); break;
            case "total-bytes": limits = new(MaximumTotalBytes: Content.Length - 1); break;
            case "duplicate": source.Objects.Add(source.Objects[0]); break;
            case "escape": source.Objects[0] = source.Objects[0] with { Name = $"{Guid.NewGuid():N}/{original:N}" }; break;
            case "traversal": source.Objects[0] = source.Objects[0] with { Name = $"{id:N}/../outside" }; break;
            case "both-selectors": source.Objects[0] = source.Objects[0] with { Snapshot = "synthetic-snapshot" }; break;
            case "wildcard": source.Objects[0] = source.Objects[0] with { ETag = "*" }; break;
            case "weak-etag": source.Objects[0] = source.Objects[0] with { ETag = "W/\"weak\"" }; break;
            default: source.Loop = true; break;
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => Capture(id, request, source, limits)); Assert.Equal(0, source.Hashes);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Expiry_or_cancellation_after_storage_read_cannot_publish_a_manifest(bool cancel)
    {
        var (id, request, original) = await Held(); var source = Source(id, original); using var cts = new CancellationTokenSource();
        source.AfterHash = () => { if (cancel) cts.Cancel(); else clock.Now = clock.Now.AddMinutes(10); return Task.CompletedTask; };
        var error = await Record.ExceptionAsync(() => Capture(id, request, source, ct: cts.Token));
        Assert.True(cancel ? error is OperationCanceledException : error is UnauthorizedAccessException, error?.ToString());
    }

    [Theory]
    [InlineData("ciphertext")][InlineData("record")][InlineData("fence")][InlineData("state")][InlineData("tables")][InlineData("payload")]
    public async Task SQL_snapshot_reader_authenticates_bytes_and_all_bound_external_summary_fields(string fault)
    {
        var (id, request, _) = await Held(); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var snapshot = await new ProductionHoldSqlInventory(db, keys, clock).CaptureLockedAsync(id, request.Current.Revision, request.Current.FenceHash!);
        using (var verified = ProductionHoldSqlInventory.OpenVerified(snapshot, keys)) Assert.Equal(id, verified.RootElement.GetProperty("RecordId").GetGuid());
        var altered = fault switch
        {
            "ciphertext" => snapshot with { ProtectedPayload = [1, 2, 3] },
            "record" => snapshot with { RecordId = Guid.NewGuid() },
            "fence" => snapshot with { FenceHash = new string('0', 64) },
            "state" => snapshot with { StateSha256 = new string('0', 64) },
            "tables" => snapshot with { Tables = [] },
            _ => snapshot with { PayloadSha256 = new string('0', 64) }
        };
        var error = Record.Exception(() => ProductionHoldSqlInventory.OpenVerified(altered, keys).Dispose());
        Assert.True(error is CryptographicException or InvalidDataException, error?.ToString());
    }

    private async Task<(Guid, ProductionHoldRequestReceipt, Guid)> Held()
    {
        var original = Guid.NewGuid(); var envelope = new Envelope { SenderEmail = "synthetic-sender@example.invalid", CreatedAt = clock.Now };
        await using var db = fixture.Open();
        await using (var creation = await db.Database.BeginTransactionAsync())
        {
            db.Add(envelope); await new ProductionRetentionLedger(db, new(db, clock), clock).PrepareNewLockedAsync(envelope, ProductionRetentionLedgerTests.Policy());
            await creation.CommitAsync();
        }
        envelope.OriginalBlob = original.ToString("N"); envelope.OriginalSha256 = SHA256.HashData(Content); await db.SaveChangesAsync();
        var request = await Hold(envelope.Id, clock, keys);
        return (envelope.Id, request, original);
    }
    private async Task<ProductionHoldRequestReceipt> Hold(Guid id, TimeProvider at, IDataProtectionProvider protection)
    {
        var command = new ProductionHoldCommand(Guid.NewGuid(), id, Guid.NewGuid(), 0, ProductionHoldOperation.Place, "Synthetic preservation", "Synthetic reason", "synthetic-reference");
        const string issuer = "https://operator.synthetic.invalid"; const string subject = "synthetic-operator";
        var operators = new ProductionOperatorPolicy(true, [new(issuer, subject, new HashSet<ProductionOperatorPermission> { command.Permission })]);
        var ticket = new AuthenticationTicket(new(new ClaimsIdentity([new("iss", issuer, ClaimValueTypes.String, issuer), new("sub", subject, ClaimValueTypes.String, issuer)], ProductionOperatorAuthority.OidcScheme)),
            new AuthenticationProperties { IssuedUtc = at.GetUtcNow(), ExpiresUtc = at.GetUtcNow().AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme);
        var authority = ProductionOperatorAuthority.FromValidatedTicket(ticket, operators, command.Permission, at);
        await using var db = fixture.Open();
        await using var tx = await db.Database.BeginTransactionAsync();
        var request = await new ProductionHoldRequests(db, protection, at).PrepareLockedAsync(authority, operators, command); await tx.CommitAsync();
        return request;
    }
    private async Task<ProductionHoldObjectSnapshot> Capture(Guid id, ProductionHoldRequestReceipt request, Fake source,
        ProductionHoldObjectLimits? limits = null, CancellationToken ct = default)
    {
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        return await new ProductionHoldObjectInventory(db, keys, clock, source).CaptureLockedAsync(id, request.Current.Revision, request.Current.FenceHash!, limits, ct);
    }
    private static HoldObjectAddress Address(Guid id, string area, string name) => new(area, $"{id:N}/{name}", "synthetic-version", "", "\"synthetic-etag\"", Content.Length);
    private static Fake Source(Guid id, Guid original) => new() { Objects = [Address(id, "originals", original.ToString("N"))] };
    private sealed class Fake : IProductionHoldObjectSource
    {
        internal List<HoldObjectAddress> Objects = []; internal string Hash = ProductionHoldObjectInventoryTests.Hash;
        internal int Lists, Hashes; internal bool Loop, Paginate; internal Func<Task>? AfterHash;
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct)
        {
            Lists++;
            var selected = Objects.Where(x => x.Area == area || area == "originals" && x.Name.Contains("/../")).ToArray();
            if (Paginate)
            {
                var start = continuation is null ? 0 : int.Parse(continuation, System.Globalization.CultureInfo.InvariantCulture);
                var page = selected.Skip(start).Take(maximum).ToArray(); var next = start + page.Length;
                return Task.FromResult(new HoldObjectPage(page, next < selected.Length ? next.ToString(System.Globalization.CultureInfo.InvariantCulture) : null));
            }
            return Task.FromResult(new HoldObjectPage(selected, Loop ? "same-cursor" : null));
        }
        public async Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress address, CancellationToken ct)
        { Hashes++; if (AfterHash is not null) await AfterHash(); return Hash; }
    }
    private sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
