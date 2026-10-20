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
