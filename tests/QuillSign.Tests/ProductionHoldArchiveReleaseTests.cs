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

public sealed class ProductionHoldArchiveReleaseTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    internal static readonly byte[] Raw = "Synthetic retained source - NO AGREEMENT"u8.ToArray();
    [Fact]
    public async Task Exact_historical_complete_bundle_releases_only_its_own_versions_after_independent_request_extensions_and_restart()
    {
        await using var run = await Run.Create(fixture); var first = await run.Plan();
        var firstState = await new ProductionHoldControls(run.Db, run.Keys, run.Time).ReadLockedAsync(run.Id);
        var sibling = Guid.NewGuid(); await run.Command(sibling, ProductionHoldOperation.Place);
        var second = await run.Plan(sibling); var release = await run.Command(run.Hold, ProductionHoldOperation.Release);
        await run.Commit();
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var store = new AzureProductionHoldArchiveReleaseStore(run.Service);
        var controls = await new ProductionHoldControls(db, run.Keys, run.Time).ReadLockedAsync(run.Id);
        foreach (var receipt in firstState.Items)
        {
            var scope = await ProductionHoldArchiveReleaseCapability.AuthorizeLockedAsync(db, run.Keys, run.Time, run.Fence, run.Hold, release, first.PlanId, receipt.Stored.Path);
            Assert.Equal(receipt.Stored, await store.InspectAsync(scope));
            Assert.Equal(receipt.Stored, await store.ReleaseAsync(scope));
            Assert.Equal(receipt.Stored, await store.ReleaseAsync(scope)); // Exact command replay, no second PUT.
            Assert.False(run.Provider.Files[receipt.Stored.Path].Held);
        }
        Assert.Equal(firstState.Items.Count, run.Provider.Clears);
        Assert.All(controls.Items.Where(x => x.PlanId == second.PlanId), x => Assert.True(run.Provider.Files[x.Stored.Path].Held));
        Assert.Equal(controls.Prefix, (await new ProductionHoldControls(db, run.Keys, run.Time).ReadLockedAsync(run.Id)).Prefix);
        Assert.True((await new ProductionHoldRequests(db, run.Keys, run.Time).ReadLockedAsync(run.Id)).BlocksDeletion);
        Assert.DoesNotContain(run.Provider.Calls, x => x.Contains("immutabilitypolicy", StringComparison.Ordinal) || x.StartsWith("DELETE", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("no-release")][InlineData("wrong-command")][InlineData("sibling")][InlineData("path")][InlineData("missing-receipt")][InlineData("other-partial")][InlineData("business")][InlineData("request-tamper")]
    public async Task Missing_authority_receipts_changed_business_or_nonextending_history_never_reach_provider(string fault)
    {
        await using var run = await Run.Create(fixture); var plan = await run.Plan(complete: fault != "missing-receipt");
        if (fault == "other-partial") _ = await run.Plan(complete: false);
        var release = fault == "no-release" ? Guid.NewGuid() : await run.Command(run.Hold, ProductionHoldOperation.Release);
        if (fault == "wrong-command") release = Guid.NewGuid();
        if (fault == "business") await run.Db.Envelopes.Where(x => x.Id == run.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Message, "Changed business evidence"));
        if (fault == "request-tamper") await run.Db.Database.ExecuteSqlInterpolatedAsync($"UPDATE [ProductionHoldRequests] SET [At]=DATEADD(second,-1,[At]) WHERE [EnvelopeId]={run.Id} AND [Revision]=1");
        var item = ProductionHoldBundlePlan.OpenVerified(plan, run.Keys, run.Time).Items[0]; var before = run.Provider.Calls.Count;
        var error = await Record.ExceptionAsync(() => ProductionHoldArchiveReleaseCapability.AuthorizeLockedAsync(run.Db, run.Keys, run.Time, run.Fence,
            fault == "sibling" ? Guid.NewGuid() : run.Hold, release, plan.PlanId, fault == "path" ? item.Path + "/foreign" : item.Path));
        Assert.True(error is DocumentConflictException or InvalidDataException, error?.ToString());
        Assert.Equal(before, run.Provider.Calls.Count); Assert.Equal(0, run.Provider.Clears);
    }

    [Theory]
    [InlineData("bad-bytes")][InlineData("wrong-version")][InlineData("wrong-etag")][InlineData("unheld")][InlineData("hold-race")][InlineData("public")][InlineData("versioning-off")]
    public async Task Inspect_rejects_provider_selector_bytes_or_protection_faults_before_clear(string fault)
    {
        await using var run = await Run.Create(fixture); var plan = await run.Plan(); var release = await run.Command(run.Hold, ProductionHoldOperation.Release);
        var scope = await run.Scope(plan, release); run.Provider.Fault = fault;
        await Assert.ThrowsAsync<InvalidDataException>(() => new AzureProductionHoldArchiveReleaseStore(run.Service).InspectAsync(scope));
        Assert.Equal(0, run.Provider.Clears);
    }

    [Theory]
    [InlineData("lost-ack")][InlineData("normal")]
    public async Task Exact_clear_and_lost_ack_recheck_bytes_and_unchanged_time_policy(string fault)
    {
        await using var run = await Run.Create(fixture); var plan = await run.Plan(); var release = await run.Command(run.Hold, ProductionHoldOperation.Release);
        var scope = await run.Scope(plan, release); run.Provider.Fault = fault;
        var fenceCalls = run.Fence.Calls; var providerCalls = run.Provider.Calls.Count;
        var result = await new AzureProductionHoldArchiveReleaseStore(run.Service).ReleaseAsync(scope);
        Assert.Equal(scope.Stored, result); Assert.Equal(1, run.Provider.Clears);
        Assert.False(run.Provider.Files[result.Path].Held);
        Assert.True(run.Fence.Calls - fenceCalls > run.Provider.Calls.Count - providerCalls);
    }

    [Theory]
    [InlineData("refusal")][InlineData("policy-changed")][InlineData("changed-after-clear")]
    public async Task Refused_clear_changed_immutability_or_changed_bytes_never_report_released(string fault)
    {
        await using var run = await Run.Create(fixture); var plan = await run.Plan(); var release = await run.Command(run.Hold, ProductionHoldOperation.Release);
        var scope = await run.Scope(plan, release); run.Provider.Fault = fault;
        await Assert.ThrowsAsync<InvalidDataException>(() => new AzureProductionHoldArchiveReleaseStore(run.Service).ReleaseAsync(scope));
        Assert.Equal(1, run.Provider.Clears);
    }

    [Theory]
    [InlineData("before")][InlineData("container")][InlineData("download")][InlineData("stream")][InlineData("clear")][InlineData("expires")]
    public async Task Dynamic_fence_or_clock_loss_stops_before_further_provider_IO(string phase)
    {
        await using var run = await Run.Create(fixture); var plan = await run.Plan(); var release = await run.Command(run.Hold, ProductionHoldOperation.Release);
        var scope = await run.Scope(plan, release); var start = run.Provider.Calls.Count;
        if (phase == "before") run.Fence.Allowed = false;
        else if (phase == "expires") run.Time.Now = run.Time.Now.AddMinutes(10);
        else run.Provider.After = operation => { if (operation == phase) run.Fence.Allowed = false; };
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => new AzureProductionHoldArchiveReleaseStore(run.Service).ReleaseAsync(scope));
        if (phase is "before" or "expires") Assert.Equal(start, run.Provider.Calls.Count);
        else Assert.Equal(phase == "container" ? 1 : phase is "download" or "stream" ? 3 : 5, run.Provider.Calls.Count - start);
        Assert.Equal(phase == "clear" ? 1 : 0, run.Provider.Clears);
    }

    private sealed class Clock : TimeProvider
    { internal DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero); public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Fence : IProductionHoldReleaseFence
    {
        internal bool Allowed = true; internal int Calls;
        public Task DemandReleaseAsync(Guid recordId, Guid holdId, Guid releaseCommandId, long requestRevision, string requestFenceHash, CancellationToken ct = default)
        { ct.ThrowIfCancellationRequested(); Calls++; if (!Allowed) throw new UnauthorizedAccessException("Synthetic revoked durable fence"); return Task.CompletedTask; }
    }
    private sealed class Run : IAsyncDisposable
    {
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider(); internal readonly Clock Time = new(); internal readonly Fence Fence = new();
        internal readonly Provider Provider = new(); internal QuillSignDbContext Db = null!; internal Guid Id, Hold = Guid.NewGuid();
        private IDbContextTransaction transaction = null!;
        internal BlobServiceClient Service { get; private set; } = null!;
        internal static async Task<Run> Create(SqlDatabaseFixture fixture)
        {
            var run = new Run { Db = fixture.Open() };
            try
            {
                var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03) { Transport = new HttpClientTransport(new HttpClient(run.Provider)) };
                options.Retry.MaxRetries = 0; options.Diagnostics.IsLoggingEnabled = false; options.Diagnostics.IsDistributedTracingEnabled = false;
                run.Service = new(new Uri("https://storage.example.invalid"), new Credential(), options);
                var e = new Envelope { SenderEmail = "synthetic-release@example.invalid", CreatedAt = run.Time.Now };
                await using (var creation = await run.Db.Database.BeginTransactionAsync())
                { run.Db.Add(e); await new ProductionRetentionLedger(run.Db, new(run.Db, run.Time), run.Time).PrepareNewLockedAsync(e, ProductionRetentionLedgerTests.Policy()); await creation.CommitAsync(); }
                run.Id = e.Id; run.Provider.Source = new("originals", $"{run.Id:N}/{Guid.NewGuid():N}", "synthetic-source-version", "", "\"synthetic-source-etag\"", Raw.Length);
                run.transaction = await run.Db.Database.BeginTransactionAsync(); await run.Command(run.Hold, ProductionHoldOperation.Place); return run;
            }
            catch { await run.DisposeAsync(); throw; }
        }
        internal async Task<Guid> Command(Guid hold, ProductionHoldOperation operation)
        {
            const string issuer = "https://operator.synthetic.invalid", subject = "synthetic-operator";
            var permission = operation == ProductionHoldOperation.Place ? ProductionOperatorPermission.PlaceHold : ProductionOperatorPermission.ReleaseHold;
            var policy = new ProductionOperatorPolicy(true, [new(issuer, subject, new HashSet<ProductionOperatorPermission> { permission })]);
            var ticket = new AuthenticationTicket(new(new ClaimsIdentity([new("iss", issuer, ClaimValueTypes.String, issuer), new("sub", subject, ClaimValueTypes.String, issuer)], ProductionOperatorAuthority.OidcScheme)),
                new AuthenticationProperties { IssuedUtc = Time.Now, ExpiresUtc = Time.Now.AddMinutes(5) }, ProductionOperatorAuthority.CookieScheme);
            var authority = ProductionOperatorAuthority.FromValidatedTicket(ticket, policy, permission, Time);
            var current = await new ProductionHoldRequests(Db, Keys, Time).ReadLockedAsync(Id);
            var command = new ProductionHoldCommand(Guid.NewGuid(), Id, hold, current.Revision, operation, "Synthetic hold", "Synthetic private reason", "synthetic-reference");
            await new ProductionHoldRequests(Db, Keys, Time).PrepareLockedAsync(authority, policy, command); return command.CommandId;
        }
        internal async Task<ProductionHoldProtectedPlan> Plan(Guid? selected = null, bool complete = true)
        {
            var hold = selected ?? Hold; var current = await new ProductionHoldRequests(Db, Keys, Time).ReadLockedAsync(Id);
            var inventory = await new ProductionHoldObjectInventory(Db, Keys, Time, new Sources(Provider.Source!)).CaptureLockedAsync(Id, current.Revision, current.FenceHash!);
            var plan = await ProductionHoldBundlePlan.FreezeLockedAsync(Db, Keys, Time, hold, Guid.NewGuid(), inventory);
            var controls = new ProductionHoldControls(Db, Keys, Time); await controls.SavePlanLockedAsync(plan);
            if (complete) foreach (var item in ProductionHoldBundlePlan.OpenVerified(plan, Keys, Time).Items)
                await controls.PreserveItemLockedAsync(Id, plan.PlanId, item.Path, Guid.NewGuid(), new(Service));
            return plan;
        }
        internal Task<ProductionHoldArchiveReleaseCapability> Scope(ProductionHoldProtectedPlan plan, Guid release)
            => ProductionHoldArchiveReleaseCapability.AuthorizeLockedAsync(Db, Keys, Time, Fence, Hold, release, plan.PlanId,
                ProductionHoldBundlePlan.OpenVerified(plan, Keys, Time).Items[0].Path);
        internal Task Commit() => transaction.CommitAsync();
        public async ValueTask DisposeAsync() { if (transaction is not null) await transaction.DisposeAsync(); if (Db is not null) await Db.DisposeAsync(); Provider.Dispose(); }
    }
    internal sealed class Sources(HoldObjectAddress source) : IProductionHoldObjectSource
    {
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope, string area, string? continuation, int maximum, CancellationToken ct) => Task.FromResult(new HoldObjectPage(area == source.Area ? [source] : [], null));
        public Task<string> HashAsync(ProductionHoldObjectScope scope, HoldObjectAddress value, CancellationToken ct) => Task.FromResult(Convert.ToHexStringLower(SHA256.HashData(Raw)));
    }
    internal sealed class File(byte[] bytes, string version)
    { internal byte[] Bytes = bytes; internal string Version = version; internal bool Held = true; }
    internal sealed class Provider : HttpMessageHandler
    {
        internal readonly Dictionary<string, File> Files = []; internal readonly List<string> Calls = []; private readonly Dictionary<string, byte[]> blocks = [];
        internal string Fault = "normal"; internal int Clears, Heads; internal Action<string>? After;
        internal HoldObjectAddress? Source;
        internal readonly Dictionary<HoldObjectAddress,byte[]> SourceFiles = [];
        private const string Tag = "\"synthetic-etag\"";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var query = QueryHelpers.ParseQuery(request.RequestUri!.Query); string Q(string n) => query.TryGetValue(n, out var v) ? v.ToString() : "";
            string H(string n) => request.Headers.TryGetValues(n, out var v) ? v.Single() : "";
            var path = request.RequestUri.AbsolutePath; var comp = Q("comp"); Calls.Add(request.Method + " " + path + "?" + request.RequestUri.Query);
            Assert.Equal("storage.example.invalid", request.RequestUri.Host);
            if (Q("restype") == "container")
            {
                Assert.True(path == "/final" || Source is { } source && path == "/" + source.Area || SourceFiles.Keys.Any(x=>path=="/"+x.Area)); Assert.Equal(HttpMethod.Get, request.Method);
                var result = Reply([]); result.Headers.TryAddWithoutValidation("x-ms-immutable-storage-with-versioning-enabled", Fault == "versioning-off" ? "false" : "true");
                if (Fault == "public") result.Headers.TryAddWithoutValidation("x-ms-blob-public-access", "blob"); After?.Invoke("container"); return result;
            }
            if (Source is { } original && path == "/" + original.Area + "/" + original.Name)
            {
                Assert.Equal(HttpMethod.Get, request.Method); Assert.Equal(original.VersionId, Q("versionid")); Assert.Equal(original.ETag, H("If-Match"));
                var read = Reply(Raw); read.Content.Headers.ContentLength = original.Length;
                read.Headers.TryAddWithoutValidation("ETag", original.ETag); read.Headers.TryAddWithoutValidation("x-ms-version-id", original.VersionId); return read;
            }
            var selected=SourceFiles.SingleOrDefault(x=>path=="/"+x.Key.Area+"/"+x.Key.Name);
            if(selected.Key is not null)
            {
                Assert.Equal(HttpMethod.Get,request.Method);Assert.Equal(selected.Key.VersionId,Q("versionid"));Assert.Equal(selected.Key.ETag,H("If-Match"));
                var read=Reply(selected.Value);read.Content.Headers.ContentLength=selected.Key.Length;
                read.Headers.TryAddWithoutValidation("ETag",selected.Key.ETag);read.Headers.TryAddWithoutValidation("x-ms-version-id",selected.Key.VersionId);return read;
            }
            Assert.StartsWith("/final/production-holds/", path); var name = path[7..];
            if (comp == "block") { Assert.Equal(HttpMethod.Put, request.Method); blocks[Q("blockid")] = await request.Content!.ReadAsByteArrayAsync(ct); var staged = Reply([]); staged.StatusCode = HttpStatusCode.Created; return staged; }
            if (comp == "blocklist")
            {
                Assert.Equal("*", H("If-None-Match")); Assert.Equal("true", H("x-ms-legal-hold"));
                var order = XDocument.Parse(await request.Content!.ReadAsStringAsync(ct)).Root!.Elements().Select(x => x.Value);
                Assert.False(Files.ContainsKey(name)); Files[name] = new(order.SelectMany(x => blocks[x]).ToArray(), "synthetic-version-" + Files.Count); var committed = Reply([]); committed.StatusCode = HttpStatusCode.Created; return committed;
            }
            if (!Files.TryGetValue(name, out var file)) return Error(HttpStatusCode.NotFound, "BlobNotFound");
            if (Q("versionid") != "") Assert.Equal(file.Version, Q("versionid"));
            if (comp == "legalhold")
            {
                Assert.Equal(HttpMethod.Put, request.Method); Assert.Equal(file.Version, Q("versionid")); Assert.Equal("false", H("x-ms-legal-hold"));
                Assert.Equal("", H("x-ms-immutability-policy-until-date")); Clears++;
                if (Fault == "refusal") return Error(HttpStatusCode.Forbidden, "AuthorizationPermissionMismatch");
                file.Held = false; After?.Invoke("clear");
                return Fault == "lost-ack" ? Error(HttpStatusCode.InternalServerError, "SyntheticLostAcknowledgement") : Reply([]);
            }
            if (Q("versionid") != "") Assert.Equal(Tag, H("If-Match"));
            if (request.Method == HttpMethod.Head) Heads++;
            var bytes = file.Bytes.ToArray(); if (request.Method == HttpMethod.Get && (Fault == "bad-bytes" || Fault == "changed-after-clear" && !file.Held)) bytes[0] ^= 1;
            var response = Reply(request.Method == HttpMethod.Head ? [] : bytes); response.Content.Headers.ContentLength = file.Bytes.Length;
            if (request.Method == HttpMethod.Get)
            { response.Content = new StreamContent(new ObservedStream(bytes, () => After?.Invoke("stream"))); response.Content.Headers.ContentLength = file.Bytes.Length; }
            response.Headers.TryAddWithoutValidation("ETag", Fault == "wrong-etag" ? "\"changed\"" : Tag);
            response.Headers.TryAddWithoutValidation("x-ms-version-id", Fault == "wrong-version" ? "changed-version" : file.Version);
            response.Headers.TryAddWithoutValidation("x-ms-legal-hold", (file.Held && Fault != "unheld" && !(Fault == "hold-race" && Heads % 2 == 0)).ToString().ToLowerInvariant());
            response.Headers.TryAddWithoutValidation("x-ms-blob-type", "BlockBlob"); response.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode", "Locked");
            response.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date", Fault == "policy-changed" && !file.Held ? "Tue, 01 Jan 2030 13:00:00 GMT" : "Tue, 01 Jan 2030 14:00:00 GMT");
            if (request.Method == HttpMethod.Get) After?.Invoke("download"); return response;
        }
        private static HttpResponseMessage Reply(byte[] bytes)
        { var result = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }; result.Headers.TryAddWithoutValidation("x-ms-version", "2023-11-03"); result.Headers.TryAddWithoutValidation("x-ms-request-id", "synthetic-no-agreement"); return result; }
        private static HttpResponseMessage Error(HttpStatusCode code, string error)
        { var response = Reply(Encoding.UTF8.GetBytes($"<Error><Code>{error}</Code><Message>Synthetic failure</Message></Error>")); response.StatusCode = code; response.Headers.TryAddWithoutValidation("x-ms-error-code", error); return response; }
    }
    private sealed class ObservedStream(byte[] bytes, Action reading) : MemoryStream(bytes, false)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { reading(); return base.ReadAsync(buffer, ct); }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) { reading(); return base.ReadAsync(buffer, offset, count, ct); }
    }
    internal sealed class Credential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken ct) => new("synthetic-no-agreement", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken ct) => ValueTask.FromResult(GetToken(context, ct));
    }
}
