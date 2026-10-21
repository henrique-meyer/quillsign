using System.Net;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionHoldArchiveInspectionTransportTests
{
    [Theory]
    [InlineData("sql")][InlineData("manifests")][InlineData("objects")]
    public async Task Exact_held_historical_version_is_read_even_when_latest_is_different_and_inspection_never_mutates(string kind)
    {
        using var test = new Provider(kind: kind); var before = test.Scope.Stored;
        Assert.Equal(before, await test.Store.InspectAsync(test.Scope));
        Assert.Equal(4, test.Calls.Count); Assert.All(test.Calls, x => Assert.True(x.Method == HttpMethod.Get || x.Method == HttpMethod.Head));
        Assert.All(test.Calls.Skip(1), x => { Assert.Equal(Provider.Version, x.Version); Assert.Equal(Provider.Tag, x.Match); });
        Assert.Equal(256 * 1024, test.LargestRead); Assert.True(test.Scope.Demands > test.Calls.Count * 2);
        Assert.Equal(before, await test.Store.InspectAsync(test.Scope)); Assert.Equal(8, test.Calls.Count); Assert.Equal(before, test.Scope.Stored);
    }
    [Theory]
    [InlineData("wrong-version")][InlineData("wrong-etag")][InlineData("wrong-length")][InlineData("wrong-type")][InlineData("unheld")]
    [InlineData("wrong-bytes")][InlineData("truncated")][InlineData("overlong")][InlineData("hold-race")][InlineData("mode-race")][InlineData("expiry-race")]
    [InlineData("public")][InlineData("versioning-off")][InlineData("download-version")][InlineData("download-etag")][InlineData("download-length")][InlineData("policy-added")]
    public async Task Selector_bytes_private_configuration_and_same_ETag_protection_changes_refuse_the_entire_observation(string mode)
    {
        using var test = new Provider(mode); await Assert.ThrowsAsync<InvalidDataException>(() => test.Store.InspectAsync(test.Scope));
        Assert.All(test.Calls, x => Assert.True(x.Method == HttpMethod.Head || x.Method == HttpMethod.Get));
        Assert.All(test.Calls.Skip(1), x => Assert.Equal(Provider.Version, x.Version));
        if (mode is "hold-race" or "mode-race" or "expiry-race" or "policy-added") Assert.Equal(4, test.Calls.Count);
    }
    [Fact]
    public async Task An_absent_time_policy_is_not_invented_but_legal_hold_must_still_remain_true()
    { using var test = new Provider("no-policy"); Assert.Equal(test.Scope.Stored, await test.Store.InspectAsync(test.Scope)); Assert.Equal(4, test.Calls.Count); }
    [Theory]
    [InlineData("before")][InlineData("container")][InlineData("before-head")][InlineData("download")][InlineData("stream")][InlineData("after-head")]
    public async Task Revoked_scope_stops_before_further_provider_IO_and_disposes_the_download(string phase)
    {
        using var test = new Provider(); if (phase == "before") test.Scope.Allowed = false;
        else test.After = operation => { if (operation == phase) test.Scope.Allowed = false; };
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => test.Store.InspectAsync(test.Scope));
        Assert.Equal(phase switch { "before" => 0, "container" => 1, "before-head" => 2, "download" or "stream" => 3, _ => 4 }, test.Calls.Count);
        if (phase is "download" or "stream" or "after-head") Assert.True(test.StreamDisposed);
    }
    [Fact]
    public async Task Scope_expiry_during_streaming_and_cancelled_inspection_cannot_read_any_more_provider_state()
    {
        using var test = new Provider(); test.After = phase => { if (phase == "stream") test.Time.Now = test.Scope.Expires; };
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => test.Store.InspectAsync(test.Scope)); Assert.Equal(3, test.Calls.Count); Assert.True(test.StreamDisposed);
        using var cancelled = new Provider(); using var stop = new CancellationTokenSource(); stop.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled.Store.InspectAsync(cancelled.Scope, stop.Token)); Assert.Empty(cancelled.Calls);
    }
    [Fact]
    public async Task A_changed_descriptor_or_backwards_clock_cannot_switch_the_pinned_archive_mid_read()
    {
        using var test = new Provider(); test.After = phase => { if (phase == "container") test.Scope.Stored = test.Scope.Stored with { VersionId = "foreign" }; };
        await Assert.ThrowsAsync<InvalidDataException>(() => test.Store.InspectAsync(test.Scope)); Assert.Single(test.Calls);
        using var clock = new Provider(); clock.After = phase => { if (phase == "container") clock.Time.Now = clock.Time.Now.AddTicks(-1); };
        await Assert.ThrowsAsync<InvalidDataException>(() => clock.Store.InspectAsync(clock.Scope)); Assert.Single(clock.Calls);
    }
    [Theory]
    [InlineData("missing")][InlineData("busy")][InlineData("unauthorized")][InlineData("forbidden")]
    public async Task Provider_failure_has_no_hidden_retry_create_or_latest_fallback(string mode)
    {
        using var test = new Provider(mode); var error = await Assert.ThrowsAsync<InvalidDataException>(() => test.Store.InspectAsync(test.Scope));
        var provider = Assert.IsType<RequestFailedException>(error.InnerException); Assert.Equal(mode switch { "missing" => 404, "unauthorized" => 401, "forbidden" => 403, _ => 503 }, provider.Status);
        Assert.Equal(mode == "missing" ? 2 : 1, test.Calls.Count); Assert.All(test.Calls, x => Assert.True(HttpMethod.Get == x.Method || HttpMethod.Head == x.Method));
    }
    [Fact]
    public async Task Provider_redirect_is_refused_without_an_authorized_request_to_another_account()
    { using var test = new Provider("redirect"); await Assert.ThrowsAsync<UnauthorizedAccessException>(() => test.Store.InspectAsync(test.Scope)); Assert.Single(test.Calls); }
    [Theory]
    [InlineData("ordinary-final")][InlineData("foreign-prefix")][InlineData("empty-id")][InlineData("uppercase-id")][InlineData("wrong-family")]
    [InlineData("extra-segment")][InlineData("source-selector")][InlineData("hash")][InlineData("length")][InlineData("empty-version")][InlineData("wildcard")][InlineData("etag")]
    public async Task Noncanonical_or_unbounded_receipts_are_rejected_before_any_provider_request(string fault)
    {
        using var test = new Provider(); var stored = test.Scope.Stored; var parts = stored.Path.Split('/');
        switch (fault)
        {
            case "ordinary-final": stored = stored with { Path = Guid.NewGuid().ToString("N") + "/final.pdf" }; break;
            case "foreign-prefix": stored = stored with { Path = stored.Path.Replace("production-holds", "business-records", StringComparison.Ordinal) }; break;
            case "empty-id": parts[1] = Guid.Empty.ToString("N"); stored = stored with { Path = string.Join('/', parts) }; break;
            case "uppercase-id": parts[1] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".ToUpperInvariant(); stored = stored with { Path = string.Join('/', parts) }; break;
            case "wrong-family": parts[4] = "source"; stored = stored with { Path = string.Join('/', parts) }; break;
            case "extra-segment": stored = stored with { Path = stored.Path + "/extra" }; break;
            case "source-selector": stored = stored with { Path = stored.Path.Replace("/sql/", "/objects/", StringComparison.Ordinal) }; break;
            case "hash": stored = stored with { Sha256 = new('d', 64) }; break;
            case "length": stored = stored with { Length = 64L * 1024 * 1024 + 1 }; break;
            case "empty-version": stored = stored with { VersionId = "" }; break;
            case "wildcard": stored = stored with { VersionId = "*" }; break;
            case "etag": stored = stored with { ETag = "*" }; break;
        }
        test.Scope.Stored = stored; await Assert.ThrowsAsync<InvalidDataException>(() => test.Store.InspectAsync(test.Scope)); Assert.Empty(test.Calls);
    }
    [Theory]
    [InlineData("http://storage.example.invalid/")][InlineData("https://storage.example.invalid/path")][InlineData("https://storage.example.invalid/?q=1")]
    [InlineData("https://storage.example.invalid/#fragment")][InlineData("https://user@storage.example.invalid/")][InlineData("https://storage-secondary.example.invalid/")]
    public void Unreviewed_endpoints_are_rejected_before_a_client_can_issue_requests(string uri)
    { Assert.Throws<InvalidDataException>(() => new AzureProductionHoldArchiveInspectionStore(new(uri), new Credential(), new Clock())); }

    private sealed class Clock : TimeProvider
    { internal DateTimeOffset Now = new(2030,1,1,12,0,0,TimeSpan.Zero); public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Scope(ProductionHoldArchiveStoredObject stored, Clock time) : IProductionHoldArchiveReadScope
    {
        public ProductionHoldArchiveStoredObject Stored { get; set; } = stored;
        internal bool Allowed = true; internal int Demands;
        internal readonly DateTimeOffset Expires = time.Now.AddMinutes(10);
        public Task DemandAsync(CancellationToken ct = default)
        { ct.ThrowIfCancellationRequested(); Demands++; if (!Allowed || time.Now >= Expires) throw new UnauthorizedAccessException("Synthetic expired/revoked inspection scope."); return Task.CompletedTask; }
    }
    private sealed record Call(HttpMethod Method, string Version, string Match);
    private sealed class Provider : HttpMessageHandler
    {
        internal const string Version = "2030-01-01T00:00:00.0000000Z", Tag = "\"retained-archive-tag\"";
        private readonly string mode; private readonly byte[] bytes = Enumerable.Range(0, 600 * 1024 + 17).Select(i => (byte)(i % 251)).ToArray();
        internal readonly Clock Time = new(); internal readonly Scope Scope;
        internal readonly List<Call> Calls = []; internal Action<string>? After;
        internal int LargestRead; internal bool StreamDisposed; private int heads;
        internal readonly AzureProductionHoldArchiveInspectionStore Store;
        internal Provider(string mode = "normal", string kind = "sql")
        {
            this.mode = mode; var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            var path = $"production-holds/{Guid.NewGuid():N}/{Guid.NewGuid():N}/{Guid.NewGuid():N}/{kind}/" + (kind == "objects" ? new string('c',64) + "/" : "") + hash;
            Scope = new(new(path, bytes.Length, hash, Version, Tag), Time);
            Store = new(new Uri("https://storage.example.invalid"), new Credential(), Time, new HttpClientTransport(new HttpClient(this, false)));
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); Assert.Equal("storage.example.invalid", request.RequestUri!.Host);
            var query = QueryHelpers.ParseQuery(request.RequestUri.Query); string Q(string key) => query.TryGetValue(key, out var value) ? value.ToString() : "";
            var match = request.Headers.TryGetValues("If-Match", out var values) ? values.Single() : ""; Calls.Add(new(request.Method, Q("versionid"), match));
            Assert.True(request.Method == HttpMethod.Get || request.Method == HttpMethod.Head, "Inspection cannot mutate provider state.");
            if (Q("restype") == "container")
            {
                Assert.Equal("/final", request.RequestUri.AbsolutePath); Assert.Equal(HttpMethod.Get, request.Method);
                if (mode == "redirect") { var redirected = Reply([]); redirected.StatusCode = HttpStatusCode.TemporaryRedirect; redirected.Headers.Location = new("https://foreign.example.invalid/"); return Task.FromResult(redirected); }
                if (mode == "busy") return Task.FromResult(Error(503, "ServerBusy"));
                if (mode is "unauthorized" or "forbidden")
                {
                    var denied = Error(mode == "unauthorized" ? 401 : 403, "AuthenticationFailed");
                    denied.Headers.TryAddWithoutValidation("WWW-Authenticate", "Bearer authorization_uri=https://login.example.invalid/synthetic/oauth2/authorize resource_id=https://storage.azure.com");
                    return Task.FromResult(denied);
                }
                var container = Reply([]); container.Headers.TryAddWithoutValidation("x-ms-has-immutability-policy", "true");
                container.Headers.TryAddWithoutValidation("x-ms-immutable-storage-with-versioning-enabled", mode == "versioning-off" ? "false" : "true");
                if (mode == "public") container.Headers.TryAddWithoutValidation("x-ms-blob-public-access", "blob");
                After?.Invoke("container"); return Task.FromResult(container);
            }
            Assert.Equal("/final/" + Scope.Stored.Path, request.RequestUri.AbsolutePath); Assert.Equal(Version, Q("versionid")); Assert.Equal(Tag, match);
            if (mode == "missing") return Task.FromResult(Error(404, "BlobNotFound"));
            var isDownload = request.Method == HttpMethod.Get; if (!isDownload) heads++;
            var content = bytes.ToArray(); if (mode == "wrong-bytes") content[0] ^= 1;
            if (mode == "truncated") content = content[..^1]; if (mode == "overlong") content = content.Concat(new byte[] { 1 }).ToArray();
            var response = Reply([]);
            if (isDownload) response.Content = new StreamContent(new Observed(content, n => { LargestRead = Math.Max(LargestRead, n); After?.Invoke("stream"); }, () => StreamDisposed = true));
            response.Content.Headers.ContentLength = mode == "wrong-length" || isDownload && mode == "download-length" ? bytes.Length + 1 : bytes.Length;
            response.Headers.TryAddWithoutValidation("ETag", mode == "wrong-etag" || isDownload && mode == "download-etag" ? "\"foreign\"" : Tag);
            response.Headers.TryAddWithoutValidation("x-ms-version-id", mode == "wrong-version" || isDownload && mode == "download-version" ? "foreign-version" : Version);
            response.Headers.TryAddWithoutValidation("x-ms-blob-type", mode == "wrong-type" ? "AppendBlob" : "BlockBlob");
            response.Headers.TryAddWithoutValidation("x-ms-legal-hold", mode == "unheld" || mode == "hold-race" && heads >= 2 ? "false" : "true");
            if (mode != "no-policy" && !(mode == "policy-added" && heads < 2))
            {
                response.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode", mode == "mode-race" && heads >= 2 ? "Unlocked" : "Locked");
                response.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date", mode == "expiry-race" && heads >= 2 ? "Tue, 01 Jan 2030 13:00:00 GMT" : "Tue, 01 Jan 2030 14:00:00 GMT");
            }
            After?.Invoke(isDownload ? "download" : heads == 1 ? "before-head" : "after-head"); return Task.FromResult(response);
        }
        private static HttpResponseMessage Reply(byte[] bytes)
        { var result = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }; result.Headers.TryAddWithoutValidation("x-ms-version", "2023-11-03"); result.Headers.TryAddWithoutValidation("x-ms-request-id", "synthetic-inspection"); return result; }
        private static HttpResponseMessage Error(int status, string code)
        { var result = Reply(Encoding.UTF8.GetBytes($"<Error><Code>{code}</Code><Message>Synthetic inspection failure</Message></Error>")); result.StatusCode = (HttpStatusCode)status; result.Headers.TryAddWithoutValidation("x-ms-error-code", code); return result; }
        protected override void Dispose(bool disposing) { if (disposing) Store.Dispose(); base.Dispose(disposing); }
    }
    private sealed class Observed(byte[] bytes, Action<int> reading, Action disposed) : MemoryStream(bytes, false)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { reading(buffer.Length); return base.ReadAsync(buffer, ct); }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) { reading(count); return base.ReadAsync(buffer, offset, count, ct); }
        protected override void Dispose(bool disposing) { if (disposing) disposed(); base.Dispose(disposing); }
    }
    private sealed class Credential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken ct) => new("synthetic-inspection", DateTimeOffset.MaxValue);
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken ct) => ValueTask.FromResult(GetToken(requestContext, ct));
    }
}
