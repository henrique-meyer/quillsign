using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionHoldObjectTransportTests
{
    private static readonly byte[] Bytes = "Synthetic private storage bytes - NO AGREEMENT"u8.ToArray();
    [Theory]
    [InlineData("version")][InlineData("snapshot")][InlineData("plain")][InlineData("unquoted-list")]
    public async Task SDK_lists_exact_private_scope_and_hashes_exact_conditional_version_or_snapshot_without_mutating(string mode)
    {
        using var run = new Run(mode); var scope = Scope(run.Id);
        var page = await run.Store.ListAsync(scope, "originals", null, 7, default); var address = Assert.Single(page.Objects);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Bytes)), await run.Store.HashAsync(scope, address, default));
        Assert.Equal(mode is "version" or "unquoted-list" ? Run.Version : "", address.VersionId); Assert.Equal(mode == "snapshot" ? Run.Version : "", address.Snapshot);
        var download = Assert.Single(run.Requests, x => x.Method == HttpMethod.Get && x.Comp == "" && x.Path != "/originals");
        Assert.Equal(Run.Tag, download.Match); Assert.Equal(address.VersionId, download.Version); Assert.Equal(address.Snapshot, download.Snapshot);
        Assert.All(run.Requests, x => Assert.True(x.Method == HttpMethod.Get || x.Method == HttpMethod.Head));
        var list = Assert.Single(run.Requests, x => x.Comp == "list"); Assert.Equal($"{run.Id:N}/", list.Prefix);
        Assert.Contains("Versions", list.Include); Assert.Contains("Snapshots", list.Include); Assert.Contains("Deleted", list.Include);
        Assert.DoesNotContain(run.Requests, x => x.Comp is "legalhold" or "immutabilitypolicy" || x.Path.Contains("other-record"));
    }
    [Theory]
    [InlineData("public")][InlineData("deleted")][InlineData("pageblob")][InlineData("missing")][InlineData("denied")]
    [InlineData("escape")][InlineData("overflow")]
    public async Task Unsafe_unavailable_or_escaped_inventory_never_reaches_a_content_read(string fault)
    {
        using var run = new Run(fault); var error = await Record.ExceptionAsync(() => run.Store.ListAsync(Scope(run.Id), "originals", null, 7, default));
        Assert.True(error is InvalidDataException or RequestFailedException, error?.ToString());
        Assert.DoesNotContain(run.Requests, x => x.Method == HttpMethod.Get && x.Comp == "" && x.Path != "/originals");
    }
    [Theory]
    [InlineData("short")][InlineData("long")][InlineData("version-mismatch")][InlineData("etag-mismatch")][InlineData("read-missing")]
    public async Task Truncated_extra_or_changed_exact_bytes_cannot_receive_a_verified_digest(string fault)
    {
        using var run = new Run(fault); var scope = Scope(run.Id);
        var address = Assert.Single((await run.Store.ListAsync(scope, "originals", null, 7, default)).Objects);
        var error = await Record.ExceptionAsync(() => run.Store.HashAsync(scope, address, default));
        Assert.True(error is InvalidDataException or RequestFailedException or IOException, error?.ToString());
        Assert.All(run.Requests, x => Assert.True(x.Method == HttpMethod.Get || x.Method == HttpMethod.Head));
    }
    [Fact]
    public async Task Invalid_or_expired_scope_stops_before_transport()
    {
        using var run = new Run("version"); var clock = new Clock(); var scope = Scope(run.Id, clock);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Store.ListAsync(scope, "other-record", null, 1, default));
        clock.Now = clock.Now.AddMinutes(10);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => run.Store.ListAsync(scope, "originals", null, 1, default)); Assert.Empty(run.Requests);
    }
    [Fact]
    public async Task SDK_continuation_is_forwarded_as_an_opaque_marker_with_the_same_record_prefix()
    {
        using var run = new Run("continuation");
        Assert.Single((await run.Store.ListAsync(Scope(run.Id), "originals", "synthetic-next-marker", 7, default)).Objects);
        Assert.Equal(2, run.Requests.Count);
    }

    internal static ProductionHoldObjectScope Scope(Guid id, Clock? clock = null)
    {
        clock ??= new(); var keys = new EphemeralDataProtectionProvider(); var version = ProductionHoldSqlInventory.Version;
        var fence = new string('a', 64); var policy = new string('b', 64); object[] tables = [];
        var state = JsonSerializer.SerializeToUtf8Bytes(new { Version = version, RecordId = id, Revision = 1L, FenceHash = fence, PolicySha256 = policy, Tables = tables });
        var stateHash = Convert.ToHexStringLower(SHA256.HashData(state));
        var control = new ProductionHoldControlPrefix(0, null);
        var plain = JsonSerializer.SerializeToUtf8Bytes(new { Version = version, RecordId = id, Revision = 1L, FenceHash = fence, PolicySha256 = policy,
            CapturedAt = clock.Now, StateSha256 = stateHash, Tables = tables, Control = control });
        var sql = new ProductionHoldSqlSnapshot(id, 1, fence, clock.Now, stateHash, Convert.ToHexStringLower(SHA256.HashData(plain)), plain.Length,
            keys.CreateProtector(version, id.ToString("N")).Protect(plain), [], control);
        return ProductionHoldObjectScope.FromVerified(sql, keys, clock);
    }
    internal sealed class Clock : TimeProvider
    {
        internal DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    private sealed record Request(HttpMethod Method, string Comp, string Path, string Version, string Snapshot, string Match, string Prefix, string Include);
    private sealed class Run : HttpMessageHandler
    {
        internal const string Version = "2030-01-01T00:00:00.0000000Z", Tag = "\"synthetic-etag\"";
        internal readonly Guid Id = Guid.NewGuid(); internal List<Request> Requests = [];
        internal readonly AzureProductionHoldObjectSource Store; private readonly string mode;
        internal Run(string mode)
        {
            this.mode = mode;
            var options = new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03) { Transport = new HttpClientTransport(new HttpClient(this)) };
            options.Retry.MaxRetries = 0; options.Diagnostics.IsLoggingEnabled = false; options.Diagnostics.IsLoggingContentEnabled = false; options.Diagnostics.IsDistributedTracingEnabled = false;
            Store = new(new(new Uri("https://storage.example.invalid"), new Credential(), options));
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var query = QueryHelpers.ParseQuery(request.RequestUri!.Query); string Q(string name) => query.TryGetValue(name, out var value) ? value.ToString() : "";
            var match = request.Headers.TryGetValues("If-Match", out var values) ? values.Single() : "";
            Requests.Add(new(request.Method, Q("comp"), request.RequestUri.AbsolutePath, Q("versionid"), Q("snapshot"), match, Q("prefix"), Q("include")));
            Assert.Equal("storage.example.invalid", request.RequestUri.Host);
            if (Q("restype") == "container" && Q("comp") == "")
            {
                Assert.Equal("/originals", request.RequestUri.AbsolutePath); Assert.Equal("container", Q("restype"));
                if (mode == "missing") return Task.FromResult(Error(HttpStatusCode.NotFound, "ContainerNotFound"));
                if (mode == "denied") return Task.FromResult(Error(HttpStatusCode.Forbidden, "AuthorizationPermissionMismatch"));
                var response = Reply([]); if (mode == "public") response.Headers.TryAddWithoutValidation("x-ms-blob-public-access", "blob");
                return Task.FromResult(response);
            }
            Assert.Equal(HttpMethod.Get, request.Method);
            if (Q("comp") == "list")
            {
                Assert.Equal("/originals", request.RequestUri.AbsolutePath); Assert.Equal("7", Q("maxresults"));
                if (mode == "continuation") Assert.Equal("synthetic-next-marker", Q("marker"));
                var name = $"{Id:N}/{Guid.Empty:N}"; if (mode == "escape") name = $"{Guid.NewGuid():N}/other-record";
                var properties = new XElement("Properties", new XElement("Last-Modified", "Tue, 01 Jan 2030 00:00:00 GMT"),
                    new XElement("Etag", mode == "unquoted-list" ? Tag.Trim('"') : Tag), new XElement("Content-Length", mode == "overflow" ? 64L * 1024 * 1024 + 1 : Bytes.Length), new XElement("BlobType", mode == "pageblob" ? "PageBlob" : "BlockBlob"));
                var blob = new XElement("Blob", new XElement("Name", name), properties);
                if (mode != "snapshot" && mode != "plain") blob.Add(new XElement("VersionId", Version));
                if (mode == "snapshot") blob.Add(new XElement("Snapshot", Version));
                if (mode == "deleted") blob.Add(new XElement("Deleted", "true"));
                var xml = new XElement("EnumerationResults", new XAttribute("ServiceEndpoint", "https://storage.example.invalid/"), new XAttribute("ContainerName", "originals"),
                    new XElement("Prefix", Q("prefix")), new XElement("Blobs", blob), new XElement("NextMarker", ""));
                return Task.FromResult(Reply(Encoding.UTF8.GetBytes(xml.ToString()), "application/xml"));
            }
            Assert.Equal(Tag, match);
            if (mode == "read-missing") return Task.FromResult(Error(HttpStatusCode.NotFound, "BlobNotFound"));
            var body = mode == "short" ? Bytes[..^1] : mode == "long" ? Bytes.Concat(new byte[] { 1 }).ToArray() : Bytes;
            var result = Reply(body); result.Content.Headers.ContentLength = Bytes.Length;
            result.Headers.TryAddWithoutValidation("ETag", mode == "etag-mismatch" ? "\"changed\"" : Tag);
            if (mode != "snapshot" && mode != "plain") result.Headers.TryAddWithoutValidation("x-ms-version-id", mode == "version-mismatch" ? "other-version" : Version);
            result.Headers.TryAddWithoutValidation("x-ms-blob-type", "BlockBlob");
            return Task.FromResult(result);
        }
        private static HttpResponseMessage Reply(byte[] body, string type = "application/octet-stream")
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(body) };
            response.Content.Headers.ContentType = new(type); response.Headers.TryAddWithoutValidation("x-ms-version", "2023-11-03");
            response.Headers.TryAddWithoutValidation("x-ms-request-id", "synthetic-no-agreement"); return response;
        }
        private static HttpResponseMessage Error(HttpStatusCode status, string code)
        { var result = Reply(Encoding.UTF8.GetBytes($"<Error><Code>{code}</Code><Message>Synthetic failure</Message></Error>"), "application/xml"); result.StatusCode = status; result.Headers.TryAddWithoutValidation("x-ms-error-code", code); return result; }
    }
    private sealed class Credential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext c, CancellationToken ct) => new("synthetic-no-agreement", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext c, CancellationToken ct) => ValueTask.FromResult(GetToken(c, ct));
    }
}
