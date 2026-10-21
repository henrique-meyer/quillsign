using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionHoldWitnessStoreTests
{
    private static readonly byte[] Bytes = "SYNTHETIC WITNESS - NO AGREEMENT"u8.ToArray();
    [Theory]
    [InlineData("normal")][InlineData("lost-ack")]
    public async Task Create_is_exact_legal_held_conditional_single_attempt_and_replay_is_readonly(string mode)
    {
        using var run = new Run(mode); var store = run.Store();
        var first = await store.CreateAsync(new(run.Id, 1, Bytes));
        Assert.Equal(Bytes, first.ProtectedPayload); Assert.True(first.LegalHold); Assert.Equal(Run.Version, first.VersionId);
        Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(Bytes)), first.Sha256);
        var again = await store.CreateAsync(new(run.Id, 1, Bytes));
        Assert.Equal(first.Path, again.Path); Assert.Equal(first.VersionId, again.VersionId); Assert.Equal(Bytes, again.ProtectedPayload);
        Assert.Equal(1, run.Writes); Assert.All(run.Requests.Where(r => r.Method == HttpMethod.Put), r => {
            Assert.Equal("*", r.NoneMatch); Assert.Equal("true", r.Legal); Assert.Empty(r.Version); Assert.Empty(r.Immutability);
        });
        Assert.All(run.Requests.Where(r => r.Version != ""), r => { Assert.Equal(Run.Version, r.Version); Assert.Equal(Run.Tag, r.Match); });
        Assert.All(run.Requests.Where(r => r.Comp == "list"), r => {
            Assert.Equal(run.Prefix, r.Prefix); Assert.Contains("Versions", r.Include); Assert.Contains("Snapshots", r.Include); Assert.Contains("Deleted", r.Include);
        });
        Assert.DoesNotContain(run.Requests, r => r.Method == HttpMethod.Delete || r.Comp is "legalhold" or "immutabilitypolicy");
    }
    [Fact]
    public async Task Different_existing_ciphertext_cannot_replay_or_overwrite()
    {
        using var run = new Run(); run.Seed(1); var changed = Bytes.ToArray(); changed[0] ^= 1;
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Store().CreateAsync(new(run.Id, 1, changed))); Assert.Equal(0, run.Writes);
    }
    [Fact]
    public async Task Empty_namespace_is_verified_not_assumed_and_later_reads_own_their_bytes()
    {
        using var run = new Run(); var store = run.Store(); Assert.Empty(await store.ReadAsync(run.Id));
        Assert.Contains(run.Requests, r => r.Comp == "list"); run.Seed(2); run.Seed(1);
        var first = await store.ReadAsync(run.Id); Assert.Equal(new long[] { 1, 2 }, first.Select(x => x.Sequence)); first[0].ProtectedPayload[0] ^= 1;
        Assert.Equal(Bytes, (await store.ReadAsync(run.Id))[0].ProtectedPayload);
    }
    [Fact]
    public async Task Explicit_indefinite_protection_opt_in_is_required_before_any_transport()
    {
        using var run = new Run(); var store = run.Store(false);
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadAsync(run.Id));
        await Assert.ThrowsAsync<InvalidDataException>(() => store.CreateAsync(new(run.Id, 1, Bytes))); Assert.Empty(run.Requests);
    }
    [Theory]
    [InlineData("http://storage.example.invalid/witness")]
    [InlineData("https://storage.example.invalid/witness?sig=forbidden")]
    [InlineData("https://storage-secondary.example.invalid/witness")]
    [InlineData("https://storage.example.invalid/witness/other")]
    [InlineData("https://storage.example.invalid/wi%2Fness")]
    [InlineData("https://storage.example.invalid/WITNESS")]
    public void Unsafe_or_secondary_endpoint_fails_before_transport(string endpoint)
    {
        using var run = new Run(); Assert.Throws<InvalidDataException>(() => run.Store(uri: new(endpoint))); Assert.Empty(run.Requests);
    }
    [Theory]
    [InlineData("public")][InlineData("versioning-off")][InlineData("missing-container")][InlineData("denied")]
    public async Task Unavailable_or_unprotected_container_cannot_look_like_empty_success(string fault)
    {
        using var run = new Run(fault); await Assert.ThrowsAsync<InvalidDataException>(() => run.Store().ReadAsync(run.Id));
        Assert.Equal(0, run.Reads); Assert.Equal(0, run.Writes);
    }
    [Theory]
    [InlineData("unknown-name")][InlineData("wrong-record")][InlineData("zero")][InlineData("sequence-overflow")]
    [InlineData("missing-version")][InlineData("fork")][InlineData("snapshot")][InlineData("deleted")][InlineData("versions-only")]
    [InlineData("pageblob")][InlineData("payload-overflow")][InlineData("aggregate-overflow")][InlineData("count-overflow")]
    [InlineData("long-marker")][InlineData("repeat-marker")]
    public async Task Complete_census_rejects_unknown_forked_deleted_or_unbounded_history_before_content_reads(string fault)
    {
        using var run = new Run(fault); run.Seed(1);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Store().ReadAsync(run.Id)); Assert.Equal(0, run.Reads); Assert.Equal(0, run.Writes);
    }
    [Theory]
    [InlineData("unheld")][InlineData("hold-removed")][InlineData("short")][InlineData("long")]
    [InlineData("wrong-version")][InlineData("wrong-etag")][InlineData("content-missing")][InlineData("changed-namespace")]
    public async Task Exact_bytes_version_and_post_read_protection_are_required(string fault)
    {
        using var run = new Run(fault); run.Seed(1);
        var error = await Assert.ThrowsAsync<InvalidDataException>(() => run.Store().ReadAsync(run.Id));
        Assert.DoesNotContain("storage.example.invalid", error.ToString()); Assert.Equal(0, run.Writes);
    }
    [Fact]
    public async Task Create_owns_payload_before_first_await()
    {
        using var run = new Run("pause"); var bytes = Bytes.ToArray(); var task = run.Store().CreateAsync(new(run.Id, 1, bytes));
        await run.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10)); bytes[0] ^= 1; run.Continue.TrySetResult();
        Assert.Equal(Bytes, (await task).ProtectedPayload); Assert.Equal(1, run.Writes);
    }
    [Theory]
    [InlineData(0, 1)][InlineData(16385, 1)][InlineData(1, 0)][InlineData(1, 65537)]
    public async Task Invalid_write_bounds_and_record_fail_before_any_IO(long sequence, int size)
    {
        using var run = new Run(); var store = run.Store();
        await Assert.ThrowsAsync<InvalidDataException>(() => store.CreateAsync(new(run.Id, sequence, new byte[size])));
        await Assert.ThrowsAsync<InvalidDataException>(() => store.ReadAsync(Guid.Empty)); Assert.Empty(run.Requests);
    }
    [Fact]
    public async Task Cancellation_does_not_resend_or_readback_an_uncertain_operation()
    {
        using var run = new Run("cancel-write"); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.Store().CreateAsync(new(run.Id, 1, Bytes)));
        Assert.Equal(1, run.Writes); Assert.Equal(HttpMethod.Put, run.Requests[^1].Method);
    }
    [Fact]
    public async Task Failed_create_without_matching_version_never_claims_success_or_hidden_retry()
    {
        using var run = new Run("write-denied"); await Assert.ThrowsAsync<InvalidDataException>(() => run.Store().CreateAsync(new(run.Id, 1, Bytes)));
        Assert.Equal(1, run.Writes); Assert.Equal(0, run.Reads);
    }

    private sealed record Request(HttpMethod Method, string Comp, string Version, string Match, string NoneMatch, string Legal, string Immutability, string Prefix, string Include);
    private sealed class Run(string mode = "normal") : HttpMessageHandler
    {
        internal const string Version = "2030-01-01T00:00:00.0000000Z", Tag = "\"synthetic-witness-etag\"";
        internal readonly Guid Id = Guid.NewGuid(); internal readonly List<Request> Requests = [];
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously), Continue = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly Dictionary<long, byte[]> stored = []; internal int Writes, Reads; private int heads, lists;
        internal string Prefix => $"production-hold-witnesses/{new string('a', 64)}/{Id:N}/";
        internal void Seed(long sequence) => stored.Add(sequence, Bytes.ToArray());
        internal AzureProductionHoldWitnessStore Store(bool enabled = true, Uri? uri = null) => new(uri ?? new("https://storage.example.invalid/witness"), new Credential(), new string('a', 64), enabled, new HttpClientTransport(new HttpClient(this)));
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var query = QueryHelpers.ParseQuery(request.RequestUri!.Query); string Q(string key) => query.TryGetValue(key, out var v) ? v.ToString() : "";
            string H(string key) => request.Headers.TryGetValues(key, out var v) ? v.Single() : "";
            var comp = Q("comp"); Requests.Add(new(request.Method, comp, Q("versionid"), H("If-Match"), H("If-None-Match"), H("x-ms-legal-hold"), H("x-ms-immutability-policy-until-date"), Q("prefix"), Q("include")));
            if (request.RequestUri.AbsolutePath == "/witness" && comp == "")
            {
                if (mode == "pause" && !Entered.Task.IsCompleted) { Entered.TrySetResult(); await Continue.Task.WaitAsync(ct); }
                if (mode == "missing-container") return Error(HttpStatusCode.NotFound, "ContainerNotFound");
                if (mode == "denied") return Error(HttpStatusCode.Forbidden, "AuthorizationPermissionMismatch");
                var result = Reply([]); result.Headers.TryAddWithoutValidation("x-ms-immutable-storage-with-versioning-enabled", mode == "versioning-off" ? "false" : "true");
                if (mode == "public") result.Headers.TryAddWithoutValidation("x-ms-blob-public-access", "blob"); return result;
            }
            if (comp == "list")
            {
                lists++; var blobs = new List<XElement>(); var rows = stored.Keys.Order().ToList();
                if (mode == "aggregate-overflow") rows = Enumerable.Range(1, 257).Select(x => (long)x).ToList();
                if (mode == "count-overflow") rows = Enumerable.Range(1, 16385).Select(x => (long)x).ToList();
                var offset = Q("marker") == "" || mode == "repeat-marker" ? 0 : int.Parse(Q("marker"), CultureInfo.InvariantCulture);
                foreach (var sequence in rows.Skip(offset).Take(128))
                {
                    var name = Prefix + sequence.ToString("D10", CultureInfo.InvariantCulture);
                    if (mode == "unknown-name") name += "-extra";
                    if (mode == "wrong-record") name = $"production-hold-witnesses/{new string('a', 64)}/{Guid.Empty:N}/0000000001";
                    if (mode == "zero") name = Prefix + "0000000000";
                    if (mode == "sequence-overflow") name = Prefix + "0000016385";
                    var length = mode is "aggregate-overflow" or "payload-overflow" ? 65536L + (mode == "payload-overflow" ? 1 : 0) : mode == "count-overflow" ? 1 : stored[sequence].Length;
                    var blob = new XElement("Blob", new XElement("Name", name), new XElement("Properties",
                        new XElement("Last-Modified", "Tue, 01 Jan 2030 00:00:00 GMT"), new XElement("Etag", Tag),
                        new XElement("Content-Length", length), new XElement("BlobType", mode == "pageblob" ? "PageBlob" : "BlockBlob")));
                    if (mode != "missing-version") blob.Add(new XElement("VersionId", Version));
                    if (mode == "snapshot") blob.Add(new XElement("Snapshot", Version));
                    if (mode == "deleted") blob.Add(new XElement("Deleted", "true"));
                    if (mode == "versions-only") blob.Add(new XElement("HasVersionsOnly", "true"));
                    blobs.Add(blob); if (mode == "fork" || mode == "changed-namespace" && lists >= 2) blobs.Add(new XElement(blob));
                }
                var next = offset + 128 < rows.Count ? (offset + 128).ToString(CultureInfo.InvariantCulture) : "";
                if (mode == "long-marker") next = new string('m', 16385); if (mode == "repeat-marker") next = "same";
                var xml = new XElement("EnumerationResults", new XAttribute("ServiceEndpoint", "https://storage.example.invalid/"), new XAttribute("ContainerName", "witness"),
                    new XElement("Prefix", Prefix), new XElement("Blobs", blobs), new XElement("NextMarker", next));
                return Reply(Encoding.UTF8.GetBytes(xml.ToString()), "application/xml");
            }
            var key = long.Parse(request.RequestUri.AbsolutePath.Split('/')[^1], CultureInfo.InvariantCulture);
            if (request.Method == HttpMethod.Put)
            {
                Writes++; Assert.Equal("*", H("If-None-Match")); Assert.Equal("true", H("x-ms-legal-hold"));
                if (mode == "cancel-write") throw new OperationCanceledException();
                if (mode == "write-denied") return Error(HttpStatusCode.Forbidden, "AuthorizationPermissionMismatch");
                Assert.False(stored.ContainsKey(key)); stored.Add(key, await request.Content!.ReadAsByteArrayAsync(ct));
                if (mode == "lost-ack") return Error(HttpStatusCode.InternalServerError, "SyntheticLostAck");
                var result = Facts([], stored[key].Length); result.StatusCode = HttpStatusCode.Created; return result;
            }
            Assert.Equal(Version, Q("versionid")); Assert.Equal(Tag, H("If-Match"));
            if (request.Method == HttpMethod.Head)
            {
                heads++; var result = Facts([], stored[key].Length);
                result.Headers.TryAddWithoutValidation("x-ms-legal-hold", mode == "unheld" || mode == "hold-removed" && heads >= 2 ? "false" : "true"); return result;
            }
            Assert.Equal(HttpMethod.Get, request.Method); Reads++;
            if (mode == "content-missing") return Error(HttpStatusCode.NotFound, "BlobNotFound");
            var bytes = stored[key]; if (mode == "short") bytes = bytes[..^1]; if (mode == "long") bytes = bytes.Append((byte)1).ToArray();
            return Facts(bytes, stored[key].Length);
        }
        private HttpResponseMessage Facts(byte[] bytes, long length)
        {
            var r = Reply(bytes); r.Content.Headers.ContentLength = length;
            r.Headers.TryAddWithoutValidation("ETag", mode == "wrong-etag" ? "\"wrong\"" : Tag);
            r.Headers.TryAddWithoutValidation("x-ms-version-id", mode == "wrong-version" ? "wrong-version" : Version);
            r.Headers.TryAddWithoutValidation("x-ms-blob-type", "BlockBlob"); return r;
        }
        private static HttpResponseMessage Reply(byte[] bytes, string type = "application/octet-stream")
        {
            var r = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) }; r.Content.Headers.ContentType = new(type);
            r.Headers.TryAddWithoutValidation("x-ms-version", "2023-11-03"); r.Headers.TryAddWithoutValidation("x-ms-request-id", "synthetic-witness-no-agreement"); return r;
        }
        private static HttpResponseMessage Error(HttpStatusCode status, string code)
        { var r = Reply(Encoding.UTF8.GetBytes($"<Error><Code>{code}</Code><Message>Synthetic failure</Message></Error>"), "application/xml"); r.StatusCode = status; r.Headers.TryAddWithoutValidation("x-ms-error-code", code); return r; }
    }
    private sealed class Credential : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext c, CancellationToken ct) => new("synthetic-no-agreement", DateTimeOffset.UtcNow.AddHours(1));
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext c, CancellationToken ct) => ValueTask.FromResult(GetToken(c, ct));
    }
}
