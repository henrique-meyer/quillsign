using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class SandboxDocxTransportTests
{
    [Fact]
    public async Task Successful_conversion_binds_source_uses_writable_output_and_deletes_every_owned_resource()
    {
        var h = new Harness(); var bytes = GotenbergDocxConverterTests.Docx();
        var pdf = await h.Convert(bytes);
        Assert.StartsWith("%PDF-", System.Text.Encoding.ASCII.GetString(pdf));
        Assert.Equal(1, h.Api.Conversions); Assert.Equal(1, h.Api.Uploads); Assert.Equal(bytes, h.Api.Source);
        Assert.Empty(h.Api.Resources); Assert.Null(h.Ledger.State.Run); Assert.Equal(1, h.Ledger.State.MonthlyAttempts);
        Assert.Contains("/tmp/quillsign-output.pdf", h.Api.Commands.Single(x => x.StartsWith("curl --fail ")));
        Assert.DoesNotContain(h.Api.Commands, x => x.Contains("-o /tmp/quillsign-input/", StringComparison.Ordinal));
        Assert.True(h.Api.IsolationCheckedBeforeUpload); Assert.Equal(2, h.Api.Deletes);
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("inspection")]
    [InlineData("enforcement")]
    [InlineData("port")]
    [InlineData("volume")]
    [InlineData("connection")]
    [InlineData("credential")]
    [InlineData("environment")]
    [InlineData("cpu")]
    [InlineData("memory")]
    [InlineData("disk")]
    [InlineData("source")]
    [InlineData("suspend")]
    [InlineData("delete")]
    [InlineData("runtime")]
    [InlineData("denial")]
    public async Task Unproved_capabilities_prevent_upload_and_preserve_no_remote_document(string mismatch)
    {
        var h = new Harness(); h.Api.Mismatch = mismatch;
        var error = await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.DoesNotContain("private", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, h.Api.Uploads); Assert.Equal(0, h.Api.Conversions); Assert.Empty(h.Api.Resources); Assert.Null(h.Ledger.State.Run);
    }

    [Fact]
    public async Task Source_digest_mismatch_does_not_execute_conversion()
    {
        var h = new Harness(); h.Api.Mismatch = "hash";
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.Equal(1, h.Api.Uploads); Assert.Equal(0, h.Api.Conversions); Assert.Empty(h.Api.Resources);
    }

    [Fact]
    public async Task Lost_create_acknowledgement_reconciles_one_owned_object_without_retrying_create()
    {
        var h = new Harness(); h.Api.CreateFailure = "after-image";
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.Equal(1, h.Api.ImageCreates); Assert.Equal(0, h.Api.SandboxCreates); Assert.Empty(h.Api.Resources);
        Assert.Null(h.Ledger.State.Run); Assert.Equal(1, h.Ledger.State.MonthlyAttempts);
    }

    [Fact]
    public async Task Unobserved_create_is_quarantined_and_late_resource_is_recovered_without_another_create()
    {
        var h = new Harness(); h.Api.CreateFailure = "before-image";
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        var run = h.Ledger.State.Run; Assert.NotNull(run); Assert.Equal("image-create", h.Ledger.State.Phase);
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.Equal(1, h.Api.ImageCreates); Assert.Equal(1, h.Ledger.State.MonthlyAttempts);
        h.Api.MaterializeLateImage();
        Assert.True(await h.Transport.RecoverAsync(default)); Assert.Empty(h.Api.Resources); Assert.Null(h.Ledger.State.Run);
        Assert.Equal(1, h.Api.ImageCreates);
    }

    [Fact]
    public async Task Uncertain_sandbox_creation_preserves_image_until_exact_sandbox_can_be_reconciled()
    {
        var h = new Harness(); h.Api.CreateFailure = "before-sandbox";
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.Equal("sandbox-create", h.Ledger.State.Phase); Assert.NotNull(h.Ledger.State.ImageId);
        Assert.Single(h.Api.Resources); Assert.Equal(0, h.Api.Deletes);
        h.Api.MaterializeLateSandbox();
        Assert.True(await h.Transport.RecoverAsync(default)); Assert.Empty(h.Api.Resources); Assert.Null(h.Ledger.State.Run);
        Assert.Equal(1, h.Api.SandboxCreates);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Failed_or_lost_delete_keeps_a_recoverable_binding_without_reconverting(bool lostAck)
    {
        var h = new Harness(); h.Api.DeleteFailure = lostAck ? "after" : "before";
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.NotNull(h.Ledger.State.Run); Assert.Equal(1, h.Api.Conversions);
        h.Api.DeleteFailure = "";
        Assert.True(await h.Transport.RecoverAsync(default)); Assert.Empty(h.Api.Resources); Assert.Null(h.Ledger.State.Run);
        Assert.Equal(1, h.Api.Conversions); Assert.Equal(1, h.Api.ImageCreates);
    }

    [Fact]
    public async Task Missing_list_entry_cannot_falsely_complete_cleanup_of_a_known_identifier()
    {
        var h = new Harness(); h.Api.OmitSandboxAfterConversion = true;
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.NotNull(h.Ledger.State.Run); Assert.NotNull(h.Ledger.State.SandboxId); Assert.NotEmpty(h.Api.Resources);
        h.Api.OmitSandboxAfterConversion = false;
        Assert.True(await h.Transport.RecoverAsync(default)); Assert.Empty(h.Api.Resources);
    }

    [Fact]
    public async Task Unexpected_unowned_inventory_is_preserved_and_prevents_provisioning()
    {
        var h = new Harness(); var foreign = h.Api.AddForeign();
        await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.True(h.Api.Resources.ContainsKey(foreign)); Assert.Equal(0, h.Api.ImageCreates); Assert.Equal(0, h.Api.Deletes);
        Assert.Equal(0, h.Ledger.State.MonthlyAttempts);
    }

    [Fact]
    public async Task Caller_cancellation_still_cleans_up_and_clears_downloaded_bytes()
    {
        var h = new Harness(); using var cancellation = new CancellationTokenSource(); h.Api.AfterDownload = cancellation.Cancel;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Convert(ct: cancellation.Token));
        Assert.Empty(h.Api.Resources); Assert.Null(h.Ledger.State.Run); Assert.All(h.Api.Downloaded!, value => Assert.Equal(0, value));
        Assert.False(h.Api.CleanupWasCancelled);
    }

    [Fact]
    public async Task Idle_storage_only_recovery_never_calls_provider()
    {
        var h = new Harness(); h.Api.FailEveryRead = true;
        Assert.True(await h.Transport.RecoverAsync(default)); Assert.Equal(0, h.Api.Calls);
    }

    [Fact]
    public async Task Budget_reservations_survive_restarts_and_roll_over_only_at_server_UTC_boundaries()
    {
        var h = new Harness(); h.Options.MaximumDailyAttempts = 1; h.Options.MaximumMonthlyAttempts = 2;
        await h.Convert(); await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.Equal(1, h.Api.ImageCreates);
        h.Clock.Now = h.Clock.Now.AddDays(1); await h.Convert();
        h.Clock.Now = h.Clock.Now.AddDays(1); await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => h.Convert());
        Assert.Equal(2, h.Api.ImageCreates);
        h.Clock.Now = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero); await h.Convert();
        Assert.Equal(3, h.Api.ImageCreates); Assert.Equal(1, h.Ledger.State.MonthlyAttempts);
    }

    [Fact]
    public async Task Shared_normalizer_retains_original_digest_and_rejects_bad_sandbox_PDF()
    {
        var h = new Harness(); var options = new GotenbergOptions { Enabled = true, Transport = "Sandbox", Sandbox = h.Options };
        using var http = new HttpClient();
        var converter = new GotenbergDocxConverter(http, options, new(), new(new()), new EnvironmentStub(), h.Transport);
        var source = GotenbergDocxConverterTests.Docx();
        using var input = new MemoryStream(source); var result = await converter.ConvertAsync(input, source.Length);
        Assert.Equal(SHA256.HashData(source), result.OriginalSha256); Assert.Equal(SHA256.HashData(result.Pdf), result.PdfSha256); Assert.Equal(2, result.Pages.Count);
        h.Api.InvalidPdf = true;
        using var other = new MemoryStream(source); await Assert.ThrowsAsync<DocumentRejectedException>(() => converter.ConvertAsync(other, source.Length));
        Assert.Empty(h.Api.Resources);
    }

    public sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = new(2026, 10, 18, 16, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
    public sealed class EnvironmentStub : Microsoft.Extensions.Hosting.IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Synthetic";
        public string ContentRootPath { get; set; } = "";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = new Microsoft.Extensions.FileProviders.NullFileProvider();
    }
    public sealed class MemoryLedger : ISandboxConversionLedger
    {
        public SandboxConversionState State = new("synthetic-scope", "", 0, "", 0);
        private readonly SemaphoreSlim gate = new(1);
        public async Task<ISandboxConversionLease> AcquireAsync(CancellationToken ct) { await gate.WaitAsync(ct); return new Lease(this); }
        private sealed class Lease(MemoryLedger owner) : ISandboxConversionLease
        {
            public SandboxConversionState State => owner.State;
            public CancellationToken Token => CancellationToken.None;
            public Task EnsureOwnedAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); return Task.CompletedTask; }
            public Task SaveAsync(SandboxConversionState state, CancellationToken ct) { ct.ThrowIfCancellationRequested(); owner.State = state; return Task.CompletedTask; }
            public ValueTask DisposeAsync() { owner.gate.Release(); return ValueTask.CompletedTask; }
        }
    }
    public sealed class Harness
    {
        public readonly MemoryLedger Ledger = new(); public readonly Provider Api = new(); public readonly Clock Clock = new(); public readonly SandboxConversionOptions Options = Configuration();
        public SandboxDocxTransport Transport => new(Api, Ledger, Options, new(), Clock, NullLogger<SandboxDocxTransport>.Instance);
        public async Task<byte[]> Convert(byte[]? bytes = null, CancellationToken ct = default)
        { bytes ??= GotenbergDocxConverterTests.Docx(); using var source = new MemoryStream(bytes); return await Transport.ConvertAsync(source, SHA256.HashData(bytes), bytes.Length, ct); }
    }
    public static SandboxConversionOptions Configuration() => new() { Region = "eastus", SubscriptionId = Guid.NewGuid().ToString("D"), ResourceGroup = "synthetic-group", GroupName = "synthetic-converter" };

    public sealed class Provider : ISandboxConversionApi
    {
        public readonly Dictionary<string, JsonObject> Resources = new(); public readonly List<string> Commands = new();
        public int Calls, ImageCreates, SandboxCreates, Deletes, Uploads, Conversions;
        public byte[] Source = []; public byte[]? Downloaded; public string Mismatch = "", CreateFailure = "", DeleteFailure = "";
        public bool IsolationCheckedBeforeUpload, OmitSandboxAfterConversion, CleanupWasCancelled, FailEveryRead, InvalidPdf;
        public Action? AfterDownload; public byte[]? PdfOverride; private JsonObject? pendingImage, pendingSandbox;
        public Task<JsonElement?> JsonAsync(HttpMethod method, string path, object? body, CancellationToken ct, bool allowMissing = false)
        {
            Calls++; if (method == HttpMethod.Delete && ct.IsCancellationRequested) CleanupWasCancelled = true; ct.ThrowIfCancellationRequested();
            if (method == HttpMethod.Get && FailEveryRead) throw new IOException("private synthetic provider failure");
            if (method == HttpMethod.Put && path == "diskimages")
            {
                ImageCreates++; var node = JsonSerializer.SerializeToNode(body)!.AsObject(); node["id"] = Guid.NewGuid().ToString("D"); node["status"] = new JsonObject { ["state"] = "Ready" };
                pendingImage = node;
                if (CreateFailure != "before-image") Resources["diskimages/" + node["id"]!.GetValue<string>()] = node;
                if (CreateFailure.EndsWith("image", StringComparison.Ordinal)) throw new HttpRequestException("private lost create response");
                return Result(node);
            }
            if (method == HttpMethod.Put && path == "sandboxes")
            {
                SandboxCreates++; var node = JsonSerializer.SerializeToNode(body)!.AsObject(); node["id"] = Guid.NewGuid().ToString("D"); node["state"] = "Running";
                node["credentialRefs"] = new JsonArray(); node["resources"]!["disk"] = "20480Mi"; node["egressPolicy"]!["enforcementMode"] = "Enforced";
                pendingSandbox = node;
                if (CreateFailure != "before-sandbox") Resources["sandboxes/" + node["id"]!.GetValue<string>()] = node;
                if (CreateFailure.EndsWith("sandbox", StringComparison.Ordinal)) throw new HttpRequestException("private lost create response");
                return Result(node);
            }
            if (method == HttpMethod.Get && path == "sandboxes" || method == HttpMethod.Get && path == "diskimages" || method == HttpMethod.Get && path == "snapshots")
            {
                var list = new JsonArray(); foreach (var pair in Resources.Where(x => x.Key.StartsWith(path + "/", StringComparison.Ordinal)))
                    if (!(path == "sandboxes" && OmitSandboxAfterConversion && Conversions > 0)) list.Add(pair.Value.DeepClone());
                return Result(list);
            }
            if (method == HttpMethod.Delete)
            {
                Deletes++; if (DeleteFailure == "before") throw new HttpRequestException("private delete failure"); Resources.Remove(path);
                if (DeleteFailure == "after") throw new HttpRequestException("private lost delete acknowledgement"); return Task.FromResult<JsonElement?>(null);
            }
            if (method == HttpMethod.Get && path.EndsWith("/egress-decisions", StringComparison.Ordinal))
                return Result(JsonNode.Parse("{\"networkEgress\":{\"denied\":[{\"host\":\"example.com\",\"method\":\"GET\",\"scheme\":\"https\"}]}}")!);
            if (method == HttpMethod.Get)
            {
                if (!Resources.TryGetValue(path, out var node)) return allowMissing ? Task.FromResult<JsonElement?>(null) : throw new IOException("private missing resource");
                if (!path.StartsWith("sandboxes/", StringComparison.Ordinal)) return Result(node);
                var value = node.DeepClone().AsObject();
                switch (Mismatch)
                {
                    case "policy": value["egressPolicy"]!["defaultAction"] = "Allow"; break;
                    case "inspection": value["egressPolicy"]!["trafficInspection"] = "Partial"; break;
                    case "enforcement": value["egressPolicy"]!["enforcementMode"] = "Audit"; break;
                    case "port": value["ports"] = new JsonArray(3000); break;
                    case "volume": value["volumes"] = new JsonArray("private-volume"); break;
                    case "connection": value["connections"] = new JsonArray("private-connection"); break;
                    case "credential": value["credentialRefs"] = new JsonArray("private-credential"); break;
                    case "environment": value["environment"] = new JsonObject { ["PRIVATE"] = "private-value" }; break;
                    case "cpu": value["resources"]!["cpu"] = "2000m"; break;
                    case "memory": value["resources"]!["memory"] = "4096Mi"; break;
                    case "disk": value["resources"]!["disk"] = "200Gi"; break;
                    case "source": value["sourcesRef"]!["diskImage"]!["id"] = Guid.NewGuid().ToString("D"); break;
                    case "suspend": value["lifecycle"]!["autoSuspendPolicy"]!["enabled"] = false; break;
                    case "delete": value["lifecycle"]!["autoDeletePolicy"]!["enabled"] = false; break;
                }
                IsolationCheckedBeforeUpload = true; return Result(value);
            }
            if (method == HttpMethod.Post && path.EndsWith("/executeShellCommand", StringComparison.Ordinal))
            {
                var command = JsonSerializer.SerializeToElement(body).GetProperty("command").GetString()!; Commands.Add(command); string stdout = "";
                if (command == "ps -eo args") stdout = Mismatch == "runtime" ? "gotenberg" : string.Join(' ', pendingSandbox!["cmd"]!.AsArray().Select(x => x!.GetValue<string>()));
                else if (command.StartsWith("curl --silent ", StringComparison.Ordinal)) stdout = Mismatch == "denial" ? "200" : "403HTTP/2 403\r\nx-deny-reason: example.com:GET\r\n";
                else if (command.StartsWith("sha256sum ", StringComparison.Ordinal)) stdout = (Mismatch == "hash" ? new string('0', 64) : Convert.ToHexStringLower(SHA256.HashData(Source))) + "  document.docx\n";
                else if (command.StartsWith("curl --fail ", StringComparison.Ordinal)) Conversions++;
                return Result(new JsonObject { ["exitCode"] = 0, ["stdout"] = stdout });
            }
            throw new InvalidOperationException("Unexpected synthetic API operation");
        }
        public async Task UploadAsync(string sandboxId, Stream source, long length, CancellationToken ct)
        { Uploads++; using var buffer = new MemoryStream(); await source.CopyToAsync(buffer, ct); Source = buffer.ToArray(); Assert.Equal(length, Source.Length); }
        public Task<byte[]> DownloadAsync(string sandboxId, long maximumBytes, CancellationToken ct)
        { Downloaded = InvalidPdf ? "%PDF-malformed"u8.ToArray() : PdfOverride?.ToArray() ?? PdfFixtures.Create(); AfterDownload?.Invoke(); return Task.FromResult(Downloaded); }
        public void MaterializeLateImage() => Resources["diskimages/" + pendingImage!["id"]!.GetValue<string>()] = pendingImage;
        public void MaterializeLateSandbox() => Resources["sandboxes/" + pendingSandbox!["id"]!.GetValue<string>()] = pendingSandbox;
        public string AddForeign()
        { var id = "sandboxes/" + Guid.NewGuid().ToString("D"); Resources[id] = new JsonObject { ["id"] = id.Split('/')[1], ["labels"] = new JsonObject { ["owner"] = "unrelated" } }; return id; }
        private static Task<JsonElement?> Result(JsonNode node) => Task.FromResult<JsonElement?>(JsonSerializer.SerializeToElement(node));
    }
}
