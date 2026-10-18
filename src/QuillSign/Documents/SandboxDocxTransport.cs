using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Azure;

namespace QuillSign.Documents;

public sealed class SandboxDocxTransport(ISandboxConversionApi api, ISandboxConversionLedger ledger, SandboxConversionOptions options,
    DocumentOptions limits, TimeProvider time, ILogger<SandboxDocxTransport> log) : ISandboxDocxTransport
{
    private const string RunLabel = "quillsign-conversion", ProfileLabel = "quillsign-profile", Profile = "v1";
    private static readonly string[] Kinds = ["sandboxes", "snapshots", "diskimages"];
    public async Task<byte[]> ConvertAsync(Stream source, byte[] sourceSha256, long length, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); options.Validate();
        if (!source.CanSeek || source.Length != length || sourceSha256.Length != 32 || length <= 0 || length > limits.MaximumBytes) throw SandboxConversionErrors.Unavailable();
        await using var owner = await ledger.AcquireAsync(ct);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(ct, owner.Token); operation.CancelAfter(TimeSpan.FromSeconds(150));
        byte[]? pdf = null; var clean = false; var completed = false;
        try
        {
            if (!await CleanupAsync(owner, operation.Token)) throw SandboxConversionErrors.Unavailable();
            var now = time.GetUtcNow().ToUniversalTime(); var day = now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture); var month = now.ToString("yyyy-MM", CultureInfo.InvariantCulture);
            var state = owner.State; var daily = state.Day == day ? state.DailyAttempts : 0; var monthly = state.Month == month ? state.MonthlyAttempts : 0;
            if (string.CompareOrdinal(state.Day, day) > 0 || string.CompareOrdinal(state.Month, month) > 0) throw SandboxConversionErrors.Unavailable();
            if (daily >= options.MaximumDailyAttempts || monthly >= options.MaximumMonthlyAttempts) throw SandboxConversionErrors.Unavailable();
            foreach (var kind in Kinds) if ((await ListAsync(kind, operation.Token)).Length != 0) throw SandboxConversionErrors.Unavailable();
            var run = Guid.NewGuid().ToString("N");
            await owner.SaveAsync(state with { Run = run, Phase = "image-create", Day = day, Month = month, DailyAttempts = daily + 1, MonthlyAttempts = monthly + 1 }, operation.Token);
            var labels = new Dictionary<string, string> { [RunLabel] = run, [ProfileLabel] = Profile, ["name"] = "quillsign-" + run };
            JsonElement image;
            try
            {
                await owner.EnsureOwnedAsync(operation.Token);
                image = Required(await api.JsonAsync(HttpMethod.Put, "diskimages", new { image = new { @base = SandboxConversionOptions.Image, entrypoint = new[] { "/usr/bin/tini", "--" }, cmd = SandboxConversionOptions.Arguments }, labels }, operation.Token));
            }
            catch (SandboxWriteNotAcceptedException)
            {
                using var rejected=CancellationTokenSource.CreateLinkedTokenSource(owner.Token);rejected.CancelAfter(TimeSpan.FromSeconds(5));
                await owner.SaveAsync(owner.State with { Run = null, Phase = "idle" }, rejected.Token); throw SandboxConversionErrors.Unavailable();
            }
            DemandOwned(image, run); DemandImage(image); var imageId = ResourceId(image);
            await owner.SaveAsync(owner.State with { Phase = "image-ready", ImageId = imageId }, operation.Token);
            while (State(image) is not ("Ready" or "Succeeded"))
            {
                if (State(image) is "Failed" or "Deleting") throw SandboxConversionErrors.Unavailable();
                await Task.Delay(TimeSpan.FromSeconds(1), operation.Token);
                image = Required(await api.JsonAsync(HttpMethod.Get, "diskimages/" + imageId, null, operation.Token)); DemandOwned(image, run); DemandImage(image);
            }
            await owner.SaveAsync(owner.State with { Phase = "sandbox-create" }, operation.Token);
            JsonElement sandbox;
            try
            {
                await owner.EnsureOwnedAsync(operation.Token);
                sandbox = Required(await api.JsonAsync(HttpMethod.Put, "sandboxes", new
                {
                    sourcesRef = new { diskImage = new { id = imageId } }, resources = new { cpu = "1000m", memory = "2048Mi", disk = "20Gi" },
                    labels, environment = new { }, ports = Array.Empty<object>(), volumes = Array.Empty<object>(), connections = Array.Empty<object>(),
                    entrypoint = new[] { "/usr/bin/tini", "--" }, cmd = SandboxConversionOptions.Arguments,
                    egressPolicy = new { defaultAction = "Deny", trafficInspection = "Full", rules = Array.Empty<object>(), hostRules = Array.Empty<object>() },
                    lifecycle = new { autoSuspendPolicy = new { enabled = true, interval = 60, mode = "Disk" }, autoDeletePolicy = new { enabled = true, deleteIntervalInSeconds = 180 } }
                }, operation.Token));
            }
            catch (SandboxWriteNotAcceptedException)
            {
                using var rejected=CancellationTokenSource.CreateLinkedTokenSource(owner.Token);rejected.CancelAfter(TimeSpan.FromSeconds(5));
                await owner.SaveAsync(owner.State with { Phase = "image-ready" }, rejected.Token); throw SandboxConversionErrors.Unavailable();
            }
            DemandOwned(sandbox, run); var sandboxId = ResourceId(sandbox); var path = "sandboxes/" + sandboxId;
            await owner.SaveAsync(owner.State with { Phase = "running", SandboxId = sandboxId }, operation.Token);
            while (State(sandbox) != "Running")
            {
                if (State(sandbox) is "Failed" or "Deleting" or "Stopped") throw SandboxConversionErrors.Unavailable();
                await Task.Delay(TimeSpan.FromMilliseconds(500), operation.Token);
                sandbox = Required(await api.JsonAsync(HttpMethod.Get, path, null, operation.Token));
            }
            // Re-read the actual capability, rather than trusting the create echo.
            sandbox = Required(await api.JsonAsync(HttpMethod.Get, path, null, operation.Token)); DemandOwned(sandbox, run); DemandIsolation(sandbox, imageId);
            var processes = await ExecuteAsync(owner, path, "ps -eo args", operation.Token);
            if (!processes.Split('\n').Any(line =>
                (line.TrimStart().StartsWith("gotenberg ", StringComparison.Ordinal) || line.TrimStart().StartsWith("/usr/bin/gotenberg ", StringComparison.Ordinal)) &&
                SandboxConversionOptions.Arguments.Skip(1).All(flag => line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(flag, StringComparer.Ordinal))))
                throw SandboxConversionErrors.Unavailable();
            var probe = await ExecuteAsync(owner, path, "curl --silent --show-error --max-time 5 --dump-header /tmp/quillsign-egress-headers --output /tmp/quillsign-egress-body --write-out '%{http_code}' https://example.com/; cat /tmp/quillsign-egress-headers; true", operation.Token);
            if (!probe.StartsWith("403", StringComparison.Ordinal) || !probe.Contains("x-deny-reason: example.com:GET", StringComparison.OrdinalIgnoreCase)) throw SandboxConversionErrors.Unavailable();
            var denied = false;
            for (var poll = 0; poll < 6 && !denied; poll++)
            {
                var decisions = Required(await api.JsonAsync(HttpMethod.Get, path + "/egress-decisions", null, operation.Token));
                denied = decisions.TryGetProperty("networkEgress", out var network) && network.TryGetProperty("denied", out var entries) && entries.ValueKind == JsonValueKind.Array &&
                    entries.EnumerateArray().Any(entry => Text(entry, "host") == "example.com" && Text(entry, "method") == "GET" && Text(entry, "scheme") == "https");
                if (!denied) await Task.Delay(TimeSpan.FromSeconds(1), operation.Token);
            }
            if (!denied) throw SandboxConversionErrors.Unavailable();
            await owner.EnsureOwnedAsync(operation.Token); source.Position = 0;
            await api.UploadAsync(sandboxId, source, length, operation.Token);
            var sourceHash = await ExecuteAsync(owner, path, "sha256sum " + SandboxConversionApi.InputPath, operation.Token);
            if (!sourceHash.StartsWith(Convert.ToHexStringLower(sourceSha256) + " ", StringComparison.Ordinal)) throw SandboxConversionErrors.Unavailable();
            await ExecuteAsync(owner, path, "for i in 1 2 3 4 5; do curl -fsS --connect-timeout 1 --max-time 2 --noproxy 127.0.0.1 http://127.0.0.1:3000/health >/dev/null && exit 0; sleep 1; done; exit 1", operation.Token);
            var command = "curl --fail --silent --show-error --connect-timeout 3 --max-time 60 --max-filesize " + limits.MaximumBytes.ToString(CultureInfo.InvariantCulture) +
                " --noproxy 127.0.0.1 -F 'files=@" + SandboxConversionApi.InputPath + ";type=application/vnd.openxmlformats-officedocument.wordprocessingml.document' -F 'exportFormFields=false' -F 'generateTaggedPdf=true' http://127.0.0.1:3000/forms/libreoffice/convert -o " + SandboxConversionApi.OutputPath;
            await ExecuteAsync(owner, path, command, operation.Token);
            pdf = await api.DownloadAsync(sandboxId, limits.MaximumBytes, operation.Token);
            operation.Token.ThrowIfCancellationRequested();
            completed = true;
        }
        catch (Exception e) when (e is HttpRequestException or IOException or RequestFailedException or SandboxWriteNotAcceptedException or JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException)
        { throw SandboxConversionErrors.Unavailable(); }
        finally
        {
            using var cleanup = CancellationTokenSource.CreateLinkedTokenSource(owner.Token); cleanup.CancelAfter(TimeSpan.FromSeconds(30));
            try { clean = await CleanupAsync(owner, cleanup.Token); }
            catch (Exception e) when (e is DocumentConversionUnavailableException or HttpRequestException or IOException or OperationCanceledException or RequestFailedException or SandboxWriteNotAcceptedException or JsonException or InvalidOperationException or KeyNotFoundException or FormatException or OverflowException) { }
            if (!clean) log.LogError("Document conversion cleanup is pending; further conversion admission remains closed.");
            if (!clean || !completed || ct.IsCancellationRequested) { if (pdf is not null) Array.Clear(pdf); }
        }
        ct.ThrowIfCancellationRequested();
        if (!clean || pdf is null) throw SandboxConversionErrors.Unavailable();
        return pdf;
    }

    // Called by storage-only maintenance or before a new conversion. A missing
    // acknowledgement is not resolved by one empty list: no blind recreation.
    public async Task<bool> RecoverAsync(CancellationToken ct)
    {
        await using var owner = await ledger.AcquireAsync(ct);
        return await CleanupAsync(owner, ct);
    }
    private async Task<bool> CleanupAsync(ISandboxConversionLease owner, CancellationToken ct)
    {
        await owner.EnsureOwnedAsync(ct);
        if (owner.State.Run is null)
        {
            // Idle maintenance needs neither provider requests nor SQL.
            return true;
        }
        var run = owner.State.Run;
        var inventory = new Dictionary<string, JsonElement[]>();
        foreach (var kind in Kinds) inventory[kind] = await ListAsync(kind, ct);
        var images = inventory["diskimages"].Where(item => Owned(item, run)).ToArray();
        var sandboxes = inventory["sandboxes"].Where(item => Owned(item, run)).ToArray();
        if (owner.State.Phase == "image-create" && owner.State.ImageId is null)
        {
            if (images.Length != 1) return false;
            await owner.SaveAsync(owner.State with { Phase = "image-ready", ImageId = ResourceId(images[0]) }, ct);
        }
        if (owner.State.Phase == "sandbox-create" && owner.State.SandboxId is null)
        {
            if (sandboxes.Length != 1) return false;
            await owner.SaveAsync(owner.State with { Phase = "running", SandboxId = ResourceId(sandboxes[0]) }, ct);
        }
        foreach (var kind in Kinds)
        {
            foreach (var item in inventory[kind].Where(item => Owned(item, run)))
            {
                var id = ResourceId(item);
                if (kind == "sandboxes" && id != owner.State.SandboxId || kind == "diskimages" && id != owner.State.ImageId) return false;
                var path = kind + "/" + id;
                var readback = await api.JsonAsync(HttpMethod.Get, path, null, ct, true);
                if (readback is null) continue;
                DemandOwned(readback.Value, run); await owner.EnsureOwnedAsync(ct);
                await api.JsonAsync(HttpMethod.Delete, path, null, ct, true);
                for (var poll = 0; ; poll++)
                {
                    if (await api.JsonAsync(HttpMethod.Get, path, null, ct, true) is null) break;
                    if (poll >= 8) return false;
                    await Task.Delay(TimeSpan.FromMilliseconds(500), ct);
                }
            }
        }
        // Known identifiers must also be absent even if a list omitted them.
        if (owner.State.SandboxId is string sandbox && await api.JsonAsync(HttpMethod.Get, "sandboxes/" + sandbox, null, ct, true) is not null ||
            owner.State.ImageId is string image && await api.JsonAsync(HttpMethod.Get, "diskimages/" + image, null, ct, true) is not null) return false;
        foreach (var kind in Kinds) if ((await ListAsync(kind, ct)).Any()) return false; // preserve unexpected inventory, close admission
        await owner.SaveAsync(owner.State with { Run = null, Phase = "idle", ImageId = null, SandboxId = null }, ct);
        return true;
    }
    private async Task<JsonElement[]> ListAsync(string kind, CancellationToken ct)
    {
        var result = Required(await api.JsonAsync(HttpMethod.Get, kind, null, ct)); JsonElement values;
        if (result.ValueKind == JsonValueKind.Array) values = result;
        else
        {
            if (result.ValueKind != JsonValueKind.Object || result.TryGetProperty("nextLink", out var link) && link.ValueKind != JsonValueKind.Null && link.GetString()?.Length > 0 || !result.TryGetProperty("value", out values)) throw SandboxConversionErrors.Unavailable();
        }
        if (values.ValueKind != JsonValueKind.Array || values.GetArrayLength() > 16) throw SandboxConversionErrors.Unavailable();
        return values.EnumerateArray().Select(item => item.Clone()).ToArray();
    }
    private async Task<string> ExecuteAsync(ISandboxConversionLease owner, string path, string command, CancellationToken ct)
    {
        await owner.EnsureOwnedAsync(ct);
        var result = Required(await api.JsonAsync(HttpMethod.Post, path + "/executeShellCommand", new { command }, ct));
        if (!result.TryGetProperty("exitCode", out var exit) || !exit.TryGetInt32(out var code) || code != 0) throw SandboxConversionErrors.Unavailable();
        return Text(result, "stdout") ?? throw SandboxConversionErrors.Unavailable();
    }
    private static void DemandImage(JsonElement image)
    {
        if (!image.TryGetProperty("image", out var definition) || Text(definition, "base") != SandboxConversionOptions.Image) throw SandboxConversionErrors.Unavailable();
    }
    private static void DemandIsolation(JsonElement sandbox, string imageId)
    {
        if (State(sandbox) != "Running" || !sandbox.TryGetProperty("egressPolicy", out var policy) || Text(policy, "defaultAction") != "Deny" ||
            Text(policy, "trafficInspection") != "Full" || Text(policy, "enforcementMode") != "Enforced" || !Empty(policy, "rules") || !Empty(policy, "hostRules") ||
            !sandbox.TryGetProperty("sourcesRef", out var sources) || !sources.TryGetProperty("diskImage", out var image) || Text(image, "id") != imageId ||
            !sandbox.TryGetProperty("resources", out var resources) || Text(resources, "cpu") != "1000m" || Text(resources, "memory") != "2048Mi" || Text(resources, "disk") is not ("20Gi" or "20480Mi") ||
            !Empty(sandbox, "ports") || !Empty(sandbox, "volumes") || !Empty(sandbox, "connections") || !Empty(sandbox, "credentialRefs") ||
            !Empty(sandbox, "environment") ||
            !sandbox.TryGetProperty("lifecycle", out var lifecycle) || !lifecycle.TryGetProperty("autoSuspendPolicy", out var suspend) ||
            !suspend.GetProperty("enabled").GetBoolean() || suspend.GetProperty("interval").GetInt32() != 60 || Text(suspend, "mode") != "Disk" ||
            !lifecycle.TryGetProperty("autoDeletePolicy", out var delete) || !delete.GetProperty("enabled").GetBoolean() || delete.GetProperty("deleteIntervalInSeconds").GetInt32() != 180)
            throw SandboxConversionErrors.Unavailable();
    }
    private static bool Empty(JsonElement value, string name) => !value.TryGetProperty(name, out var field) || field.ValueKind == JsonValueKind.Array && field.GetArrayLength() == 0 || field.ValueKind == JsonValueKind.Object && !field.EnumerateObject().Any();
    private static bool Owned(JsonElement item, string run) => item.ValueKind == JsonValueKind.Object && item.TryGetProperty("labels", out var labels) && Text(labels, RunLabel) == run && Text(labels, ProfileLabel) == Profile;
    private static void DemandOwned(JsonElement item, string run) { if (!Owned(item, run)) throw SandboxConversionErrors.Unavailable(); }
    private static string ResourceId(JsonElement item) => SandboxConversionApi.Id(Text(item, "id") ?? "");
    private static string? Text(JsonElement item, string name) => item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out var field) && field.ValueKind == JsonValueKind.String ? field.GetString() : null;
    private static string? State(JsonElement item) => Text(item, "state") ?? (item.TryGetProperty("status", out var status) ? Text(status, "state") : null);
    private static JsonElement Required(JsonElement? item) => item ?? throw SandboxConversionErrors.Unavailable();
}
