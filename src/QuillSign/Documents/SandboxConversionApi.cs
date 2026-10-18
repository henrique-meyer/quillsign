using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;

namespace QuillSign.Documents;

public interface ISandboxConversionApi
{
    Task<JsonElement?> JsonAsync(HttpMethod method, string path, object? body, CancellationToken ct, bool allowMissing = false);
    Task UploadAsync(string sandboxId, Stream source, long length, CancellationToken ct);
    Task<byte[]> DownloadAsync(string sandboxId, long maximumBytes, CancellationToken ct);
}

// Fixed regional origin, managed identity, no redirects, retries, provider-body
// disclosure or HTTP logging. Returned URLs are never used as authority.
public sealed class SandboxConversionApi(HttpClient http, TokenCredential credential, SandboxConversionOptions options) : ISandboxConversionApi
{
    public const string InputPath = "/tmp/quillsign-input/document.docx";
    public const string OutputPath = "/tmp/quillsign-output.pdf";
    private const string Version = "2026-02-01-preview";
    public async Task<JsonElement?> JsonAsync(HttpMethod method, string path, object? body, CancellationToken ct, bool allowMissing = false)
    {
        using var request = Request(method, path);
        if (body is not null) request.Content = JsonContent.Create(body);
        using var response = await SendAsync(request, ct);
        if (allowMissing && response.StatusCode == HttpStatusCode.NotFound) return null;
        if ((int)response.StatusCode is < 200 or >= 300)
        {
            if (method == HttpMethod.Put && path is "diskimages" or "sandboxes" && (int)response.StatusCode is 400 or 401 or 403 or 404 or 405 or 413 or 415 or 422 or 429)
                throw new SandboxWriteNotAcceptedException();
            throw SandboxConversionErrors.Unavailable();
        }
        var bytes = await ReadAsync(response, 1024 * 1024, ct);
        try { if (bytes.Length == 0) return null; using var document = JsonDocument.Parse(bytes, new() { MaxDepth = 32 }); return document.RootElement.Clone(); }
        catch (JsonException) { throw SandboxConversionErrors.Unavailable(); }
        finally { Array.Clear(bytes); }
    }
    public async Task UploadAsync(string sandboxId, Stream source, long length, CancellationToken ct)
    {
        using var request = Request(HttpMethod.Put, $"sandboxes/{Id(sandboxId)}/files", "&path=" + Uri.EscapeDataString(InputPath) + "&createDirs=true");
        // The converter owns this temporary source stream for the request lifetime.
        request.Content = new StreamContent(source);
        request.Content.Headers.ContentType = new("application/octet-stream");
        request.Content.Headers.ContentLength = length;
        using var response = await SendAsync(request, ct);
        if ((int)response.StatusCode is < 200 or >= 300) throw SandboxConversionErrors.Unavailable();
    }
    public async Task<byte[]> DownloadAsync(string sandboxId, long maximumBytes, CancellationToken ct)
    {
        using var request = Request(HttpMethod.Get, $"sandboxes/{Id(sandboxId)}/files", "&path=" + Uri.EscapeDataString(OutputPath));
        using var response = await SendAsync(request, ct);
        if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentEncoding.Count != 0 ||
            response.Content.Headers.ContentType?.MediaType is not ("application/pdf" or "application/octet-stream") ||
            response.Content.Headers.ContentLength is long size && (size <= 0 || size > maximumBytes)) throw SandboxConversionErrors.Unavailable();
        var bytes = await ReadAsync(response, maximumBytes, ct);
        if (!bytes.AsSpan().StartsWith("%PDF-"u8) || response.Content.Headers.ContentLength is long expected && expected != bytes.Length)
        { Array.Clear(bytes); throw SandboxConversionErrors.Unavailable(); }
        return bytes;
    }
    private HttpRequestMessage Request(HttpMethod method, string path, string query = "")
    {
        if (path.Contains("..", StringComparison.Ordinal) || path.StartsWith('/') || path.Contains('?') || path.Contains('#') || path.Contains('\\') || path.Contains(':'))
            throw SandboxConversionErrors.Unavailable();
        return new(method, new Uri(options.Origin, options.GroupPath + path + "?api-version=" + Version + query))
        { Version = HttpVersion.Version11, VersionPolicy = HttpVersionPolicy.RequestVersionExact };
    }
    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        AccessToken token;
        try { token = await credential.GetTokenAsync(new TokenRequestContext(["https://dynamicsessions.io/.default"]), ct); }
        catch (Exception e) when (e is AuthenticationFailedException or OperationCanceledException) { throw new SandboxWriteNotAcceptedException(); }
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        return await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
    }
    private static async Task<byte[]> ReadAsync(HttpResponseMessage response, long maximum, CancellationToken ct)
    {
        await using var body = await response.Content.ReadAsStreamAsync(ct); using var bytes = new MemoryStream();
        var buffer = new byte[65536]; int count;
        while ((count = await body.ReadAsync(buffer, ct)) != 0)
        {
            if (bytes.Length + count > maximum) throw SandboxConversionErrors.Unavailable();
            bytes.Write(buffer, 0, count);
        }
        return bytes.ToArray();
    }
    internal static string Id(string value) => Guid.TryParseExact(value, "D", out var id) && id != Guid.Empty ? id.ToString("D") : throw SandboxConversionErrors.Unavailable();
}

internal sealed class SandboxWriteNotAcceptedException : Exception;
