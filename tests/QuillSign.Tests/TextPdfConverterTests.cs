using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class TextPdfConverterTests
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Literal_text_is_owned_escaped_and_gated_before_the_existing_DOCX_transport(bool bom)
    {
        const string text = "  SYNTHETIC TEXT - NO AGREEMENT\r\n<svg onload='test'>& literal\r{\\rtf1 {\\field INCLUDEPICTURE https://example.invalid/image}}\n\t=WEBSERVICE(\"https://example.invalid/\") café 😀";
        var original = (bom ? new byte[] { 0xef, 0xbb, 0xbf } : []).Concat(Encoding.UTF8.GetBytes(text)).ToArray();
        using var source = new MemoryStream(original.ToArray());
        var handler = new Handler(async request =>
        {
            Assert.Equal("/forms/libreoffice/convert", request.RequestUri!.AbsolutePath);
            var form = Assert.IsType<MultipartFormDataContent>(request.Content);
            var file = form.Single(x => x.Headers.ContentDisposition!.Name!.Trim('"') == "files");
            Assert.Equal("document.docx", file.Headers.ContentDisposition!.FileName!.Trim('"'));
            using var zip = new ZipArchive(new MemoryStream(await file.ReadAsByteArrayAsync()));
            Assert.Equal(3, zip.Entries.Count);
            var xml = XDocument.Load(zip.GetEntry("word/document.xml")!.Open());
            XNamespace w = "http://schemas.openxmlformats.org/wordprocessingml/2006/main";
            var paragraphs = xml.Descendants(w + "p").ToArray(); Assert.Equal(4, paragraphs.Length);
            Assert.Equal("  SYNTHETIC TEXT - NO AGREEMENT", paragraphs[0].Value);
            Assert.Equal("<svg onload='test'>& literal", paragraphs[1].Value);
            Assert.Contains("INCLUDEPICTURE", paragraphs[2].Value); Assert.Single(xml.Descendants(w + "tab"));
            Assert.Contains("café 😀", paragraphs[3].Value);
            Assert.DoesNotContain(xml.Descendants(), x => x.Name.LocalName is "instrText" or "fldSimple" or "hyperlink" or "altChunk");
            source.Position = 0; source.Write(new byte[original.Length]);
            return Pdf();
        });
        using var http = new HttpClient(handler);
        var result = await Client(http).ConvertAsync(source, original.Length);
        Assert.Equal(SHA256.HashData(original), result.OriginalSha256);
        Assert.Equal(SHA256.HashData(result.Pdf), result.PdfSha256);
        Assert.Equal(2, result.Pages.Count); Assert.True(source.CanRead); Assert.Equal(1, handler.Calls);
    }

    public static TheoryData<byte[]> Unsupported => new()
    {
        Array.Empty<byte>(), Encoding.UTF8.GetBytes(" \r\n\t"), new byte[] { 0xef, 0xbb, 0xbf },
        new byte[] { 0xc0, 0xaf }, new byte[] { 0xed, 0xa0, 0x80 }, new byte[] { 0xf4, 0x90, 0x80, 0x80 },
        new byte[] { 0xff, 0xfe, 0x41, 0 }, new byte[] { 0x41, 0, 0x42 }, new byte[] { 0x41, 0x1b, 0x42 },
        Encoding.UTF8.GetBytes("bad\u0085control"), Encoding.UTF8.GetBytes("bad\uffffxml"),
        Encoding.UTF8.GetBytes("{\\rtf1\0 binary}")
    };

    [Theory][MemberData(nameof(Unsupported))]
    public async Task Invalid_text_never_reaches_HTTP(byte[] bytes)
    {
        var handler = new Handler(_ => Task.FromResult(Pdf())); using var http = new HttpClient(handler);
        using var source = new MemoryStream(bytes);
        var error = await Assert.ThrowsAsync<DocumentRejectedException>(() => Client(http).ConvertAsync(source, bytes.Length));
        Assert.Equal(0, handler.Calls); Assert.DoesNotContain("binary", error.Message); Assert.Null(error.InnerException);
    }

    [Theory]
    [InlineData("disabled")][InlineData("invalid-origin")][InlineData("invalid-limits")][InlineData("mismatch")]
    [InlineData("actual-size")][InlineData("declared-size")][InlineData("cancelled")]
    public async Task Configuration_size_and_cancellation_fail_before_transmission(string kind)
    {
        var handler = new Handler(_ => Task.FromResult(Pdf())); using var http = new HttpClient(handler);
        var options = Options(); var limits = new DocumentOptions { MaximumBytes = 2048 };
        if (kind == "disabled") options.Enabled = false;
        if (kind == "invalid-origin") options.BaseUrl = "https://example.invalid/private";
        if (kind == "invalid-limits") limits.MaximumPages = 0;
        using var source = new MemoryStream(kind == "actual-size" ? new byte[2049] : Encoding.UTF8.GetBytes("synthetic"));
        using var cancellation = new CancellationTokenSource(); if (kind == "cancelled") cancellation.Cancel();
        var length = kind switch { "declared-size" => 2049, "mismatch" => source.Length + 1, "actual-size" => 1000, _ => source.Length };
        Assert.NotNull(await Record.ExceptionAsync(() => Client(http, options, limits).ConvertAsync(source, length, cancellation.Token)));
        Assert.Equal(0, handler.Calls);
        if (kind is "disabled" or "invalid-origin" or "invalid-limits" or "declared-size" or "cancelled") Assert.Equal(0, source.Position);
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Wrapper_expansion_is_bounded_before_HTTP(bool paragraphs)
    {
        var handler = new Handler(_ => Task.FromResult(Pdf())); using var http = new HttpClient(handler);
        var bytes = Encoding.UTF8.GetBytes(paragraphs ? "text" + new string('\n', 1000000) : new string('&', 1800000));
        using var source = new MemoryStream(bytes);
        await Assert.ThrowsAsync<DocumentRejectedException>(() => Client(http).ConvertAsync(source, bytes.Length));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task The_generated_package_must_fit_the_configured_upload_bound_too()
    {
        var random = new Random(92); var text = new string(Enumerable.Range(0, 1024).Select(_ => (char)random.Next(32, 127)).ToArray());
        var handler = new Handler(_ => Task.FromResult(Pdf())); using var http = new HttpClient(handler);
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(text));
        await Assert.ThrowsAsync<DocumentRejectedException>(() => Client(http, limits: new() { MaximumBytes = 1024 }).ConvertAsync(source, source.Length));
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task A_source_read_failure_does_not_expose_its_message_or_call_HTTP()
    {
        var handler = new Handler(_ => Task.FromResult(Pdf())); using var http = new HttpClient(handler);
        using var source = new BrokenStream();
        var error = await Assert.ThrowsAsync<DocumentRejectedException>(() => Client(http).ConvertAsync(source, 100));
        Assert.DoesNotContain("private", error.Message); Assert.Null(error.InnerException); Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task The_total_deadline_includes_reading_untrusted_text()
    {
        var handler = new Handler(_ => Task.FromResult(Pdf())); using var http = new HttpClient(handler);
        var options = Options(); options.TimeoutSeconds = 1; using var source = new WaitingStream();
        var error = await Assert.ThrowsAsync<DocumentConversionUnavailableException>(() => Client(http, options).ConvertAsync(source, 100));
        Assert.Contains("timed out", error.Message); Assert.Equal(0, handler.Calls);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(25));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Client(http, options).ConvertAsync(source, 100, cancel.Token));
    }

    [Theory][InlineData(400)][InlineData(302)][InlineData(503)]
    public async Task Transport_failures_retain_safe_shared_semantics_without_retries(int status)
    {
        var handler = new Handler(_ => Task.FromResult(new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent("private provider content") }));
        using var http = new HttpClient(handler); using var source = new MemoryStream(Encoding.UTF8.GetBytes("synthetic"));
        var error = await Record.ExceptionAsync(() => Client(http).ConvertAsync(source, source.Length));
        Assert.True(error is DocumentRejectedException or DocumentConversionUnavailableException);
        Assert.DoesNotContain("private", error.Message); Assert.Equal(1, handler.Calls);
    }

    private static TextPdfConverter Client(HttpClient http, GotenbergOptions? options = null, DocumentOptions? limits = null)
    {
        options ??= Options(); limits ??= new(); var environment = new EnvironmentStub();
        return new(limits, options, environment, new(limits), new(http, options, limits, new(limits), environment));
    }
    private static GotenbergOptions Options() => new() { Enabled = true, BaseUrl = "http://127.0.0.1:3000" };
    private static HttpResponseMessage Pdf()
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(PdfFixtures.Create()) };
        response.Content.Headers.ContentType = new("application/pdf"); return response;
    }
    private sealed class Handler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) { Calls++; return respond(request); }
    }
    private sealed class WaitingStream : MemoryStream
    { public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) { await Task.Delay(Timeout.Infinite, ct); return 0; } }
    private sealed class BrokenStream : MemoryStream
    { public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default) => ValueTask.FromException<int>(new IOException("private source detail")); }
    private sealed class EnvironmentStub : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "SyntheticTextTests";
        public string ContentRootPath { get; set; } = "";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
