using System.Security.Cryptography;
using PdfSharp.Pdf.IO;
using QuillSign.Documents;
using PigDocument = UglyToad.PdfPig.PdfDocument;

namespace QuillSign.Tests;

public sealed class SenderPdfRendererTests
{
    [Fact]
    public void Distribution_retains_the_pinned_embedded_font_and_unmodified_dependency_notices()
    {
        using var font = typeof(SenderPdfRenderer).Assembly.GetManifestResourceStream("QuillSign.Fonts.LiberationSans-Regular.ttf");
        Assert.NotNull(font);
        Assert.Equal("76d04c18ea243f426b7de1f3ad208e927008f961dc5945e5aad352d0dfde8ee8", Convert.ToHexStringLower(SHA256.HashData(font)));
        foreach (var notice in new[] {
            ("PdfPig-LICENSE.txt","4c510e162f896ea43b4b1cf1b743641d7c756f1004d0e5eaf0615b28b7ded409"),
            ("PdfPig-NOTICES.txt","d7a07a105f64d9240ed40a8ebe0c45658616c1660bf9fd8a36e2dbf3165f6e92") })
            Assert.Equal(notice.Item2, Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory,"licenses",notice.Item1)))));
    }
    [Fact]
    public void Sender_text_dates_and_checkboxes_preserve_source_content_pages_and_output_hashes()
    {
        var source = Source(); var before = source.Bytes.ToArray();
        var fields = new[] { Text() with { Value = "Cafe\u0301 — Καλημέρα — Пример — € 123\nSecond line" },
            Text() with { Id = Guid.NewGuid(), Type = "Date", Y = .4m, Value = "2028-02-29" },
            Text() with { Id = Guid.NewGuid(), Type = "Checkbox", Y = .6m, Width = .04m, Height = .04m, Value = "false" } };
        var result = Renderer().Render(source.Bytes, SHA256.HashData(source.Bytes), source.Pages, fields);
        Assert.Equal(before, source.Bytes); Assert.Equal(SHA256.HashData(before), result.SourceSha256);
        Assert.Equal(SHA256.HashData(result.Bytes), result.Sha256); Assert.NotEqual(before, result.Bytes);
        using var parsed = PigDocument.Open(result.Bytes); Assert.Equal(2, parsed.NumberOfPages);
        var first = parsed.GetPage(1).Text;
        foreach (var text in new[] { "Synthetic document", "Café", "Καλημέρα", "Пример", "€ 123", "Second line", "2028-02-29" }) Assert.Contains(text, first);
        Assert.Contains("Synthetic document", parsed.GetPage(2).Text); Assert.DoesNotContain("Second line", parsed.GetPage(2).Text);
        using var input = new MemoryStream(result.Bytes); using var pdf = PdfReader.Open(input, PdfDocumentOpenMode.Import);
        Assert.Equal(2, pdf.PageCount);
    }

    [Theory]
    [InlineData("missing-id")]
    [InlineData("assigned")]
    [InlineData("signature")]
    [InlineData("bad-type")]
    [InlineData("bad-page")]
    [InlineData("out-of-page")]
    [InlineData("zero-width")]
    [InlineData("missing-value")]
    [InlineData("blank-value")]
    [InlineData("oversized-value")]
    [InlineData("overflow")]
    [InlineData("tiny-field")]
    [InlineData("checkbox")]
    [InlineData("date")]
    [InlineData("emoji")]
    [InlineData("cjk")]
    [InlineData("arabic")]
    [InlineData("control")]
    [InlineData("tab")]
    [InlineData("invalid-unicode")]
    public void Invalid_sender_fields_fail_without_returning_output(string kind)
    {
        var source = Source(); var field = Text();
        field = kind switch
        {
            "missing-id" => field with { Id = Guid.Empty }, "assigned" => field with { SignerId = Guid.NewGuid() },
            "signature" => field with { Type = "Signature" }, "bad-type" => field with { Type = "text" },
            "bad-page" => field with { Page = 3 }, "out-of-page" => field with { X = .9m },
            "zero-width" => field with { Width = 0 }, "missing-value" => field with { Value = null },
            "blank-value" => field with { Value = " " }, "oversized-value" => field with { Value = new string('x',4001) },
            "overflow" => field with { Value = new string('W',4000) }, "tiny-field" => field with { Width = .001m, Height = .001m },
            "checkbox" => field with { Type = "Checkbox", Value = "yes" }, "date" => field with { Type = "Date", Value = "2026-02-29" },
            "emoji" => field with { Value = "🙂" }, "cjk" => field with { Value = "漢字" }, "arabic" => field with { Value = "مرحبا" },
            "control" => field with { Value = "bad\0value" }, "tab" => field with { Value = "bad\tvalue" },
            _ => field with { Value = "\ud800" }
        };
        RenderedSenderPdf? result = null;
        Assert.Throws<DocumentRejectedException>(() => result = Renderer().Render(source.Bytes, SHA256.HashData(source.Bytes), source.Pages, [field]));
        Assert.Null(result);
    }

    [Fact]
    public void Changed_source_hash_geometry_duplicate_ids_and_byte_page_field_limits_are_rejected()
    {
        var source = Source(); var hash = SHA256.HashData(source.Bytes); var field = Text();
        Assert.Throws<DocumentRejectedException>(() => Renderer().Render(source.Bytes.Concat(new byte[] { 0 }).ToArray(), hash, source.Pages, [field]));
        Assert.Throws<DocumentRejectedException>(() => Renderer().Render(source.Bytes, [], source.Pages, [field]));
        Assert.Throws<DocumentRejectedException>(() => Renderer().Render(source.Bytes, hash, [source.Pages[0] with { Rotation = 90 },source.Pages[1]], [field]));
        Assert.Throws<DocumentRejectedException>(() => Renderer().Render(source.Bytes, hash, [source.Pages[0] with { Width = 613 },source.Pages[1]], [field]));
        Assert.Throws<DocumentRejectedException>(() => Renderer().Render(source.Bytes, hash, [source.Pages[0] with { CropBox = null! },source.Pages[1]], [field]));
        Assert.Throws<DocumentRejectedException>(() => Renderer().Render(source.Bytes, hash, source.Pages, [field,field]));
        Assert.Throws<DocumentRejectedException>(() => new SenderPdfRenderer(source.Bytes.Length - 1,20,200).Render(source.Bytes, hash, source.Pages, [field]));
        Assert.Throws<DocumentRejectedException>(() => new SenderPdfRenderer(25 * 1024 * 1024,1,200).Render(source.Bytes, hash, source.Pages, [field]));
        Assert.Throws<DocumentRejectedException>(() => new SenderPdfRenderer(25 * 1024 * 1024,20,1).Render(source.Bytes, hash, source.Pages, [field,field with { Id = Guid.NewGuid() }]));
        // Source fits, but serialization of its embedded-font output exceeds the configured bound.
        RenderedSenderPdf? output = null;
        Assert.Throws<DocumentRejectedException>(() => output = new SenderPdfRenderer(source.Bytes.Length + 2048,20,200).Render(source.Bytes, hash, source.Pages, [field]));
        Assert.Null(output);
    }

    [Theory]
    [InlineData("signed")]
    [InlineData("xfa")]
    [InlineData("encrypted")]
    [InlineData("truncated")]
    [InlineData("malformed")]
    public void Renderer_rechecks_upload_policy_even_when_caller_supplies_the_correct_hash(string kind)
    {
        var source = Source();
        var bytes = kind switch
        {
            "signed" => PdfFixtures.Create(catalog:"/AcroForm << /Fields [<< /FT /Sig /V << /Type /Sig /ByteRange [0 1 2 3] /Contents <0000> >> >>] >>"),
            "xfa" => PdfFixtures.Create(catalog:"/AcroForm << /XFA (synthetic) >>"),
            "encrypted" => PdfFixtures.Encrypted(false), "truncated" => source.Bytes[..^10],
            _ => System.Text.Encoding.ASCII.GetBytes("%PDF-1.7\nsynthetic bad PDF\n%%EOF")
        };
        Assert.Throws<DocumentRejectedException>(() => Renderer().Render(bytes,SHA256.HashData(bytes),source.Pages,[Text()]));
    }

    [Fact]
    public async Task Repeated_and_concurrent_instances_share_one_font_resolver_and_keep_field_values_isolated()
    {
        var source = Source(); var hash = SHA256.HashData(source.Bytes);
        var results = await Task.WhenAll(Enumerable.Range(0,8).Select(i => Task.Run(() =>
            Renderer().Render(source.Bytes,hash,source.Pages,[Text() with { Value = "Synthetic parallel value " + i }]))));
        for (var i = 0; i < results.Length; i++)
        {
            using var parsed = PigDocument.Open(results[i].Bytes); Assert.Contains("Synthetic parallel value " + i,parsed.GetPage(1).Text);
            for (var j = 0; j < results.Length; j++) if (i != j) Assert.DoesNotContain("Synthetic parallel value " + j,parsed.GetPage(1).Text);
        }
        var repeated = Renderer().Render(source.Bytes,hash,source.Pages,[]);
        using var originalOnly = PigDocument.Open(repeated.Bytes); Assert.DoesNotContain("Synthetic parallel value",originalOnly.GetPage(1).Text);
    }

    private static SenderPdfRenderer Renderer() => new(25 * 1024 * 1024,20,200);
    private static SenderPrefillField Text() => new(Guid.NewGuid(),null,"Text",1,.1m,.2m,.75m,.1m,"Synthetic sender value");
    private static (byte[] Bytes,IReadOnlyList<PageGeometry> Pages) Source()
    {
        using var input = new MemoryStream(PdfFixtures.Create()); using var output = new MemoryStream();
        var pages = new PdfValidation(new()).Rewrite(input,output); return (output.ToArray(),pages);
    }
}
