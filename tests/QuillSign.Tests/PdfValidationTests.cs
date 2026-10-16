using System.Text;
using PdfSharp.Pdf.IO;
using QuillSign.Documents;

namespace QuillSign.Tests;

public sealed class PdfValidationTests
{
    [Fact]
    public void Valid_pdf_is_rewritten_with_page_geometry_and_rotation_preserved()
    {
        var source = PdfFixtures.Create(rotation: 90);
        using var input = new MemoryStream(source); using var output = new MemoryStream();
        var pages = new PdfValidation(new()).Rewrite(input, output);
        Assert.Equal(2, pages.Count);
        Assert.All(pages, page => { Assert.Equal(612, page.Width); Assert.Equal(792, page.Height); Assert.Equal(90, page.Rotation); });
        Assert.NotEqual(source, output.ToArray());
        output.Position = 0;
        using var reopened = PdfReader.Open(output, PdfDocumentOpenMode.Import);
        Assert.Equal(2, reopened.PageCount); Assert.Equal(90, reopened.Pages[0].Rotate);
    }
    [Theory]
    [InlineData("plain")]
    [InlineData("header-only")]
    [InlineData("truncated")]
    [InlineData("xfa")]
    [InlineData("signature")]
    [InlineData("empty-user-encryption")]
    [InlineData("password-encryption")]
    [InlineData("too-many-pages")]
    [InlineData("rotation")]
    [InlineData("geometry")]
    [InlineData("non-finite")]
    public void Unsupported_and_malformed_pdfs_are_rejected(string kind)
    {
        var bytes = kind switch
        {
            "plain" => Encoding.ASCII.GetBytes("This is not a PDF file."),
            "header-only" => Encoding.ASCII.GetBytes("%PDF-1.7\nsynthetic\n%%EOF"),
            "truncated" => PdfFixtures.Create()[..^10],
            "xfa" => PdfFixtures.Create(catalog: "/AcroForm << /XFA (synthetic) >>"),
            "signature" => PdfFixtures.Create(catalog: "/AcroForm << /Fields [<< /FT /Sig /V << /Type /Sig /ByteRange [0 1 2 3] /Contents <0000> >> >>] >>"),
            "empty-user-encryption" => PdfFixtures.Encrypted(false),
            "password-encryption" => PdfFixtures.Encrypted(true),
            "too-many-pages" => PdfFixtures.Create(21),
            "rotation" => PdfFixtures.Create(rotation: 45),
            "non-finite" => PdfFixtures.Create(media: "0 0 1e999 792"),
            _ => PdfFixtures.Create(media: "0 0 0 0")
        };
        using var input = new MemoryStream(bytes); using var output = new MemoryStream();
        Assert.Throws<DocumentRejectedException>(() => new PdfValidation(new()).Rewrite(input, output));
        Assert.Empty(output.ToArray());
    }
    [Fact]
    public void Crop_offsets_and_user_units_are_recorded_for_the_actual_preview_area()
    {
        using var input = new MemoryStream(PdfFixtures.Create(1, rotation: 270, pageEntries: "/CropBox [10 20 310 420] /UserUnit 2"));
        using var output = new MemoryStream();
        var page = Assert.Single(new PdfValidation(new()).Rewrite(input, output));
        Assert.Equal(600, page.Width); Assert.Equal(800, page.Height);
        Assert.Equal(270, page.Rotation); Assert.Equal(2, page.UserUnit);
        Assert.Equal(new double[] { 10, 20, 310, 420 }, page.CropBox);
    }
    [Fact]
    public void Output_bound_cannot_be_exceeded_by_normalization_or_seeking()
    {
        using var input = new MemoryStream(PdfFixtures.Create()); using var output = new MemoryStream();
        var limited = new BoundedDocumentStream(output, 32);
        Assert.Throws<DocumentRejectedException>(() => new PdfValidation(new()).Rewrite(input, limited));
        Assert.True(output.Length <= 32);
        Assert.Throws<DocumentRejectedException>(() => limited.SetLength(33));
        Assert.Throws<DocumentRejectedException>(() => limited.Seek(33, SeekOrigin.Begin));
    }
    [Fact]
    public void Display_filename_drops_paths_controls_and_reserved_characters()
    {
        Assert.Equal("synthetic.pdf", DocumentWorkflow.Filename("../../synthetic.PDF"));
        Assert.Equal("synthetic.pdf", DocumentWorkflow.Filename("C:\\temporary\\synthetic.pdf"));
        Assert.Equal("badname.pdf", DocumentWorkflow.Filename("bad\r\n<name>.pdf"));
        Assert.Throws<DocumentRejectedException>(() => DocumentWorkflow.Filename("fake.pdf.exe"));
        Assert.True(DocumentWorkflow.Filename(new string('a', 500) + ".pdf").Length <= 124);
    }
}
