using System.Text;
using MimeKit;
using QuillSign.Email;

namespace QuillSign.Tests;

public sealed class EmailSubjectTests
{
    private static readonly Guid First = Guid.Parse("11111111-2222-3333-4444-555555555555");
    private static readonly Guid Second = Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    private static OutgoingEmail Snapshot(string subject, Guid? document) => PdfEmailAttachments.Snapshot(
        new("recipient@example.invalid", subject, "Synthetic text", "<p>Synthetic HTML</p>", document), new(), default);

    [Theory]
    [InlineData("Verify your email to start your document")]
    [InlineData("Review your signing request")]
    [InlineData("Reminder: review your signing request")]
    [InlineData("Review your replacement signing invitation")]
    [InlineData("Review your corrected signing invitation")]
    [InlineData("Your completed QuillSign records")]
    [InlineData("Your signing request was declined")]
    [InlineData("A QuillSign signing request was voided")]
    public void Each_document_subject_keeps_one_stable_full_reference_and_distinguishes_other_documents(string subject)
    {
        var first = Snapshot(subject, First);
        var second = Snapshot(subject, Second);
        Assert.Equal(subject + " [QS-11111111222233334444555555555555]", first.Subject);
        Assert.Equal(subject + " [QS-aaaaaaaabbbbccccddddeeeeeeeeeeee]", second.Subject);
        Assert.NotEqual(first.Subject, second.Subject);
        var repeated = PdfEmailAttachments.Snapshot(first, new(), default);
        Assert.Equal(first.Subject, repeated.Subject);
        Assert.Equal("Synthetic text", repeated.Text);
        Assert.Equal("<p>Synthetic HTML</p>", repeated.Html);
    }

    [Fact]
    public void Generic_lookup_without_a_document_keeps_its_truthful_subject()
        => Assert.Equal("Your private document lookup link", Snapshot("Your private document lookup link", null).Subject);

    [Fact]
    public void Long_unicode_subject_retains_the_full_reference_without_splitting_a_character()
    {
        var original = new string('a', 959) + "🔏" + new string('b', 37);
        Assert.Equal(998, original.Length);
        var result = Snapshot(original, First);
        Assert.InRange(result.Subject.Length, 1, 998);
        Assert.EndsWith(" [QS-11111111222233334444555555555555]", result.Subject);
        _ = new UTF8Encoding(false, true).GetBytes(result.Subject);
        Assert.Equal(result.Subject, PdfEmailAttachments.Snapshot(result, new(), default).Subject);
    }

    [Theory]
    [InlineData("Synthetic\r\nBcc: other@example.invalid")]
    [InlineData("Synthetic\0")]
    public void Invalid_subject_headers_are_rejected_before_formatting(string subject)
        => Assert.Throws<ArgumentException>(() => Snapshot(subject, First));

    [Fact]
    public void An_empty_document_reference_is_rejected()
        => Assert.Throws<ArgumentException>(() => Snapshot("Synthetic", Guid.Empty));

    [Fact]
    public async Task Prepared_MIME_preserves_the_same_subject_after_ordinary_normalization()
    {
        var message = Snapshot("Sample agreement", First);
        var artifact = await PreparedRawMime.PrepareAsync(message, "sender@example.invalid", "QuillSign");
        using var input = artifact.OpenRead();
        using var mime = await MimeMessage.LoadAsync(input);
        Assert.Equal("Sample agreement [QS-11111111222233334444555555555555]", mime.Subject);
        Assert.Equal(message.Subject, mime.Subject);
        Assert.Equal(message.Text, mime.TextBody);
        Assert.Equal(message.Html, mime.HtmlBody);
        Assert.Equal(First.ToString("N"), mime.Headers["X-QuillSign-Envelope"]);
    }
}
