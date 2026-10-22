using System.Net;
using Amazon;
using Amazon.Runtime;
using Amazon.SimpleEmailV2;
using Amazon.SimpleEmailV2.Model;
using QuillSign.Email;

namespace QuillSign.Tests;

public sealed class PdfEmailAttachmentTests
{
    private static byte[] Bytes=>"%PDF-1.7\nSynthetic transport-only bytes\n%%EOF"u8.ToArray();
    [Fact]
    public void Attachment_owns_exact_bytes_and_derived_length_without_writable_or_exposable_buffers()
    {
        var source=Bytes;var expected=source.ToArray();var file=new PdfEmailAttachment("Synthetic résumé.pdf",source);source[^1]^=1;
        using var first=file.OpenRead();Assert.Equal(expected.Length,file.Length);Assert.Equal(expected,first.ToArray());
        Assert.False(first.CanWrite);Assert.False(first.TryGetBuffer(out _));Assert.Throws<UnauthorizedAccessException>(()=>first.GetBuffer());
        Assert.Throws<NotSupportedException>(()=>first.WriteByte(0));var clone=first.ToArray();clone[0]^=1;first.Position=first.Length;
        using var next=file.OpenRead();Assert.Equal(0,next.Position);Assert.Equal(expected,next.ToArray());
    }
    [Theory]
    [InlineData("")][InlineData(".pdf")][InlineData("../secret.pdf")][InlineData("folder\\file.pdf")][InlineData("file.pdf\r\nBcc: someone")]
    [InlineData("file.png")][InlineData(" file.pdf")][InlineData("file.pdf ")][InlineData("file:stream.pdf")][InlineData("a..pdf")]
    public void Unsafe_names_cannot_construct_attachments(string name)=>Assert.Throws<ArgumentException>(()=>new PdfEmailAttachment(name,Bytes));
    [Fact]
    public void Unsupported_content_and_hard_oversize_are_rejected_before_copying()
    {
        Assert.Throws<ArgumentException>(()=>new PdfEmailAttachment("file.pdf","PNG"u8.ToArray()));
        Assert.Throws<EmailAttachmentLimitException>(()=>new PdfEmailAttachment("file.pdf",new byte[EmailAttachmentOptions.HardDecodedBytes+1]));
        Assert.Throws<ArgumentException>(()=>new PdfEmailAttachment(new string('a',117)+".pdf",Bytes));
    }
    [Theory]
    [InlineData("count")][InlineData("duplicate")][InlineData("decoded")][InlineData("message")]
    public async Task Invalid_or_oversize_messages_never_resolve_database_or_provider(string kind)
    {
        var options=new EmailOptions {Enabled=true};var a=new PdfEmailAttachment("executed.pdf",Bytes);var b=new PdfEmailAttachment("certificate.pdf",Bytes);
        IReadOnlyList<PdfEmailAttachment> files=kind=="count" ? new[]{a,b,new PdfEmailAttachment("third.pdf",Bytes)} : kind=="duplicate" ? new[]{a,new PdfEmailAttachment("EXECUTED.PDF",Bytes)} : new[]{a,b};
        if(kind=="decoded")options.Attachments.MaximumDecodedBytes=a.Length+b.Length-1;if(kind=="message")options.Attachments.MaximumMessageBytes=65536;
        var calls=0;var sender=new EmailSender(options,()=>throw new InvalidOperationException("No database access expected"),()=> {calls++;throw new InvalidOperationException("No provider expected");});
        await Assert.ThrowsAnyAsync<ArgumentException>(()=>sender.SendAsync(new("recipient@example.invalid","Synthetic","Text","<p>HTML</p>",Attachments:files)));Assert.Equal(0,calls);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task SES_preserves_simple_alternatives_and_sends_raw_exact_bytes_with_explicit_Base64(bool attachments)
    {
        var options=Options();using var client=new CaptureSes();var files=new[]{new PdfEmailAttachment("executed.pdf",Bytes),new PdfEmailAttachment("certificate.pdf",Bytes)};
        var id=Guid.NewGuid();var message=new OutgoingEmail("recipient@example.invalid","Synthetic","Plain text","<p>HTML</p>",id,attachments ? files : null);
        Assert.Equal(new EmailDelivery("Ses","synthetic-provider-id"),await new SesEmailTransport(client,options).SendAsync(message,default));
        var request=client.Request!;Assert.Null(request.Content.Raw);Assert.Equal(message.Text,request.Content.Simple.Body.Text.Data);Assert.Equal(message.Html,request.Content.Simple.Body.Html.Data);
        Assert.Equal($"Synthetic [QS-{id:N}]",request.Content.Simple.Subject.Data);
        Assert.Equal(id.ToString("N"),Assert.Single(request.Content.Simple.Headers).Value);Assert.Equal("recipient@example.invalid",Assert.Single(request.Destination.ToAddresses));
        Assert.Equal(attachments ? 2 : 0,client.Bytes.Count);
        if(attachments)foreach(var (file,part) in files.Zip(request.Content.Simple.Attachments)) {
            Assert.Equal(file.FileName,part.FileName);Assert.Equal(PdfEmailAttachment.ContentType,part.ContentType);Assert.Equal(AttachmentContentDisposition.ATTACHMENT,part.ContentDisposition);
            Assert.Equal(AttachmentContentTransferEncoding.BASE64,part.ContentTransferEncoding);Assert.False(part.RawContent.CanRead);
        }
        else Assert.Null(request.Content.Simple.Attachments);
        Assert.All(client.Bytes,x=>Assert.Equal(Bytes,x));
    }
    [Theory]
    [InlineData(400,false)][InlineData(429,true)][InlineData(500,null)][InlineData(0,null)][InlineData(-1,null)]
    public async Task SES_attachment_failures_preserve_definite_rejection_and_ambiguous_submission(int status,bool? retryable)
    {
        using var client=new CaptureSes {Failure=status switch {0=>new IOException("Synthetic unknown submission"),-1=>new OperationCanceledException("Synthetic cancellation after submission"),_=>new AmazonSimpleEmailServiceV2Exception("Synthetic provider failure") {StatusCode=(HttpStatusCode)status}}};
        var error=await Record.ExceptionAsync(()=>new SesEmailTransport(client,Options()).SendAsync(new("recipient@example.invalid","Synthetic","Text","HTML",Attachments:[new("executed.pdf",Bytes)]),default));
        Assert.NotNull(error);
        if(retryable is { } retry)Assert.Equal(retry,Assert.IsType<EmailNotSubmittedException>(error).Retryable);else Assert.IsNotType<EmailNotSubmittedException>(error);
        Assert.Equal(1,client.Calls);Assert.Single(client.Bytes);Assert.All(client.Request!.Content.Simple.Attachments,x=>Assert.False(x.RawContent.CanRead));
    }
    [Theory]
    [InlineData("Ses")][InlineData("Smtp")]
    public async Task Already_cancelled_or_oversize_adapter_operations_never_submit(string provider)
    {
        using var client=new CaptureSes();var options=Options();options.Smtp=new() {Host="127.0.0.1",Port=1,UseStartTls=false};
        IEmailTransport transport=provider=="Ses" ? new SesEmailTransport(client,options) : new SmtpEmailTransport(options);
        using var cancelled=new CancellationTokenSource();cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>transport.SendAsync(new("recipient@example.invalid","Synthetic","Text","HTML",Attachments:[new("executed.pdf",Bytes)]),cancelled.Token));Assert.Equal(0,client.Calls);
        options.Attachments.MaximumDecodedBytes=Bytes.Length-1;
        await Assert.ThrowsAsync<EmailAttachmentLimitException>(()=>transport.SendAsync(new("recipient@example.invalid","Synthetic","Text","HTML",Attachments:[new("executed.pdf",Bytes)]),default));Assert.Equal(0,client.Calls);
    }
    internal static EmailOptions Options()=>new() {Enabled=true,FromEmail="noreply@example.invalid",Ses=new() {ConfigurationSet="synthetic"}};
    internal sealed class CaptureSes() : AmazonSimpleEmailServiceV2Client(new AnonymousAWSCredentials(),RegionEndpoint.USEast1)
    {
        public SendEmailRequest? Request;public int Calls;public Exception? Failure;public List<byte[]> Bytes=[];
        public override async Task<SendEmailResponse> SendEmailAsync(SendEmailRequest request,CancellationToken cancellationToken=default) {
            Calls++;Request=request;
            foreach(var file in request.Content.Simple.Attachments??[]) {using var copy=new MemoryStream();await file.RawContent.CopyToAsync(copy,cancellationToken);Bytes.Add(copy.ToArray());}
            if(Failure is not null)throw Failure;return new() {MessageId="synthetic-provider-id"};
        }
    }
}
