using System.Text.Json;
using MimeKit;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Tests;

public sealed class PdfEmailAttachmentIntegrationTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Actual_local_SMTP_capture_preserves_plain_HTML_and_exact_decoded_PDF_attachments(bool attach)
    {
        var a=PdfFixtures.Create(text:"Synthetic executed transport fixture - NO AGREEMENT");var b=PdfFixtures.Create(text:"Synthetic certificate transport fixture - NO AGREEMENT");
        var recipient="synthetic-attachments-"+Guid.NewGuid().ToString("N")+"@example.invalid";var options=PdfEmailAttachmentTests.Options();
        options.Provider="Smtp";options.Smtp=new() {Host="127.0.0.1",Port=int.Parse(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_SMTP_PORT")!),UseStartTls=false};
        var envelope=Guid.NewGuid();var message=new OutgoingEmail(recipient,"Synthetic PDF transport","Synthetic plain body","<p>Synthetic HTML body</p>",envelope,
            attach ? new[]{new PdfEmailAttachment("Synthetic résumé executed.pdf",a),new PdfEmailAttachment("Synthetic certificate.pdf",b)} : null);
        await using var db=fixture.Open();var delivery=await new EmailSender(options,()=>db,()=>new SmtpEmailTransport(options)).SendAsync(message);Assert.Equal("Smtp",delivery.Provider);
        using var http=new HttpClient {BaseAddress=new Uri("http://127.0.0.1:"+Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT"))};string? id=null;
        for(var attempt=0;attempt<20 && id is null;attempt++) {
            using var list=JsonDocument.Parse(await http.GetStringAsync("/api/v1/messages"));
            id=list.RootElement.GetProperty("messages").EnumerateArray().FirstOrDefault(x=>x.GetProperty("To").EnumerateArray().Any(t=>t.GetProperty("Address").GetString()==recipient)) is var item && item.ValueKind!=JsonValueKind.Undefined ? item.GetProperty("ID").GetString() : null;
            if(id is null)await Task.Delay(100);
        }
        Assert.NotNull(id);var raw=await http.GetByteArrayAsync("/api/v1/message/"+id+"/raw");using var captured=await MimeMessage.LoadAsync(new MemoryStream(raw));
        Assert.Equal(recipient,Assert.Single(captured.To.Mailboxes).Address);Assert.Equal(message.Text,captured.TextBody?.TrimEnd());Assert.Equal(message.Html,captured.HtmlBody?.TrimEnd());
        Assert.Equal(envelope.ToString("N"),captured.Headers["X-QuillSign-Envelope"]);var parts=captured.Attachments.Cast<MimePart>().ToArray();Assert.Equal(attach ? 2 : 0,parts.Length);
        if(attach) {
            Assert.Equal(message.Attachments!.Select(x=>x.FileName),parts.Select(x=>x.FileName));
            foreach(var (expected,part) in new[]{a,b}.Zip(parts)) {
                Assert.Equal("application/pdf",part.ContentType.MimeType);Assert.Equal(ContentDisposition.Attachment,part.ContentDisposition?.Disposition);Assert.Equal(ContentEncoding.Base64,part.ContentTransferEncoding);
                using var decoded=new MemoryStream();await part.Content!.DecodeToAsync(decoded);Assert.Equal(expected,decoded.ToArray());
            }
        }
    }
    [Fact]
    public async Task Sender_snapshots_the_list_before_provider_construction_and_keeps_disabled_suppressed_and_cancelled_gates()
    {
        var bytes=PdfFixtures.Create(text:"Synthetic attachment ownership - NO AGREEMENT");var expected=bytes.ToArray();var file=new PdfEmailAttachment("executed.pdf",bytes);bytes[^1]^=1;
        var files=new List<PdfEmailAttachment> {file};var options=PdfEmailAttachmentTests.Options();using var client=new PdfEmailAttachmentTests.CaptureSes();await using var db=fixture.Open();
        var recipient="synthetic-gates-"+Guid.NewGuid().ToString("N")+"@example.invalid";var message=new OutgoingEmail(recipient,"Synthetic","Text","HTML",Attachments:files);
        var sender=new EmailSender(options,()=>db,()=> {files.Clear();return new SesEmailTransport(client,options);});await sender.SendAsync(message);
        Assert.Empty(files);Assert.Equal(expected,Assert.Single(client.Bytes));
        files.Add(file);
        db.Suppressions.Add(new() {Email=recipient,Reason=SuppressionReason.Complaint});await db.SaveChangesAsync();
        await Assert.ThrowsAsync<RecipientSuppressedException>(()=>sender.SendAsync(message));Assert.Equal(1,client.Calls);
        options.Enabled=false;var unavailable=new EmailSender(options,()=>throw new InvalidOperationException("Database forbidden"),()=>throw new InvalidOperationException("Provider forbidden"));
        await Assert.ThrowsAsync<EmailDisabledException>(()=>unavailable.SendAsync(message));options.Enabled=true;using var cancelled=new CancellationTokenSource();cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>unavailable.SendAsync(message,cancelled.Token));Assert.Equal(1,client.Calls);
    }
}
