using System.Data;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Storage;
using Shared=QuillSign.Tests.DocumentWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class ImageDocumentWorkflowTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("png")][InlineData("jpg")][InlineData("jpeg")]
    public async Task Actual_images_persist_exact_original_and_normalized_hashes_media_geometry_and_safe_provenance(string extension)
    {
        await using var h=await Shared.CreateAsync(fixture,true);h.Retention.PurgeAfterDays=7;
        var input=extension=="png" ? ImagePdfConverterTests.Png(orientation:6) : ImagePdfConverterTests.Jpeg(orientation:6);var expected=input.ToArray();using var source=new Probe(input);
        Assert.True(await Upload(h,source,filename:"../unsafe<name>."+extension.ToUpperInvariant()));Assert.True(source.CanRead);input[0]^=1;
        var e=await h.StateAsync();Assert.Equal("unsafename.pdf",e.Title);Assert.Equal(extension=="png" ? "image/png" : "image/jpeg",e.OriginalMime);Assert.Null(e.PreviewConfirmedAt);Assert.Equal(1,e.PageCount);
        Assert.Equal(expected,await Original(h,e));Assert.Equal(SHA256.HashData(expected),e.OriginalSha256);var pdf=await Pdf(h,e);Assert.Equal(SHA256.HashData(pdf),e.PdfSha256);
        using(var document=UglyToad.PdfPig.PdfDocument.Open(pdf)) {var page=document.GetPage(1);var image=Assert.Single(page.GetImages());Assert.Equal(48,image.WidthInSamples);Assert.Equal(80,image.HeightInSamples);Assert.Equal(612,page.Width);Assert.Equal(792,page.Height);}
        Assert.DoesNotContain("PRIVATE-MARKER",Encoding.Latin1.GetString(pdf));
        await using var db=fixture.Open();var policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==e.Id);Assert.Equal(e.OriginalSha256,policy.OriginalSha256);Assert.Equal(e.PdfSha256,policy.PdfSha256);
        var audit=await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==e.Id);Assert.Equal(AuditHash.Compute(audit),audit.Hash);using var data=JsonDocument.Parse(audit.DataJson);var conversion=data.RootElement.GetProperty("conversion");
        Assert.Equal("image-stb-v1",conversion.GetProperty("version").GetString());Assert.Equal("unsafename."+extension,conversion.GetProperty("originalFilename").GetString());Assert.Equal(e.OriginalMime,conversion.GetProperty("originalMime").GetString());Assert.Equal(expected.Length,conversion.GetProperty("originalBytes").GetInt64());Assert.Equal(pdf.Length,conversion.GetProperty("pdfBytes").GetInt64());Assert.Equal(48,conversion.GetProperty("width").GetInt32());Assert.Equal(80,conversion.GetProperty("height").GetInt32());
        Assert.Equal(UploadRetention.Digest(policy),data.RootElement.GetProperty("retentionSha256").GetString());
        Assert.True(await h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default)));
    }

    [Fact]
    public async Task All_three_source_kinds_replace_in_both_directions_without_resetting_retention_or_preserving_stale_preparation()
    {
        await using var h=await Shared.CreateAsync(fixture,true);h.Retention.PurgeAfterDays=7;var clock=new Clock();h.Time=clock;
        Assert.True(await Upload(h));await using var db=fixture.Open();var first=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id);var originalDigest=UploadRetention.Digest(first);
        foreach(var kind in new[]{"pdf","image","docx","image","pdf","docx"})
        {
            var old=await h.StateAsync();Assert.True(await h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,old.RowVersion,old.PdfBlob!,true,null,null,default)));
            db.Fields.Add(new(){EnvelopeId=h.Id,Type=FieldType.Text,Page=1,X=.1m,Y=.1m,Width=.2m,Height=.1m,Value="SYNTHETIC"});await db.SaveChangesAsync();
            await db.Envelopes.Where(x=>x.Id==h.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.AiRolesJson,"{}").SetProperty(x=>x.AiModel,"synthetic"));
            h.Retention.PurgeAfterDays=30;clock.Now=clock.Now.AddHours(1);
            if(kind=="pdf")Assert.True(await h.UploadAsync(PdfFixtures.Create()));
            else if(kind=="image")Assert.True(await Upload(h));
            else Assert.True(await DocxDocumentWorkflowTests.Upload(h,new(){Pdf=await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory,"Fixtures","synthetic-conversion.pdf"))},bytes:await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory,"Fixtures","synthetic-conversion.docx"))));
            var current=await h.StateAsync();Assert.Null(current.PreviewConfirmedAt);Assert.Null(current.AiRolesJson);Assert.Null(current.AiModel);Assert.False(await db.Fields.AnyAsync(x=>x.EnvelopeId==h.Id));
            Assert.Null(await h.WithAsync(w=>w.ReadAsync(h.Sender,h.PublicId,old.PdfBlob!,default)));Assert.Equal(originalDigest,UploadRetention.Digest(await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id)));
        }
    }

    [Theory]
    [InlineData("suffix")][InlineData("mismatch")][InlineData("broken")][InlineData("length")][InlineData("oversize")][InlineData("pixels")]
    public async Task Rejected_input_preserves_the_confirmed_source_without_new_objects_or_audit(string failure)
    {
        await using var h=await Confirmed();var before=await h.StateAsync();var writes=h.Store.Writes;
        var bytes=failure=="broken" ? "PRIVATE-MARKER"u8.ToArray() : failure=="pixels" ? ImagePdfConverterTests.Png(width:12001,height:1) : ImagePdfConverterTests.Png();using var input=new Probe(bytes);
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>Upload(h,input,filename:failure=="suffix" ? "synthetic.gif" : failure=="mismatch" ? "synthetic.jpg" : "synthetic.png",declared:failure=="length" ? bytes.Length+1 : failure=="oversize" ? 11*1024*1024 : null));
        Assert.True(input.CanRead);Assert.Equal(before.RowVersion,(await h.StateAsync()).RowVersion);Assert.Equal(writes,h.Store.Writes);if(failure is "suffix" or "oversize")Assert.Equal(0,input.Reads);
    }

    [Theory]
    [InlineData("other")][InlineData("stale")][InlineData("sent")][InlineData("unverified")]
    public async Task Initial_authority_or_version_failure_does_not_read_input(string reason)
    {
        await using var h=await Confirmed();var before=await h.StateAsync();var writes=h.Store.Writes;using var input=new Probe(ImagePdfConverterTests.Png());
        if(reason is "sent" or "unverified") {await using var db=fixture.Open();if(reason=="sent")await db.Envelopes.Where(x=>x.Id==h.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Sent));else await db.Envelopes.Where(x=>x.Id==h.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SenderVerifiedAt,(DateTimeOffset?)null));}
        var principal=reason=="other" ? SenderConfiguration.Principal(new(h.Id,h.PublicId,"other@example.invalid")) : h.Sender;
        if(reason=="stale")await Assert.ThrowsAsync<DocumentConflictException>(()=>Upload(h,input,version:new byte[8]));
        else Assert.False(await Upload(h,input,sender:principal));Assert.Equal(0,input.Reads);Assert.Equal(writes,h.Store.Writes);
    }

    [Theory]
    [InlineData("revoke")][InlineData("version")][InlineData("cancel")]
    public async Task Authority_version_and_cancellation_are_rechecked_after_owned_conversion_before_writing(string change)
    {
        await using var h=await Confirmed();var before=await h.StateAsync();var writes=h.Store.Writes;using var cancel=new CancellationTokenSource();using var input=new Probe(ImagePdfConverterTests.Png());
        input.AfterFirst=async()=>{if(change=="cancel")cancel.Cancel();else {await using var db=fixture.Open();if(change=="revoke")await db.Envelopes.Where(x=>x.Id==h.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SenderVerifiedAt,(DateTimeOffset?)null));else await db.Envelopes.Where(x=>x.Id==h.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Title,"Updated synthetic"));}};
        if(change=="cancel")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Upload(h,input,ct:cancel.Token));
        else if(change=="version")await Assert.ThrowsAsync<DocumentConflictException>(()=>Upload(h,input));else Assert.False(await Upload(h,input));
        Assert.Equal(writes,h.Store.Writes);Assert.Equal(before.PdfBlob,(await h.StateAsync()).PdfBlob);
    }

    [Theory]
    [InlineData("before")][InlineData("input")][InlineData("audit")]
    public async Task Fixed_retention_cutoff_is_preserved_at_every_conversion_publication_boundary(string crossing)
    {
        await using var h=await Shared.CreateAsync(fixture,true);var clock=new Clock();h.Time=clock;h.Retention.PurgeAfterDays=7;await h.UploadAsync(PdfFixtures.Create());var before=await h.StateAsync();await using var db=fixture.Open();var policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id);using var input=new Probe(ImagePdfConverterTests.Png());
        void Cross()=>clock.Now=policy.DeleteAfter;
        if(crossing=="before")Cross();if(crossing=="input")input.AfterFirst=()=>{Cross();return Task.CompletedTask;};if(crossing=="audit")h.AuditFailure.AfterInsert=Cross;
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>Upload(h,input));Assert.Equal(before.RowVersion,(await h.StateAsync()).RowVersion);Assert.Equal(policy.DeleteAfter,(await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id)).DeleteAfter);if(crossing=="before")Assert.Equal(0,input.Reads);
    }

    [Theory]
    [InlineData("storage")][InlineData("audit")][InlineData("commit")]
    public async Task Rollback_and_lost_commit_preserve_the_correct_source_pair_and_stale_retries_never_reconvert(string failure)
    {
        await using var h=await Confirmed();var before=await h.StateAsync();var writes=h.Store.Writes;if(failure=="storage")h.Store.FailWrite=writes+2;if(failure=="audit")h.AuditFailure.Enabled=true;if(failure=="commit")h.CommitFailure.Enabled=true;
        if(failure=="audit")Assert.IsType<IOException>((await Assert.ThrowsAsync<DbUpdateException>(()=>Upload(h))).InnerException);
        else await Assert.ThrowsAsync<IOException>(()=>Upload(h));var after=await h.StateAsync();h.AuditFailure.Enabled=false;h.CommitFailure.Enabled=false;
        if(failure=="commit") {Assert.NotEqual(before.PdfBlob,after.PdfBlob);Assert.Equal("image/png",after.OriginalMime);Assert.NotEmpty(await Pdf(h,after));using var retry=new Probe(ImagePdfConverterTests.Png());await Assert.ThrowsAsync<DocumentConflictException>(()=>Upload(h,retry,version:before.RowVersion));Assert.Equal(0,retry.Reads);}
        else {Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.PdfBlob,after.PdfBlob);Assert.NotEmpty(await Pdf(h,after));}
    }

    [Fact]
    public async Task Input_reads_have_no_SQL_transaction_or_open_connection_and_external_transactions_are_refused()
    {
        await using var h=await Shared.CreateAsync(fixture);using var input=new Probe(ImagePdfConverterTests.Png());
        await h.WithDatabaseAsync(async db=>{input.AfterFirst=()=>{Assert.Null(db.Database.CurrentTransaction);Assert.Equal(ConnectionState.Closed,db.Database.GetDbConnection().State);return Task.CompletedTask;};Assert.True(await Service(h,db).UploadAsync(h.Sender,h.PublicId,(await h.StateAsync()).RowVersion,"synthetic.png",input,input.Length,null,null));return true;});
        using var other=new Probe(ImagePdfConverterTests.Png());var current=await h.StateAsync();await h.WithDatabaseAsync(async db=>{await using var transaction=await db.Database.BeginTransactionAsync();await Assert.ThrowsAsync<InvalidOperationException>(()=>Service(h,db).UploadAsync(h.Sender,h.PublicId,current.RowVersion,"synthetic.png",other,other.Length,null,null));await transaction.RollbackAsync();return true;});Assert.Equal(0,other.Reads);
    }

    [Fact]
    public async Task Concurrent_image_requests_have_one_original_PDF_pair_and_one_upload_event()
    {
        await using var h=await Shared.CreateAsync(fixture,true);h.Retention.PurgeAfterDays=7;var before=await h.StateAsync();
        async Task<bool> Try(){try{return await Upload(h,version:before.RowVersion);}catch(DocumentConflictException){return false;}}
        var results=await Task.WhenAll(Try(),Try());Assert.Single(results,x=>x);var e=await h.StateAsync();Assert.Equal("image/png",e.OriginalMime);Assert.NotEmpty(await Pdf(h,e));await using var db=fixture.Open();Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Id).ToArrayAsync());Assert.Single(await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==h.Id).ToArrayAsync());
    }

    public static async Task<byte[]> PersistedPdfForProof(SqlDatabaseFixture fixture,string filename,Stream input)
    {await using var h=await Shared.CreateAsync(fixture,true);h.Retention.PurgeAfterDays=7;var state=await h.StateAsync();Assert.True(await h.WithDatabaseAsync(db=>Service(h,db).UploadAsync(h.Sender,h.PublicId,state.RowVersion,filename,input,input.Length,null,null)));return await Pdf(h,await h.StateAsync());}
    private async Task<Shared> Confirmed(){var h=await Shared.CreateAsync(fixture);await h.UploadAsync(PdfFixtures.Create());var e=await h.StateAsync();await h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default));return h;}
    private static ImageDocumentWorkflow Service(Shared h,QuillSignDbContext db){var o=new DocumentOptions();return new(new(db,h.Store,new(o),o,new(db,h.Time),h.Time,NullLogger<DocumentWorkflow>.Instance,h.Retention,h.PurgeJobs(db)),new(o,new(o)));}
    private static async Task<bool> Upload(Shared h,Probe? input=null,string filename="synthetic.png",byte[]? version=null,long? declared=null,ClaimsPrincipal? sender=null,CancellationToken ct=default)
    {using var owned=input is null ? new Probe(ImagePdfConverterTests.Png()) : null;var source=input ?? owned!;version??=(await h.StateAsync()).RowVersion;return await h.WithDatabaseAsync(db=>Service(h,db).UploadAsync(sender??h.Sender,h.PublicId,version,filename,source,declared??source.Length,null,null,ct));}
    private static async Task<byte[]> Original(Shared h,Envelope e){using var bytes=new MemoryStream();await h.Store.Inner.CopyToAsync(h.Sender,new(h.Id,DocumentBlobKind.Original,Guid.ParseExact(e.OriginalBlob!,"N")),bytes);return bytes.ToArray();}
    private static async Task<byte[]> Pdf(Shared h,Envelope e){await using var file=await h.WithAsync(w=>w.ReadAsync(h.Sender,h.PublicId,e.PdfBlob!,default));using var bytes=new MemoryStream();await file!.CopyToAsync(bytes);return bytes.ToArray();}
    private sealed class Clock:TimeProvider{public DateTimeOffset Now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed class Probe(byte[] bytes):MemoryStream(bytes,false)
    {public int Reads;public Func<Task>? AfterFirst;public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default){Reads++;var count=await base.ReadAsync(buffer,ct);if(Reads==1 && AfterFirst is not null)await AfterFirst();return count;}}
}
