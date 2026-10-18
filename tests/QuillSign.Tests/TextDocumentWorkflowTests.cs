using System.Data;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;
using Harness=QuillSign.Tests.DocumentWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class TextDocumentWorkflowTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private static readonly byte[] Text=new byte[]{0xef,0xbb,0xbf}.Concat(Encoding.UTF8.GetBytes("SYNTHETIC TEXT - NO AGREEMENT\r\n<markup>& literal\n\t=WEBSERVICE(\"https://example.invalid/\") café")).ToArray();

    [Fact]
    public async Task Original_owned_text_and_PDF_hashes_audit_retention_and_confirmation_are_bound()
    {
        await using var h=await Harness.CreateAsync(fixture,true);h.Retention.PurgeAfterDays=7;
        var bytes=Text.ToArray();var provider=new DocxDocumentWorkflowTests.Provider{Before=()=>{Array.Clear(bytes);return Task.CompletedTask;}};
        Assert.True(await Upload(h,provider,bytes,filename:"../literal.TXT"));var state=await h.StateAsync();
        Assert.Equal("literal.pdf",state.Title);Assert.Equal(TextDocumentWorkflow.Mime,state.OriginalMime);Assert.Equal(SHA256.HashData(Text),state.OriginalSha256);Assert.Null(state.PreviewConfirmedAt);Assert.Equal(2,state.PageCount);
        using var original=new MemoryStream();await h.Store.Inner.CopyToAsync(h.Sender,new(h.Id,DocumentBlobKind.Original,Guid.ParseExact(state.OriginalBlob!,"N")),original);Assert.Equal(Text,original.ToArray());
        await using var pdf=await h.WithAsync(w=>w.ReadAsync(h.Sender,h.PublicId,state.PdfBlob!,default));Assert.NotNull(pdf);Assert.Equal(state.PdfSha256,await SHA256.HashDataAsync(pdf));
        using var zip=new ZipArchive(new MemoryStream(provider.LastOriginal!));Assert.Equal(3,zip.Entries.Count);using var reader=new StreamReader(zip.GetEntry("word/document.xml")!.Open());var xml=await reader.ReadToEndAsync();Assert.Contains("&lt;markup&gt;&amp; literal",xml);Assert.DoesNotContain("instrText",xml);Assert.Contains("=WEBSERVICE",xml);
        await using(var db=fixture.Open())
        {
            var audit=Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Id).ToArrayAsync());Assert.Equal(AuditHash.Compute(audit),audit.Hash);using var data=JsonDocument.Parse(audit.DataJson);var conversion=data.RootElement.GetProperty("conversion");
            Assert.Equal("text-docx-gotenberg-v1",conversion.GetProperty("version").GetString());Assert.Equal("literal.txt",conversion.GetProperty("originalFilename").GetString());Assert.Equal(TextDocumentWorkflow.Mime,conversion.GetProperty("originalMime").GetString());Assert.Equal(Text.Length,conversion.GetProperty("originalBytes").GetInt64());
            var policy=await new UploadRetention(db,h.Retention,h.Time).ReadAsync(state);Assert.NotNull(policy);Assert.Equal(policy.StartedAt.AddDays(7),policy.DeleteAfter);Assert.Equal(state.OriginalSha256,policy.OriginalSha256);Assert.Equal(state.PdfSha256,policy.PdfSha256);Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==h.Id));
        }
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,state.RowVersion,state.PdfBlob!,false,null,null,default)));
        Assert.True(await h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,state.RowVersion,state.PdfBlob!,true,null,null,default)));
    }

    [Theory]
    [InlineData("encoding")][InlineData("empty")][InlineData("binary")][InlineData("length")][InlineData("filename")][InlineData("disabled")]
    [InlineData("provider")][InlineData("output")][InlineData("stale")][InlineData("unverified")][InlineData("cutoff")]
    public async Task Rejected_text_preserves_previous_source_confirmation_and_fixed_deadline(string mode)
    {
        await using var h=await Prepared();var before=await h.StateAsync();DocumentRetentionSnapshot policy;await using(var db=fixture.Open())policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id);
        var provider=new DocxDocumentWorkflowTests.Provider();var bytes=mode switch {"encoding"=>new byte[]{0xff,0xfe,0x41,0},"binary"=>new byte[]{0x41,0,0x42},"empty"=>" \r\n"u8.ToArray(),_=>Text};
        if(mode=="provider")provider.Status=System.Net.HttpStatusCode.ServiceUnavailable;if(mode=="output")provider.InvalidPdf=true;
        if(mode=="unverified"){await using var db=fixture.Open();var e=await db.Envelopes.SingleAsync(x=>x.Id==h.Id);e.SenderVerifiedAt=null;await db.SaveChangesAsync();before=await h.StateAsync();}
        if(mode=="cutoff")h.Time=new Clock(policy.DeleteAfter);
        using var input=new MemoryStream(bytes);var error=await Record.ExceptionAsync(async()=>{var result=await Upload(h,provider,bytes,filename:mode=="filename" ? "private.doc" : "synthetic.txt",version:mode=="stale" ? new byte[8]:before.RowVersion,length:mode=="length"?bytes.Length+1:null,enabled:mode!="disabled",source:input);if(mode=="unverified")Assert.False(result);});
        if(mode!="unverified")Assert.NotNull(error);if(error is not null){Assert.DoesNotContain("PRIVATE",error.Message);Assert.Null(error.InnerException);}
        var after=await h.StateAsync();Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.OriginalBlob,after.OriginalBlob);Assert.Equal(before.PdfBlob,after.PdfBlob);Assert.Equal(before.PreviewConfirmedAt,after.PreviewConfirmedAt);
        Assert.Equal(mode is "provider" or "output"?1:0,provider.Calls);if(mode is "stale" or "unverified" or "disabled" or "cutoff")Assert.Equal(0,input.Position);
        await using var check=fixture.Open();Assert.Equal(policy.DeleteAfter,(await check.DocumentRetentionSnapshots.SingleAsync(x=>x.EnvelopeId==h.Id)).DeleteAfter);
    }

    [Theory][InlineData("authority")][InlineData("revision")][InlineData("cutoff")][InlineData("cancel")]
    public async Task After_converter_checks_prevent_writes_after_authority_revision_or_cutoff_changes(string mode)
    {
        await using var h=await Prepared();var before=await h.StateAsync();var writes=h.Store.Writes;DateTimeOffset deadline;await using(var db=fixture.Open())deadline=(await db.DocumentRetentionSnapshots.SingleAsync(x=>x.EnvelopeId==h.Id)).DeleteAfter;
        var clock=new Clock(h.Time.GetUtcNow());h.Time=clock;
        using var cancel=new CancellationTokenSource();var provider=new DocxDocumentWorkflowTests.Provider{Before=async()=>{
            if(mode=="cancel"){cancel.Cancel();return;}if(mode=="cutoff"){clock.Now=deadline;return;}
            await using var db=fixture.Open();var e=await db.Envelopes.SingleAsync(x=>x.Id==h.Id);if(mode=="authority")e.SenderVerifiedAt=null;else e.Title="Concurrent edit";await db.SaveChangesAsync();}};
        var error=await Record.ExceptionAsync(async()=>{var result=await Upload(h,provider,version:before.RowVersion,ct:cancel.Token);if(mode=="authority")Assert.False(result);});
        if(mode!="authority")Assert.NotNull(error);Assert.Equal(writes,h.Store.Writes);Assert.Equal(before.PdfBlob,(await h.StateAsync()).PdfBlob);Assert.Equal(1,provider.Calls);
    }

    [Theory][InlineData("write1")][InlineData("write2")][InlineData("audit")][InlineData("commit")]
    public async Task Storage_rollback_and_uncertain_commit_keep_the_correct_original_PDF_pair(string mode)
    {
        await using var h=await Prepared();var before=await h.StateAsync();if(mode.StartsWith("write"))h.Store.FailWrite=h.Store.Writes+(mode=="write1"?1:2);if(mode=="audit")h.AuditFailure.Enabled=true;if(mode=="commit")h.CommitFailure.Enabled=true;
        var provider=new DocxDocumentWorkflowTests.Provider();Assert.NotNull(await Record.ExceptionAsync(()=>Upload(h,provider,version:before.RowVersion)));var after=await h.StateAsync();
        if(mode=="commit")
        {Assert.NotEqual(before.PdfBlob,after.PdfBlob);Assert.Equal(SHA256.HashData(Text),after.OriginalSha256);h.CommitFailure.Enabled=false;await Assert.ThrowsAsync<DocumentConflictException>(()=>Upload(h,provider,version:before.RowVersion));Assert.Equal(1,provider.Calls);}
        else {Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.OriginalBlob,after.OriginalBlob);Assert.Equal(before.PreviewConfirmedAt,after.PreviewConfirmedAt);}
        await using var read=await h.WithAsync(w=>w.ReadAsync(h.Sender,h.PublicId,after.PdfBlob!,default));Assert.NotNull(read);Assert.Equal(after.PdfSha256,await SHA256.HashDataAsync(read));
    }

    [Fact]
    public async Task Conversion_runs_without_SQL_connection_and_replacement_keeps_first_retention()
    {
        await using var h=await Prepared();var before=await h.StateAsync();DocumentRetentionSnapshot policy;await using(var db=fixture.Open())policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id);h.Retention.PurgeAfterDays=30;
        await h.WithDatabaseAsync(async db=>{var provider=new DocxDocumentWorkflowTests.Provider{Before=()=>{Assert.Null(db.Database.CurrentTransaction);Assert.Equal(ConnectionState.Closed,db.Database.GetDbConnection().State);return Task.CompletedTask;}};using var source=new MemoryStream(Text);return await Service(h,db,provider).UploadAsync(h.Sender,h.PublicId,before.RowVersion,"synthetic.txt",source,source.Length,null,null);});
        var after=await h.StateAsync();Assert.Null(after.PreviewConfirmedAt);await using var check=fixture.Open();Assert.Equal(policy.DeleteAfter,(await new UploadRetention(check,h.Retention,h.Time).ReadAsync(after))!.DeleteAfter);
    }

    private async Task<Harness> Prepared(){var h=await Harness.CreateAsync(fixture,true);h.Retention.PurgeAfterDays=7;await h.UploadAsync(PdfFixtures.Create());var e=await h.StateAsync();await h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default));return h;}
    private static async Task<bool> Upload(Harness h,DocxDocumentWorkflowTests.Provider provider,byte[]? bytes=null,string filename="synthetic.txt",byte[]? version=null,long? length=null,bool enabled=true,MemoryStream? source=null,CancellationToken ct=default)
    {version??=(await h.StateAsync()).RowVersion;using var owned=source is null?new MemoryStream(bytes??Text):null;var input=source??owned!;return await h.WithDatabaseAsync(db=>Service(h,db,provider,enabled).UploadAsync(h.Sender,h.PublicId,version,filename,input,length??input.Length,null,null,ct));}
    private static TextDocumentWorkflow Service(Harness h,QuillSignDbContext db,DocxDocumentWorkflowTests.Provider provider,bool enabled=true)
    {
        var limits=new DocumentOptions{EnableTextUploads=enabled};var options=new GotenbergOptions{Enabled=true,BaseUrl="https://converter.example.invalid"};var environment=new EnvironmentStub();var gate=new DocxPackageValidation(limits);
        var converter=new GotenbergDocxConverter(new HttpClient(provider,false),options,limits,new(limits),environment);
        var documents=new DocumentWorkflow(db,h.Store,new(limits),limits,new(db,h.Time),h.Time,NullLogger<DocumentWorkflow>.Instance,h.Retention,h.PurgeJobs(db));return new(documents,new(limits,options,environment,gate,converter),limits,options,environment);
    }
    private sealed class Clock(DateTimeOffset now):TimeProvider {public DateTimeOffset Now=now;public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed class EnvironmentStub:IHostEnvironment
    {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Tests";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}
