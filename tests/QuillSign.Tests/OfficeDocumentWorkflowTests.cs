using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;
using Harness=QuillSign.Tests.DocumentWorkflowTests.Harness;
using Provider=QuillSign.Tests.DocxDocumentWorkflowTests.Provider;

namespace QuillSign.Tests;

public sealed class OfficeDocumentWorkflowTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory][InlineData(OfficeSourceKind.Pptx)][InlineData(OfficeSourceKind.Xlsx)][InlineData(OfficeSourceKind.Odt)][InlineData(OfficeSourceKind.Rtf)]
    public async Task Family_original_derived_PDF_hashes_MIME_audit_retention_and_explicit_confirmation_are_bound(OfficeSourceKind kind)
    {
        await using var h=await Harness.CreateAsync(fixture,true);h.Retention.PurgeAfterDays=7;var bytes=Source(kind);var expected=bytes.ToArray();var provider=Response(kind);provider.Before=()=>{Array.Clear(bytes);return Task.CompletedTask;};Assert.True(await Upload(h,provider,kind,bytes,filename:"../synthetic"+OfficeDocumentWorkflow.Family(kind).Extension.ToUpperInvariant()));var e=await h.StateAsync();
        Assert.Equal("synthetic.pdf",e.Title);Assert.Equal(OfficeDocumentWorkflow.Family(kind).Mime,e.OriginalMime);Assert.Equal(SHA256.HashData(expected),e.OriginalSha256);Assert.Null(e.PreviewConfirmedAt);Assert.Equal(2,e.PageCount);
        using var saved=new MemoryStream();await h.Store.Inner.CopyToAsync(h.Sender,new(h.Id,DocumentBlobKind.Original,Guid.ParseExact(e.OriginalBlob!,"N")),saved);Assert.Equal(expected,saved.ToArray());await using var pdf=await h.WithAsync(w=>w.ReadAsync(h.Sender,h.PublicId,e.PdfBlob!,default));Assert.NotNull(pdf);Assert.Equal(e.PdfSha256,await SHA256.HashDataAsync(pdf));
        await using(var db=fixture.Open())
        {
            var audit=Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Id).ToArrayAsync());Assert.Equal(AuditHash.Compute(audit),audit.Hash);using var data=JsonDocument.Parse(audit.DataJson);var conversion=data.RootElement.GetProperty("conversion");Assert.Equal(OfficeDocumentWorkflow.Family(kind).Pipeline,conversion.GetProperty("version").GetString());Assert.Equal("synthetic"+OfficeDocumentWorkflow.Family(kind).Extension,conversion.GetProperty("originalFilename").GetString());Assert.Equal(OfficeDocumentWorkflow.Family(kind).Mime,conversion.GetProperty("originalMime").GetString());Assert.Equal(expected.Length,conversion.GetProperty("originalBytes").GetInt64());Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(provider.LastOriginal!)),conversion.GetProperty("conversionInputSha256").GetString());Assert.Equal(provider.LastOriginal!.Length,conversion.GetProperty("conversionInputBytes").GetInt64());
            if(kind is OfficeSourceKind.Xlsx or OfficeSourceKind.Rtf)Assert.NotEqual(expected,provider.LastOriginal);else Assert.Equal(expected,provider.LastOriginal);
            var policy=await new UploadRetention(db,h.Retention,h.Time).ReadAsync(e);Assert.NotNull(policy);Assert.Equal(policy.StartedAt.AddDays(7),policy.DeleteAfter);Assert.Equal(e.OriginalSha256,policy.OriginalSha256);Assert.Equal(e.PdfSha256,policy.PdfSha256);Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==h.Id));
        }
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,e.RowVersion,e.PdfBlob!,false,null,null,default)));Assert.True(await h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default)));
    }
    [Theory][InlineData(OfficeSourceKind.Pptx)][InlineData(OfficeSourceKind.Xlsx)][InlineData(OfficeSourceKind.Odt)][InlineData(OfficeSourceKind.Rtf)]
    public async Task Each_gate_rejects_wrong_active_or_disguised_content_without_provider_or_mutation(OfficeSourceKind kind)
    {
        await using var h=await Prepared();var before=await h.StateAsync();var provider=Response(kind);var bytes=kind==OfficeSourceKind.Rtf?"{\\rtf1\\ansi{\\object PRIVATE-MARKER}}"u8.ToArray():Source(kind==OfficeSourceKind.Xlsx?OfficeSourceKind.Pptx:OfficeSourceKind.Xlsx);using var input=new MemoryStream(bytes);await Assert.ThrowsAsync<DocumentRejectedException>(()=>Upload(h,provider,kind,bytes,source:input));Assert.Equal(0,provider.Calls);await Same(h,before);
    }
    [Theory][InlineData("master")][InlineData("family")][InlineData("transport")][InlineData("converter")][InlineData("filename")][InlineData("length")][InlineData("stale")][InlineData("unverified")][InlineData("cutoff")][InlineData("provider")][InlineData("geometry")]
    public async Task Failed_authority_configuration_or_conversion_preserves_confirmed_source_and_deadline(string mode)
    {
        await using var h=await Prepared();var before=await h.StateAsync();DocumentRetentionSnapshot policy;await using(var db=fixture.Open())policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id);
        var provider=Response(OfficeSourceKind.Xlsx);if(mode=="provider")provider.Status=System.Net.HttpStatusCode.ServiceUnavailable;if(mode=="geometry")provider.Pdf=PdfFixtures.Create(pages:2);
        if(mode=="unverified"){await using var db=fixture.Open();var e=await db.Envelopes.SingleAsync(x=>x.Id==h.Id);e.SenderVerifiedAt=null;await db.SaveChangesAsync();before=await h.StateAsync();}if(mode=="cutoff")h.Time=new Clock(policy.DeleteAfter);
        var bytes=Source(OfficeSourceKind.Xlsx);using var input=new MemoryStream(bytes);var error=await Record.ExceptionAsync(async()=>{var result=await Upload(h,provider,OfficeSourceKind.Xlsx,bytes,source:input,version:mode=="stale"?new byte[8]:before.RowVersion,filename:mode=="filename"?"synthetic.doc":"synthetic.xlsx",length:input.Length+(mode=="length"?1:0),mode:mode);if(mode=="unverified")Assert.False(result);});if(mode!="unverified")Assert.NotNull(error);if(error is not null){Assert.DoesNotContain("PRIVATE-MARKER",error.Message);Assert.Null(error.InnerException);}Assert.Equal(mode is "provider" or "geometry"?1:0,provider.Calls);if(mode is "master" or "family" or "transport" or "converter" or "stale" or "unverified" or "cutoff" or "filename")Assert.Equal(0,input.Position);await Same(h,before);await using var check=fixture.Open();Assert.Equal(policy.DeleteAfter,(await check.DocumentRetentionSnapshots.SingleAsync(x=>x.EnvelopeId==h.Id)).DeleteAfter);
    }
    [Theory][InlineData("authority")][InlineData("revision")][InlineData("cutoff")][InlineData("cancel")]
    public async Task Post_conversion_fences_run_before_writes_and_without_a_SQL_connection(string mode)
    {
        await using var h=await Prepared();var before=await h.StateAsync();var writes=h.Store.Writes;DateTimeOffset deadline;await using(var db=fixture.Open())deadline=(await db.DocumentRetentionSnapshots.SingleAsync(x=>x.EnvelopeId==h.Id)).DeleteAfter;var clock=new Clock(h.Time.GetUtcNow());h.Time=clock;using var cancel=new CancellationTokenSource();
        await h.WithDatabaseAsync(async db=>{var provider=Response(OfficeSourceKind.Rtf);provider.Before=async()=>{Assert.Null(db.Database.CurrentTransaction);Assert.Equal(ConnectionState.Closed,db.Database.GetDbConnection().State);if(mode=="cancel"){cancel.Cancel();return;}if(mode=="cutoff"){clock.Now=deadline;return;}await using var concurrent=fixture.Open();var e=await concurrent.Envelopes.SingleAsync(x=>x.Id==h.Id);if(mode=="authority")e.SenderVerifiedAt=null;else e.Title="Concurrent edit";await concurrent.SaveChangesAsync();};using var input=new MemoryStream(Source(OfficeSourceKind.Rtf));var error=await Record.ExceptionAsync(async()=>{var result=await Service(h,db,provider).UploadAsync(h.Sender,h.PublicId,before.RowVersion,OfficeSourceKind.Rtf,"synthetic.rtf",input,input.Length,null,null,cancel.Token);if(mode=="authority")Assert.False(result);});if(mode!="authority")Assert.NotNull(error);Assert.Equal(1,provider.Calls);return true;});Assert.Equal(writes,h.Store.Writes);Assert.Equal(before.PdfBlob,(await h.StateAsync()).PdfBlob);
    }
    [Theory][InlineData("write1")][InlineData("write2")][InlineData("audit")][InlineData("commit")]
    public async Task Rollback_and_uncertain_commit_preserve_correct_owned_original_PDF_pair(string mode)
    {
        await using var h=await Prepared();var before=await h.StateAsync();if(mode.StartsWith("write"))h.Store.FailWrite=h.Store.Writes+(mode=="write1"?1:2);if(mode=="audit")h.AuditFailure.Enabled=true;if(mode=="commit")h.CommitFailure.Enabled=true;var provider=Response(OfficeSourceKind.Xlsx);var bytes=Source(OfficeSourceKind.Xlsx);Assert.NotNull(await Record.ExceptionAsync(()=>Upload(h,provider,OfficeSourceKind.Xlsx,bytes)));var after=await h.StateAsync();if(mode=="commit"){Assert.NotEqual(before.PdfBlob,after.PdfBlob);Assert.Equal(SHA256.HashData(bytes),after.OriginalSha256);h.CommitFailure.Enabled=false;await Assert.ThrowsAsync<DocumentConflictException>(()=>Upload(h,provider,OfficeSourceKind.Xlsx,bytes,version:before.RowVersion));Assert.Equal(1,provider.Calls);}else await Same(h,before);await using var saved=await h.WithAsync(w=>w.ReadAsync(h.Sender,h.PublicId,after.PdfBlob!,default));Assert.NotNull(saved);Assert.Equal(after.PdfSha256,await SHA256.HashDataAsync(saved));
    }
    [Fact]
    public async Task Successful_replacement_keeps_first_retention_and_clears_confirmation_only_once()
    {
        await using var h=await Prepared();DocumentRetentionSnapshot policy;await using(var db=fixture.Open())policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id);h.Retention.PurgeAfterDays=30;var before=await h.StateAsync();Assert.True(await Upload(h,Response(OfficeSourceKind.Odt),OfficeSourceKind.Odt));var after=await h.StateAsync();Assert.Null(after.PreviewConfirmedAt);Assert.NotEqual(before.PdfBlob,after.PdfBlob);await using var check=fixture.Open();Assert.Equal(policy.DeleteAfter,(await new UploadRetention(check,h.Retention,h.Time).ReadAsync(after))!.DeleteAfter);
    }
    public static byte[] Source(OfficeSourceKind kind)=>kind switch{OfficeSourceKind.Pptx=>PptxPackageValidationTests.PackageWithAssets(),OfficeSourceKind.Xlsx=>XlsxPackageValidationTests.Package(),OfficeSourceKind.Odt=>OdtPackageValidationTests.Package(true),OfficeSourceKind.Rtf=>RtfPackageValidationTests.Package(),_=>throw new ArgumentException()};
    internal static Provider Response(OfficeSourceKind kind)=>new(){Pdf=PdfFixtures.Create(pages:2,media:kind switch{OfficeSourceKind.Pptx=>"0 0 960 540",OfficeSourceKind.Xlsx=>"0 0 841.8897637795276 595.2755905511812",OfficeSourceKind.Odt=>"0 0 595.2755905511812 841.8897637795276",_=>"0 0 612 792"},text:"SYNTHETIC OFFICE - NO AGREEMENT")};
    private static async Task Same(Harness h,Envelope before){var after=await h.StateAsync();Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.PdfBlob,after.PdfBlob);Assert.Equal(before.OriginalBlob,after.OriginalBlob);Assert.Equal(before.PreviewConfirmedAt,after.PreviewConfirmedAt);}
    private async Task<Harness> Prepared(){var h=await Harness.CreateAsync(fixture,true);h.Retention.PurgeAfterDays=7;await h.UploadAsync(PdfFixtures.Create());var e=await h.StateAsync();await h.WithAsync(w=>w.ConfirmAsync(h.Sender,h.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default));return h;}
    private static async Task<bool> Upload(Harness h,Provider provider,OfficeSourceKind kind,byte[]? bytes=null,string? filename=null,byte[]? version=null,long? length=null,MemoryStream? source=null,string mode="",CancellationToken ct=default){version??=(await h.StateAsync()).RowVersion;using var owned=source is null?new MemoryStream(bytes??Source(kind)):null;var input=source??owned!;return await h.WithDatabaseAsync(db=>Service(h,db,provider,mode).UploadAsync(h.Sender,h.PublicId,version,kind,filename??"synthetic"+OfficeDocumentWorkflow.Family(kind).Extension,input,length??input.Length,null,null,ct));}
    private static OfficeDocumentWorkflow Service(Harness h,QuillSignDbContext db,Provider provider,string mode="")
    {
        var limits=new DocumentOptions{EnableOfficeUploads=mode!="master"};var options=new GotenbergOptions{Enabled=mode!="converter",BaseUrl="https://converter.example.invalid",Transport=mode=="transport"?"Sandbox":"Http"};var formats=new OfficeConversionOptions{PptxEnabled=mode!="family",XlsxEnabled=mode!="family",OdtEnabled=mode!="family",RtfEnabled=mode!="family"};var env=new EnvironmentStub();var converter=new GotenbergDocxConverter(new HttpClient(provider,false),options,limits,new(limits),env);var documents=new DocumentWorkflow(db,h.Store,new(limits),limits,new(db,h.Time),h.Time,NullLogger<DocumentWorkflow>.Instance,h.Retention,h.PurgeJobs(db));return new(documents,new(formats,converter),limits,formats,options,env,new(limits),new(limits),new(limits),new(limits,new(limits)));
    }
    private sealed class Clock(DateTimeOffset now):TimeProvider{public DateTimeOffset Now=now;public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed class EnvironmentStub:IHostEnvironment{public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Tests";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}
