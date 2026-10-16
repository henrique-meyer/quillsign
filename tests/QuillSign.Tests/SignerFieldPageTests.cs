using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using PdfSharp.Pdf;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class SignerFieldPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Read_only_pages_are_scoped_encoded_private_and_never_apply_a_field()
    {
        await using var r=await Create();
        foreach(var path in new[]{Path(r),Review(r),Path(r)+"?handler=Snapshot"}) {
            using var response=await r.Client.GetAsync(path); r.Cookies(response); Assert.Equal(HttpStatusCode.OK,response.StatusCode);
            Assert.True(response.Headers.CacheControl!.NoStore); Assert.Equal("no-referrer",Assert.Single(response.Headers.GetValues("Referrer-Policy")));
            var body=await response.Content.ReadAsStringAsync(); Assert.DoesNotContain("PRIVATE OTHER SIGNER",body); Assert.DoesNotContain("<img src=x onerror=",body);
        }
        var review=await r.Client.GetStringAsync(Review(r)); Assert.Contains("7 required entries missing",review); Assert.Contains("Prepare exact review PDF",review);
        await using var db=fixture.Open(); Assert.All(await db.Fields.Where(x=>x.EnvelopeId==r.Envelope.Id && x.SignerId==r.Signer.Id).ToArrayAsync(),x=>Assert.Null(x.FilledAt));
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.Envelope.Id));
    }
    [Fact]
    public async Task Explicit_single_field_apply_clear_and_replay_use_CSRF_and_verified_current_marks()
    {
        await using var r=await Create(); var adoption=await Adopt(r); var page=await Page(r); var field=await Field(r,FieldType.Signature);
        using(var bad=await Change(r,page,field,adoption:adoption,csrf:false))Assert.Equal(HttpStatusCode.BadRequest,bad.StatusCode);
        using(var good=await Change(r,page,field,adoption:adoption)) { Assert.Equal(HttpStatusCode.OK,good.StatusCode); Assert.Null(good.Headers.Location); Assert.False(good.Headers.Contains("Set-Cookie")); Assert.Contains("Applied",await good.Content.ReadAsStringAsync()); }
        using(var replay=await Change(r,page,field,adoption:adoption))Assert.Contains("AlreadyApplied",await replay.Content.ReadAsStringAsync());
        field=await Field(r,FieldType.Signature);
        using(var clear=await Change(r,page,field,action:"Clear"))Assert.Equal(HttpStatusCode.OK,clear.StatusCode);
        await using var db=fixture.Open(); Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.Envelope.Id && x.Event=="field_filled").ToArrayAsync());
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==r.Envelope.Id && x.Event=="field_cleared").ToArrayAsync());
        Assert.All(await db.Fields.Where(x=>x.EnvelopeId==r.Envelope.Id && x.SignerId==r.Signer.Id).ToArrayAsync(),x=>Assert.Null(x.FilledAt));
        Assert.Null((await db.Signers.SingleAsync(x=>x.Id==r.Signer.Id)).SignedAt);
    }
    [Fact]
    public async Task HTML_success_uses_clean_redirect_and_once_only_HttpOnly_notice()
    {
        await using var r=await Create(); var page=await Page(r); var field=await Field(r,FieldType.FullName);
        using var result=await Change(r,page,field,json:false); Assert.Equal(HttpStatusCode.Redirect,result.StatusCode); Assert.Equal(Path(r),result.Headers.Location!.OriginalString);
        Assert.Contains("httponly",Assert.Single(result.Headers.GetValues("Set-Cookie")),StringComparison.OrdinalIgnoreCase); r.Cookies(result);
        using var shown=await r.Client.GetAsync(Path(r)); r.Cookies(shown); Assert.Contains("Field saved. Signing is not complete.",await shown.Content.ReadAsStringAsync());
        Assert.DoesNotContain("Field saved. Signing is not complete.",await Page(r));
    }
    [Fact]
    public async Task Conflicts_return_latest_owned_state_without_overwriting_and_replacement_requires_reapply()
    {
        await using var r=await Create(); var first=await Adopt(r); var page=await Page(r); var text=await Field(r,FieldType.Text);
        using(var saved=await Change(r,page,text,value:"saved first"))Assert.Equal(HttpStatusCode.OK,saved.StatusCode);
        using(var conflict=await Change(r,page,text,value:"unsaved attempt")) { Assert.Equal(HttpStatusCode.Conflict,conflict.StatusCode); Assert.Contains("saved first",await conflict.Content.ReadAsStringAsync()); }
        var mark=await Field(r,FieldType.Signature); using(var saved=await Change(r,page,mark,adoption:first))Assert.Equal(HttpStatusCode.OK,saved.StatusCode);
        var second=await Adopt(r); var review=await r.Client.GetStringAsync(Review(r)); Assert.Contains("Reapply or clear",review); Assert.Contains("1 entries need reapplication",review); Assert.DoesNotContain("alt=\"Saved Signature\"",review);
        mark=await Field(r,FieldType.Signature);
        using(var stale=await Change(r,page,mark,adoption:first))Assert.Equal(HttpStatusCode.Conflict,stale.StatusCode);
        using(var reapplied=await Change(r,page,mark,adoption:second))Assert.Equal(HttpStatusCode.OK,reapplied.StatusCode);
        Assert.Contains("alt=\"Saved Signature\"",await r.Client.GetStringAsync(Review(r)));
    }
    [Theory]
    [InlineData(FieldType.Text,"")][InlineData(FieldType.Text,"e\u0301\r\n<img src=x onerror=alert(1)>")]
    [InlineData(FieldType.Checkbox,"false")][InlineData(FieldType.Checkbox,"true")][InlineData(FieldType.Date,"2026-10-16")][InlineData(FieldType.FullName,null)]
    public async Task Manual_entries_and_server_name_are_saved_and_reviewed_as_text(FieldType type,string? value)
    {
        await using var r=await Create(); var page=await Page(r); var field=await Field(r,type);
        using var result=await Change(r,page,field,value:value); Assert.Equal(HttpStatusCode.OK,result.StatusCode);
        await using var db=fixture.Open(); var saved=await db.Fields.SingleAsync(x=>x.Id==field.Id);
        Assert.Equal(type==FieldType.FullName ? r.Signer.FullName : value!.Replace("\r\n","\n").Normalize(),saved.Value);
        var review=await r.Client.GetStringAsync(Review(r)); Assert.DoesNotContain("<img src=x onerror=",review);
        if(type==FieldType.Checkbox)Assert.Contains(value=="true" ? "Checked" : "Unchecked",review);
        if(type==FieldType.Text && value=="")Assert.Contains("7 required entries missing",review);
    }
    [Theory]
    [InlineData(FieldType.FullName,"override")][InlineData(FieldType.DateSigned,"2026-10-16")][InlineData(FieldType.Checkbox,"yes")][InlineData(FieldType.Date,"2026-02-30")]
    public async Task Read_only_and_invalid_values_never_write(FieldType type,string value)
    {
        await using var r=await Create(); var page=await Page(r); using var response=await Change(r,page,await Field(r,type),value:value);
        Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode); await using var db=fixture.Open(); Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.Envelope.Id));
    }
    [Fact]
    public async Task Current_assets_remain_exact_after_preview_expiry_and_storage_failures_do_not_report_success()
    {
        await using var r=await Create(); var adopted=await Adopt(r); r.Clock.Advance(TimeSpan.FromMinutes(11));
        using(var response=await r.Client.GetAsync(Path(r)+"?handler=Snapshot")) {
            Assert.Equal(HttpStatusCode.OK,response.StatusCode); using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal(adopted,json.RootElement.GetProperty("marks").GetProperty("id").GetGuid());
            Assert.Equal(SignaturePng.Normalize(SignatureAdoptionTests.Mark()).Bytes,Convert.FromBase64String(json.RootElement.GetProperty("marks").GetProperty("signature").GetString()!));
        }
        var page=await Page(r); r.Storage.TamperRead=true;
        foreach(var path in new[]{Path(r),Review(r),Path(r)+"?handler=Snapshot"}) { using var response=await r.Client.GetAsync(path); Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); }
        using var failed=await Change(r,page,await Field(r,FieldType.Signature),adoption:adopted); Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode);
        await using var db=fixture.Open(); Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.Envelope.Id && x.Event=="field_filled"));
    }
    [Theory]
    [InlineData("sender")][InlineData("consent")][InlineData("expiry")][InlineData("signed")][InlineData("foreign-field")][InlineData("request")]
    public async Task Changed_scope_and_foreign_fields_cannot_read_or_mutate(string kind)
    {
        await using var r=await Create(); var page=await Page(r); var field=await Field(r,FieldType.Text);
        if(kind=="sender") { await r.Session("sender"); var cookies=string.Join("; ",r.Client.DefaultRequestHeaders.GetValues("Cookie").Single().Split("; ").Where(x=>!x.StartsWith("QuillSign.Signer="))); r.Client.DefaultRequestHeaders.Remove("Cookie"); r.Client.DefaultRequestHeaders.Add("Cookie",cookies); }
        if(kind=="expiry")r.Clock.Advance(TimeSpan.FromHours(2));
        await using(var db=fixture.Open()) {
            if(kind=="consent")await db.Signers.Where(x=>x.Id==r.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ConsentAt,(DateTimeOffset?)null));
            if(kind=="signed")await db.Signers.Where(x=>x.Id==r.Signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Signed));
            if(kind=="foreign-field")field=await db.Fields.AsNoTracking().SingleAsync(x=>x.EnvelopeId==r.Envelope.Id && x.SignerId!=r.Signer.Id);
        }
        using var changed=await Change(r,page,field,value:"must not save",path:kind=="request" ? "/sign/"+Guid.NewGuid().ToString("N")+"/fields" : null);
        Assert.Contains(changed.StatusCode,new[]{HttpStatusCode.NotFound,HttpStatusCode.Unauthorized});
        if(kind is not ("foreign-field" or "request")) { using var read=await r.Client.GetAsync(Review(r)); Assert.Contains(read.StatusCode,new[]{HttpStatusCode.NotFound,HttpStatusCode.Unauthorized}); }
    }
    [Fact]
    public async Task Interaction_limit_is_separate_from_signature_limit_and_returns_recoverable_JSON()
    {
        await using var r=await Create(); r.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        for(var i=0;i<120;i++) { using var response=await r.Client.GetAsync(Path(r)+"?handler=Snapshot"); Assert.Equal(HttpStatusCode.OK,response.StatusCode); }
        using var limited=await r.Client.GetAsync(Path(r)+"?handler=Snapshot"); Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode); Assert.Contains("saving has not been confirmed",await limited.Content.ReadAsStringAsync());
        using var signature=await r.Client.GetAsync(r.Path); Assert.Equal(HttpStatusCode.OK,signature.StatusCode);
    }
    private async Task<SignaturePageTests.Browser> Create()
    {
        var r=await SignaturePageTests.Browser.Create(fixture); using var pdf=new PdfDocument(); pdf.AddPage(); pdf.AddPage(); using var stream=new MemoryStream(); pdf.Save(stream,false); var bytes=stream.ToArray();
        await r.Storage.WriteAsync(BlobStorageTests.Sender(r.Envelope.Id),new(r.Envelope.Id,DocumentBlobKind.Normalized,Guid.Parse(r.Envelope.SentPdfBlob!)),new MemoryStream(bytes),bytes.Length);
        await using var db=fixture.Open(); await db.Envelopes.Where(x=>x.Id==r.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,SHA256.HashData(bytes)).SetProperty(x=>x.PageCount,2));
        var other=new Signer { EnvelopeId=r.Envelope.Id,Email="other@example.invalid",FullName="PRIVATE OTHER SIGNER",Order=2 }; db.Add(other);
        foreach(var type in Enum.GetValues<FieldType>())db.Add(new DocumentField { EnvelopeId=r.Envelope.Id,SignerId=r.Signer.Id,Type=type,Page=1,X=.1m,Y=.1m+(int)type*.1m,Width=.6m,Height=.05m,Required=true,Label=type==FieldType.Text ? "<img src=x onerror=alert(1)>" : null });
        db.Add(new DocumentField { EnvelopeId=r.Envelope.Id,SignerId=r.Signer.Id,Type=FieldType.Signature,Page=2,X=.1m,Y=.1m,Width=.4m,Height=.1m,Required=true });
        db.Add(new DocumentField { EnvelopeId=r.Envelope.Id,SignerId=other.Id,Type=FieldType.Text,Page=1,X=.1m,Y=.8m,Width=.4m,Height=.1m,Label="PRIVATE OTHER SIGNER" }); await db.SaveChangesAsync();
        r.Identity=r.Identity with { DocumentHash=Convert.ToHexStringLower(SHA256.HashData(bytes)) }; await r.Session("signer"); return r;
    }
    private async Task<DocumentField> Field(SignaturePageTests.Browser r,FieldType type) { await using var db=fixture.Open(); return await db.Fields.AsNoTracking().FirstAsync(x=>x.EnvelopeId==r.Envelope.Id && x.SignerId==r.Signer.Id && x.Type==type && x.Page==1); }
    private static async Task<string> Page(SignaturePageTests.Browser r) { using var response=await r.Client.GetAsync(Path(r)); Assert.Equal(HttpStatusCode.OK,response.StatusCode); r.Cookies(response); return await response.Content.ReadAsStringAsync(); }
    private static string Path(SignaturePageTests.Browser r)=>"/sign/"+r.Envelope.PublicId+"/fields";
    private static string Review(SignaturePageTests.Browser r)=>"/sign/"+r.Envelope.PublicId+"/review";
    private static async Task<Guid> Adopt(SignaturePageTests.Browser r)
    { r.Client.DefaultRequestHeaders.Accept.Clear(); var page=await r.Get(); using var preview=await r.Preview(page); using var json=JsonDocument.Parse(await preview.Content.ReadAsStringAsync()); using var adopted=await r.Adopt(page,json.RootElement.GetProperty("receipt").GetString()!); Assert.Equal(HttpStatusCode.Redirect,adopted.StatusCode); using var snapshot=JsonDocument.Parse(await r.Client.GetStringAsync(Path(r)+"?handler=Snapshot")); return snapshot.RootElement.GetProperty("marks").GetProperty("id").GetGuid(); }
    private static Task<HttpResponseMessage> Change(SignaturePageTests.Browser r,string page,DocumentField field,string action="Apply",string? value=null,Guid? adoption=null,bool csrf=true,bool json=true,string? path=null)
    {
        r.Client.DefaultRequestHeaders.Accept.Clear(); if(json)r.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        var form=new Dictionary<string,string> { ["FieldId"]=field.Id.ToString(),["Version"]=Convert.ToBase64String(field.RowVersion),["Action"]=action };
        if(value is not null)form["Value"]=value; if(adoption is not null)form["AdoptionId"]=adoption.ToString()!; if(csrf)form["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page);
        return r.Client.PostAsync(path??Path(r),new FormUrlEncodedContent(form));
    }
}
