using System.Net;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using Flow=QuillSign.Tests.CompletionDownloadTests.Flow;

namespace QuillSign.Tests;

public sealed class CompletionReaderPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Every_frozen_party_opens_readonly_records_and_downloads_exact_pair_after_original_deadline()
    {
        await using var f=await Flow.Create(fixture,true); f.Clock.Advance(f.Run.Signing.Envelope.ExpiresAt!.Value.AddSeconds(1)-f.Clock.GetUtcNow());
        f.Run.Seal.Options.Pfx.Path="unavailable";
        var parties=new List<(PartyType Type,Guid? Id)> {(PartyType.Sender,null)};
        await using(var db=fixture.Open()) {
            parties.AddRange(await db.Signers.Where(x=>x.EnvelopeId==f.Id).Select(x=>new ValueTuple<PartyType,Guid?>(PartyType.Signer,x.Id)).ToArrayAsync());
            parties.AddRange(await db.Recipients.Where(x=>x.EnvelopeId==f.Id).Select(x=>new ValueTuple<PartyType,Guid?>(PartyType.Recipient,x.Id)).ToArrayAsync());
        }
        Assert.Equal(4,parties.Count);
        foreach(var party in parties) {
            f.Restore([]); var link=await Issue(f,party.Type,party.Id); var before=await Audits(f);
            using(var scanner=await f.Client.GetAsync("/complete/access?token="+link.RawToken)) {
                f.Take(scanner); var html=await scanner.Content.ReadAsStringAsync(); Assert.Equal(HttpStatusCode.OK,scanner.StatusCode); Assert.DoesNotContain(link.RawToken,html);
                Assert.DoesNotContain("Open records</button>",html); Assert.True(scanner.Headers.CacheControl!.NoStore);
            }
            Assert.Equal(before,await Audits(f)); Assert.Null(await Used(link));
            var entry=await Get(f,"/complete/access");
            using(var noCsrf=await Post(f,"/complete/access?handler=Begin",entry,new() {{"code",link.RawToken}},false))Assert.Equal(HttpStatusCode.BadRequest,noCsrf.StatusCode);
            var pending=await Begin(f,link.RawToken); Assert.Null(await Used(link)); Assert.Equal(before,await Audits(f));
            Assert.DoesNotContain(link.RawToken,pending); Assert.DoesNotContain(f.Cookies[CompletionReaderBrowser.PendingCookie],pending);
            using(var open=await Post(f,"/complete/access?handler=Redeem",pending,new() {{"nonce",Nonce(pending)}})) {
                Assert.Equal(HttpStatusCode.Redirect,open.StatusCode); Assert.Equal("/complete/"+f.PublicId,open.Headers.Location!.OriginalString);
                Assert.Contains(open.Headers.GetValues("Set-Cookie"),x=>x.StartsWith("QuillSign.CompletionReader=") && x.Contains("httponly") && x.Contains("samesite=strict"));
            }
            Assert.DoesNotContain(f.Cookies.Keys,x=>x is "QuillSign.Sender" or "QuillSign.Signer"); Assert.NotNull(await Used(link));
            var reads=f.Store.Reads; var page=await Get(f,"/complete/"+f.PublicId); Assert.Equal(reads,f.Store.Reads);
            Assert.Contains("Your completed records",page); Assert.Contains("Download certificate of completion",page);
            Assert.DoesNotContain(f.Cookies[CompletionReaderBrowser.ReceiptCookie],page); Assert.DoesNotContain(link.RawToken,page);
            foreach(var kind in new[]{"executed","certificate"}) {
                var count=await f.Count(); using(var unprepared=await f.Client.GetAsync(Resource(f,kind)))Assert.Equal(HttpStatusCode.NotFound,unprepared.StatusCode); Assert.Equal(count,await f.Count());
                using(var noCsrf=await Download(f,page,kind,false))Assert.Equal(HttpStatusCode.BadRequest,noCsrf.StatusCode);
                using(var prepared=await Download(f,page,kind)) {Assert.Equal(HttpStatusCode.Redirect,prepared.StatusCode);Assert.Equal(Resource(f,kind),prepared.Headers.Location!.OriginalString);}
                Assert.Equal(count+1,await f.Count()); var grants=f.Cookies.ToDictionary(); var audits=await Audits(f);
                using(var pdf=await f.Client.GetAsync(Resource(f,kind))) {
                    f.Take(pdf); Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);Assert.Equal(kind=="executed" ? f.Published.ExecutedBytes : f.Published.CertificateBytes,await pdf.Content.ReadAsByteArrayAsync());
                    Assert.Equal("attachment",pdf.Content.Headers.ContentDisposition!.DispositionType); Assert.True(pdf.Headers.CacheControl!.NoStore);
                }
                Assert.Equal(audits,await Audits(f)); f.Restore(grants);
                using(var replay=await f.Client.GetAsync(Resource(f,kind)))Assert.Equal(HttpStatusCode.OK,replay.StatusCode);
                Assert.Equal(audits,await Audits(f));
            }
            using(var edit=await f.Client.GetAsync("/draft/"+f.PublicId+"/review"))Assert.NotEqual(HttpStatusCode.OK,edit.StatusCode);
        }
        Assert.Equal(8,await f.Count());Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);
    }

    internal static async Task<CompletionAccessLink> Issue(Flow f,PartyType type=PartyType.Sender,Guid? id=null) {
        using var scope=f.App.Services.CreateScope(); return (await scope.ServiceProvider.GetRequiredService<CompletionAccess>().IssueAsync(f.Id,type,id))!;
    }
    internal static async Task<string> Get(Flow f,string url) {using var r=await f.Client.GetAsync(url);f.Take(r);Assert.Equal(HttpStatusCode.OK,r.StatusCode);return await r.Content.ReadAsStringAsync();}
    internal static async Task<string> Begin(Flow f,string code) {
        var entry=await Get(f,"/complete/access");using var begun=await Post(f,"/complete/access?handler=Begin",entry,new() {{"code",code}});
        Assert.Equal(HttpStatusCode.Redirect,begun.StatusCode);Assert.Equal("/complete/access",begun.Headers.Location!.OriginalString);return await Get(f,"/complete/access");
    }
    internal static async Task Open(Flow f,CompletionAccessLink link) {
        var pending=await Begin(f,link.RawToken);using var r=await Post(f,"/complete/access?handler=Redeem",pending,new() {{"nonce",Nonce(pending)}});Assert.Equal(HttpStatusCode.Redirect,r.StatusCode);
    }
    internal static string Nonce(string html)=>Regex.Match(html,"name=\"nonce\" value=\"([a-f0-9]{32})\"").Groups[1].Value;
    internal static string Resource(Flow f,string kind)=>"/complete/"+f.PublicId+"/final/"+kind;
    internal static Task<HttpResponseMessage> Download(Flow f,string page,string kind,bool csrf=true)=>Post(f,"/complete/"+f.PublicId+"?handler=Download",page,new() {{"kind",kind}},csrf);
    internal static async Task<HttpResponseMessage> Post(Flow f,string url,string page,Dictionary<string,string> body,bool csrf=true) {
        if(csrf)body["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page);
        var r=await f.Client.PostAsync(url,new FormUrlEncodedContent(body));f.Take(r);return r;
    }
    private async Task<DateTimeOffset?> Used(CompletionAccessLink link) {await using var db=fixture.Open();return await db.AuthTokens.Where(x=>x.Id==link.TokenId).Select(x=>x.UsedAt).SingleAsync();}
    internal async Task<int> Audits(Flow f) {await using var db=fixture.Open();return await db.AuditEvents.CountAsync(x=>x.EnvelopeId==f.Id);}
}
