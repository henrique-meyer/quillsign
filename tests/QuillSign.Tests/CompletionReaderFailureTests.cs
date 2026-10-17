using System.Net;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using Flow=QuillSign.Tests.CompletionDownloadTests.Flow;
using static QuillSign.Tests.CompletionReaderPageTests;

namespace QuillSign.Tests;

public sealed class CompletionReaderFailureTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Competing_pending_links_expiry_CSRF_and_consumed_redemption_never_silently_change_identity()
    {
        await using var f=await Flow.Create(fixture,true); var first=await Issue(f); var next=await Issue(f);
        var old=await Begin(f,first.RawToken);var current=await Begin(f,next.RawToken);
        using(var csrf=await Post(f,"/complete/access?handler=Redeem",current,new() {{"nonce",Nonce(current)}},false))Assert.Equal(HttpStatusCode.BadRequest,csrf.StatusCode);
        using(var conflict=await Post(f,"/complete/access?handler=Redeem",old,new() {{"nonce",Nonce(old)}})) {
            Assert.Equal(HttpStatusCode.Conflict,conflict.StatusCode);Assert.Contains("another tab",await conflict.Content.ReadAsStringAsync());
        }
        await using(var db=fixture.Open())Assert.Equal(0,await db.AuthTokens.CountAsync(x=>x.EnvelopeId==f.Id && x.UsedAt!=null && x.Purpose==TokenPurpose.CompletionAccess));
        using(var open=await Post(f,"/complete/access?handler=Redeem",current,new() {{"nonce",Nonce(current)}}))Assert.Equal(HttpStatusCode.Redirect,open.StatusCode);
        using(var replay=await Post(f,"/complete/access?handler=Redeem",current,new() {{"nonce",Nonce(current)}}))Assert.Equal(HttpStatusCode.Conflict,replay.StatusCode);
        var retry=await Begin(f,next.RawToken);using(var consumed=await Post(f,"/complete/access?handler=Redeem",retry,new() {{"nonce",Nonce(retry)}}))Assert.Equal(HttpStatusCode.BadRequest,consumed.StatusCode);
        var expiring=await Begin(f,first.RawToken);f.Clock.Advance(TimeSpan.FromMinutes(10));
        using(var expired=await Post(f,"/complete/access?handler=Redeem",expiring,new() {{"nonce",Nonce(expiring)}}))Assert.Equal(HttpStatusCode.Conflict,expired.StatusCode);
        await using(var db=fixture.Open())Assert.Null((await db.AuthTokens.SingleAsync(x=>x.Id==first.TokenId)).UsedAt);
    }

    [Theory]
    [InlineData("audit")][InlineData("commit")][InlineData("lost-commit")]
    public async Task Unconfirmed_redemption_never_sets_login_or_silently_replays_a_consumed_link(string failure)
    {
        await using var f=await Flow.Create(fixture,true);var link=await Issue(f);var page=await Begin(f,link.RawToken);
        f.Faults.Event="completion_access_redeemed";f.Faults.RejectAudit=failure=="audit";f.Faults.RejectCommit=failure=="commit";f.Faults.LoseCommit=failure=="lost-commit";
        using(var failed=await Post(f,"/complete/access?handler=Redeem",page,new() {{"nonce",Nonce(page)}})) {
            Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode);Assert.Contains("may already have been used",await failed.Content.ReadAsStringAsync());
            Assert.DoesNotContain(failed.Headers.GetValues("Set-Cookie"),x=>x.StartsWith("QuillSign.CompletionReader=") || x.StartsWith(CompletionReaderBrowser.ReceiptCookie+"="));
        }
        f.Faults.Event="";f.Faults.RejectAudit=false;f.Faults.RejectCommit=false;
        await using(var db=fixture.Open())Assert.Equal(failure=="lost-commit",(await db.AuthTokens.SingleAsync(x=>x.Id==link.TokenId)).UsedAt is not null);
        page=await Begin(f,link.RawToken);using var retry=await Post(f,"/complete/access?handler=Redeem",page,new() {{"nonce",Nonce(page)}});
        Assert.Equal(failure=="lost-commit" ? HttpStatusCode.BadRequest : HttpStatusCode.Redirect,retry.StatusCode);
        Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);
    }

    [Theory]
    [InlineData("missing")][InlineData("corrupt")][InlineData("token")][InlineData("source")]
    public async Task Final_preparation_and_reads_fail_closed_and_storage_recovery_preserves_original_pair(string fault)
    {
        await using var f=await Flow.Create(fixture,true);var link=await Issue(f);await Open(f,link);var page=await Get(f,"/complete/"+f.PublicId);
        using(var prepare=await Download(f,page,"executed"))Assert.Equal(HttpStatusCode.Redirect,prepare.StatusCode);
        var grants=f.Cookies.ToDictionary();var before=await f.Count();var changed=false;
        if(fault is "missing" or "corrupt")f.Store.Fault=fault;
        else f.Store.AfterRead=async ()=> {if(changed)return;changed=true;await using var db=fixture.Open();
            if(fault=="token")await db.AuthTokens.Where(x=>x.Id==link.TokenId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.UsedAt,x=>x.UsedAt));
            else await db.Signers.Where(x=>x.EnvelopeId==f.Id && x.Order==2).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Viewed));};
        using(var denied=await f.Client.GetAsync(Resource(f,"executed")))Assert.Contains(denied.StatusCode,new[]{HttpStatusCode.NotFound,HttpStatusCode.ServiceUnavailable});
        Assert.Equal(before,await f.Count());
        if(fault is "missing" or "corrupt") {
            using(var denied=await Download(f,page,"certificate"))Assert.Equal(HttpStatusCode.ServiceUnavailable,denied.StatusCode);
            Assert.Equal(before,await f.Count());f.Store.Fault=null;f.Restore(grants);
            using var recovered=await f.Client.GetAsync(Resource(f,"executed"));Assert.Equal(HttpStatusCode.OK,recovered.StatusCode);Assert.Equal(f.Published.ExecutedBytes,await recovered.Content.ReadAsByteArrayAsync());
        } else Assert.True(changed);
        Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);
    }

    [Fact]
    public async Task Reader_grants_cannot_cross_audiences_kinds_receipts_named_cookie_sessions_or_original_expiry()
    {
        await using var f=await Flow.Create(fixture,true,true);await Open(f,await Issue(f));Assert.StartsWith("chunks-",f.Cookies["QuillSign.CustomReader"]);var page=await Get(f,"/complete/"+f.PublicId);
        using(var prepared=await Download(f,page,"executed"))Assert.Equal(HttpStatusCode.Redirect,prepared.StatusCode);
        var saved=f.Cookies.ToDictionary();var grant=saved.Single(x=>x.Key.StartsWith("QuillSign.Final.Reader."));var reads=f.Store.Reads;
        foreach(var url in new[]{Resource(f,"certificate"),Resource(f,"executed").Replace(f.PublicId,Guid.NewGuid().ToString("N")),Resource(f,"executed").Replace("/complete/","/draft/"),Resource(f,"executed").Replace("/complete/","/sign/")}) {
            using var denied=await f.Client.GetAsync(url);Assert.Equal(HttpStatusCode.NotFound,denied.StatusCode);
        }
        f.Set(grant.Key.Replace("Executed","Certificate"),grant.Value);using(var renamed=await f.Client.GetAsync(Resource(f,"certificate")))Assert.Equal(HttpStatusCode.NotFound,renamed.StatusCode);
        f.Restore(saved);
        foreach(var name in new[]{CompletionReaderBrowser.ReceiptCookie,"QuillSign.CustomReader"}) {
            foreach(var value in new string?[]{null,"forged"}) {
                f.Set(name,value);using var denied=await f.Client.GetAsync(Resource(f,"executed"));Assert.Equal(HttpStatusCode.NotFound,denied.StatusCode);f.Restore(saved);
            }
        }
        Assert.Equal(reads,f.Store.Reads);
        await Open(f,await Issue(f));reads=f.Store.Reads;
        using(var newSession=await f.Client.GetAsync(Resource(f,"executed")))Assert.Equal(HttpStatusCode.NotFound,newSession.StatusCode);
        Assert.Equal(reads,f.Store.Reads);
        f.Restore(saved);f.Clock.Advance(TimeSpan.FromMinutes(2));using(var expiredGrant=await f.Client.GetAsync(Resource(f,"executed")))Assert.Equal(HttpStatusCode.NotFound,expiredGrant.StatusCode);
        f.Clock.Advance(TimeSpan.FromHours(1));using(var expired=await f.Client.GetAsync("/complete/"+f.PublicId))Assert.Equal(HttpStatusCode.NotFound,expired.StatusCode);
        Assert.Equal(1,await f.Count());Assert.Equal(2,f.Store.Writes);
    }
}
