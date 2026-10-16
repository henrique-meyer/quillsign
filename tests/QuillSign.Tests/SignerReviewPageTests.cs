using System.Net;
using System.Security.Cryptography;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using Harness=QuillSign.Tests.SignerCheckpointTests.Harness;

namespace QuillSign.Tests;

public sealed class SignerReviewPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Explicit_review_access_Finish_and_worker_publish_exact_owned_copy_once()
    {
        await using var f=await Flow.Create(fixture); var page=await f.Page();
        await using(var db=fixture.Open())Assert.False(await db.SignerReviewCandidates.AnyAsync(x=>x.EnvelopeId==f.H.EnvelopeId));
        using(var noCsrf=await f.Post("Prepare",page,csrf:false))Assert.Equal(HttpStatusCode.BadRequest,noCsrf.StatusCode);
        using(var prepared=await f.Post("Prepare",page)) {
            Assert.Equal(HttpStatusCode.Redirect,prepared.StatusCode); Assert.Equal(f.Path,prepared.Headers.Location!.OriginalString);
            var cookie=prepared.Headers.GetValues("Set-Cookie").Single(x=>x.StartsWith(SignerReviewBrowser.ReviewCookie+"="));
            Assert.Contains("httponly",cookie); Assert.Contains("samesite=strict",cookie); Assert.Contains("path=/sign/"+f.H.R.H.Envelope.PublicId,cookie);
        }
        page=await f.Page(); Assert.Contains("Prospective Date Signed",page); Assert.DoesNotContain(f.Cookies[SignerReviewBrowser.ReviewCookie],page);
        using(var noAccess=await f.Post("Finish",page))Assert.Equal(HttpStatusCode.BadRequest,noAccess.StatusCode);
        using var pdf=await f.Client.GetAsync(f.Path+"?handler=Pdf&download=true"); f.Take(pdf); Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);
        var bytes=await pdf.Content.ReadAsByteArrayAsync(); var receipt=f.Cookies[SignerReviewBrowser.ReviewCookie]; var candidate=(await f.H.R.Read(receipt))!;
        Assert.Equal(candidate.Pdf,bytes); Assert.Equal(candidate.Candidate.PdfSha256,Convert.ToHexStringLower(SHA256.HashData(bytes)));
        using(var missingCsrf=await f.Post("Finish",page,csrf:false))Assert.Equal(HttpStatusCode.BadRequest,missingCsrf.StatusCode);
        using(var accepted=await f.Post("Finish",page)) { Assert.Equal(HttpStatusCode.Redirect,accepted.StatusCode); Assert.Equal(f.Confirmed,accepted.Headers.Location!.OriginalString); }
        Assert.Contains("being processed",await f.Page(f.Confirmed));
        using(var pending=await f.Client.GetAsync(f.Confirmed+"?handler=Pdf"))Assert.Equal(HttpStatusCode.NotFound,pending.StatusCode);
        foreach(var suffix in new[]{"/fields","/signature","/review",""}) {
            using var frozen=await f.Client.GetAsync("/sign/"+f.H.R.H.Envelope.PublicId+suffix); Assert.Equal(HttpStatusCode.Redirect,frozen.StatusCode); Assert.Equal(f.Confirmed,frozen.Headers.Location!.OriginalString);
        }
        Assert.True(await f.H.Once()); Assert.Contains("copy is ready",await f.Page(f.Confirmed));
        using(var own=await f.Client.GetAsync(f.Confirmed+"?handler=Pdf")) { Assert.Equal(HttpStatusCode.OK,own.StatusCode); Assert.Equal(bytes,await own.Content.ReadAsByteArrayAsync()); }
        f.H.R.H.Clock.Advance(TimeSpan.FromMinutes(11));
        using(var replay=await f.Post("Finish",page))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
        Assert.Contains("copy is ready",await f.Page(f.Confirmed));
        await using(var db=fixture.Open()) {
            var finish=Assert.Single(await db.SignerFinishAcceptances.Where(x=>x.EnvelopeId==f.H.EnvelopeId).ToArrayAsync());
            Assert.NotNull(finish.ProcessedAt); Assert.Equal(candidate.Candidate.ProspectiveDate,finish.ProspectiveDate);
            Assert.Equal(finish.FinishedAt,(await db.Signers.SingleAsync(x=>x.Id==f.H.R.H.Signer.Id)).SignedAt);
            Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==f.H.EnvelopeId && x.Event=="signer_finish_accepted").ToArrayAsync());
        }
    }

    [Theory]
    [InlineData("ack")][InlineData("review")][InlineData("method")][InlineData("statement")][InlineData("missing-access")][InlineData("forged-access")]
    [InlineData("missing-review")][InlineData("forged-review")][InlineData("expired")][InlineData("nonce")][InlineData("field")][InlineData("replacement")][InlineData("foreign")]
    public async Task Missing_stale_or_mixed_proofs_and_intent_cannot_Finish(string kind)
    {
        await using var f=await Flow.Create(fixture); var page=await f.Prepare();
        using(var pdf=await f.Client.GetAsync(f.Path+"?handler=Pdf")) { f.Take(pdf); Assert.Equal(HttpStatusCode.OK,pdf.StatusCode); }
        var values=new Dictionary<string,string>();
        if(kind=="ack")values["Acknowledged"]="false"; if(kind=="review")values["Reviewed"]="false";
        if(kind=="method")values["AccessMethod"]="unverified"; if(kind=="statement")values["StatementVersion"]="wrong";
        if(kind=="missing-access")f.Set(SignerReviewBrowser.AccessCookie,null); if(kind=="forged-access")f.Set(SignerReviewBrowser.AccessCookie,"forged");
        if(kind=="missing-review")f.Set(SignerReviewBrowser.ReviewCookie,null); if(kind=="forged-review")f.Set(SignerReviewBrowser.ReviewCookie,"forged");
        if(kind=="expired")f.H.R.H.Clock.Advance(TimeSpan.FromMinutes(11));
        if(kind=="nonce") { f.H.R.H.Identity=f.H.R.H.Identity with { SessionId=Guid.NewGuid() }; await f.Session(); }
        if(kind=="field")await f.H.R.Clear(f.H.R.H.Field(FieldType.Text).Id);
        if(kind=="replacement")await f.H.R.H.Adopt(80);
        if(kind=="foreign") {
            await using var other=await Flow.Create(fixture); _=await other.Prepare(); using var foreignPdf=await other.Client.GetAsync(other.Path+"?handler=Pdf"); other.Take(foreignPdf);
            f.Set(SignerReviewBrowser.ReviewCookie,other.Cookies[SignerReviewBrowser.ReviewCookie]); f.Set(SignerReviewBrowser.AccessCookie,other.Cookies[SignerReviewBrowser.AccessCookie]);
        }
        using var denied=await f.Post("Finish",page,values); Assert.Contains(denied.StatusCode,new[]{HttpStatusCode.BadRequest,HttpStatusCode.Conflict});
        await using var db=fixture.Open(); Assert.False(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==f.H.EnvelopeId));
        Assert.Null((await db.Fields.SingleAsync(x=>x.Id==f.H.R.H.Field(FieldType.DateSigned).Id)).Value);
    }

    [Theory]
    [InlineData("storage")][InlineData("audit")][InlineData("hint")][InlineData("work-disabled")][InlineData("commit")]
    public async Task Failures_preserve_truthful_state_and_recover_once(string kind)
    {
        await using var f=await Flow.Create(fixture); var page=await f.Prepare();
        using(var pdf=await f.Client.GetAsync(f.Path+"?handler=Pdf"))f.Take(pdf);
        f.H.R.H.Blobs.TamperReviewRead=kind=="storage"; f.H.R.H.Faults.FailAudit=kind=="audit"; f.H.Signals.FailHint=kind=="hint"; f.H.R.Work.Enabled=kind!="work-disabled";
        // The confirmation lookup has no acceptance yet and returns without a commit.
        if(kind=="commit")f.H.R.H.Faults.FailCommitNumber=f.H.R.H.Faults.Commits+1;
        using(var failed=await f.Post("Finish",page)) {
            Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode); var body=await failed.Content.ReadAsStringAsync(); Assert.Contains("could not be confirmed",body);
            if(kind is "audit" or "hint" or "work-disabled") {
                Assert.Matches("<input(?=[^>]*name=\"Reviewed\")(?=[^>]*checked)[^>]*>",body);
                Assert.Matches("<input(?=[^>]*name=\"Acknowledged\")(?=[^>]*checked)[^>]*>",body);
            }
        }
        f.H.R.H.Blobs.TamperReviewRead=false; f.H.R.H.Faults.FailAudit=false; f.H.Signals.FailHint=false; f.H.R.Work.Enabled=true; f.H.R.H.Faults.FailCommitNumber=0;
        if(kind=="commit") {
            f.Set(SignerReviewBrowser.AcceptedCookie,null);
            using var recovered=await f.Client.GetAsync(f.Path); f.Take(recovered); Assert.Equal(HttpStatusCode.Redirect,recovered.StatusCode); Assert.Equal(f.Confirmed,recovered.Headers.Location!.OriginalString);
        }
        using(var retry=await f.Post("Finish",page))Assert.Equal(HttpStatusCode.Redirect,retry.StatusCode);
        await using var db=fixture.Open(); Assert.Single(await db.SignerFinishAcceptances.Where(x=>x.EnvelopeId==f.H.EnvelopeId).ToArrayAsync());
        Assert.Single(await db.WorkItems.Where(x=>x.EnvelopeId==f.H.EnvelopeId && x.Kind==WorkKind.Rendering).ToArrayAsync());
    }

    [Fact]
    public async Task Foreign_paths_sender_sessions_private_headers_and_confirmation_storage_errors_fail_closed()
    {
        await using var f=await Flow.Create(fixture); var page=await f.Prepare();
        using(var pdf=await f.Client.GetAsync(f.Path+"?handler=Pdf")) { f.Take(pdf); Assert.True(pdf.Headers.CacheControl!.NoStore); Assert.Equal("no-referrer",Assert.Single(pdf.Headers.GetValues("Referrer-Policy"))); }
        using(var foreign=await f.Client.GetAsync("/sign/"+Guid.NewGuid().ToString("N")+"/review?handler=Pdf"))Assert.Equal(HttpStatusCode.NotFound,foreign.StatusCode);
        using(var accepted=await f.Post("Finish",page))Assert.Equal(HttpStatusCode.Redirect,accepted.StatusCode);
        await f.Session("sender"); f.Set("QuillSign.Signer",null);
        using(var sender=await f.Client.GetAsync(f.Confirmed))Assert.Equal(HttpStatusCode.Unauthorized,sender.StatusCode);
        await f.Session(); f.H.R.H.Blobs.TamperReviewRead=true;
        using(var unavailable=await f.Client.GetAsync(f.Confirmed)) { Assert.Equal(HttpStatusCode.ServiceUnavailable,unavailable.StatusCode); Assert.DoesNotContain("<h1>Your Finish was accepted",await unavailable.Content.ReadAsStringAsync()); }
        f.H.R.H.Blobs.TamperReviewRead=false;
    }

    [Fact]
    public async Task Unverified_PDF_never_issues_access_evidence_and_repreparation_requires_new_access()
    {
        await using var f=await Flow.Create(fixture); var page=await f.Prepare(); f.H.R.H.Blobs.TamperReviewRead=true;
        using(var failed=await f.Client.GetAsync(f.Path+"?handler=Pdf")) {
            Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode);
            Assert.False(failed.Headers.TryGetValues("Set-Cookie",out var cookies) && cookies.Any(x=>x.StartsWith(SignerReviewBrowser.AccessCookie+"=")));
        }
        f.H.R.H.Blobs.TamperReviewRead=false;
        using(var good=await f.Client.GetAsync(f.Path+"?handler=Pdf")) { f.Take(good); Assert.Equal(HttpStatusCode.OK,good.StatusCode); }
        using(var prepare=await f.Post("Prepare",page))Assert.Equal(HttpStatusCode.Redirect,prepare.StatusCode);
        Assert.False(f.Cookies.ContainsKey(SignerReviewBrowser.AccessCookie));
        using(var denied=await f.Post("Finish",page))Assert.Equal(HttpStatusCode.BadRequest,denied.StatusCode);
    }

    [Theory]
    [InlineData("session")][InlineData("void")][InlineData("envelope-expiry")]
    public async Task Accepted_proof_never_extends_session_or_envelope_access(string kind)
    {
        await using var f=await Flow.Create(fixture); var page=await f.Prepare(); using(var pdf=await f.Client.GetAsync(f.Path+"?handler=Pdf"))f.Take(pdf);
        using(var done=await f.Post("Finish",page))Assert.Equal(HttpStatusCode.Redirect,done.StatusCode);
        if(kind=="session")f.H.R.H.Clock.Advance(TimeSpan.FromHours(3));
        else { await using var db=fixture.Open(); if(kind=="void")await db.Envelopes.Where(x=>x.Id==f.H.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            else await db.Envelopes.Where(x=>x.Id==f.H.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,f.H.R.H.Clock.GetUtcNow().AddSeconds(-1))); }
        foreach(var path in new[]{f.Confirmed,f.Confirmed+"?handler=Pdf",f.Path+"?handler=Pdf"}) { using var denied=await f.Client.GetAsync(path); Assert.Contains(denied.StatusCode,new[]{HttpStatusCode.Unauthorized,HttpStatusCode.NotFound}); }
    }

    [Fact]
    public async Task Confirmation_requests_are_rate_limited_with_private_recoverable_JSON()
    {
        await using var f=await Flow.Create(fixture); f.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        for(var i=0;i<120;i++) { using var response=await f.Client.GetAsync(f.Confirmed); Assert.Equal(HttpStatusCode.NotFound,response.StatusCode); }
        using var limited=await f.Client.GetAsync(f.Confirmed); Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode);
        Assert.True(limited.Headers.CacheControl!.NoStore); Assert.Contains("Check your signing confirmation",await limited.Content.ReadAsStringAsync());
    }

    internal sealed class Flow : IAsyncDisposable
    {
        public Harness H=null!; public HttpClient Client=null!; public Dictionary<string,string> Cookies=[];
        public string Path=>"/sign/"+H.R.H.Envelope.PublicId+"/review"; public string Confirmed=>"/sign/"+H.R.H.Envelope.PublicId+"/confirmed";
        public static async Task<Flow> Create(SqlDatabaseFixture fixture) { var f=new Flow { H=await Harness.Create(fixture,browser:true) }; f.Client=f.H.App.GetTestClient(); await f.Session(); return f; }
        public async Task Session(string kind="signer") { using var r=await Client.GetAsync("/test-session/"+kind); Take(r); }
        public void Take(HttpResponseMessage response) { if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values) { var pair=value.Split(';')[0].Split('=',2); Set(pair[0],pair[1]); } }
        public void Set(string name,string? value) { if(string.IsNullOrEmpty(value))Cookies.Remove(name); else Cookies[name]=value; Client.DefaultRequestHeaders.Remove("Cookie"); Client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",Cookies.Select(x=>x.Key+"="+x.Value))); }
        public async Task<string> Page(string? path=null) { using var r=await Client.GetAsync(path??Path); Take(r); var body=await r.Content.ReadAsStringAsync(); Assert.True(r.StatusCode==HttpStatusCode.OK,$"{r.StatusCode}: {body.Split('\n')[0]}"); return body; }
        public async Task<string> Prepare() { var page=await Page(); using var r=await Post("Prepare",page); Assert.Equal(HttpStatusCode.Redirect,r.StatusCode); return await Page(); }
        public async Task<HttpResponseMessage> Post(string handler,string page,Dictionary<string,string>? values=null,bool csrf=true) {
            var form=new Dictionary<string,string> { ["Reviewed"]="true",["Acknowledged"]="true",["AccessMethod"]="download",["StatementVersion"]=SignerFinishStatement.Version };
            if(values is not null)foreach(var pair in values)form[pair.Key]=pair.Value;
            if(csrf)form["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page);
            var result=await Client.PostAsync(Path+"?handler="+handler,new FormUrlEncodedContent(form)); Take(result); return result;
        }
        public async ValueTask DisposeAsync() { Client.Dispose(); await H.DisposeAsync(); }
    }
}
