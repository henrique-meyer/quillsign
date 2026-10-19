using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Harness=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SenderSendPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("rejected")][InlineData("ambiguous")][InlineData("bounced")][InlineData("complained")]
    public async Task Failed_or_unknown_delivery_is_never_reported_as_queued_or_delivered(string kind)
    {
        await using var f=await Flow.Create(fixture); var page=await f.Page(); using(var sent=await f.Send(page))Assert.Equal(HttpStatusCode.Redirect,sent.StatusCode);
        if(kind=="rejected") { f.H.Sender.Failure=new EmailNotSubmittedException(false); Assert.True(await f.H.Once()); }
        else if(kind=="ambiguous") { f.H.Sender.Failure=new IOException("Synthetic unknown provider response"); await Assert.ThrowsAsync<IOException>(()=>f.H.Once()); }
        else { Assert.True(await f.H.Once()); await using var db=fixture.Open(); await db.EmailOutbox.Where(x=>x.EnvelopeId==f.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,kind=="bounced" ? EmailStatus.Bounced : EmailStatus.Complained)); }
        var status=await f.Page(f.Status); var expected=kind switch { "rejected"=>"Invitation not sent; delivery needs attention","ambiguous"=>"Invitation submission not confirmed","bounced"=>"Invitation bounced; delivery needs attention",_=>"Invitation complaint reported" }; Assert.Contains(expected,status);
        using(var replay=await f.Send(page))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode); Assert.Equal(1,f.H.Sender.Calls);
    }

    [Theory]
    [InlineData(false,SenderSendStatement.Version)][InlineData(true,"stale-statement")]
    public async Task Backend_Send_requires_explicit_current_intent(bool intent,string version)
    {
        await using var f=await Flow.Create(fixture); using var scope=f.H.App.Services.CreateScope();
        await Assert.ThrowsAsync<QuillSign.Documents.DocumentRejectedException>(()=>scope.ServiceProvider.GetRequiredService<SendDraftWorkflow>().SendAsync(f.H.Principal,f.H.Envelope.PublicId,f.H.Version,true,intent,version,null,null));
        await f.H.AssertUnsent(fixture); Assert.Empty(f.H.Blobs.Created);
    }

    [Fact]
    public async Task Public_Send_invitation_consent_Finish_and_checkpoint_have_truthful_sender_progress()
    {
        await using var f=await Flow.Create(fixture); var reviewed=await f.Page();
        using(var sent=await f.Send(reviewed))Assert.Equal(HttpStatusCode.Redirect,sent.StatusCode);
        Assert.True(await f.H.Once());
        var token=Regex.Match(f.H.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value; Assert.Equal(43,token.Length);
        var invitation="/sign/invitation?token="+token; var landing=await f.Page(invitation);
        await using(var db=fixture.Open())Assert.Null((await db.AuthTokens.SingleAsync(x=>x.EnvelopeId==f.H.Envelope.Id)).UsedAt);
        using(var redeem=await f.Post("/sign/invitation",landing,new() { ["Token"]=token }))Assert.Equal(HttpStatusCode.Redirect,redeem.StatusCode);
        var signing="/sign/"+f.H.Envelope.PublicId; var consent=await f.Page(signing);
        Assert.Contains("Opened; consent pending",await f.Page(f.Status));
        using(var agreed=await f.Post(signing,consent,new() { ["Receipt"]=Flow.Value(consent,"Receipt"),["Agreement"]="true",["CanRetain"]="true",["AccessMethod"]="download" }))Assert.Equal(HttpStatusCode.Redirect,agreed.StatusCode);
        Assert.Contains("Consent recorded; signing incomplete",await f.Page(f.Status));
        var signature=await f.Page(signing+"/signature"); using var form=new MultipartFormDataContent();
        form.Add(new StringContent(SignaturePageTests.Browser.Token(signature)),"__RequestVerificationToken"); form.Add(new StringContent("Drawn"),"Method");
        foreach(var name in new[]{"Signature","Initials"}) { var file=new ByteArrayContent(SignatureAdoptionTests.Mark()); file.Headers.ContentType=new("image/png"); form.Add(file,name,"synthetic.png"); }
        using var preview=await f.Client.PostAsync(signing+"/signature?handler=Preview",form); Assert.Equal(HttpStatusCode.OK,preview.StatusCode);
        using var previewJson=JsonDocument.Parse(await preview.Content.ReadAsStringAsync());
        using(var adopt=await f.Post(signing+"/signature?handler=Adopt",signature,new() { ["Receipt"]=previewJson.RootElement.GetProperty("receipt").GetString()!,["Acknowledged"]="true",["StatementVersion"]=SignatureAdoptionStatement.Version }))Assert.Equal(HttpStatusCode.Redirect,adopt.StatusCode);
        var fieldsPage=await f.Page(signing+"/fields"); using var fieldsResponse=await f.Client.GetAsync(signing+"/fields?handler=Snapshot"); Assert.Equal(HttpStatusCode.OK,fieldsResponse.StatusCode);
        using var snapshot=JsonDocument.Parse(await fieldsResponse.Content.ReadAsStringAsync()); var state=snapshot.RootElement.GetProperty("snapshot"); var field=state.GetProperty("fields")[0];
        using(var apply=await f.Post(signing+"/fields",fieldsPage,new() { ["FieldId"]=field.GetProperty("id").GetString()!,["Version"]=field.GetProperty("version").GetString()!,["Action"]="Apply",["AdoptionId"]=state.GetProperty("adoptionId").GetString()! }))Assert.Equal(HttpStatusCode.Redirect,apply.StatusCode);
        var reviewPath=signing+"/review"; var review=await f.Page(reviewPath);
        using(var prepare=await f.Post(reviewPath+"?handler=Prepare",review,new()))Assert.Equal(HttpStatusCode.Redirect,prepare.StatusCode);
        review=await f.Page(reviewPath); using var pdf=await f.Client.GetAsync(reviewPath+"?handler=Pdf&download=true"); f.Take(pdf); Assert.Equal(HttpStatusCode.OK,pdf.StatusCode); var exact=await pdf.Content.ReadAsByteArrayAsync();
        using(var finish=await f.Post(reviewPath+"?handler=Finish",review,new() { ["Reviewed"]="true",["Acknowledged"]="true",["AccessMethod"]="download",["StatementVersion"]=SignerFinishStatement.Version }))Assert.Equal(HttpStatusCode.Redirect,finish.StatusCode);
        Assert.Contains("Finish accepted; signing copy processing",await f.Page(f.Status));
        Assert.True(await f.H.Once()); Assert.Contains("Signed at",await f.Page(f.Status));
        using(var copy=await f.Client.GetAsync(signing+"/confirmed?handler=Pdf")) { Assert.Equal(HttpStatusCode.OK,copy.StatusCode); Assert.Equal(exact,await copy.Content.ReadAsByteArrayAsync()); }
        Assert.True(await f.H.Once()); Assert.Equal(2,f.H.Sender.Calls);
        await using(var db=fixture.Open()) { Assert.Equal(SignerStatus.Signed,(await db.Signers.SingleAsync(x=>x.Id==f.H.First.Id)).Status); Assert.Equal(SignerStatus.Notified,(await db.Signers.SingleAsync(x=>x.Id==f.H.Second.Id)).Status); Assert.Equal(2,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==f.H.Envelope.Id)); Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.SingleAsync(x=>x.Id==f.H.Envelope.Id)).Status); }
        using(var replay=await f.Send(reviewed))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
    }

    [Fact]
    public async Task JSON_and_read_only_recovery_do_not_disclose_proofs_or_repeat_delivery()
    {
        await using var f=await Flow.Create(fixture); var page=await f.Page();
        using(var sent=await f.Send(page,json:true)) { Assert.Equal(HttpStatusCode.OK,sent.StatusCode); var body=await sent.Content.ReadAsStringAsync(); Assert.Contains(f.Status,body); Assert.DoesNotContain("invitationWorkId",body); Assert.False(sent.Headers.TryGetValues("Set-Cookie",out _)); }
        f.H.App.Services.GetRequiredService<EmailOptions>().Enabled=false;
        using(var recovered=await f.Send(page,json:true))Assert.Equal(HttpStatusCode.OK,recovered.StatusCode);
        using(var stale=await f.Send(page,new() { ["Version"]=Convert.ToBase64String(new byte[8]) },json:true))Assert.Equal(HttpStatusCode.Conflict,stale.StatusCode);
        using(var status=await f.Client.GetAsync(f.Status)) { Assert.Equal(HttpStatusCode.OK,status.StatusCode); var body=await status.Content.ReadAsStringAsync(); Assert.Contains("Invitation queued",body); Assert.DoesNotContain("invitationWorkId",body,StringComparison.OrdinalIgnoreCase); Assert.True(status.Headers.CacheControl!.NoStore); }
        await using var db=fixture.Open(); Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==f.H.Envelope.Id).ToArrayAsync()); Assert.Equal(0,f.H.Sender.Calls);
    }

    [Fact]
    public async Task Status_reads_are_rate_limited_without_a_Send_or_status_write()
    {
        await using var f=await Flow.Create(fixture); f.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        for(var i=0;i<120;i++) { using var read=await f.Client.GetAsync(f.Status); Assert.Equal(HttpStatusCode.NotFound,read.StatusCode); }
        using var limited=await f.Client.GetAsync(f.Status); Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode); Assert.True(limited.Headers.CacheControl!.NoStore); Assert.Contains("before repeating Send",await limited.Content.ReadAsStringAsync()); await f.H.AssertUnsent(fixture);
    }

    [Fact]
    public async Task Reviewed_Send_is_deliberate_private_immutable_and_replays_without_a_second_invitation()
    {
        await using var f=await Flow.Create(fixture); var page=await f.Page(); Assert.Contains(SenderSendStatement.Text,page);
        Assert.Contains("Electronic-record disclosure for this request",page);
        await using(var db=fixture.Open()) { Assert.Equal(EnvelopeStatus.Draft,(await db.Envelopes.SingleAsync(x=>x.Id==f.H.Envelope.Id)).Status); Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==f.H.Envelope.Id)); }
        using(var csrf=await f.Send(page,csrf:false))Assert.Equal(HttpStatusCode.BadRequest,csrf.StatusCode);
        using(var sent=await f.Send(page)) { Assert.Equal(HttpStatusCode.Redirect,sent.StatusCode); Assert.Equal(f.Status,sent.Headers.Location!.OriginalString); Assert.Contains("httponly",Assert.Single(sent.Headers.GetValues("Set-Cookie"))); }
        var status=await f.Page(f.Status); Assert.Contains("Invitation queued",status); Assert.Contains("does not confirm inbox delivery",status);
        Assert.Contains("&lt;b&gt;Synthetic NO AGREEMENT&lt;/b&gt;",status); Assert.DoesNotContain("<b>Synthetic",status);
        using(var replay=await f.Send(page))Assert.Equal(HttpStatusCode.Redirect,replay.StatusCode);
        using(var review=await f.Client.GetAsync(f.Path)) { Assert.Equal(HttpStatusCode.Redirect,review.StatusCode); Assert.Equal(f.Status,review.Headers.Location!.OriginalString); }
        using(var fields=await f.Client.GetAsync(f.Path.Replace("/review","/fields")))Assert.Equal(HttpStatusCode.NotFound,fields.StatusCode);
        await using(var db=fixture.Open()) {
            Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==f.H.Envelope.Id).ToArrayAsync());
            var evidence=Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==f.H.Envelope.Id && x.Event=="sent").ToArrayAsync());
            Assert.Contains("reviewedVersion",evidence.DataJson); Assert.Contains(SenderSendStatement.Text,evidence.DataJson); Assert.Contains(SenderSendStatement.Sha256,evidence.DataJson);
        }
        Assert.True(await f.H.Once()); Assert.Equal(1,f.H.Sender.Calls); Assert.Contains("Invitation submitted",await f.Page(f.Status));
        Assert.True(await f.H.Once()); Assert.Equal(1,f.H.Sender.Calls);
    }

    [Theory]
    [InlineData("exclusions")][InlineData("intent")][InlineData("statement")][InlineData("version")][InlineData("stale")]
    [InlineData("policy")][InlineData("email")][InlineData("work")][InlineData("expiry")]
    public async Task Missing_intent_stale_review_or_unavailable_settings_cannot_send(string kind)
    {
        await using var f=await Flow.Create(fixture); var page=await f.Page(); var values=new Dictionary<string,string>();
        if(kind=="exclusions")values["ExclusionsAcknowledged"]="false"; if(kind=="intent")values["SendAcknowledged"]="false";
        if(kind=="statement")values["StatementVersion"]="wrong"; if(kind=="version")values["Version"]="forged";
        if(kind=="stale") { await using var db=fixture.Open(); await db.Envelopes.Where(x=>x.Id==f.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Message,"Changed review")); }
        if(kind=="policy")f.H.App.Services.GetRequiredService<ElectronicRecordOptions>().PaperCopyFees="";
        if(kind=="email")f.H.App.Services.GetRequiredService<EmailOptions>().Enabled=false;
        if(kind=="work")f.H.App.Services.GetRequiredService<WorkOptions>().Enabled=false;
        if(kind=="expiry") { await using var db=fixture.Open(); await db.Envelopes.Where(x=>x.Id==f.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,f.H.Clock.GetUtcNow())); }
        using var response=await f.Send(page,values); Assert.Contains(response.StatusCode,new[]{HttpStatusCode.BadRequest,HttpStatusCode.Conflict,HttpStatusCode.ServiceUnavailable});
        await f.H.AssertUnsent(fixture); Assert.Empty(f.H.Blobs.Created);
    }

    [Theory]
    [InlineData("blob")][InlineData("audit")][InlineData("hint")][InlineData("commit")]
    public async Task Failures_and_unknown_commit_recover_exactly_one_frozen_request(string kind)
    {
        await using var f=await Flow.Create(fixture); var page=await f.Page();
        f.H.Blobs.FailWrite=kind=="blob"; f.H.Faults.FailAudit=kind=="audit"; f.H.Signals.FailHint=kind=="hint"; f.H.Faults.FailCommit=kind=="commit";
        using(var failed=await f.Send(page)) { Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode); Assert.Contains("could not be confirmed",await failed.Content.ReadAsStringAsync()); }
        f.H.Blobs.FailWrite=false; f.H.Faults.FailAudit=false; f.H.Signals.FailHint=false; f.H.Faults.FailCommit=false;
        using(var retry=await f.Send(page))Assert.Equal(HttpStatusCode.Redirect,retry.StatusCode);
        await using var db=fixture.Open(); Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==f.H.Envelope.Id).ToArrayAsync());
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==f.H.Envelope.Id && x.Event=="sent").ToArrayAsync());
        Assert.True(await f.H.Once()); Assert.Equal(1,f.H.Sender.Calls);
    }

    [Theory]
    [InlineData("foreign")][InlineData("audit")][InlineData("completion")][InlineData("expiry")][InlineData("session")]
    public async Task Private_status_is_scoped_verified_and_truthful(string kind)
    {
        await using var f=await Flow.Create(fixture);
        if(kind=="expiry") {await using var draft=fixture.Open();await draft.Envelopes.Where(x=>x.Id==f.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,f.H.Clock.GetUtcNow().AddMinutes(1)));}
        var page=await f.Page(); using(var sent=await f.Send(page))Assert.Equal(HttpStatusCode.Redirect,sent.StatusCode);
        var path=f.Status;
        await using(var db=fixture.Open()) {
            if(kind=="foreign")path="/draft/"+Guid.NewGuid().ToString("N")+"/sent";
            if(kind=="audit")await db.AuditEvents.Where(x=>x.EnvelopeId==f.H.Envelope.Id && x.Event=="sent").ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));
            if(kind=="completion")await db.Envelopes.Where(x=>x.Id==f.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Completed));
        }
        if(kind=="session") { f.H.Clock.Advance(TimeSpan.FromHours(3)); f.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json"); }
        if(kind=="expiry")f.H.Clock.Advance(TimeSpan.FromMinutes(2));
        using var response=await f.Client.GetAsync(path);
        if(kind=="foreign")Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);
        else if(kind=="session")Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);
        else if(kind=="expiry") { Assert.Equal(HttpStatusCode.OK,response.StatusCode); Assert.Contains("Expired",await response.Content.ReadAsStringAsync()); }
        else { Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode); Assert.Contains("could not be verified",await response.Content.ReadAsStringAsync()); }
    }

    internal sealed class Flow : IAsyncDisposable
    {
        public Harness H=null!; public HttpClient Client=null!; private Dictionary<string,string> cookies=[];
        public string Path=>"/draft/"+H.Envelope.PublicId+"/review"; public string Status=>"/draft/"+H.Envelope.PublicId+"/sent";
        public static async Task<Flow> Create(SqlDatabaseFixture fixture) { var f=new Flow { H=await Harness.Create(fixture,browser:true) }; f.Client=f.H.App.GetTestClient(); using var session=await f.Client.GetAsync("/test-session"); f.Take(session); return f; }
        public void Take(HttpResponseMessage response) { if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values) { var pair=value.Split(';')[0].Split('=',2); if(pair[1].Length==0)cookies.Remove(pair[0]); else cookies[pair[0]]=pair[1]; } Client.DefaultRequestHeaders.Remove("Cookie"); Client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value))); }
        public async Task<string> Page(string? path=null) { using var result=await Client.GetAsync(path??Path); Take(result); var body=await result.Content.ReadAsStringAsync(); Assert.True(result.StatusCode==HttpStatusCode.OK,$"{result.StatusCode}: {body.Split('\n')[0]}"); Assert.True(result.Headers.CacheControl!.NoStore); return body; }
        public async Task<HttpResponseMessage> Send(string page,Dictionary<string,string>? values=null,bool csrf=true,bool json=false) {
            Client.DefaultRequestHeaders.Accept.Clear(); if(json)Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
            var form=new Dictionary<string,string> { ["Version"]=Value(page,"Version"),["ExclusionsAcknowledged"]="true",["SendAcknowledged"]="true",["StatementVersion"]=SenderSendStatement.Version };
            var reminder=Value(page,"ReminderSha256");if(reminder.Length>0)form["ReminderSha256"]=reminder;
            var scheduling=Value(page,"ReminderSchedulingVersion");if(scheduling.Length>0)form["ReminderSchedulingVersion"]=scheduling;
            if(values is not null)foreach(var pair in values)form[pair.Key]=pair.Value;
            if(csrf)form["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page);
            var response=await Client.PostAsync(Path+"?handler=Send",new FormUrlEncodedContent(form)); Take(response); return response;
        }
        public static string Value(string page,string name)=>WebUtility.HtmlDecode(Regex.Match(page,"name=\""+Regex.Escape(name)+"\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
        public async Task<HttpResponseMessage> Post(string path,string page,Dictionary<string,string> form) { form["__RequestVerificationToken"]=SignaturePageTests.Browser.Token(page); var response=await Client.PostAsync(path,new FormUrlEncodedContent(form)); Take(response); return response; }
        public async ValueTask DisposeAsync() { Client.Dispose(); await H.DisposeAsync(); }
    }
}
