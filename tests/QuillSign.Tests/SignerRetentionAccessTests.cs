using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Legal;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SignerRetentionAccessTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task New_sessions_and_proofs_are_capped_without_changing_existing_identity_bindings()
    {
        await using var r=await Run.Create(fixture);var invitation=await r.Invitation();var redeemed=(await r.Use<SignerAccess,VerifiedSigner?>(s=>s.RedeemAsync(invitation.RawToken,null,null)))!;Assert.Equal(r.Cutoff,redeemed.SessionExpiresAt);
        var context=(await r.Context())!;Assert.Equal(r.Identity,context.Identity);Assert.True(context.Identity.SessionExpiresAt>r.Cutoff);
        using var scope=r.H.App.Services.CreateScope();var receipts=scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>();Assert.Equal(r.Cutoff,receipts.Read(receipts.Create(context),r.Identity)!.ExpiresAt);
        await r.Consent();var preview=(await r.Preview())!;Assert.Equal(r.Cutoff,preview.ExpiresAt);Assert.Equal(SignatureAdoptionResult.Adopted,await r.Use<SignatureAdoption,SignatureAdoptionResult>(s=>s.AdoptAsync(r.Principal,r.PublicId,preview.Receipt,true,SignatureAdoptionStatement.Version,null,null)));
        await r.ApplySignature();var review=(await r.Use<SignerReviewCandidates,SignerReviewPrepared?>(s=>s.PrepareAsync(r.Principal,r.PublicId)))!;await using var db=fixture.Open();var p=await db.SignerReviewCandidates.SingleAsync(x=>x.Id==review.Id);Assert.Equal(r.Cutoff,p.ExpiresAt);Assert.Equal(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(r.Identity)),p.SessionSha256);
    }

    [Theory]
    [InlineData("redemption")][InlineData("consent")][InlineData("decline")][InlineData("adoption")]
    public async Task An_audit_crossing_cutoff_rolls_back_the_entire_public_mutation(string operation)
    {
        await using var r=await Run.Create(fixture);SignerInvitation? invitation=null;SignaturePreviewData? preview=null;if(operation=="redemption")invitation=await r.Invitation();if(operation=="adoption"){await r.Consent();preview=await r.Preview();}
        var before=await r.Counts();r.H.Faults.Event=operation switch{"redemption"=>"link_opened","consent"=>"consent_given","decline"=>"declined",_=>"signature_adopted"};r.H.Faults.BeforeAudit=_=>{r.Expire();return Task.CompletedTask;};
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(async()=>
        {
            if(operation=="redemption")await r.Use<SignerAccess,VerifiedSigner?>(s=>s.RedeemAsync(invitation!.RawToken,null,null));else if(operation=="consent")await r.Consent();else if(operation=="decline")await r.Use<SignerConsent,SignerReadContext?>(s=>s.DeclineAsync(r.Principal,r.PublicId,"Synthetic NO AGREEMENT",null,null));else await r.Use<SignatureAdoption,SignatureAdoptionResult>(s=>s.AdoptAsync(r.Principal,r.PublicId,preview!.Receipt,true,SignatureAdoptionStatement.Version,null,null));
        });
        Assert.Equal(before,await r.Counts());Assert.Equal(0,r.H.Sender.Calls);await using var db=fixture.Open();if(invitation is not null)Assert.Null((await db.AuthTokens.SingleAsync(x=>x.Id==invitation.Record.Id)).UsedAt);
    }

    [Theory]
    [InlineData("missing")][InlineData("policy")][InlineData("marker")]
    public async Task Broken_policy_fails_privately_after_authorizing_the_exact_identity(string corruption)
    {
        await using var r=await Run.Create(fixture);await using(var db=fixture.Open())
        {
            if(corruption=="missing")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ExecuteDeleteAsync();else if(corruption=="policy")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Days,30).SetProperty(x=>x.DeleteAfter,r.Policy!.StartedAt.AddDays(30)));
            else {var a=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event=="document_uploaded");var data=JsonNode.Parse(a.DataJson)!;data["retentionSha256"]=new string('0',64);a.DataJson=data.ToJsonString();a.Hash=AuditHash.Compute(a);await db.AuditEvents.Where(x=>x.EnvelopeId==a.EnvelopeId && x.Sequence==a.Sequence).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,a.DataJson).SetProperty(x=>x.Hash,a.Hash));}
        }
        var wrong=SignerAccessConfiguration.Principal(r.Identity with{Email="other@example.invalid"});Assert.Null(await r.Use<SignerAccess,SignerReadContext?>(s=>s.GetContextAsync(wrong,r.PublicId)));var reads=r.H.Blobs.Reads;await Assert.ThrowsAsync<SignerRetentionEvidenceException>(()=>r.Context());
        await r.SignIn();using var response=await r.Flow!.Client.GetAsync(r.Signing);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.True(response.Headers.CacheControl!.NoStore);var body=await response.Content.ReadAsStringAsync();Assert.DoesNotContain(r.H.First.Email,body);Assert.DoesNotContain(r.H.Envelope.Title!,body);Assert.Equal(reads,r.H.Blobs.Reads);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Later_global_settings_do_not_enroll_ordinary_or_legacy_demo_records(bool demo)
    {await using var r=await Run.Create(fixture,enrolled:false,demo:demo);var before=await r.Counts();r.H.App.Services.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays=7;r.Expire();Assert.NotNull(await r.Context());Assert.Equal(before,await r.Counts());await using var db=fixture.Open();Assert.False(await db.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id));}

    [Theory]
    [InlineData("cutoff")][InlineData("slow")][InlineData("storage")]
    public async Task PDF_and_disclosure_HTTP_reads_refuse_expired_bytes_and_recover_explicitly(string failure)
    {
        await using var r=await Run.Create(fixture);await r.SignIn();Assert.Contains("Electronic",await r.Flow!.Page(r.Signing));var before=await r.Counts();if(failure=="cutoff")r.Expire();else if(failure=="slow")r.H.Blobs.AfterRead=r.Expire;else r.H.Blobs.FailRead=true;
        using(var pdf=await r.Flow.Client.GetAsync(r.Signing+"?handler=Pdf&download=true")){Assert.Equal(failure=="storage" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Gone,pdf.StatusCode);Assert.DoesNotContain("%PDF",await pdf.Content.ReadAsStringAsync());Assert.True(pdf.Headers.CacheControl!.NoStore);}Assert.Equal(before,await r.Counts());
        if(failure=="storage"){r.H.Blobs.FailRead=false;using var recovered=await r.Flow.Client.GetAsync(r.Signing+"?handler=Pdf&download=true");Assert.Equal(HttpStatusCode.OK,recovered.StatusCode);Assert.Equal(r.H.Source,await recovered.Content.ReadAsByteArrayAsync());}
        else {using var disclosure=await r.Flow.Client.GetAsync(r.Signing+"?handler=Disclosure");Assert.Equal(HttpStatusCode.Gone,disclosure.StatusCode);Assert.DoesNotContain(r.H.First.Email,await disclosure.Content.ReadAsStringAsync());}
    }

    [Fact]
    public async Task Accepted_checkpoint_identity_survives_processing_but_own_downloads_stop_at_cutoff()
    {
        await using var r=await Run.Create(fixture);var exact=await r.FinishThroughHttp();await using(var db=fixture.Open()){var f=await db.SignerFinishAcceptances.SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id);Assert.Equal(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(r.Identity)),f.SessionSha256);}
        Assert.True(await r.H.Once());using(var pdf=await r.Flow!.Client.GetAsync(r.Signing+"/confirmed?handler=Pdf")){Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);Assert.Equal(exact,await pdf.Content.ReadAsByteArrayAsync());}
        var before=await r.Counts();r.Expire();using(var pdf=await r.Flow!.Client.GetAsync(r.Signing+"/confirmed?handler=Pdf")){Assert.Equal(HttpStatusCode.Gone,pdf.StatusCode);Assert.DoesNotContain("%PDF",await pdf.Content.ReadAsStringAsync());}using(var edit=await r.Flow!.Client.GetAsync(r.Signing+"/fields"))Assert.Equal(HttpStatusCode.Gone,edit.StatusCode);Assert.Equal(before,await r.Counts());
    }

    [Fact]
    public async Task Trusted_checkpoint_work_and_history_reads_still_verify_after_public_session_expiry()
    {
        await using var r=await Run.Create(fixture);var exact=await r.FinishThroughHttp();r.Expire();r.H.Clock.Advance(TimeSpan.FromHours(2));Assert.True(await r.H.Once());await using var db=fixture.Open();var f=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id);Assert.NotNull(f.ProcessedAt);Assert.Equal(SignerStatus.Signed,(await db.Signers.SingleAsync(x=>x.Id==r.H.First.Id)).Status);Assert.Equal(exact,await r.H.Read(f.PdfObjectId));Assert.Equal(0,r.H.Sender.Calls);
    }

    [Fact]
    public async Task Finish_crossing_cutoff_during_acceptance_leaves_no_acceptance_or_checkpoint_job()
    {
        await using var r=await Run.Create(fixture);var review=await r.PrepareThroughHttp();var before=await r.Counts();r.H.Faults.Event="signer_finish_accepted";r.H.Faults.BeforeAudit=_=>{r.Expire();return Task.CompletedTask;};using var result=await r.Flow!.Post(r.Signing+"/review?handler=Finish",review,new(){["Reviewed"]="true",["Acknowledged"]="true",["AccessMethod"]="download",["StatementVersion"]=SignerFinishStatement.Version});Assert.True(result.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Gone);Assert.Equal(before,await r.Counts());
    }

    public sealed class BrowserSession:IAsyncDisposable
    {
        private readonly Run run;private BrowserSession(Run run)=>this.run=run;
        public string PublicId=>run.PublicId;public DateTimeOffset Cutoff=>run.Cutoff;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port)=>new(await Run.Create(fixture,port:port));
        public void Expire()=>run.Expire();public void FailRead(bool value)=>run.H.Blobs.FailRead=value;public Task<bool> ProcessCheckpoint()=>run.H.Once();public ValueTask DisposeAsync()=>run.DisposeAsync();
    }

    internal sealed class Run:IAsyncDisposable
    {
        public Shared H=null!;public DocumentRetentionSnapshot? Policy;public DateTimeOffset Cutoff;public VerifiedSigner Identity=null!;public SenderSendPageTests.Flow? Flow;private SqlDatabaseFixture fixture=null!;private int? port;
        public string PublicId=>H.Envelope.PublicId;public string Signing=>"/sign/"+PublicId;public ClaimsPrincipal Principal=>SignerAccessConfiguration.Principal(Identity);
        public static async Task<Run> Create(SqlDatabaseFixture fixture,bool enrolled=true,bool demo=true,int? port=null,DateTimeOffset? initialTime=null)
        {
            var r=new Run{fixture=fixture,port=port};if(enrolled){var retained=await RetentionSigningDeadlineTests.Retained.Create(fixture,browser:true,browserPort:port,syntheticSigner:()=>r.Identity,initialTime:initialTime);r.H=retained.H;r.Policy=retained.Policy;r.Cutoff=retained.Policy.DeleteAfter;}else{r.H=await Shared.Create(fixture,browser:true,browserPort:port,syntheticSigner:()=>r.Identity);r.Cutoff=r.H.Clock.GetUtcNow().AddDays(7);}
            var h=r.H;var frozen=new DocumentBlob(h.Envelope.Id,DocumentBlobKind.Normalized,Guid.NewGuid());using(var bytes=new MemoryStream(h.Source,false))await h.Blobs.WriteAsync(h.Principal,frozen,bytes,bytes.Length,default);
            await using(var db=fixture.Open())
            {
                var e=await db.Envelopes.SingleAsync(x=>x.Id==h.Envelope.Id);e.IsDemo=demo;e.Status=EnvelopeStatus.Sent;e.SentAt=h.Clock.GetUtcNow();e.ExclusionsAckAt=e.SentAt;e.ExpiresAt=e.SentAt.Value.AddDays(30);e.SentPdfBlob=frozen.ObjectId.ToString("N");e.SentPdfSha256=SHA256.HashData(h.Source);var disclosure=h.App.Services.GetRequiredService<ElectronicRecordDisclosure>().Build(e.PublicId,e.Title!,e.SenderEmail);e.ErsdVersion=disclosure.Version;e.ErsdText=disclosure.Text;e.ErsdSha256=disclosure.Sha256;
                db.Fields.Add(new(){EnvelopeId=e.Id,SignerId=h.First.Id,Type=FieldType.Text,Label="Synthetic text entry",Page=1,X=.1m,Y=.65m,Width=.5m,Height=.08m,Required=false});await db.SaveChangesAsync();h.Envelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==e.Id);h.Version=h.Envelope.RowVersion;
            }
            h.Clock.Advance(r.Cutoff-h.Clock.GetUtcNow()-TimeSpan.FromMinutes(1));r.Identity=new(h.Envelope.Id,h.Envelope.PublicId,h.First.Id,h.First.Email,frozen.ObjectId,Convert.ToHexStringLower(h.Envelope.SentPdfSha256!),Convert.ToHexStringLower(h.Envelope.ErsdSha256!),r.Cutoff.AddHours(1));if(port is not null)h.App.Services.GetRequiredService<SenderOptions>().RequestsPerWindow=1000;return r;
        }
        public void Expire()=>H.Clock.Advance(Cutoff-H.Clock.GetUtcNow());
        public async Task<T> Use<TService,T>(Func<TService,Task<T>> operation) where TService:notnull{using var scope=H.App.Services.CreateScope();return await operation(scope.ServiceProvider.GetRequiredService<TService>());}
        public Task<SignerReadContext?> Context()=>Use<SignerAccess,SignerReadContext?>(s=>s.GetContextAsync(Principal,PublicId));
        public async Task<SignerInvitation> Invitation(){var token=H.App.Services.GetRequiredService<SignerInvitationFactory>().Create(H.Envelope.Id,H.First.Id,H.First.Email,H.Envelope.ExpiresAt,Identity.DocumentId,H.Envelope.SentPdfSha256!,H.Envelope.ErsdSha256!);await using var db=fixture.Open();db.AuthTokens.Add(token.Record);await db.SaveChangesAsync();return token;}
        public async Task Consent(){var context=(await Context())!;using var scope=H.App.Services.CreateScope();var receipt=scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(context);Assert.Equal(ConsentResult.Accepted,await scope.ServiceProvider.GetRequiredService<SignerConsent>().AcceptAsync(Principal,PublicId,receipt,true,true,"download",null,null));}
        public Task<SignaturePreviewData?> Preview()=>Use<SignatureAdoption,SignaturePreviewData?>(s=>s.PrepareAsync(Principal,PublicId,new(SignatureAdoptionTests.Mark(),SignatureAdoptionTests.Mark(),SignatureMethod.Drawn)));
        public async Task ApplySignature(){await using var db=fixture.Open();var f=await db.Fields.AsNoTracking().SingleAsync(x=>x.EnvelopeId==H.Envelope.Id && x.Type==FieldType.Signature);var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==H.First.Id);Assert.Equal(SignerFieldOutcome.Applied,(await Use<SignerFields,SignerFieldResult>(s=>s.ChangeAsync(Principal,PublicId,new(f.Id,Convert.ToBase64String(f.RowVersion),SignerFieldAction.Apply,AdoptionId:signer.SignatureAdoptionId),null,null))).Outcome);}
        public async Task<string> Counts(){await using var db=fixture.Open();var s=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==H.First.Id);var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==H.Envelope.Id);return JsonSerializer.Serialize(new{EnvelopeVersion=e.RowVersion,e.Status,s.ConsentAt,s.SignatureAdoptionId,SignerVersion=s.RowVersion,Audits=await db.AuditEvents.CountAsync(x=>x.EnvelopeId==H.Envelope.Id),Work=await db.WorkItems.CountAsync(x=>x.EnvelopeId==H.Envelope.Id),Outbox=await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==H.Envelope.Id),Finishes=await db.SignerFinishAcceptances.CountAsync(x=>x.EnvelopeId==H.Envelope.Id)});}
        public async Task SignIn(){Flow=new(){H=H,Client=port is null ? H.App.GetTestClient() : new HttpClient(new HttpClientHandler{AllowAutoRedirect=false,UseCookies=false}){BaseAddress=new Uri("http://127.0.0.1:"+port)}};using var auth=await Flow.Client.GetAsync("/test-signer-session");Flow.Take(auth);Assert.Equal(HttpStatusCode.OK,auth.StatusCode);}
        public async Task<string> PrepareThroughHttp()
        {
            await SignIn();var f=Flow!;var page=await f.Page(Signing);using(var pdf=await f.Client.GetAsync(Signing+"?handler=Pdf&download=true")){f.Take(pdf);Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);}using(var consent=await f.Post(Signing,page,new(){["Receipt"]=SenderSendPageTests.Flow.Value(page,"Receipt"),["Agreement"]="true",["CanRetain"]="true",["AccessMethod"]="download"}))Assert.Equal(HttpStatusCode.Redirect,consent.StatusCode);
            var signature=await f.Page(Signing+"/signature");using var form=new MultipartFormDataContent();form.Add(new StringContent(SignaturePageTests.Browser.Token(signature)),"__RequestVerificationToken");form.Add(new StringContent("Drawn"),"Method");foreach(var name in new[]{"Signature","Initials"}){var file=new ByteArrayContent(SignatureAdoptionTests.Mark());file.Headers.ContentType=new("image/png");form.Add(file,name,"synthetic.png");}using var preview=await f.Client.PostAsync(Signing+"/signature?handler=Preview",form);f.Take(preview);Assert.Equal(HttpStatusCode.OK,preview.StatusCode);using var json=JsonDocument.Parse(await preview.Content.ReadAsStringAsync());using(var adopt=await f.Post(Signing+"/signature?handler=Adopt",signature,new(){["Receipt"]=json.RootElement.GetProperty("receipt").GetString()!,["Acknowledged"]="true",["StatementVersion"]=SignatureAdoptionStatement.Version}))Assert.Equal(HttpStatusCode.Redirect,adopt.StatusCode);
            await ApplySignature();var path=Signing+"/review";var review=await f.Page(path);using(var prepared=await f.Post(path+"?handler=Prepare",review,new()))Assert.Equal(HttpStatusCode.Redirect,prepared.StatusCode);review=await f.Page(path);using(var pdf=await f.Client.GetAsync(path+"?handler=Pdf&download=true")){f.Take(pdf);Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);}return review;
        }
        public async Task<byte[]> FinishThroughHttp(){var review=await PrepareThroughHttp();using(var result=await Flow!.Post(Signing+"/review?handler=Finish",review,new(){["Reviewed"]="true",["Acknowledged"]="true",["AccessMethod"]="download",["StatementVersion"]=SignerFinishStatement.Version}))Assert.Equal(HttpStatusCode.Redirect,result.StatusCode);await using var db=fixture.Open();var f=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.EnvelopeId==H.Envelope.Id);return await H.Read(f.PdfObjectId);}
        public async ValueTask DisposeAsync(){Flow?.Client.Dispose();await H.DisposeAsync();}
    }
}
