using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;
public sealed class SendDraftWorkflowTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Send_freezes_exact_prefilled_bytes_and_disclosure_with_one_first_signer_work_and_atomic_evidence()
    {
        await using var run = await Harness.Create(fixture); var sent = (await run.Send())!;
        await using var db = fixture.Open(); var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == run.Envelope.Id);
        Assert.Equal(EnvelopeStatus.Sent,envelope.Status); Assert.Equal(run.Clock.GetUtcNow(),envelope.SentAt); Assert.Equal(envelope.SentAt,envelope.ExclusionsAckAt);
        Assert.Equal(run.Envelope.PdfBlob,envelope.PdfBlob); Assert.NotEqual(envelope.PdfBlob,envelope.SentPdfBlob);
        Assert.Equal(run.Source,await run.Read(Guid.Parse(envelope.PdfBlob!))); var frozen = await run.Read(Guid.Parse(envelope.SentPdfBlob!));
        Assert.NotEqual(run.Source,frozen); Assert.Equal(SHA256.HashData(frozen),envelope.SentPdfSha256); Assert.Equal(Convert.ToHexStringLower(envelope.SentPdfSha256!),sent.DocumentHash);
        using (var pdf = UglyToad.PdfPig.PdfDocument.Open(frozen)) Assert.Contains("Synthetic sender prefill",pdf.GetPage(1).Text);
        Assert.True(ElectronicRecordDisclosure.Verify(new(envelope.ErsdVersion!,envelope.PublicId,envelope.Title!,envelope.SenderEmail,envelope.ErsdText!,envelope.ErsdSha256!)));
        Assert.Equal(sent.DisclosureHash,Convert.ToHexStringLower(envelope.ErsdSha256!)); Assert.False(await db.AuthTokens.AnyAsync(x => x.EnvelopeId == envelope.Id));
        var email = await db.EmailOutbox.SingleAsync(x => x.EnvelopeId == envelope.Id); Assert.Equal(run.First.Email,email.To); Assert.Equal("signer-invitation",email.Template);
        var work=await db.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).ToArrayAsync();Assert.Equal(2,work.Length);
        Assert.Single(work,x=>x.Kind==WorkKind.Email);var expiry=Assert.Single(work,x=>x.Kind==WorkKind.Expiry);Assert.Equal(envelope.ExpiresAt,expiry.AvailableAt);Assert.Equal(0,expiry.Attempts);Assert.Equal(2,run.Signals.Published);
        var events = await db.AuditEvents.Where(x => x.EnvelopeId == envelope.Id).OrderBy(x => x.Sequence).ToArrayAsync();
        Assert.Equal(new[] { "fields_finalized","sent" },events.Select(x => x.Event)); Assert.All(events,x => Assert.Equal(AuditHash.Compute(x),x.Hash)); Assert.Equal(events[0].Hash,events[1].PrevHash);
        Assert.Contains("queued",events[1].DataJson); Assert.Null((await db.Signers.AsNoTracking().SingleAsync(x => x.Id == run.First.Id)).ConsentAt);
        using var scope = run.App.Services.CreateScope();
        Assert.Null(await scope.ServiceProvider.GetRequiredService<DocumentWorkflow>().GetAsync(run.Principal,envelope.PublicId,default));
        Assert.Null(await scope.ServiceProvider.GetRequiredService<SignerSetup>().GetAsync(run.Principal,envelope.PublicId));
        Assert.Null(await scope.ServiceProvider.GetRequiredService<DraftDetails>().GetAsync(run.Principal,envelope.PublicId));
    }
    [Fact]
    public async Task Concurrent_send_freezes_and_queues_only_once()
    {
        await using var run = await Harness.Create(fixture);
        var results = await Task.WhenAll(Enumerable.Range(0,4).Select(async _ => { try { return await run.Send(); } catch (DocumentConflictException) { return null; } }));
        Assert.All(results,x=>Assert.NotNull(x)); Assert.Single(results.Select(x=>x!.InvitationWorkId).Distinct()); Assert.Single(run.Blobs.Created);
        await using var db = fixture.Open(); Assert.Single(await db.EmailOutbox.Where(x => x.EnvelopeId == run.Envelope.Id).ToArrayAsync());
    }
    [Theory]
    [InlineData("stale")][InlineData("exclusions")][InlineData("expired")][InlineData("unconfirmed")][InlineData("sender-value")]
    [InlineData("policy")][InlineData("suppressed")][InlineData("email-disabled")][InlineData("work-disabled")][InlineData("source-hash")]
    public async Task Invalid_send_cannot_freeze_or_commit_state_evidence_tokens_or_work(string kind)
    {
        await using var run = await Harness.Create(fixture); await using (var db = fixture.Open())
        {
            var e = await db.Envelopes.SingleAsync(x => x.Id == run.Envelope.Id);
            if (kind == "expired") e.ExpiresAt = run.Clock.GetUtcNow();
            if (kind == "unconfirmed") e.PreviewConfirmedAt = null;
            if (kind == "sender-value") (await db.Fields.FirstAsync(x => x.EnvelopeId == e.Id && x.SignerId == null)).Value = "";
            if (kind == "suppressed") db.Suppressions.Add(new() { Email = run.First.Email,Reason = SuppressionReason.Bounce });
            if (kind == "source-hash") e.PdfSha256 = SHA256.HashData([1]);
            await db.SaveChangesAsync(); run.Version = e.RowVersion;
        }
        if (kind == "stale") run.Version = new byte[8];
        if (kind == "policy") run.App.Services.GetRequiredService<ElectronicRecordOptions>().PaperCopyFees = "";
        if (kind == "email-disabled") run.App.Services.GetRequiredService<EmailOptions>().Enabled = false;
        if (kind == "work-disabled") run.App.Services.GetRequiredService<WorkOptions>().Enabled = false;
        var error = await Record.ExceptionAsync(() => run.Send(kind != "exclusions"));
        var expected = kind switch { "stale" => typeof(DocumentConflictException),"policy" => typeof(DisclosureRejectedException),
            "suppressed" => typeof(RecipientSuppressedException),"email-disabled" or "work-disabled" => typeof(EmailDisabledException),_ => typeof(DocumentRejectedException) };
        Assert.IsType(expected,error); Assert.Empty(run.Blobs.Created);
        await run.AssertUnsent(fixture);
    }
    [Theory]
    [InlineData("foreign")][InlineData("mixed")][InlineData("duplicate")]
    public async Task Send_requires_one_exact_verified_sender_identity(string kind)
    {
        await using var run = await Harness.Create(fixture); var principal = SenderConfiguration.Principal(new(run.Envelope.Id,run.Envelope.PublicId,run.Envelope.SenderEmail));
        if (kind == "foreign") principal = SenderConfiguration.Principal(new(Guid.NewGuid(),run.Envelope.PublicId,run.Envelope.SenderEmail));
        if (kind == "mixed") principal.AddIdentity(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier,"other")],"another-scheme"));
        if (kind == "duplicate") ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(ClaimTypes.Email,run.Envelope.SenderEmail));
        using var scope = run.App.Services.CreateScope(); Assert.Null(await scope.ServiceProvider.GetRequiredService<SendDraftWorkflow>().SendAsync(principal,run.Envelope.PublicId,run.Version,true,true,SenderSendStatement.Version,null,null));
        Assert.Empty(run.Blobs.Created); await run.AssertUnsent(fixture);
    }
    [Theory]
    [InlineData("blob")][InlineData("hint")][InlineData("audit")][InlineData("expires-during-storage")]
    public async Task Known_failure_rolls_back_and_removes_the_orphan_frozen_blob(string kind)
    {
        await using var run = await Harness.Create(fixture);
        run.Blobs.FailWrite = kind == "blob"; run.Signals.FailHint = kind == "hint"; run.Faults.FailAudit = kind == "audit";
        if (kind == "expires-during-storage") { await using var db = fixture.Open(); var e = await db.Envelopes.SingleAsync(x => x.Id == run.Envelope.Id); e.ExpiresAt = run.Clock.GetUtcNow().AddMinutes(1); await db.SaveChangesAsync(); run.Version = e.RowVersion; run.Blobs.AfterWrite = () => run.Clock.Advance(TimeSpan.FromMinutes(2)); }
        var error = await Record.ExceptionAsync(() => run.Send());
        Assert.IsType(kind == "audit" ? typeof(DbUpdateException) : kind == "expires-during-storage" ? typeof(DocumentRejectedException) : typeof(IOException),error);
        Assert.Single(run.Blobs.Created); Assert.Single(run.Blobs.Deleted); await run.AssertUnsent(fixture);
        Assert.Equal(run.Source,await run.Read(Guid.Parse(run.Envelope.PdfBlob!)));
        if (kind != "expires-during-storage") { run.Blobs.FailWrite = false; run.Signals.FailHint = false; run.Faults.FailAudit = false; Assert.NotNull(await run.Send()); }
    }
    [Fact]
    public async Task Lost_commit_acknowledgement_preserves_referenced_frozen_blob_and_hint_for_recovery()
    {
        await using var run = await Harness.Create(fixture); run.Faults.FailCommit = true;
        await Assert.ThrowsAsync<IOException>(() => run.Send()); Assert.Empty(run.Blobs.Deleted);
        await using var db = fixture.Open(); var e = await db.Envelopes.SingleAsync(x => x.Id == run.Envelope.Id); Assert.Equal(EnvelopeStatus.Sent,e.Status);
        Assert.NotEmpty(await run.Read(Guid.Parse(e.SentPdfBlob!))); Assert.Equal(2,await db.WorkItems.CountAsync(x => x.EnvelopeId == e.Id)); Assert.Equal(0,run.Signals.Published);
    }
    [Fact]
    public async Task Queue_delay_does_not_consume_invitation_life_and_the_first_signer_can_redeem_frozen_context()
    {
        await using var run = await Harness.Create(fixture); var sent = (await run.Send())!; var at = run.Clock.GetUtcNow(); run.Clock.Advance(TimeSpan.FromDays(3));
        Assert.True(await run.Once()); Assert.Equal(1,run.Sender.Calls); var outgoing = run.Sender.Last!;
        Assert.Contains("&lt;b&gt;",outgoing.Html); Assert.DoesNotContain("<b>Synthetic",outgoing.Html); Assert.Contains("/sign/invitation?token=",outgoing.Text);
        var token = Regex.Match(outgoing.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value; Assert.Equal(43,token.Length);
        await using var db = fixture.Open(); var stored = await db.AuthTokens.SingleAsync(x => x.EnvelopeId == run.Envelope.Id);
        Assert.Equal(run.Clock.GetUtcNow().AddHours(24),stored.ExpiresAt); Assert.True(stored.ExpiresAt > at.AddHours(24));
        Assert.Equal(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(token)),stored.TokenSha256);
        var email = await db.EmailOutbox.SingleAsync(x => x.Id == sent.InvitationWorkId); Assert.DoesNotContain(token,email.PayloadJson);
        var submitted = await db.AuditEvents.SingleAsync(x => x.EnvelopeId == run.Envelope.Id && x.Event == "invitation_submitted");
        Assert.Equal(PartyType.System,submitted.ActorType); Assert.Null(submitted.ActorEmail); Assert.Null(submitted.ActorId); Assert.Contains(run.First.Id.ToString(),submitted.DataJson);
        Assert.DoesNotContain(await db.AuditEvents.Where(x => x.EnvelopeId == run.Envelope.Id).ToArrayAsync(),x => x.DataJson.Contains(token));
        using var scope = run.App.Services.CreateScope(); var access = scope.ServiceProvider.GetRequiredService<SignerAccess>();
        var identity = (await access.RedeemAsync(token,null,null))!; Assert.Equal(run.First.Id,identity.SignerId);
        var context = (await access.GetContextAsync(SignerAccessConfiguration.Principal(identity),run.Envelope.PublicId))!; Assert.Equal(sent.DocumentHash,context.Identity.DocumentHash);
        Assert.Equal(sent.DisclosureHash,context.Identity.DisclosureHash);
        await run.Signals.PublishAsync(sent.InvitationWorkId,TimeSpan.Zero,default); Assert.True(await run.Once()); Assert.Equal(1,run.Sender.Calls);
    }
    [Theory]
    [InlineData("definite")][InlineData("ambiguous")]
    public async Task Dispatch_retries_only_definite_non_submission_and_keeps_ambiguity_safe(string kind)
    {
        await using var run = await Harness.Create(fixture); var sent = (await run.Send())!;
        run.Sender.Failure = kind == "definite" ? new EmailNotSubmittedException(true) : new IOException("Synthetic unknown acceptance");
        if (kind == "ambiguous") await Assert.ThrowsAsync<IOException>(() => run.Once()); else Assert.True(await run.Once());
        var firstToken = Regex.Match(run.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        run.Sender.Failure = null; run.Clock.Advance(TimeSpan.FromMinutes(6)); await run.Signals.PublishAsync(sent.InvitationWorkId,TimeSpan.Zero,default); Assert.True(await run.Once());
        await using var db = fixture.Open(); var email = await db.EmailOutbox.SingleAsync(x => x.Id == sent.InvitationWorkId);
        Assert.Equal(kind == "definite" ? 2 : 1,run.Sender.Calls);
        if (kind == "definite") { Assert.Equal(EmailStatus.Sent,email.Status); Assert.NotEqual(firstToken,Regex.Match(run.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value); Assert.Equal(2,await db.AuthTokens.CountAsync(x => x.EnvelopeId == run.Envelope.Id)); }
        else { Assert.Equal(EmailStatus.Failed,email.Status); Assert.Equal("submission-ambiguous",email.LastError); }
    }
    [Theory]
    [InlineData("voided")][InlineData("expired")][InlineData("disclosure")][InlineData("email")][InlineData("order")][InlineData("suppression")]
    public async Task Dispatch_rechecks_current_frozen_scope_before_activating_any_token(string kind)
    {
        await using var run = await Harness.Create(fixture); var sent = (await run.Send())!;
        await using (var db = fixture.Open())
        {
            var e = await db.Envelopes.SingleAsync(x => x.Id == run.Envelope.Id);
            if (kind == "voided") e.Status = EnvelopeStatus.Voided;
            if (kind == "expired") e.ExpiresAt = run.Clock.GetUtcNow();
            if (kind == "disclosure") e.ErsdText += "tampered";
            if (kind == "email") (await db.Signers.SingleAsync(x => x.Id == run.First.Id)).Email = "changed@example.invalid";
            if (kind == "order") { using var scope = run.App.Services.CreateScope(); var email = await db.EmailOutbox.SingleAsync(x => x.Id == sent.InvitationWorkId); email.To = run.Second.Email; email.PayloadJson = scope.ServiceProvider.GetRequiredService<SignerInvitationProtection>().Protect(new(run.Second.Id)); }
            if (kind == "suppression") db.Suppressions.Add(new() { Email = run.First.Email,Reason = SuppressionReason.Complaint });
            await db.SaveChangesAsync();
        }
        Assert.True(await run.Once()); Assert.Equal(0,run.Sender.Calls); await using var inspect = fixture.Open(); Assert.False(await inspect.AuthTokens.AnyAsync(x => x.EnvelopeId == run.Envelope.Id));
    }
    [Fact]
    public async Task Dispatch_clamps_to_request_expiry_and_cannot_regress_signer_progress_after_provider_acceptance()
    {
        await using var run = await Harness.Create(fixture); var end = run.Clock.GetUtcNow().AddMinutes(30);
        await using (var db = fixture.Open()) { var e = await db.Envelopes.SingleAsync(x => x.Id == run.Envelope.Id); e.ExpiresAt = end; await db.SaveChangesAsync(); run.Version = e.RowVersion; }
        Assert.NotNull(await run.Send()); run.Clock.Advance(TimeSpan.FromMinutes(10));
        run.Sender.BeforeReturn = async () => { await using var db = fixture.Open(); await db.Signers.Where(x => x.Id == run.First.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Status,SignerStatus.Viewed)); };
        Assert.True(await run.Once()); await using var inspect = fixture.Open();
        Assert.Equal(end,(await inspect.AuthTokens.SingleAsync(x => x.EnvelopeId == run.Envelope.Id)).ExpiresAt);
        Assert.Equal(SignerStatus.Viewed,(await inspect.Signers.SingleAsync(x => x.Id == run.First.Id)).Status);
        Assert.Contains(end.ToString("u"),run.Sender.Last!.Text);
    }
    [Fact]
    public async Task Freeze_canonicalizes_title_to_the_exact_disclosure_header_and_keeps_future_signer_access_valid()
    {
        await using var run = await Harness.Create(fixture); await using (var db = fixture.Open()) { var e = await db.Envelopes.SingleAsync(x => x.Id == run.Envelope.Id); e.Title = " Cafe\u0301 synthetic "; await db.SaveChangesAsync(); run.Version = e.RowVersion; }
        Assert.NotNull(await run.Send()); Assert.True(await run.Once());
        var token = Regex.Match(run.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        using var scope = run.App.Services.CreateScope(); var identity = await scope.ServiceProvider.GetRequiredService<SignerAccess>().RedeemAsync(token,null,null); Assert.NotNull(identity);
        await using var inspect = fixture.Open(); Assert.Equal("Café synthetic",(await inspect.Envelopes.SingleAsync(x => x.Id == run.Envelope.Id)).Title);
    }
    [Fact]
    public async Task Invitation_delivers_to_local_Mailpit_with_the_safe_landing_link()
    {
        await using var run = await Harness.Create(fixture,true); var sent = (await run.Send())!; Assert.True(await run.Once());
        using var http = new HttpClient(); var json = await http.GetStringAsync("http://127.0.0.1:" + Environment.GetEnvironmentVariable("QUILLSIGN_TEST_MAIL_PORT") + "/api/v1/search?query=to:" + run.First.Email);
        Assert.Contains("Review your signing request",json); await using var db = fixture.Open(); Assert.Equal(EmailStatus.Sent,(await db.EmailOutbox.SingleAsync(x => x.Id == sent.InvitationWorkId)).Status);
    }
    internal sealed class Harness : IAsyncDisposable
    {
        public WebApplication App = null!; public Envelope Envelope = null!; public Signer First = null!,Second = null!; public byte[] Source = [],Version = [];
        public Clock Clock = new(); public Faults Faults = new(); public FakeSender Sender = new(); public FaultBlobs Blobs = null!; public Signals Signals = null!;
        private QueueClient queue = null!; private BlobContainerClient hints = null!; private BlobClient keyBlob = null!;
        public ClaimsPrincipal Principal => SenderConfiguration.Principal(new(Envelope.Id,Envelope.PublicId,Envelope.SenderEmail));
        public static async Task<Harness> Create(SqlDatabaseFixture fixture,bool smtp = false,bool browser=false,int? browserPort=null,Func<VerifiedSigner?>? syntheticSigner=null)
        {
            var run = new Harness(); var name = "sendtest-" + Guid.NewGuid().ToString("N"); var storage = Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;
            using var source = fixture.Open(); var connection = source.Database.GetConnectionString();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(SendDraftWorkflow).Assembly.FullName,EnvironmentName = "Development",ContentRootPath = AppContext.BaseDirectory,
                WebRootPath=browserPort is null ? null : Path.GetFullPath("../../../../../src/QuillSign/wwwroot",AppContext.BaseDirectory) }); builder.Logging.ClearProviders();
            var outputRoot=Path.Combine(AppContext.BaseDirectory,"wwwroot");
            if(browserPort is not null && Directory.Exists(outputRoot))builder.Environment.WebRootFileProvider=new Microsoft.Extensions.FileProviders.CompositeFileProvider(builder.Environment.WebRootFileProvider,new Microsoft.Extensions.FileProviders.PhysicalFileProvider(outputRoot));
            builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> {
                ["Storage:Provider"]="Azurite",["Storage:ConnectionString"]=storage,["DataProtection:ApplicationName"]=name,["DataProtection:KeyRingBlobName"]=name+".xml",
                ["Work:Enabled"]="true",["Work:QueueName"]=name,["Work:HintContainer"]=name,["Email:Enabled"]="true",["Email:Provider"]="Smtp",
                ["Email:FromEmail"]="noreply@example.invalid",["Email:BaseUrl"]="http://localhost:5084",["Email:Smtp:Host"]="127.0.0.1",["Email:Smtp:Port"]=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_SMTP_PORT"),["Email:Smtp:UseStartTls"]="false" });
            builder.Services.AddRazorPages(); builder.Services.AddDbContext<QuillSignDbContext>(o => o.UseSqlServer(connection).AddInterceptors(run.Faults));
            builder.Services.AddQuillSignStorage(builder.Configuration,builder.Environment); builder.Services.AddQuillSignEmail(builder.Configuration,builder.Environment); builder.Services.AddQuillSignWork(builder.Configuration,builder.Environment);
            builder.Services.AddQuillSignSender(builder.Configuration,builder.Environment); builder.Services.AddQuillSignSignerSetup(builder.Configuration); builder.Services.AddQuillSignFieldEditor(builder.Configuration); builder.Services.AddQuillSignDocuments(builder.Configuration); builder.Services.AddScoped<SendDraftWorkflow>();
            builder.Services.AddSingleton(ElectronicRecordDisclosureTests.Policy()); builder.Services.AddSingleton<TimeProvider>(run.Clock); if (!smtp) builder.Services.AddSingleton<IEmailSender>(run.Sender);
            run.queue = new QueueClient(storage,name,new QueueClientOptions(QueueClientOptions.ServiceVersion.V2023_11_03));
            var service = new BlobServiceClient(storage,new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)); run.hints = service.GetBlobContainerClient(name); run.keyBlob = service.GetBlobContainerClient("keys").GetBlobClient(name+".xml");
            run.Signals = new(new AzureWorkSignals(run.queue,run.hints,new() { Enabled=true,QueueName=name,HintContainer=name },true)); builder.Services.AddSingleton<IWorkSignals>(run.Signals);
            run.Blobs = new(new AzureBlobStore(service,25*1024*1024,true)); builder.Services.AddSingleton<IBlobStore>(run.Blobs);
            if(browser) {
                if(browserPort is { } port) builder.WebHost.UseUrls("http://127.0.0.1:"+port); else builder.WebHost.UseTestServer();
                builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> { ["ConnectionStrings:Database"]=connection });
                builder.Services.AddScoped<SenderSentStatus>(); builder.Services.AddScoped<Func<SenderSentStatus>>(sp=>()=>sp.GetRequiredService<SenderSentStatus>());
                builder.Services.AddScoped<Func<SendDraftWorkflow>>(sp=>()=>sp.GetRequiredService<SendDraftWorkflow>()); builder.Services.AddScoped<SenderSendReadiness>();
                builder.Services.AddQuillSignSignerAccess(builder.Configuration,builder.Environment); builder.Services.AddQuillSignSignerConsent();
                builder.Services.AddScoped<SignaturePreviewProtection>(); builder.Services.AddScoped<SignatureAdoption>(); builder.Services.AddScoped<SignerFields>(); builder.Services.AddScoped<SignerFieldView>();
                builder.Services.AddScoped<SignerReviewProtection>(); builder.Services.AddScoped<SignerReviewCandidates>(); builder.Services.AddScoped<SignerFinish>(); builder.Services.AddScoped<SignerCheckpointReads>(); builder.Services.AddSignerReviewBrowser();
            }
            run.App=builder.Build();
            using var normalized = new MemoryStream(); var pages = new PdfValidation(new()).Rewrite(new MemoryStream(PdfFixtures.Create(text:"Synthetic NO AGREEMENT")),normalized); run.Source = normalized.ToArray();
            run.Envelope = new Envelope { SenderEmail="sender-"+name+"@example.invalid",Title="<b>Synthetic NO AGREEMENT</b>",Message="<b>Synthetic message</b>",SenderVerifiedAt=run.Clock.GetUtcNow(),PreviewConfirmedAt=run.Clock.GetUtcNow(),PdfBlob=Guid.NewGuid().ToString("N"),PdfSha256=SHA256.HashData(run.Source),PageCount=pages.Count,PageSizesJson=JsonSerializer.Serialize(pages),ExpiresAt=run.Clock.GetUtcNow().AddDays(30) };
            run.First = new Signer { EnvelopeId=run.Envelope.Id,FullName="Synthetic first signer",Email="first-"+name+"@example.invalid",Order=1 }; run.Second = new Signer { EnvelopeId=run.Envelope.Id,FullName="Synthetic second signer",Email="second-"+name+"@example.invalid",Order=2 };
            await using (var scope = run.App.Services.CreateAsyncScope()) { var db = scope.ServiceProvider.GetRequiredService<QuillSignDbContext>(); db.AddRange(run.Envelope,run.First,run.Second,
                new DocumentField { EnvelopeId=run.Envelope.Id,Type=FieldType.Text,Page=1,X=.1m,Y=.3m,Width=.7m,Height=.1m,Value="Synthetic sender prefill" },
                new DocumentField { EnvelopeId=run.Envelope.Id,SignerId=run.First.Id,Type=FieldType.Signature,Page=1,X=.1m,Y=.5m,Width=.4m,Height=.1m }); await db.SaveChangesAsync(); run.Version=run.Envelope.RowVersion; }
            await run.Blobs.Inner.WriteAsync(run.Principal,new(run.Envelope.Id,DocumentBlobKind.Normalized,Guid.Parse(run.Envelope.PdfBlob)),new MemoryStream(run.Source),run.Source.Length);
            if(browser) {
                if(browserPort is not null)run.App.Use(async(context,next)=>{context.Response.Headers["X-Content-Type-Options"]="nosniff";context.Response.Headers["Referrer-Policy"]="no-referrer";context.Response.Headers["Content-Security-Policy"]="default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data: blob:; font-src 'self' data: blob:; worker-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";await next();});
                if(browserPort is not null) run.App.UseStaticFiles();
                run.App.UseRouting(); run.App.UseRateLimiter(); run.App.UseAuthentication(); run.App.UseAuthorization(); run.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
                run.App.MapGet("/test-session",async (Microsoft.AspNetCore.Http.HttpContext context)=> {
                    await context.SignInAsync(EnvelopeStorageAuthorization.SenderScheme,run.Principal,new AuthenticationProperties { ExpiresUtc=run.Clock.GetUtcNow().AddHours(2),AllowRefresh=false }); return "ok";
                });
                if(syntheticSigner is not null)run.App.MapGet("/test-signer-session",async(Microsoft.AspNetCore.Http.HttpContext context)=>{
                    var identity=syntheticSigner();if(identity is null)return Microsoft.AspNetCore.Http.Results.NotFound();
                    await context.SignInAsync(SignerAccessConfiguration.Scheme,SignerAccessConfiguration.Principal(identity),SignerAccessConfiguration.Ticket(identity));return Microsoft.AspNetCore.Http.Results.Text("ok","text/plain");
                });
                await run.App.StartAsync();
            }
            return run;
        }
        public async Task<SentDraft?> Send(bool acknowledged = true,string? reviewedRetentionSha256=null) { using var scope = App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<SendDraftWorkflow>().SendAsync(Principal,Envelope.PublicId,Version,acknowledged,true,SenderSendStatement.Version,"127.0.0.1","synthetic-send-test",reviewedRetentionSha256:reviewedRetentionSha256); }
        public async Task<bool> Once() { using var scope = App.Services.CreateScope(); return await scope.ServiceProvider.GetRequiredService<WorkProcessor>().RunOnceAsync(default); }
        public async Task<byte[]> Read(Guid id) { using var result = new MemoryStream(); await Blobs.Inner.CopyToAsync(Principal,new(Envelope.Id,DocumentBlobKind.Normalized,id),result); return result.ToArray(); }
        public async Task AssertUnsent(SqlDatabaseFixture fixture) { await using var db = fixture.Open(); var e = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == Envelope.Id); Assert.Equal(EnvelopeStatus.Draft,e.Status); Assert.Null(e.SentPdfBlob); Assert.Null(e.ErsdText); Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == e.Id)); Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == e.Id)); Assert.False(await db.AuthTokens.AnyAsync(x => x.EnvelopeId == e.Id)); }
        public async ValueTask DisposeAsync()
        {
            await App.DisposeAsync();
            foreach (var blob in Blobs.Created.Append(new(Envelope.Id,DocumentBlobKind.Normalized,Guid.Parse(Envelope.PdfBlob!))).Distinct())
                await Blobs.Inner.DeleteAsync(Principal,blob);
            await queue.DeleteIfExistsAsync(); await hints.DeleteIfExistsAsync(); await keyBlob.DeleteIfExistsAsync();
        }
    }
    internal sealed class Clock : TimeProvider
    {
        private DateTimeOffset now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        private global::System.Diagnostics.Stopwatch? elapsed;
        public override DateTimeOffset GetUtcNow()=>now+(elapsed?.Elapsed??TimeSpan.Zero);
        public void Advance(TimeSpan value)=>now+=value;
        public void TrackElapsed()=>elapsed??=global::System.Diagnostics.Stopwatch.StartNew();
    }
    internal sealed class FakeSender : IEmailSender
    {
        public int Calls; public OutgoingEmail? Last; public Exception? Failure; public Func<Task>? BeforeReturn;
        public async Task<EmailDelivery> SendAsync(OutgoingEmail email,CancellationToken ct)
        { Calls++; Last=email; if(Failure is not null)throw Failure; if (BeforeReturn is not null) await BeforeReturn(); return new("Smtp","synthetic-receipt"); }
    }
    internal sealed class FaultBlobs(IBlobStore inner) : IBlobStore { public IBlobStore Inner=>inner; public List<DocumentBlob> Created=[],Deleted=[]; public bool FailWrite,FailRead; public int Reads; public Action? AfterWrite,AfterRead;
        public async Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,long length,CancellationToken ct) { Created.Add(b); await inner.WriteAsync(p,b,s,length,ct); AfterWrite?.Invoke(); if(FailWrite)throw new IOException("Synthetic lost write response"); }
        public Func<ClaimsPrincipal,DocumentBlob,Stream,CancellationToken,Task<long>>? SyntheticSignerRead;
        public async Task<long> CopyToAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,CancellationToken ct) {Interlocked.Increment(ref Reads);if(FailRead)throw new IOException("Synthetic read failure.");var length=SyntheticSignerRead is not null && p.Identities.Any(x=>x.AuthenticationType==SignerAccessConfiguration.Scheme) ? await SyntheticSignerRead(p,b,s,ct) : await inner.CopyToAsync(p,b,s,ct);AfterRead?.Invoke();return length;}
        public Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct) { Deleted.Add(b); return inner.DeleteAsync(p,b,ct); } }
    internal sealed class Faults : DbTransactionInterceptor, ISaveChangesInterceptor
    {
        public bool FailCommit,FailAudit,RejectCommit; private string? target; private bool armed;
        public string? Event {get=>target;set {target=value;armed=false;}}
        public Func<QuillSignDbContext,Task>? BeforeAudit;
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default) { if(FailCommit && (Event is null || armed)) {armed=false;throw new IOException("Synthetic lost commit acknowledgement");} return Task.CompletedTask; }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,TransactionEventData e,InterceptionResult result,CancellationToken ct=default) {
            if(RejectCommit && (Event is null || armed)) {armed=false;throw new IOException("Synthetic rejected commit");}return ValueTask.FromResult(result);
        }
        public async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> result,CancellationToken ct=default) {
            if(e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && (Event is null || x.Entity.Event==Event))) {
                armed=true;if(BeforeAudit is not null)await BeforeAudit((QuillSignDbContext)e.Context);
                if(FailAudit)throw new DbUpdateException("Synthetic audit failure");
            }return result;
        }
    }
    internal sealed class Signals(IWorkSignals inner) : IWorkSignals
    { public bool FailHint,FailPublish; public int Published,HintCalls,FailHintAfterWriteAt,FailPublishAt;
        public async Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct) {var call=Interlocked.Increment(ref HintCalls);if(FailHint)throw new IOException("Synthetic hint failure");await inner.PutHintAsync(id,due,ct);if(FailHintAfterWriteAt==call)throw new IOException("Synthetic lost hint acknowledgement");}
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct) {var call=Interlocked.Increment(ref Published);if(FailPublish || FailPublishAt==call)throw new IOException("Synthetic queue publication failure");return inner.PublishAsync(id,delay,ct);}
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>inner.RemoveHintAsync(id,ct); public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>inner.ReceiveAsync(ct); public Task DeferAsync(WorkDelivery d,TimeSpan delay,CancellationToken ct)=>inner.DeferAsync(d,delay,ct); public Task AcknowledgeAsync(WorkDelivery d,CancellationToken ct)=>inner.AcknowledgeAsync(d,ct); public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>inner.ReadDueAsync(id,ct);
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>inner.RecoverAsync(now,ct); public Task VerifyAsync(CancellationToken ct)=>inner.VerifyAsync(ct); }
}
