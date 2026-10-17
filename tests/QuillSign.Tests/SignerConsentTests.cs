using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PdfSharp.Pdf;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Legal;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;
using QuillSign.Email;

namespace QuillSign.Tests;
public sealed class SignerConsentTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private readonly Clock clock = new();
    private readonly EphemeralDataProtectionProvider protection = new();
    private SignerReceiptProtection Receipts => new(protection,clock);
    private SignerAccess Access(QuillSignDbContext db) => new(db,new(db,clock),new(),clock);
    private SignerConsent Consent(QuillSignDbContext db,Signals? signals = null,bool enabled = false) => new(db,Access(db),Receipts,new(db,clock),
        new(db,() => signals ?? throw new InvalidOperationException(),new() { Enabled = enabled },new(protection),clock),clock);

    [Fact]
    public async Task Concurrent_consent_is_atomic_idempotent_attributed_and_leaves_document_fields_untouched()
    {
        var seed = await Seed(); var receipt = Receipts.Create(seed.Identity);
        var results = await Task.WhenAll(Enumerable.Range(0,4).Select(async _ =>
        { await using var db = fixture.Open(); return await Consent(db).AcceptAsync(seed.Principal,seed.Envelope.PublicId,receipt,true,true,"preview","127.0.0.1",new string('u',2500)); }));
        Assert.Single(results,x => x == ConsentResult.Accepted); Assert.Equal(3,results.Count(x => x == ConsentResult.AlreadyAccepted));
        await using var inspect = fixture.Open(); var saved = await inspect.Signers.SingleAsync(x => x.Id == seed.Signer.Id);
        Assert.Equal(clock.GetUtcNow(),saved.ConsentAt); Assert.Equal(2048,saved.ConsentUa!.Length); Assert.Equal(SignerStatus.Viewed,saved.Status);
        var audit = await inspect.AuditEvents.SingleAsync(x => x.EnvelopeId == seed.Envelope.Id && x.Event == "consent_given");
        Assert.Equal(seed.Signer.Id,audit.ActorId); Assert.Equal(PartyType.Signer,audit.ActorType); Assert.Equal(AuditHash.Compute(audit),audit.Hash);
        Assert.Contains(seed.Identity.DocumentHash,audit.DataJson); Assert.Contains(seed.Identity.DisclosureHash,audit.DataJson);
        Assert.Contains("hash_verified_pdf_prepared",audit.DataJson); Assert.DoesNotContain(receipt,audit.DataJson);
        Assert.Equal(seed.Envelope.RowVersion,(await inspect.Envelopes.AsNoTracking().SingleAsync(x => x.Id == seed.Envelope.Id)).RowVersion);
        Assert.Equal("unchanged",(await inspect.Fields.SingleAsync(x => x.EnvelopeId == seed.Envelope.Id)).Value);
        Assert.Null(await Consent(inspect).DeclineAsync(seed.Principal,seed.Envelope.PublicId,"after consent",null,null));
    }
    [Theory]
    [InlineData("missing")][InlineData("tampered")][InlineData("foreign")][InlineData("expired")]
    [InlineData("agreement")][InlineData("retention")][InlineData("method")][InlineData("document")][InlineData("disclosure")][InlineData("state")]
    public async Task Missing_affirmations_receipt_or_current_scope_prevent_consent(string kind)
    {
        var seed = await Seed(); string? receipt = Receipts.Create(seed.Identity);
        if (kind == "missing") receipt = null;
        if (kind == "tampered") receipt += "broken";
        if (kind == "foreign") receipt = Receipts.Create(seed.Identity with { SignerId = Guid.NewGuid() });
        if (kind == "expired") clock.Advance(TimeSpan.FromMinutes(10));
        await using var db = fixture.Open();
        if (kind is "document" or "disclosure" or "state")
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == seed.Envelope.Id);
            if (kind == "document") envelope.SentPdfSha256 = SHA256.HashData([99]);
            if (kind == "disclosure") envelope.ErsdText += "changed";
            if (kind == "state") envelope.Status = EnvelopeStatus.Voided;
            await db.SaveChangesAsync();
        }
        var result = await Consent(db).AcceptAsync(seed.Principal,seed.Envelope.PublicId,receipt,kind != "agreement",kind != "retention",kind == "method" ? "made-up" : "download",null,null);
        Assert.Contains(result,new[] { ConsentResult.InvalidContext,ConsentResult.InvalidEvidence });
        Assert.Null((await db.Signers.AsNoTracking().SingleAsync(x => x.Id == seed.Signer.Id)).ConsentAt);
        Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == seed.Envelope.Id && x.Event == "consent_given"));
    }
    [Fact]
    public async Task Decline_closes_every_session_and_queues_one_protected_notification_with_post_commit_publication()
    {
        var seed = await Seed(); var signals = new Signals();
        signals.OnPublish = async () => { await using var inspect = fixture.Open(); Assert.Equal(EnvelopeStatus.Declined,(await inspect.Envelopes.SingleAsync(x => x.Id == seed.Envelope.Id)).Status); };
        await using var db = fixture.Open(); var service = Consent(db,signals,true);
        Assert.NotNull(await service.DeclineAsync(seed.Principal,seed.Envelope.PublicId,"<b>Synthetic reason</b>",null,null));
        Assert.Null(await service.DeclineAsync(seed.Principal,seed.Envelope.PublicId,null,null,null));
        Assert.Equal(1,signals.Hints); Assert.Equal(1,signals.Published);
        Assert.Null(await Access(db).GetContextAsync(seed.Principal,seed.Envelope.PublicId));
        Assert.NotNull(await Access(db).GetContextAsync(seed.Principal,seed.Envelope.PublicId,declinedConfirmation:true));
        var email = await db.EmailOutbox.SingleAsync(x => x.EnvelopeId == seed.Envelope.Id);
        Assert.Equal("signer-declined",email.Template); Assert.DoesNotContain("Synthetic reason",email.PayloadJson);
        var payload = new DeclinePayloadProtection(protection).Read(email.PayloadJson);
        Assert.Equal("<b>Synthetic reason</b>",payload.Reason);
        Assert.Single(await db.WorkItems.Where(x => x.EnvelopeId == seed.Envelope.Id).ToArrayAsync());
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == seed.Envelope.Id && x.Event == "declined").ToArrayAsync());
        Assert.Equal(ConsentResult.InvalidContext,await service.AcceptAsync(seed.Principal,seed.Envelope.PublicId,Receipts.Create(seed.Identity),true,true,"preview",null,null));
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Disabled_work_preserves_notification_and_explicit_republish_is_scoped_and_idempotent(bool failPublish)
    {
        var seed = await Seed(); await using var db = fixture.Open();
        Assert.NotNull(await Consent(db).DeclineAsync(seed.Principal,seed.Envelope.PublicId,null,null,null));
        var email = await db.EmailOutbox.SingleAsync(x => x.EnvelopeId == seed.Envelope.Id); var signals = new Signals { FailPublish = failPublish };
        var writer = new DeclineNotificationWriter(db,() => signals,new() { Enabled = true },new(protection),clock);
        Assert.False(await writer.RepublishAsync(Guid.NewGuid(),default)); Assert.True(await writer.RepublishAsync(email.Id,default)); Assert.Equal(1,signals.Hints);
        await db.EmailOutbox.Where(x => x.Id == email.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.SubmissionStartedAt,clock.GetUtcNow()));
        Assert.False(await writer.RepublishAsync(email.Id,default));
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Audit_failure_rolls_back_consent_or_decline_and_outbox_then_retry_succeeds(bool decline)
    {
        var seed = await Seed(); await using var original = fixture.Open();
        await using (var bad = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(original.Database.GetConnectionString()).AddInterceptors(new RejectAudit()).Options))
        {
            if (decline) await Assert.ThrowsAsync<DbUpdateException>(() => Consent(bad).DeclineAsync(seed.Principal,seed.Envelope.PublicId,null,null,null));
            else await Assert.ThrowsAsync<DbUpdateException>(() => Consent(bad).AcceptAsync(seed.Principal,seed.Envelope.PublicId,Receipts.Create(seed.Identity),true,true,"download",null,null));
        }
        Assert.Null((await original.Signers.AsNoTracking().SingleAsync(x => x.Id == seed.Signer.Id)).ConsentAt);
        Assert.Equal(EnvelopeStatus.Sent,(await original.Envelopes.AsNoTracking().SingleAsync(x => x.Id == seed.Envelope.Id)).Status);
        Assert.False(await original.EmailOutbox.AnyAsync(x => x.EnvelopeId == seed.Envelope.Id));
        if (decline) Assert.NotNull(await Consent(original).DeclineAsync(seed.Principal,seed.Envelope.PublicId,null,null,null));
        else Assert.Equal(ConsentResult.Accepted,await Consent(original).AcceptAsync(seed.Principal,seed.Envelope.PublicId,Receipts.Create(seed.Identity),true,true,"download",null,null));
    }
    [Theory]
    [InlineData("valid")][InlineData("hash")][InlineData("malformed")][InlineData("missing")][InlineData("oversize")]
    public async Task Frozen_PDF_is_bounded_verified_and_validated_before_exposure(string kind)
    {
        var seed = await Seed(); await using var db = fixture.Open(); var context = (await Access(db).GetContextAsync(seed.Principal,seed.Envelope.PublicId))!;
        var blobs = new Blobs(seed.Pdf) { Failure = kind == "missing",Oversize = kind == "oversize" };
        if (kind == "hash") blobs.Bytes = Pdf();
        if (kind == "malformed") { blobs.Bytes = Encoding.ASCII.GetBytes("%PDF-1.7\nmalformed\n%%EOF"); context = context with { DocumentSha256 = SHA256.HashData(blobs.Bytes) }; }
        var reader = new SignerPdfAccess(blobs,new());
        if (kind == "valid") Assert.Equal(seed.Pdf,await reader.PrepareAsync(seed.Principal,context));
        else if (kind == "missing") await Assert.ThrowsAsync<IOException>(() => reader.PrepareAsync(seed.Principal,context));
        else await Assert.ThrowsAsync<DocumentRejectedException>(() => reader.PrepareAsync(seed.Principal,context));
    }
    [Fact]
    public async Task Razor_invitation_GET_is_non_consuming_POST_requires_CSRF_and_clean_consent_flow_is_scoped()
    {
        var seed = await Seed(); await using var app = await App(seed); using var client = app.GetTestClient();
        var cookies = new Dictionary<string,string>();
        async Task<string> Get(string path) { using var response = await client.GetAsync(path); Cookies(response,cookies,client); return await response.Content.ReadAsStringAsync(); }
        var landing = await Get("/sign/invitation?token=" + seed.Invitation.RawToken);
        Assert.Contains("Open request",landing);
        await using (var inspect = fixture.Open()) Assert.Null((await inspect.AuthTokens.SingleAsync(x => x.Id == seed.Invitation.Record.Id)).UsedAt);
        using (var noCsrf = await client.PostAsync("/sign/invitation",new FormUrlEncodedContent(new Dictionary<string,string> { ["Token"] = seed.Invitation.RawToken }))) Assert.Equal(HttpStatusCode.BadRequest,noCsrf.StatusCode);
        using (var opened = await client.PostAsync("/sign/invitation",Form(landing,new() { ["Token"] = seed.Invitation.RawToken })))
        {
            Assert.Equal(HttpStatusCode.Redirect,opened.StatusCode); Assert.Equal("/sign/" + seed.Envelope.PublicId,opened.Headers.Location!.OriginalString);
            Cookies(opened,cookies,client);
        }
        var path = "/sign/" + seed.Envelope.PublicId; var page = await Get(path);
        Assert.Contains(WebUtility.HtmlEncode(seed.Envelope.Title!),page); Assert.DoesNotContain("<b>Synthetic",page);
        Assert.DoesNotContain("checked=",page); Assert.Contains(seed.Envelope.ErsdText!.Split('\n')[0],WebUtility.HtmlDecode(page));
        var receipt = Input(page,"Receipt"); Assert.NotEmpty(receipt);
        using (var foreign = await client.GetAsync("/sign/" + Guid.NewGuid().ToString("N"))) Assert.Equal(HttpStatusCode.NotFound,foreign.StatusCode);
        using (var pdf = await client.GetAsync(path + "?handler=Pdf&download=true"))
        { Assert.Equal(seed.Pdf,await pdf.Content.ReadAsByteArrayAsync()); Assert.True(pdf.Headers.CacheControl!.NoStore); Assert.Equal("attachment",pdf.Content.Headers.ContentDisposition!.DispositionType); }
        using (var disclosure = await client.GetAsync(path + "?handler=Disclosure")) Assert.Equal(seed.Envelope.ErsdText,await disclosure.Content.ReadAsStringAsync());
        using (var failed = await client.PostAsync(path,Form(page,new() { ["Receipt"] = receipt,["Agreement"] = "true",["AccessMethod"] = "preview" }))) Assert.Equal(HttpStatusCode.BadRequest,failed.StatusCode);
        using (var accepted = await client.PostAsync(path,Form(page,new() { ["Receipt"] = receipt,["Agreement"] = "true",["CanRetain"] = "true",["AccessMethod"] = "preview" }))) Assert.Equal(HttpStatusCode.Redirect,accepted.StatusCode);
        Assert.Contains("No signature has been recorded",await Get(path));
        using (var replay = await client.PostAsync("/sign/invitation",Form(landing,new() { ["Token"] = seed.Invitation.RawToken }))) Assert.Equal(HttpStatusCode.BadRequest,replay.StatusCode);
    }
    [Fact]
    public async Task Razor_failed_storage_blocks_initial_receipt_and_later_consent_and_invitation_is_rate_limited()
    {
        var seed = await Seed(); var blobs = new Blobs(seed.Pdf) { Failure = true }; await using var app = await App(seed,blobs); using var client = app.GetTestClient(); var cookies = new Dictionary<string,string>();
        using (var session = await client.GetAsync("/synthetic-session")) Cookies(session,cookies,client);
        var path = "/sign/" + seed.Envelope.PublicId;
        using (var initial = await client.GetAsync(path)) { Assert.Equal(HttpStatusCode.ServiceUnavailable,initial.StatusCode); Assert.Empty(Input(await initial.Content.ReadAsStringAsync(),"Receipt")); }
        blobs.Failure = false; using var good = await client.GetAsync(path); Cookies(good,cookies,client); var html = await good.Content.ReadAsStringAsync(); Assert.NotEmpty(Input(html,"Receipt"));
        blobs.Failure = true;
        using (var failed = await client.PostAsync(path,Form(html,new() { ["Receipt"] = Input(html,"Receipt"),["Agreement"] = "true",["CanRetain"] = "true",["AccessMethod"] = "download" })))
        { Assert.Equal(HttpStatusCode.ServiceUnavailable,failed.StatusCode); Assert.Empty(Input(await failed.Content.ReadAsStringAsync(),"Receipt")); }
        await using var inspect = fixture.Open(); Assert.Null((await inspect.Signers.SingleAsync(x => x.Id == seed.Signer.Id)).ConsentAt);
        for (var i = 0; i < 20; i++) { using var response = await client.GetAsync("/sign/invitation"); Assert.Equal(HttpStatusCode.OK,response.StatusCode); }
        using var limited = await client.GetAsync("/sign/invitation"); Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode);
    }
    [Fact]
    public async Task Razor_decline_is_CSRF_protected_clean_and_ends_session_after_truthful_confirmation()
    {
        var seed = await Seed(); await using var app = await App(seed); using var client = app.GetTestClient(); var cookies = new Dictionary<string,string>();
        using (var session = await client.GetAsync("/synthetic-session")) Cookies(session,cookies,client);
        var path = "/sign/" + seed.Envelope.PublicId;
        using var page = await client.GetAsync(path); Cookies(page,cookies,client); var html = await page.Content.ReadAsStringAsync();
        using (var bad = await client.PostAsync(path + "?handler=Decline",new FormUrlEncodedContent(new Dictionary<string,string>()))) Assert.Equal(HttpStatusCode.BadRequest,bad.StatusCode);
        using (var declined = await client.PostAsync(path + "?handler=Decline",Form(html,new() { ["Reason"] = "Synthetic only" })))
        { Assert.Equal(HttpStatusCode.Redirect,declined.StatusCode); Assert.Equal(path + "/declined",declined.Headers.Location!.OriginalString); }
        using var thanks = await client.GetAsync(path + "/declined"); Cookies(thanks,cookies,client);
        Assert.Contains("email delivery may be delayed or unavailable",await thanks.Content.ReadAsStringAsync());
        using var ended = await client.GetAsync(path); Assert.Equal(HttpStatusCode.Unauthorized,ended.StatusCode);
    }
    private async Task<WebApplication> App(SeedData seed,Blobs? blobs = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { ApplicationName = typeof(SignerConsent).Assembly.FullName,EnvironmentName = "Development",ContentRootPath = AppContext.BaseDirectory });
        builder.Logging.ClearProviders(); builder.WebHost.UseTestServer(); builder.Services.AddRazorPages();
        builder.Services.AddScoped(_ => fixture.Open()); builder.Services.AddSingleton<TimeProvider>(clock);
        builder.Services.AddQuillSignSender(new ConfigurationBuilder().Build(),builder.Environment);
        builder.Services.AddQuillSignSignerAccess(new ConfigurationBuilder().Build(),builder.Environment);
        builder.Services.AddQuillSignSignerConsent();
        builder.Services.AddSingleton(new EmailOptions());
        builder.Services.AddSingleton(new DocumentOptions()); builder.Services.AddSingleton<IBlobStore>(blobs ?? new Blobs(seed.Pdf));
        builder.Services.AddScoped<DeclineNotificationWriter>(); builder.Services.AddScoped<DeclinePayloadProtection>(); builder.Services.AddSingleton(new WorkOptions());
        builder.Services.AddScoped<Func<IWorkSignals>>(_ => () => throw new InvalidOperationException("disabled"));
        var app = builder.Build(); app.UseRouting(); app.UseRateLimiter(); app.UseAuthentication(); app.UseAuthorization(); app.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
        app.MapGet("/synthetic-session",async (Microsoft.AspNetCore.Http.HttpContext context) => { await context.SignInAsync(SignerAccessConfiguration.Scheme,seed.Principal,SignerAccessConfiguration.Ticket(seed.Identity)); return "ok"; });
        await app.StartAsync(); return app;
    }
    private static string Input(string html,string name) => WebUtility.HtmlDecode(Regex.Match(html,"<input[^>]*name=\"" + name + "\"[^>]*value=\"([^\"]*)\"").Groups[1].Value);
    private static FormUrlEncodedContent Form(string html,Dictionary<string,string> values) { values["__RequestVerificationToken"] = Input(html,"__RequestVerificationToken"); return new(values); }
    private static void Cookies(HttpResponseMessage response,Dictionary<string,string> cookies,HttpClient client)
    { if (response.Headers.TryGetValues("Set-Cookie",out var values)) foreach (var value in values) { var pair = value.Split(';')[0].Split('=',2); cookies[pair[0]] = pair[1]; } client.DefaultRequestHeaders.Remove("Cookie"); client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x => x.Key + "=" + x.Value))); }
    private async Task<SeedData> Seed()
    {
        var pdf = Pdf(); var envelope = new Envelope { SenderEmail = "sender@example.invalid",Title = "<b>Synthetic test - NO AGREEMENT</b>",Status = EnvelopeStatus.Sent,
            SenderVerifiedAt = clock.GetUtcNow(),SentAt = clock.GetUtcNow(),SentPdfBlob = Guid.NewGuid().ToString("N"),SentPdfSha256 = SHA256.HashData(pdf),ExpiresAt = clock.GetUtcNow().AddDays(2) };
        var disclosure = new ElectronicRecordDisclosure(ElectronicRecordDisclosureTests.Policy()).Build(envelope.PublicId,envelope.Title,envelope.SenderEmail);
        envelope.ErsdVersion = disclosure.Version; envelope.ErsdText = disclosure.Text; envelope.ErsdSha256 = disclosure.Sha256;
        var signer = new Signer { EnvelopeId = envelope.Id,FullName = "Synthetic signer",Email = "signer@example.invalid" };
        var invite = new SignerInvitationFactory(new(),clock).Create(envelope.Id,signer.Id,signer.Email,envelope.ExpiresAt,Guid.Parse(envelope.SentPdfBlob),envelope.SentPdfSha256,disclosure.Sha256);
        await using var db = fixture.Open(); db.AddRange(envelope,signer,invite.Record,new DocumentField { EnvelopeId = envelope.Id,Type = FieldType.Text,X = .1m,Y = .1m,Width = .2m,Height = .1m,Value = "unchanged" }); await db.SaveChangesAsync();
        var identity = new VerifiedSigner(envelope.Id,envelope.PublicId,signer.Id,signer.Email,Guid.Parse(envelope.SentPdfBlob),Convert.ToHexStringLower(envelope.SentPdfSha256),Convert.ToHexStringLower(disclosure.Sha256),clock.GetUtcNow().AddHours(2));
        return new(envelope,signer,invite,identity,SignerAccessConfiguration.Principal(identity),pdf);
    }
    private static byte[] Pdf() { using var pdf = new PdfDocument(); pdf.AddPage(); pdf.Info.Title = Guid.NewGuid().ToString(); using var memory = new MemoryStream(); pdf.Save(memory,false); return memory.ToArray(); }
    private sealed record SeedData(Envelope Envelope,Signer Signer,SignerInvitation Invitation,VerifiedSigner Identity,ClaimsPrincipal Principal,byte[] Pdf);
    private sealed class Clock : TimeProvider { private DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds()); public override DateTimeOffset GetUtcNow() => now; public void Advance(TimeSpan value) => now += value; }
    private sealed class Blobs(byte[] bytes) : IBlobStore
    {
        public byte[] Bytes = bytes; public bool Failure, Oversize;
        public async Task<long> CopyToAsync(ClaimsPrincipal principal,DocumentBlob blob,Stream output,CancellationToken ct = default)
        { EnvelopeStorageAuthorization.DemandRead(principal,blob); if (Failure) throw new IOException("Synthetic unavailable"); if (Oversize) output.SetLength(65 * 1024 * 1024); await output.WriteAsync(Bytes,ct); return Bytes.Length; }
        public Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,long l,CancellationToken ct = default) => throw new NotSupportedException();
        public Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct = default) => throw new NotSupportedException();
    }
    private sealed class RejectAudit : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> r,CancellationToken ct = default)
        { if (e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x => x.State == EntityState.Added)) throw new DbUpdateException("Synthetic audit failure"); return ValueTask.FromResult(r); }
    }
    private sealed class Signals : IWorkSignals
    {
        public int Hints,Published; public Func<Task>? OnPublish; public bool FailPublish;
        public Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct) { Hints++; return Task.CompletedTask; }
        public async Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct) { Published++; if (FailPublish) throw new IOException("Synthetic queue outage"); if (OnPublish is not null) await OnPublish(); }
        public Task RemoveHintAsync(Guid id,CancellationToken ct) => Task.CompletedTask;
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct) => Task.FromResult<WorkDelivery?>(null);
        public Task DeferAsync(WorkDelivery d,TimeSpan delay,CancellationToken ct) => Task.CompletedTask;
        public Task AcknowledgeAsync(WorkDelivery d,CancellationToken ct) => Task.CompletedTask;
        public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>Task.FromResult<DateTimeOffset?>(null);
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct) => Task.FromResult(0);
        public Task VerifyAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
