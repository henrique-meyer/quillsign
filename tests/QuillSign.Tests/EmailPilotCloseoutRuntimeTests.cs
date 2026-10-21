using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotCloseoutBrowserTests
{
    private const string Capability="1234567890123456789012345678901234567890123";
    [Fact]
    public void Fixed_closeout_proof_is_private_new_purpose_and_cannot_renew_the_configured_deadline()
    {
        var h=new Harness();var http=Http();Assert.True(h.Browser.Unlock(http,Capability));var cookie=http.Response.Headers.SetCookie.Single()!;
        Assert.Contains("httponly",cookie,StringComparison.OrdinalIgnoreCase);Assert.Contains("samesite=strict",cookie,StringComparison.OrdinalIgnoreCase);
        var session=Assert.IsType<EmailPilotCloseoutOperatorSession>(h.Browser.Read(Http(cookie.Split(';')[0])));
        Assert.Equal(h.Options.Until,session.Until);Assert.DoesNotContain(Capability,JsonSerializer.Serialize(session));Assert.DoesNotContain(Capability,session.ToString());
        h.Clock.Now+=TimeSpan.FromMinutes(10);Assert.True(h.Browser.Unlock(Http(),Capability));Assert.Equal(h.Options.Until,h.Browser.Read(Http(cookie.Split(';')[0]))!.Until);
        h.Clock.Now=h.Options.Until;Assert.Null(h.Browser.Read(Http(cookie.Split(';')[0])));Assert.False(h.Browser.Unlock(Http(),Capability));
    }
    [Theory]
    [InlineData("disabled")][InlineData("public")][InlineData("work")][InlineData("identity")][InlineData("parent")][InlineData("deadline")]
    public void Original_session_does_not_restore_a_changed_configuration(string change)
    {
        var h=new Harness();var http=Http();Assert.True(h.Browser.Unlock(http,Capability));var cookie=http.Response.Headers.SetCookie.Single()!.Split(';')[0];
        if(change=="disabled")h.Options.Enabled=false;if(change=="public")h.Email.Enabled=true;if(change=="work")h.Work.Enabled=false;
        if(change=="identity")h.Options.AuthorizationId=Guid.NewGuid().ToString("N");if(change=="parent")h.Options.AccountingParentRunIds=[h.Options.AccountingParentRunIds[0],Guid.NewGuid().ToString("N")];
        if(change=="deadline")h.Options.Until-=TimeSpan.FromMinutes(1);Assert.Null(h.Browser.Read(Http(cookie)));
    }
    [Fact]
    public void Wrong_capability_or_nonlocal_cleartext_resolves_no_keys_and_old_operator_purpose_is_rejected()
    {
        var h=new Harness();Assert.False(h.Browser.Unlock(Http(),"wrong"));var remote=Http();remote.Request.Host=new("outside.invalid");Assert.False(h.Browser.Unlock(remote,Capability));Assert.Equal(0,h.Reads);
        var old=h.Keys.CreateProtector("QuillSign.PilotOperator.v1","session").Protect("{}");Assert.Null(h.Browser.Read(Http("QuillSign.PilotCloseoutOperator="+old)));
        var https=Http();https.Request.Scheme="https";Assert.True(h.Browser.Unlock(https,Capability));
    }
    [Fact]
    public void Notice_is_bound_to_this_new_operator_nonce_and_shorter_than_the_original_fixed_deadline()
    {
        var h=new Harness();EmailPilotCloseoutOperatorSession Login(){var c=Http();Assert.True(h.Browser.Unlock(c,Capability));return h.Browser.Read(Http(c.Response.Headers.SetCookie.Single()!.Split(';')[0]))!;}
        var session=Login();var notice=Http();h.Browser.SetNotice(notice,session,EmailPilotOperatorNotice.LookupSaved);var cookie=notice.Response.Headers.SetCookie.Single()!.Split(';')[0];
        Assert.Null(h.Browser.TakeNotice(Http(cookie),Login()));Assert.Equal(EmailPilotOperatorNotice.LookupSaved,h.Browser.TakeNotice(Http(cookie),session));
        h.Clock.Now+=TimeSpan.FromMinutes(2);Assert.Null(h.Browser.TakeNotice(Http(cookie),session));
    }
    [Fact]
    public void Null_closeout_payload_preserves_legacy_bytes_and_new_purpose_has_strict_canonical_shape()
    {
        var keys=new EphemeralDataProtectionProvider();var protection=new LookupDeliveryProtection(keys);var id=Guid.NewGuid();var now=DateTimeOffset.UtcNow;
        var old=new LookupMailPayload("lookup-mail-v1",id,"sender@example.invalid",new string('a',64),now,now.AddMinutes(15),null);
        Assert.DoesNotContain("CloseoutId",JsonSerializer.Serialize(old));var newer=old with {CloseoutId=Guid.NewGuid()};
        var row=new EmailOutbox{Id=id,To=old.Email,Template=LookupDeliveryProtection.Template,AvailableAt=now,PayloadJson=protection.Protect(newer)};
        Assert.Equal(newer,protection.Read(row));
        var clear=JsonSerializer.Serialize(newer);var future=clear[..^1]+",\"future\":true}";
        row.PayloadJson=JsonSerializer.Serialize(new ProtectedWorkPayload(keys.CreateProtector("QuillSign.LookupDelivery.Payload.v1").Protect(future)));
        Assert.Throws<InvalidDataException>(()=>protection.Read(row));
    }
    private static DefaultHttpContext Http(string? cookie=null)
    {var h=new DefaultHttpContext();h.Request.Scheme="http";h.Request.Host=new("localhost");if(cookie is not null)h.Request.Headers.Cookie=cookie;return h;}
    internal sealed class Harness
    {
        internal readonly Clock Clock=new();internal readonly EmailOptions Email=new();internal readonly WorkOptions Work=new(){Enabled=true};
        internal readonly IDataProtectionProvider Keys=new EphemeralDataProtectionProvider();internal readonly EmailPilotCloseoutOptions Options;internal readonly EmailPilotCloseoutOperatorBrowser Browser;internal int Reads;
        internal Harness(){var first=Guid.NewGuid().ToString("N");var second=Guid.NewGuid().ToString("N");Options=new(){Enabled=true,AuthorizationId=Guid.NewGuid().ToString("N"),CapabilitySha256=Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(Capability))),StartsAt=Clock.Now,Until=Clock.Now.AddMinutes(30),AccountingParentRunIds=[first,second],CompletionParentRunId=first,VoidParentRunId=second,CompletionRecordId=Guid.NewGuid().ToString("N"),VoidRecordId=Guid.NewGuid().ToString("N"),DeclineRecordId=Guid.NewGuid().ToString("N"),CompletionWorkIds=Enumerable.Range(0,4).Select(_=>Guid.NewGuid().ToString("N")).ToArray(),VoidWorkIds=Enumerable.Range(0,2).Select(_=>Guid.NewGuid().ToString("N")).ToArray()};
            Browser=new(Options,Email,Work,Clock,new Environment(),()=>{Reads++;return Keys;});}
    }
    internal sealed class Clock:TimeProvider{internal DateTimeOffset Now=new(2026,10,21,10,0,0,TimeSpan.Zero);public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed class Environment:IHostEnvironment
    {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Synthetic";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}

public sealed class EmailPilotCloseoutPageTests
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task New_private_page_requires_body_capability_and_CSRF_without_resolving_a_backend(bool enabled)
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();h.Options.Enabled=enabled;
        var builder=Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder(new Microsoft.AspNetCore.Builder.WebApplicationOptions
            {ApplicationName=typeof(EmailPilotOptions).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();
        builder.WebHost.UseTestServer();
        builder.Host.UseDefaultServiceProvider(o=>{o.ValidateScopes=true;o.ValidateOnBuild=false;});
        builder.Services.AddRazorPages();builder.Services.AddSingleton(h.Options);builder.Services.AddSingleton(h.Email);builder.Services.AddSingleton(h.Work);
        builder.Services.AddSingleton<TimeProvider>(h.Clock);builder.Services.AddSingleton(h.Browser);
        var resolutions=0;builder.Services.AddScoped<Func<EmailPilotCloseoutOperator>>(_=>()=>{resolutions++;throw new InvalidOperationException("No backend for this boundary host.");});
        await using var app=builder.Build();app.UseRouting();app.MapRazorPages();await app.StartAsync();using var client=app.GetTestClient();client.BaseAddress=new("http://localhost");
        const string path="/operator/pilot-closeout";using var page=await client.GetAsync(path+"?Capability=must-not-echo");
        Assert.Equal(enabled?System.Net.HttpStatusCode.OK:System.Net.HttpStatusCode.NotFound,page.StatusCode);
        Assert.Contains("no-store",page.Headers.CacheControl?.ToString());Assert.Contains("noindex",Assert.Single(page.Headers.GetValues("X-Robots-Tag")));
        var html=await page.Content.ReadAsStringAsync();Assert.DoesNotContain("must-not-echo",html);Assert.DoesNotContain("googletagmanager",html);Assert.DoesNotContain("rel=\"canonical\"",html);
        if(enabled) {
            var csrf=System.Text.RegularExpressions.Regex.Match(html,"name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;Assert.NotEmpty(csrf);
            var cookies=page.Headers.GetValues("Set-Cookie").Select(x=>x.Split(';')[0]);client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies));
            using var inert=await client.PostAsync(path+"?handler=Verification",new FormUrlEncodedContent(new Dictionary<string,string>{{"__RequestVerificationToken",csrf}}));Assert.Equal(System.Net.HttpStatusCode.Forbidden,inert.StatusCode);
            using var noCsrf=await client.PostAsync(path+"?handler=Unlock",new FormUrlEncodedContent(new Dictionary<string,string>{{"Capability","1234567890123456789012345678901234567890123"}}));Assert.Equal(System.Net.HttpStatusCode.BadRequest,noCsrf.StatusCode);
            using var unlock=await client.PostAsync(path+"?handler=Unlock",new FormUrlEncodedContent(new Dictionary<string,string>{{"__RequestVerificationToken",csrf},{"Capability","1234567890123456789012345678901234567890123"}}));
            Assert.Equal(System.Net.HttpStatusCode.Redirect,unlock.StatusCode);Assert.Equal(path,unlock.Headers.Location?.OriginalString);
        }
        Assert.Equal(0,resolutions);
    }
}

public sealed class EmailPilotCloseoutTokenTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Durable_closeout_marker_cannot_downgrade_to_ordinary_lookup_when_the_new_backend_is_absent(bool marker)
    {
        await using var db=fixture.Open();var keys=new EphemeralDataProtectionProvider();var clock=TimeProvider.System;var links=new DocumentLookupProtection(keys,clock);
        var now=clock.GetUtcNow();var raw=Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var token=new AuthToken{Purpose=TokenPurpose.Lookup,PartyType=PartyType.System,PartyId=marker?Guid.NewGuid():null,Email="",ExpiresAt=now.AddMinutes(15),TokenSha256=SHA256.HashData(Encoding.UTF8.GetBytes(raw))};
        db.AuthTokens.Add(token);await db.SaveChangesAsync();db.ChangeTracker.Clear();
        var transport=links.Link(new LookupIssuance(token.Id,Convert.ToBase64String(token.RowVersion),raw,"sender@example.invalid",now,token.ExpiresAt));
        var lookup=new DocumentLookup(db,null!,links,new(),clock);var result=await lookup.RedeemAsync(transport);
        if(marker){Assert.Null(result);Assert.Null((await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==token.Id)).UsedAt);}
        else Assert.NotNull(result);
    }
}
