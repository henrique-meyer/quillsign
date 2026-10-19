using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotOperatorBrowserTests
{
    private const string Capability="1234567890123456789012345678901234567890123";
    [Fact]
    public void Anonymous_or_invalid_capability_entry_resolves_no_key_ring_and_never_authenticates()
    {
        var h=new Run();var http=Http();Assert.Null(h.Browser.Read(http));
        foreach(var value in new string?[]{null,"",new string('x',44),new string('a',43),new string('a',10000)})Assert.False(h.Browser.Unlock(http,value));
        Assert.Equal(0,h.KeyReads);Assert.False(http.Response.Headers.ContainsKey("Set-Cookie"));
        http.Request.Headers.Cookie="QuillSign.PilotOperator=forged";Assert.Null(h.Browser.Read(http));Assert.Equal(0,h.KeyReads);
    }
    [Theory]
    [InlineData("disabled")][InlineData("public")][InlineData("work")][InlineData("run")][InlineData("capability")][InlineData("mailboxes")]
    public void Existing_operator_cookie_does_not_restore_changed_or_closed_configuration(string change)
    {
        var h=new Run();var cookie=h.Login();var before=h.KeyReads;
        if(change=="disabled")h.Options.Enabled=false;
        if(change=="public")h.Email.Enabled=true;
        if(change=="work")h.Work.Enabled=false;
        if(change=="run")h.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="capability")h.Admission.CapabilitySha256=new string('a',64);
        if(change=="mailboxes")h.Options.Mailboxes=h.Options.Mailboxes with{Recipient="changed@example.invalid"};
        Assert.Null(h.Browser.Read(Http(cookie)));
        if(change is not ("run" or "mailboxes"))Assert.False(h.Browser.Unlock(Http(),Capability));
        if(change is "disabled" or "public" or "work")Assert.Equal(before,h.KeyReads);
    }
    [Fact]
    public void Protected_operator_cookie_is_private_fixed_purpose_and_not_serializable_capability_or_sender_authority()
    {
        var h=new Run();var http=Http();Assert.True(h.Browser.Unlock(http,Capability));var raw=http.Response.Headers.SetCookie.Single()!;
        Assert.Contains("httponly",raw,StringComparison.OrdinalIgnoreCase);Assert.Contains("samesite=strict",raw,StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/",raw,StringComparison.OrdinalIgnoreCase);Assert.DoesNotContain(Capability,raw);
        var session=Assert.IsType<EmailPilotOperatorSession>(h.Browser.Read(Http(raw.Split(';')[0])));
        Assert.Equal(Guid.ParseExact(h.Options.RunId,"N"),session.RunId);Assert.Equal(h.Clock.Now.AddHours(1),session.ExpiresAt);
        Assert.DoesNotContain(Capability,JsonSerializer.Serialize(session));Assert.DoesNotContain(Capability,session.ToString());
        h.Clock.Now+=TimeSpan.FromHours(1);Assert.Null(h.Browser.Read(Http(raw.Split(';')[0])));
    }
    [Theory]
    [InlineData(false,false)][InlineData(false,true)][InlineData(true,false)]
    public void Production_cookie_requires_HTTPS_and_uses_host_prefix_with_secure_flag(bool development,bool https)
    {
        var h=new Run(development);var http=Http(https:https);
        var expected=development||https;Assert.Equal(expected,h.Browser.Unlock(http,Capability));
        if(!expected){Assert.Equal(0,h.KeyReads);return;}
        var raw=http.Response.Headers.SetCookie.Single()!;
        if(!development){Assert.StartsWith("__Host-QuillSign.PilotOperator=",raw);Assert.Contains("secure",raw,StringComparison.OrdinalIgnoreCase);}
    }
    [Fact]
    public void Wrong_purpose_corrupt_cookie_and_notice_from_another_operator_nonce_are_rejected()
    {
        var h=new Run();var cookie=h.Login();var session=h.Browser.Read(Http(cookie))!;
        var http=Http();h.Browser.SetNotice(http,session,EmailPilotOperatorNotice.EnvelopeSaved);
        var notice=http.Response.Headers.SetCookie.Single()!.Split(';')[0];
        Assert.Null(h.Browser.Read(Http(notice.Replace(".Notice=","="))));
        Assert.Null(h.Browser.Read(Http(cookie[..^1]+(cookie[^1]=='a'?'b':'a'))));
        Assert.Equal(EmailPilotOperatorNotice.EnvelopeSaved,h.Browser.TakeNotice(Http(notice),session));
        var other=h.Browser.Read(Http(h.Login()))!;Assert.Null(h.Browser.TakeNotice(Http(notice),other));
        h.Clock.Now+=TimeSpan.FromMinutes(2);Assert.Null(h.Browser.TakeNotice(Http(notice),session));
    }
    private static DefaultHttpContext Http(string? cookie=null,bool https=false)
    {
        var http=new DefaultHttpContext();http.Request.Scheme=https?"https":"http";http.Request.Host=new("localhost");
        if(cookie is not null)http.Request.Headers.Cookie=cookie;return http;
    }
    private sealed class Run
    {
        internal readonly EmailPilotOptions Options=new(){Enabled=true,RunId=Guid.NewGuid().ToString("N"),Mailboxes=new("sender@example.invalid","first@example.invalid","second@example.invalid","recipient@example.invalid")};
        internal readonly EmailPilotAdmissionOptions Admission=new(){CapabilitySha256=Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(Capability)))};
        internal readonly EmailOptions Email=new();internal readonly WorkOptions Work=new(){Enabled=true};internal readonly Clock Clock=new();
        internal readonly EmailPilotOperatorBrowser Browser;internal int KeyReads;
        internal Run(bool development=true){var keys=new EphemeralDataProtectionProvider();Browser=new(Options,Admission,Email,Work,Clock,new Environment(development),()=>{KeyReads++;return keys;});}
        internal string Login(){var http=Http();Assert.True(Browser.Unlock(http,Capability));return http.Response.Headers.SetCookie.Single()!.Split(';')[0];}
    }
    private sealed class Clock:TimeProvider{internal DateTimeOffset Now=new(2026,10,18,10,0,0,TimeSpan.Zero);public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed class Environment(bool development):IHostEnvironment
    {public string EnvironmentName{get;set;}=development?"Development":"Production";public string ApplicationName{get;set;}="Synthetic";public string ContentRootPath{get;set;}="";public IFileProvider ContentRootFileProvider{get;set;}=new NullFileProvider();}
}
