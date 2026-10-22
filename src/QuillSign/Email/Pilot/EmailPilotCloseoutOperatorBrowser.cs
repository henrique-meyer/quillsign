using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Email.Pilot;

// This proof has a new purpose, cookie and fixed configured deadline. An old
// pilot operator cookie is never closeout, mailbox, sender or signing authority.
public sealed class EmailPilotCloseoutOperatorSession
{
    internal EmailPilotCloseoutOperatorSession(Guid id,string capability,Guid nonce,string configuration,DateTimeOffset until)
    {AuthorizationId=id;Capability=capability;Nonce=nonce;Configuration=configuration;Until=until;}
    public Guid AuthorizationId {get;}
    public DateTimeOffset Until {get;}
    internal string Capability {get;}
    internal Guid Nonce {get;}
    internal string Configuration {get;}
    public override string ToString()=>"Restricted closeout operator session";
}

public sealed class EmailPilotCloseoutOperatorBrowser(EmailPilotCloseoutOptions options,EmailOptions email,Work.WorkOptions work,
    TimeProvider time,IHostEnvironment environment,Func<IDataProtectionProvider> keys,EmailPilotOptions? pilot=null)
{
    private sealed record Proof(string Version,Guid Id,string Capability,Guid Nonce,string Configuration,DateTimeOffset IssuedAt,DateTimeOffset Until);
    private sealed record Notice(Guid Id,Guid Nonce,EmailPilotOperatorNotice Code,DateTimeOffset Until);
    private const string Version="closeout-operator-v1";
    public const string Path="/operator/pilot-closeout";
    private string Cookie=>environment.IsDevelopment()?"QuillSign.PilotCloseoutOperator":"__Host-QuillSign.PilotCloseoutOperator";
    private IDataProtector Protector(string purpose)=>keys().CreateProtector("QuillSign.PilotCloseoutOperator.v1",purpose);
    private CookieOptions Cookies(DateTimeOffset? until=null)=>new(){HttpOnly=true,Secure=!environment.IsDevelopment(),SameSite=SameSiteMode.Strict,Path="/",IsEssential=true,Expires=until};
    private EmailPilotCloseoutConfiguration? Configuration()
    {
        if(email.Enabled || !work.Enabled)return null;
        try {var c=options.Capture();return c.StartsAt<=time.GetUtcNow() && c.Until>time.GetUtcNow()?c:null;}
        catch(InvalidOperationException){return null;}
    }
    public bool Available=>Configuration() is not null;
    private static string Digest(EmailPilotCloseoutConfiguration c)=>Convert.ToHexStringLower(EmailPilotCanonical.Hash(c));
    private static bool Capability(string? value,string hash)
    {try{return value is not null && CryptographicOperations.FixedTimeEquals(EmailPilotCanonical.Capability(value),Convert.FromHexString(hash));}catch(ArgumentException){return false;}}
    internal bool Live(EmailPilotCloseoutOperatorSession s)=>Configuration() is {} c && s.AuthorizationId==c.AuthorizationId &&
        s.Until==c.Until && s.Until>time.GetUtcNow() && s.Configuration==Digest(c) && Capability(s.Capability,c.CapabilitySha256);
    public bool Unlock(HttpContext http,string? capability)
    {
        EmailPilotOperatorBrowser.PrivateHeaders(http);
        if(Configuration() is not {} c || !Capability(capability,c.CapabilitySha256) ||
            !http.Request.IsHttps && !(environment.IsDevelopment() && Uri.TryCreate("http://"+http.Request.Host,UriKind.Absolute,out var local) && local.IsLoopback))return false;
        var now=time.GetUtcNow();var p=new Proof(Version,c.AuthorizationId,capability!,Guid.NewGuid(),Digest(c),now,c.Until);
        var raw=Protector("session").Protect(JsonSerializer.Serialize(p));
        var s=new EmailPilotCloseoutOperatorSession(p.Id,p.Capability,p.Nonce,p.Configuration,p.Until);
        if(!Live(s))return false;http.Response.Cookies.Append(Cookie,raw,Cookies(p.Until));return true;
    }
    public EmailPilotCloseoutOperatorSession? Read(HttpContext http)
        => ReadCore(http,false);
    internal EmailPilotCloseoutOperatorSession? ReadReceipt(HttpContext http)
        => ReadCore(http,true);
    internal bool LiveReceipt(EmailPilotCloseoutOperatorSession s)
    {
        var c=ReceiptConfiguration();return c is not null && s.AuthorizationId==c.AuthorizationId && s.Until==c.Until &&
            s.Until>time.GetUtcNow() && s.Configuration==Digest(c) && Capability(s.Capability,c.CapabilitySha256);
    }
    private EmailPilotCloseoutConfiguration? ReceiptConfiguration()
    {
        if(email.Enabled||!work.Enabled||pilot is not {Enabled:false}||time.GetUtcNow().Offset!=TimeSpan.Zero)return null;
        try {var c=options.CaptureReceiptConfiguration();return c.StartsAt<=time.GetUtcNow()&&c.Until>time.GetUtcNow()?c:null;}
        catch(InvalidOperationException){return null;}
    }
    private EmailPilotCloseoutOperatorSession? ReadCore(HttpContext http,bool receipt)
    {
        if((receipt?ReceiptConfiguration() is null:!Available) || !http.Request.Cookies.TryGetValue(Cookie,out var raw) || raw.Length is <32 or >4096)return null;
        try {
            var json=Protector("session").Unprotect(raw);var p=JsonSerializer.Deserialize<Proof>(json);var now=time.GetUtcNow();
            if(p is null || JsonSerializer.Serialize(p)!=json || p.Version!=Version || p.Nonce==Guid.Empty || p.IssuedAt.Offset!=TimeSpan.Zero ||
                p.Until.Offset!=TimeSpan.Zero || p.IssuedAt>now || p.IssuedAt>=p.Until || p.Until>p.IssuedAt.AddMinutes(30))return null;
            var s=new EmailPilotCloseoutOperatorSession(p.Id,p.Capability,p.Nonce,p.Configuration,p.Until);return (receipt?LiveReceipt(s):Live(s))?s:null;
        }catch(Exception e)when(e is CryptographicException or JsonException or ArgumentException){return null;}
    }
    public void SetNotice(HttpContext http,EmailPilotCloseoutOperatorSession s,EmailPilotOperatorNotice code)
    {
        if(!Live(s) || !Enum.IsDefined(code))return;var until=new[]{time.GetUtcNow().AddMinutes(2),s.Until}.Min();
        var raw=Protector("notice").Protect(JsonSerializer.Serialize(new Notice(s.AuthorizationId,s.Nonce,code,until)));
        if(Live(s))http.Response.Cookies.Append(Cookie+".Notice",raw,Cookies(until));
    }
    public EmailPilotOperatorNotice? TakeNotice(HttpContext http,EmailPilotCloseoutOperatorSession s)
    {
        if(!http.Request.Cookies.TryGetValue(Cookie+".Notice",out var raw))return null;http.Response.Cookies.Delete(Cookie+".Notice",Cookies());
        if(!Live(s) || raw.Length is <32 or >4096)return null;
        try {var json=Protector("notice").Unprotect(raw);var n=JsonSerializer.Deserialize<Notice>(json);
            return n is not null && JsonSerializer.Serialize(n)==json && n.Id==s.AuthorizationId && n.Nonce==s.Nonce && Enum.IsDefined(n.Code) &&
                n.Until>time.GetUtcNow() && n.Until<=s.Until && n.Until<=time.GetUtcNow().AddMinutes(2)?n.Code:null;
        }catch(Exception e)when(e is CryptographicException or JsonException or ArgumentException){return null;}
    }
    public void Lock(HttpContext http)
    {http.Response.Cookies.Delete(Cookie,Cookies());http.Response.Cookies.Delete(Cookie+".Notice",Cookies());}
}
