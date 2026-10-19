using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Email.Pilot;

// Opaque operator state, never sender/signing authority or a serializable secret.
public sealed class EmailPilotOperatorSession
{
    internal EmailPilotOperatorSession(Guid runId,string capability,Guid nonce,DateTimeOffset expiresAt,string configurationSha256)
    {RunId=runId;Capability=capability;Nonce=nonce;ExpiresAt=expiresAt;ConfigurationSha256=configurationSha256;}
    public Guid RunId {get;}
    public DateTimeOffset ExpiresAt {get;}
    internal string Capability {get;}
    internal Guid Nonce {get;}
    internal string ConfigurationSha256 {get;}
    public override string ToString()=>"Restricted pilot operator session";
}
public enum EmailPilotOperatorNotice { EnvelopeSaved, LookupSaved, SimulatorSaved, WakePending, Unavailable }

public sealed class EmailPilotOperatorBrowser(EmailPilotOptions options,EmailPilotAdmissionOptions admission,EmailOptions email,
    Work.WorkOptions work,TimeProvider time,IHostEnvironment environment,Func<IDataProtectionProvider> keys)
{
    private sealed record Proof(string Version,Guid RunId,string Capability,Guid Nonce,string ConfigurationSha256,DateTimeOffset IssuedAt,DateTimeOffset ExpiresAt);
    private sealed record Notice(Guid RunId,Guid Nonce,EmailPilotOperatorNotice Code,DateTimeOffset ExpiresAt);
    private const string Version="pilot-operator-v1";
    public const string Path="/operator/pilot";
    public bool Available=>options.Enabled && !email.Enabled && work.Enabled && Guid.TryParseExact(options.RunId,"N",out var id) &&
        id!=Guid.Empty && options.Mailboxes?.Valid()==true && EmailPilotCanonical.Hash(admission.CapabilitySha256);
    private string Cookie=>environment.IsDevelopment()?"QuillSign.PilotOperator":"__Host-QuillSign.PilotOperator";
    private string NoticeCookie=>Cookie+".Notice";
    private IDataProtector Protector(string purpose)=>keys().CreateProtector("QuillSign.PilotOperator.v1",purpose);
    private CookieOptions CookieOptions(DateTimeOffset? until=null)=>new(){HttpOnly=true,Secure=!environment.IsDevelopment(),SameSite=SameSiteMode.Strict,
        Path="/",IsEssential=true,Expires=until};
    public static void PrivateHeaders(HttpContext http)
    {http.Response.Headers.CacheControl="no-store";http.Response.Headers["Referrer-Policy"]="no-referrer";http.Response.Headers["X-Robots-Tag"]="noindex, nofollow, noarchive";}
    private string ConfigurationSha256()=>Convert.ToHexStringLower(EmailPilotCanonical.Hash(new{options.RunId,options.Mailboxes,admission.CapabilitySha256}));
    internal bool Live(EmailPilotOperatorSession session)=>Available && session.RunId.ToString("N")==options.RunId && session.ExpiresAt>time.GetUtcNow() &&
        EmailPilotSimulator.Capability(session.Capability,admission) && session.ConfigurationSha256==ConfigurationSha256();
    public bool Unlock(HttpContext http,string? capability)
    {
        PrivateHeaders(http);
        if(!Available || capability is null || !EmailPilotSimulator.Capability(capability,admission) ||
            !http.Request.IsHttps && !(environment.IsDevelopment() && Uri.TryCreate("http://"+http.Request.Host,UriKind.Absolute,out var local) && local.IsLoopback))return false;
        var now=time.GetUtcNow();var proof=new Proof(Version,Guid.ParseExact(options.RunId,"N"),capability,Guid.NewGuid(),ConfigurationSha256(),now,now.AddHours(1));
        var encoded=Protector("session").Protect(JsonSerializer.Serialize(proof));
        if(!Available || !EmailPilotSimulator.Capability(capability,admission))return false;
        http.Response.Cookies.Append(Cookie,encoded,CookieOptions(proof.ExpiresAt));return true;
    }
    public EmailPilotOperatorSession? Read(HttpContext http)
    {
        if(!Available || !http.Request.Cookies.TryGetValue(Cookie,out var raw) || raw.Length is <32 or >4096)return null;
        try {
            var proof=JsonSerializer.Deserialize<Proof>(Protector("session").Unprotect(raw));var now=time.GetUtcNow();
            if(proof is null || proof.Version!=Version || proof.Nonce==Guid.Empty || proof.IssuedAt.Offset!=TimeSpan.Zero || proof.ExpiresAt.Offset!=TimeSpan.Zero ||
                proof.IssuedAt>now || proof.ExpiresAt<=now || proof.ExpiresAt<=proof.IssuedAt || proof.ExpiresAt>proof.IssuedAt.AddHours(1))return null;
            var result=new EmailPilotOperatorSession(proof.RunId,proof.Capability,proof.Nonce,proof.ExpiresAt,proof.ConfigurationSha256);return Live(result)?result:null;
        } catch(Exception e)when(e is CryptographicException or JsonException or ArgumentException){return null;}
    }
    public void SetNotice(HttpContext http,EmailPilotOperatorSession session,EmailPilotOperatorNotice code)
    {
        if(!Live(session) || !Enum.IsDefined(code))return;
        var until=new[]{time.GetUtcNow().AddMinutes(2),session.ExpiresAt}.Min();
        var raw=Protector("notice").Protect(JsonSerializer.Serialize(new Notice(session.RunId,session.Nonce,code,until)));
        if(Live(session))http.Response.Cookies.Append(NoticeCookie,raw,CookieOptions(until));
    }
    public EmailPilotOperatorNotice? TakeNotice(HttpContext http,EmailPilotOperatorSession session)
    {
        if(!http.Request.Cookies.TryGetValue(NoticeCookie,out var raw))return null;
        http.Response.Cookies.Delete(NoticeCookie,CookieOptions());
        if(!Live(session) || raw.Length is <32 or >4096)return null;
        try {
            var value=JsonSerializer.Deserialize<Notice>(Protector("notice").Unprotect(raw));
            return value is not null && value.RunId==session.RunId && value.Nonce==session.Nonce && Enum.IsDefined(value.Code) &&
                value.ExpiresAt>time.GetUtcNow() && value.ExpiresAt<=session.ExpiresAt && value.ExpiresAt<=time.GetUtcNow().AddMinutes(2)?value.Code:null;
        }catch(Exception e)when(e is CryptographicException or JsonException or ArgumentException){return null;}
    }
    public void Lock(HttpContext http)
    {http.Response.Cookies.Delete(Cookie,CookieOptions());http.Response.Cookies.Delete(NoticeCookie,CookieOptions());}
}
