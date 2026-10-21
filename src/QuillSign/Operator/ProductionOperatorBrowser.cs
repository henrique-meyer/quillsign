using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Lifecycle;

namespace QuillSign.Operator;

internal sealed record OperatorSelection(Guid RecordId,string Session,DateTimeOffset Until);
internal sealed record OperatorConfirmation(ProductionHoldCommand Command,string? WitnessHead,string Session,string Issuer,string Subject,DateTimeOffset Until);
public sealed class ProductionOperatorBrowser(ProductionOperatorOptions options,IDataProtectionProvider keys,TimeProvider time)
{
    private const string SelectionCookie="__Host-QuillSign.Operator.Record";
    internal async Task<(AuthenticationTicket Ticket,ProductionOperatorAuthority Authority)> RequireAsync(HttpContext context,ProductionOperatorPermission permission)
    {
        if(!options.Enabled)throw ProductionOperatorAuthority.Denied();var result=await context.AuthenticateAsync(ProductionOperatorAuthority.CookieScheme);
        if(!result.Succeeded||result.Ticket is null)throw ProductionOperatorAuthority.Denied();
        ProductionOperatorAuthentication.DemandPrincipal(result.Principal!,options);
        return(result.Ticket,ProductionOperatorAuthority.FromValidatedTicket(result.Ticket,options.Policy(),permission,time));
    }
    internal static string Session(AuthenticationTicket ticket)=>ticket.Principal.FindFirst(ProductionOperatorAuthentication.SessionClaim)?.Value??throw ProductionOperatorAuthority.Denied();
    internal void Select(HttpContext context,AuthenticationTicket ticket,Guid id)
    {
        if(id==Guid.Empty)throw ProductionOperatorAuthority.Denied();var until=ticket.Properties.ExpiresUtc??throw ProductionOperatorAuthority.Denied();
        context.Response.Cookies.Append(SelectionCookie,keys.CreateProtector("production-operator-selection-v1").Protect(JsonSerializer.Serialize(new OperatorSelection(id,Session(ticket),until))),
            new(){Path="/",HttpOnly=true,Secure=true,SameSite=SameSiteMode.Strict,Expires=until,IsEssential=true});
    }
    internal Guid Selected(HttpContext context,AuthenticationTicket ticket)
    {
        try {var raw=context.Request.Cookies[SelectionCookie];if(raw is null||raw.Length>4096)throw ProductionOperatorAuthority.Denied();
            var value=JsonSerializer.Deserialize<OperatorSelection>(keys.CreateProtector("production-operator-selection-v1").Unprotect(raw))??throw ProductionOperatorAuthority.Denied();
            if(value.Session!=Session(ticket)||value.RecordId==Guid.Empty||value.Until<=time.GetUtcNow()||value.Until>ticket.Properties.ExpiresUtc)throw ProductionOperatorAuthority.Denied();return value.RecordId;
        }catch(Exception e)when(e is System.Security.Cryptography.CryptographicException or JsonException){throw ProductionOperatorAuthority.Denied();}
    }
    internal string Confirm(AuthenticationTicket ticket,ProductionHoldCommand command,string? head)
    {
        _=command.Digest();var until=time.GetUtcNow().AddMinutes(2);if(ticket.Properties.ExpiresUtc is not{} end)throw ProductionOperatorAuthority.Denied();if(end<until)until=end;
        return keys.CreateProtector("production-operator-confirmation-v1").Protect(JsonSerializer.Serialize(new OperatorConfirmation(command,head,Session(ticket),
            ticket.Principal.FindFirst("iss")!.Value,ticket.Principal.FindFirst("sub")!.Value,until)));
    }
    internal OperatorConfirmation Open(AuthenticationTicket ticket,string raw)
    {
        try {if(raw.Length>16384)throw ProductionOperatorAuthority.Denied();var value=JsonSerializer.Deserialize<OperatorConfirmation>(keys.CreateProtector("production-operator-confirmation-v1").Unprotect(raw))??throw ProductionOperatorAuthority.Denied();
            _=value.Command.Digest();if(value.Session!=Session(ticket)||value.Issuer!=ticket.Principal.FindFirst("iss")?.Value||value.Subject!=ticket.Principal.FindFirst("sub")?.Value||
                value.Until<=time.GetUtcNow()||value.Until>ticket.Properties.ExpiresUtc)throw ProductionOperatorAuthority.Denied();return value;
        }catch(Exception e)when(e is System.Security.Cryptography.CryptographicException or JsonException){throw ProductionOperatorAuthority.Denied();}
    }
    public bool Enabled=>options.Enabled;
    public void Clear(HttpContext context)=>context.Response.Cookies.Delete(SelectionCookie,new(){Path="/",Secure=true,HttpOnly=true,SameSite=SameSiteMode.Strict});
}
