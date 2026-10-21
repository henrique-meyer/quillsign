using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Lifecycle;

namespace QuillSign.Operator;

internal sealed record OperatorSelection(Guid RecordId,string Session,DateTimeOffset Until);
internal sealed record OperatorConfirmation(ProductionHoldCommand Command,string? WitnessHead,string Session,string Issuer,string Subject,DateTimeOffset Until);
internal sealed record OperatorDeletionConfirmation(string Version,Guid RecordId,Guid DeletionId,Guid AuthorizationId,long Sequence,string WitnessHead,
    Guid PublicationId,string PublicationSha256,string FinalReceiptsSha256,string Commitment,string Purpose,string Session,string Issuer,string Subject,
    DateTimeOffset CreatedAt,DateTimeOffset TicketIssuedAt,DateTimeOffset TicketExpiresAt,DateTimeOffset Until);
public sealed class ProductionOperatorBrowser(ProductionOperatorOptions options,IDataProtectionProvider keys,TimeProvider time)
{
    private const string SelectionCookie="__Host-QuillSign.Operator.Record";
    private const string DeletionConfirmationVersion="production-operator-deletion-confirmation-v1";
    private static readonly JsonSerializerOptions DeletionJson=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=4};
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
    internal string ConfirmDeletion(AuthenticationTicket ticket,Guid recordId,Guid deletionId,long sequence,string head,
        ProductionDeletionCompletedFacts facts,string commitment,string purpose)
    {
        if(ticket.Properties.IssuedUtc is not{} issued||ticket.Properties.ExpiresUtc is not{} end)throw ProductionOperatorAuthority.Denied();
        var now=time.GetUtcNow();var until=now.AddMinutes(2);if(end<until)until=end;
        var value=new OperatorDeletionConfirmation(DeletionConfirmationVersion,recordId,deletionId,Guid.NewGuid(),sequence,head,facts.PublicationId,
            facts.PublicationSha256,facts.FinalReceiptsSha256,commitment,purpose,Session(ticket),ticket.Principal.FindFirst("iss")!.Value,ticket.Principal.FindFirst("sub")!.Value,now,issued,end,until);
        DemandDeletion(ticket,value);var raw=keys.CreateProtector(DeletionConfirmationVersion).Protect(JsonSerializer.Serialize(value,DeletionJson));
        return raw.Length<=16384?raw:throw ProductionOperatorAuthority.Denied();
    }
    internal OperatorDeletionConfirmation OpenDeletion(AuthenticationTicket ticket,string raw)
    {
        try
        {
            if(string.IsNullOrEmpty(raw)||raw.Length>16384)throw ProductionOperatorAuthority.Denied();
            var json=keys.CreateProtector(DeletionConfirmationVersion).Unprotect(raw);if(json.Length>12288)throw ProductionOperatorAuthority.Denied();
            var value=JsonSerializer.Deserialize<OperatorDeletionConfirmation>(json,DeletionJson)??throw ProductionOperatorAuthority.Denied();
            if(JsonSerializer.Serialize(value,DeletionJson)!=json)throw ProductionOperatorAuthority.Denied();DemandDeletion(ticket,value);return value;
        }
        catch(Exception e)when(e is System.Security.Cryptography.CryptographicException or JsonException or ArgumentException){throw ProductionOperatorAuthority.Denied();}
    }
    private void DemandDeletion(AuthenticationTicket ticket,OperatorDeletionConfirmation value)
    {
        var now=time.GetUtcNow();static bool Hash(string s)=>s is {Length:64}&&s.All(char.IsAsciiHexDigitLower);
        if(value.Version!=DeletionConfirmationVersion||value.RecordId==Guid.Empty||value.DeletionId==Guid.Empty||value.AuthorizationId==Guid.Empty||value.Sequence<1||
            value.PublicationId==Guid.Empty||!Hash(value.WitnessHead)||!Hash(value.PublicationSha256)||!Hash(value.FinalReceiptsSha256)||
            !ProductionOperatorAuthority.Text(value.Commitment,2048)||!ProductionOperatorAuthority.Text(value.Purpose,256)||
            !Guid.TryParseExact(value.Session,"N",out var sessionId)||sessionId==Guid.Empty||!ProductionOperatorAuthority.Text(value.Issuer,2048)||!ProductionOperatorAuthority.Text(value.Subject,256)||
            value.Session!=Session(ticket)||value.Issuer!=ticket.Principal.FindFirst("iss")?.Value||value.Subject!=ticket.Principal.FindFirst("sub")?.Value||
            ticket.Properties.IssuedUtc!=value.TicketIssuedAt||ticket.Properties.ExpiresUtc!=value.TicketExpiresAt||
            value.CreatedAt.Offset!=TimeSpan.Zero||value.TicketIssuedAt.Offset!=TimeSpan.Zero||value.TicketExpiresAt.Offset!=TimeSpan.Zero||value.Until.Offset!=TimeSpan.Zero||
            value.TicketIssuedAt>value.CreatedAt||value.CreatedAt>now||value.TicketExpiresAt<=value.TicketIssuedAt||value.Until<=now||value.Until<=value.CreatedAt||
            value.Until>value.CreatedAt.AddMinutes(2)||value.Until>value.TicketExpiresAt)throw ProductionOperatorAuthority.Denied();
    }
    public bool Enabled=>options.Enabled;
    public void Clear(HttpContext context)=>context.Response.Cookies.Delete(SelectionCookie,new(){Path="/",Secure=true,HttpOnly=true,SameSite=SameSiteMode.Strict});
}
