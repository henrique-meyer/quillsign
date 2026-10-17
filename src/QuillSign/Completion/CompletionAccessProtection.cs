using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Data;
using QuillSign.Email;

namespace QuillSign.Completion;

public sealed class CompletionAccessOptions
{
    public int LinkHours {get;set;}=24;
    public int SessionHours {get;set;}=1;
    internal void Validate() {
        if(LinkHours is <1 or >168 || SessionHours is <1 or >24)throw new InvalidOperationException("Configure bounded completion link and readonly session lifetimes.");
    }
}

public sealed record CompletionReaderIdentity(Guid TokenId,string TokenRevision,Guid EnvelopeId,string PublicId,PartyType Party,Guid? PartyId,string Email,
    Guid PublicationId,string RecipeSha256,string PartySha256,Guid SessionId,DateTimeOffset RedeemedAt,DateTimeOffset ExpiresAt);
public sealed record CompletionReaderSession(CompletionReaderIdentity Identity,string Receipt);
public sealed record CompletionAccessLink(Guid TokenId,string RawToken,DateTimeOffset ExpiresAt);

// Internal authentication primitive for the later readonly HTTP flow. Neither the
// principal nor its protected receipt can be used as sender/signer edit authority.
public sealed class CompletionAccessProtection(IDataProtectionProvider provider,TimeProvider time)
{
    public const string Version="completion-access-v1",Scheme="QuillSign.CompletionReader";
    private sealed record Payload(string Version,string Scheme,CompletionReaderIdentity Identity);
    private readonly IDataProtector protector=provider.CreateProtector("QuillSign.CompletionReader.Session.v1");
    internal string Protect(CompletionReaderIdentity identity) {
        if(!Valid(identity))throw new InvalidDataException("Invalid readonly completion identity.");
        var value=protector.Protect(JsonSerializer.Serialize(new Payload(Version,Scheme,identity)));
        return value.Length<=3800 ? value : throw new InvalidDataException("Readonly completion session exceeds its bound.");
    }
    internal CompletionReaderIdentity? Read(string? value) {
        if(value is not {Length:>0 and <=3800})return null;
        try {
            var payload=JsonSerializer.Deserialize<Payload>(protector.Unprotect(value));
            return payload?.Version==Version && payload.Scheme==Scheme && Valid(payload.Identity) ? payload.Identity : null;
        } catch(Exception e) when(e is CryptographicException or JsonException or ArgumentException) {return null;}
    }
    private bool Valid(CompletionReaderIdentity? i) {
        if(i is null || i.TokenId==Guid.Empty || i.EnvelopeId==Guid.Empty || i.PublicationId==Guid.Empty || i.SessionId==Guid.Empty ||
            !Guid.TryParseExact(i.PublicId,"N",out var publicId) || publicId==Guid.Empty ||
            (i.Party==PartyType.Sender ? i.PartyId is not null : i.Party is not (PartyType.Signer or PartyType.Recipient) || i.PartyId is null || i.PartyId==Guid.Empty) ||
            !Hash(i.RecipeSha256) || !Hash(i.PartySha256) || i.Email is not {Length:>0 and <=320} || i.RedeemedAt>time.GetUtcNow() ||
            i.ExpiresAt<=time.GetUtcNow() || i.ExpiresAt<=i.RedeemedAt || i.ExpiresAt>i.RedeemedAt.AddHours(24))return false;
        try {return EmailAddress.Normalize(i.Email)==i.Email && Convert.FromBase64String(i.TokenRevision) is {Length:8} bytes && Convert.ToBase64String(bytes)==i.TokenRevision;}
        catch(ArgumentException) {return false;} catch(FormatException) {return false;}
    }
    private static bool Hash(string? value)=>value is {Length:64} && value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static ClaimsPrincipal Principal(CompletionReaderIdentity i)=>new(new ClaimsIdentity([
        new("quillsign:completion-token",i.TokenId.ToString("N")),new("quillsign:completion-envelope",i.EnvelopeId.ToString("N")),
        new("quillsign:completion-public-id",i.PublicId),new("quillsign:completion-session",i.SessionId.ToString("N")),
        new("quillsign:completion-publication",i.PublicationId.ToString("N")),new(ClaimTypes.Email,i.Email),
        new("quillsign:completion-expiry",i.ExpiresAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))
    ],Scheme));

    internal static bool Matches(ClaimsPrincipal principal,CompletionReaderIdentity i) {
        var identities=principal.Identities.Where(x=>x.IsAuthenticated).ToArray(); if(identities.Length!=1 || identities[0].AuthenticationType!=Scheme)return false;
        var expected=Principal(i).Claims.ToArray(); var actual=identities[0].Claims.ToArray();
        return actual.Length==expected.Length && expected.All(c=>actual.Count(x=>x.Type==c.Type && x.Value==c.Value)==1);
    }
}
