using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Completion;

public sealed record FinalDownloadAvailability(DateTimeOffset CompletedAt,DateTimeOffset? RetainedUntil);
public sealed record PreparedFinalDownload(string Url,DateTimeOffset ExpiresAt);
public sealed record FinalDownload(byte[] Bytes,string FileName);

// Authentication is always performed using the named cookie scheme. A public ID or
// a protected grant alone never grants storage access or restores editing authority.
public sealed class CompletionDownloads(QuillSignDbContext db,TimeProvider time,IHostEnvironment environment,
    IOptionsMonitor<CookieAuthenticationOptions> cookies,IDataProtectionProvider protection,
    SignerCheckpointReads checkpoints,CompletionEvidenceCollector collector,Func<CompletionPublication> publication,AuditWriter audit)
{
    public const string Version="final-download-v1";
    private readonly IDataProtector protector=protection.CreateProtector("QuillSign.FinalDownload.v1");
    private sealed record Actor(Guid EnvelopeId,PartyType Party,Guid? PartyId,string Email,byte[] Session,byte[]? Acceptance,DateTimeOffset Until);
    private sealed record Proof(string Version,Guid EnvelopeId,string PublicId,PartyType Party,Guid? PartyId,byte[] Session,byte[]? Acceptance,
        Guid PublicationId,byte[] Recipe,byte[] Revision,FinalDocumentKind Kind,byte[] Reference,Guid Nonce,DateTimeOffset IssuedAt,DateTimeOffset ExpiresAt);

    public async Task<FinalDownloadAvailability?> AvailabilityAsync(HttpContext http,string publicId,PartyType party,CancellationToken ct=default)
    {
        var actor=await Authenticate(http,publicId,party,ct); if(actor is null)return null;
        var saved=await CompletionDownloadState.ReadAsync(db,actor.EnvelopeId,time,ct);
        return saved is null || saved.PurgeAfter<=time.GetUtcNow() ? null : new(saved.CompletedAt,saved.PurgeAfter);
    }

    public async Task<PreparedFinalDownload?> PrepareAsync(HttpContext http,string publicId,PartyType party,string kind,CancellationToken ct=default)
    {
        if(ParseKind(kind) is not { } selected)return null;
        var actor=await Authenticate(http,publicId,party,ct); if(actor is null)return null;
        var saved=await CompletionDownloadState.ReadAsync(db,actor.EnvelopeId,time,ct); if(saved is null || saved.PurgeAfter<=time.GetUtcNow())return null;
        var verified=await publication().ReadAsync(actor.EnvelopeId,ct); if(verified is null || !saved.Matches(verified))throw Invalid();
        var again=await Authenticate(http,publicId,party,ct); if(!SameActor(actor,again))return null;
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        await Recheck(saved,actor,ct);
        var now=time.GetUtcNow(); var until=new[]{now.AddMinutes(2),actor.Until,saved.PurgeAfter??DateTimeOffset.MaxValue}.Min();
        if(until<=now)return null;
        var file=selected==FinalDocumentKind.Executed ? saved.Executed : saved.Certificate;
        var proof=new Proof(Version,actor.EnvelopeId,publicId,party,actor.PartyId,actor.Session,actor.Acceptance,saved.Id,saved.Recipe,saved.Revision,
            selected,DownloadPublication.Reference(file),Guid.NewGuid(),now,until);
        var encoded=protector.Protect(JsonSerializer.Serialize(proof)); if(encoded.Length>3800)throw Invalid();
        await audit.AppendAsync(actor.EnvelopeId,"final_download_prepared",actor.Email,null,null,ct,JsonSerializer.Serialize(new {
            version=Version,publicationId=saved.Id,kind,fileSha256=Convert.ToHexStringLower(file.Sha256),nonce=proof.Nonce,
            referenceSha256=Convert.ToHexStringLower(proof.Reference),expiresAt=until,meaning="Verified download prepared; receipt or saving is not confirmed."
        }),party,actor.PartyId);
        // An unknown commit outcome returns no grant. Retrying may record another explicit
        // preparation, but cannot regenerate or replace the immutable final packet.
        await transaction.CommitAsync(ct);
        var options=Options(http,publicId,party); options.MaxAge=until-time.GetUtcNow();
        if(options.MaxAge<=TimeSpan.Zero)return null;
        http.Response.Cookies.Append(Cookie(party,selected),encoded,options);
        return new(Path(publicId,party)+"/"+kind,until);
    }

    public async Task<FinalDownload?> ReadAsync(HttpContext http,string publicId,PartyType party,string kind,CancellationToken ct=default)
    {
        if(ParseKind(kind) is not { } selected)return null;
        var proof=ReadProof(http,publicId,party,selected); if(proof is null)return null;
        var actor=await Authenticate(http,publicId,party,ct); if(!Matches(proof,actor))return null;
        var saved=await CompletionDownloadState.ReadAsync(db,actor!.EnvelopeId,time,ct); if(!Matches(proof,saved))return null;
        var verified=await publication().ReadAsync(actor.EnvelopeId,ct); if(verified is null || !saved!.Matches(verified))throw Invalid();
        var again=await Authenticate(http,publicId,party,ct); if(!Matches(proof,again) || !SameActor(actor,again))return null;
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        await Recheck(saved,actor,ct); if(proof.ExpiresAt<=time.GetUtcNow())return null;
        await transaction.CommitAsync(ct);
        // Clearing is a convenience for this browser, not global replay prevention. An
        // authenticated clone can repeat this read until the original short expiry.
        http.Response.Cookies.Delete(Cookie(party,selected),Options(http,publicId,party));
        return new(selected==FinalDocumentKind.Executed ? verified.ExecutedBytes : verified.CertificateBytes,FileName(saved.Title,kind));
    }

    private async Task<Actor?> Authenticate(HttpContext http,string publicId,PartyType party,CancellationToken ct)
    {
        if(party is not (PartyType.Sender or PartyType.Signer) || !Guid.TryParseExact(publicId,"N",out var id) || id==Guid.Empty)return null;
        var scheme=party==PartyType.Sender ? EnvelopeStorageAuthorization.SenderScheme : SignerAccessConfiguration.Scheme;
        var authenticated=await http.AuthenticateAsync(scheme); var now=time.GetUtcNow();
        if(!authenticated.Succeeded || authenticated.Principal is null || authenticated.Properties?.ExpiresUtc is not { } until || until<=now)return null;
        var settings=cookies.Get(scheme); var raw=settings.CookieManager.GetRequestCookie(http,settings.Cookie.Name!);
        if(string.IsNullOrEmpty(raw) || raw.Length>32768)return null;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        var session=Hash(raw);
        if(party==PartyType.Sender) {
            var identity=SendDraftWorkflow.Identity(authenticated.Principal,publicId); if(identity is null)return null;
            var e=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==identity.Value.Id,ct);
            if(e?.PublicId!=publicId || e.SenderEmail!=identity.Value.Email || e.SenderVerifiedAt is null || e.Status!=EnvelopeStatus.Completed || e.PurgeAfter<=now)return null;
            return new(e.Id,party,null,e.SenderEmail,session,null,until);
        }
        var signer=SignerAccessConfiguration.ReadIdentity(authenticated.Principal,now); if(signer?.PublicId!=publicId)return null;
        var receipt=Get(http,SignerReviewBrowser.AcceptedCookie)??Get(http,SignerReviewBrowser.ReviewCookie); if(receipt is null)return null;
        if(await checkpoints.ConfirmAsync(authenticated.Principal,publicId,receipt,ct) is null)return null;
        var envelope=await db.Envelopes.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==signer.EnvelopeId,ct);
        if(envelope?.Status!=EnvelopeStatus.Completed || envelope.PurgeAfter<=time.GetUtcNow())return null;
        until=new[]{until,signer.SessionExpiresAt,envelope.ExpiresAt??DateTimeOffset.MaxValue}.Min();
        return until<=time.GetUtcNow() ? null : new(signer.EnvelopeId,party,signer.SignerId,signer.Email,session,Hash(receipt),until);
    }

    private async Task Recheck(DownloadPublication saved,Actor actor,CancellationToken ct)
    {
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={saved.EnvelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e is null || actor.Until<=time.GetUtcNow() || e.PurgeAfter<=time.GetUtcNow())throw Invalid();
        var current=await CompletionDownloadState.ReadAsync(db,saved.EnvelopeId,time,ct);
        if(current is null || current.Id!=saved.Id || !Same(current.Recipe,saved.Recipe) || !current.Revision.AsSpan().SequenceEqual(saved.Revision))throw Invalid();
        await CompletionDownloadState.RecheckSourceAsync(collector,saved,ct);
        if(actor.Until<=time.GetUtcNow() || e.PurgeAfter<=time.GetUtcNow())throw Invalid();
    }

    private Proof? ReadProof(HttpContext http,string id,PartyType party,FinalDocumentKind kind)
    {
        var raw=Get(http,Cookie(party,kind)); if(raw is null)return null;
        try {
            var p=JsonSerializer.Deserialize<Proof>(protector.Unprotect(raw)); var now=time.GetUtcNow();
            return p is not null && p.Version==Version && p.PublicId==id && p.Party==party && p.Kind==kind &&
                p.EnvelopeId!=Guid.Empty && p.PublicationId!=Guid.Empty && p.Nonce!=Guid.Empty &&
                (party==PartyType.Sender ? p.PartyId is null && p.Acceptance is null : p.PartyId is { } signer && signer!=Guid.Empty && p.Acceptance is {Length:32}) &&
                p.Session is {Length:32} && p.Recipe is {Length:32} && p.Revision is {Length:8} && p.Reference is {Length:32} &&
                p.IssuedAt<=now && p.ExpiresAt>now && p.ExpiresAt>p.IssuedAt && p.ExpiresAt<=p.IssuedAt.AddMinutes(2) ? p : null;
        } catch(Exception e) when(e is CryptographicException or JsonException or ArgumentException) {return null;}
    }
    private bool Matches(Proof proof,Actor? actor)=>actor is not null && proof.EnvelopeId==actor.EnvelopeId && proof.Party==actor.Party && proof.PartyId==actor.PartyId &&
        Same(proof.Session,actor.Session) && SameNullable(proof.Acceptance,actor.Acceptance) && proof.ExpiresAt<=actor.Until && proof.ExpiresAt>time.GetUtcNow();
    private bool Matches(Proof proof,DownloadPublication? saved)=>saved is not null && saved.Id==proof.PublicationId && saved.EnvelopeId==proof.EnvelopeId &&
        saved.PublicId==proof.PublicId && Same(proof.Recipe,saved.Recipe) && proof.Revision.AsSpan().SequenceEqual(saved.Revision) && (saved.PurgeAfter is null || saved.PurgeAfter>time.GetUtcNow()) &&
        Same(proof.Reference,DownloadPublication.Reference(proof.Kind==FinalDocumentKind.Executed ? saved.Executed : saved.Certificate));
    private static bool SameActor(Actor actor,Actor? again)=>again is not null && actor.EnvelopeId==again.EnvelopeId && actor.Party==again.Party && actor.PartyId==again.PartyId &&
        actor.Email==again.Email && actor.Until==again.Until && Same(actor.Session,again.Session) && SameNullable(actor.Acceptance,again.Acceptance);
    private static bool Same(byte[]? a,byte[]? b)=>CompletionEvidenceValidation.Same(a,b);
    private static bool SameNullable(byte[]? a,byte[]? b)=>a is null ? b is null : Same(a,b);
    private static byte[] Hash(string value)=>SHA256.HashData(Encoding.UTF8.GetBytes(value));
    private static string? Get(HttpContext http,string name)=>http.Request.Cookies.TryGetValue(name,out var v) && v.Length is >0 and <=3800 ? v : null;
    private CookieOptions Options(HttpContext http,string id,PartyType party)=>new() {HttpOnly=true,SameSite=SameSiteMode.Strict,Secure=!environment.IsDevelopment() || http.Request.IsHttps,
        Path=Path(id,party),IsEssential=true};
    private static string Path(string id,PartyType party)=>(party==PartyType.Sender ? "/draft/" : "/sign/")+id+"/final";
    private static string Cookie(PartyType party,FinalDocumentKind kind)=>"QuillSign.Final."+party+"."+kind;
    private static FinalDocumentKind? ParseKind(string kind)=>kind switch {"executed"=>FinalDocumentKind.Executed,"certificate"=>FinalDocumentKind.Certificate,_=>null};
    private static string FileName(string title,string kind) {
        var clean=new string(title.Where(c=>char.IsLetterOrDigit(c) || c is ' ' or '-' or '_').Take(80).ToArray()).Trim();
        return "QuillSign-"+(clean.Length==0 ? "document" : clean)+"-"+kind+".pdf";
    }
    private static InvalidDataException Invalid()=>new("Final download could not be verified. Retry from your private confirmation page.");
}

public static class CompletionDownloadConfiguration
{
    public static IServiceCollection AddCompletionDownloads(this IServiceCollection services)
    {
        services.AddScoped<CompletionDownloads>(); services.AddScoped<Func<CompletionDownloads>>(sp=>()=>sp.GetRequiredService<CompletionDownloads>());
        services.AddScoped<Func<CompletionPublication>>(sp=>()=>sp.GetRequiredService<CompletionPublication>()); return services;
    }
}
