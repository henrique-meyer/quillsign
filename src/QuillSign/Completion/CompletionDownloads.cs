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
using QuillSign.Documents;

namespace QuillSign.Completion;

public sealed record FinalDownloadAvailability(DateTimeOffset CompletedAt,DateTimeOffset? RetainedUntil);
public sealed record PreparedFinalDownload(string Url,DateTimeOffset ExpiresAt);
public sealed record FinalDownload(byte[] Bytes,string FileName);

// Authentication is always performed using the named cookie scheme. A public ID or
// a protected grant alone never grants storage access or restores editing authority.
public sealed class CompletionDownloads(QuillSignDbContext db,TimeProvider time,IHostEnvironment environment,
    IOptionsMonitor<CookieAuthenticationOptions> cookies,IDataProtectionProvider protection,
    SignerCheckpointReads checkpoints,CompletionEvidenceCollector collector,Func<CompletionPublication> publication,AuditWriter audit,Func<CompletionReaderBrowser> readers,QuillSign.Email.Pilot.EmailPilotReadBounds? pilotBounds=null)
{
    internal ProductionCompletionReadAdmission? HoldAdmission {get;init;}
    public const string Version="final-download-v2";
    private readonly IDataProtector protector=protection.CreateProtector("QuillSign.FinalDownload.v1");
    private sealed record Actor(string Audience,Guid EnvelopeId,PartyType Party,Guid? PartyId,string Email,byte[] Session,byte[]? Acceptance,DateTimeOffset Until);
    private sealed record Proof(string Version,string Audience,Guid EnvelopeId,string PublicId,PartyType Party,Guid? PartyId,byte[] Session,byte[]? Acceptance,
        Guid PublicationId,byte[] Recipe,byte[] Revision,FinalDocumentKind Kind,byte[] Reference,Guid Nonce,DateTimeOffset IssuedAt,DateTimeOffset ExpiresAt);

    public async Task<FinalDownloadAvailability?> AvailabilityAsync(HttpContext http,string publicId,PartyType party,CancellationToken ct=default)
    {
        var actor=await Authenticate(http,publicId,party,ct); if(actor is null)return null;
        var saved=await CompletionDownloadState.ReadAsync(db,actor.EnvelopeId,time,ct);
        if(saved is null || saved.PurgeAfter<=time.GetUtcNow())return null;
        var retained=await RetainedCompleted(actor.EnvelopeId,publicId,party==PartyType.Sender ? actor.Email : null,ct);
        if(retained is null || actor.Until<=time.GetUtcNow())return null;
        return new(saved.CompletedAt,Earlier(saved.PurgeAfter,retained.Deadline));
    }

    public async Task<PreparedFinalDownload?> PrepareAsync(HttpContext http,string publicId,PartyType party,string kind,CancellationToken ct=default)
        =>await Prepare(http,publicId,party,kind,false,ct);
    public async Task<PreparedFinalDownload?> PrepareReaderAsync(HttpContext http,string publicId,string kind,CancellationToken ct=default)
        =>await Prepare(http,publicId,PartyType.Recipient,kind,true,ct);
    private async Task<PreparedFinalDownload?> Prepare(HttpContext http,string publicId,PartyType party,string kind,bool reader,CancellationToken ct)
    {
        if(ParseKind(kind) is not { } selected)return null;
        var actor=await Authenticate(http,publicId,party,ct,reader); if(actor is null)return null;
        var saved=await CompletionDownloadState.ReadAsync(db,actor.EnvelopeId,time,ct); if(saved is null || saved.PurgeAfter<=time.GetUtcNow())return null;
        var prepared=HoldAdmission is null?null:await HoldAdmission.PrepareAsync(db,new(db,collector,publication,time,pilotBounds),actor.EnvelopeId,ct);
        var verified=HoldAdmission is null?await publication().ReadAsync(actor.EnvelopeId,ct):prepared?.Verified; if(verified is null || !saved.Matches(verified))throw Invalid();
        var again=await Authenticate(http,publicId,party,ct,reader); if(!SameActor(actor,again))return null;
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var deadline=await Recheck(saved,actor,http,publicId,ct);
        var now=time.GetUtcNow(); var until=new[]{now.AddMinutes(2),actor.Until,saved.PurgeAfter??DateTimeOffset.MaxValue,deadline??DateTimeOffset.MaxValue}.Min();
        if(until<=now)return null;
        var file=selected==FinalDocumentKind.Executed ? saved.Executed : saved.Certificate;
        var proof=new Proof(Version,actor.Audience,actor.EnvelopeId,publicId,actor.Party,actor.PartyId,actor.Session,actor.Acceptance,saved.Id,saved.Recipe,saved.Revision,
            selected,DownloadPublication.Reference(file),Guid.NewGuid(),now,until);
        var encoded=protector.Protect(JsonSerializer.Serialize(proof)); if(encoded.Length>3800)throw Invalid();
        var operation=HoldAdmission is null?null:await HoldAdmission.BeginLockedAsync(db,actor.EnvelopeId,"completion/download",proof.Nonce.ToString("N"),ct);
        await audit.AppendAsync(actor.EnvelopeId,"final_download_prepared",actor.Email,null,null,ct,JsonSerializer.Serialize(new {
            version=Version,publicationId=saved.Id,kind,fileSha256=Convert.ToHexStringLower(file.Sha256),nonce=proof.Nonce,
            referenceSha256=Convert.ToHexStringLower(proof.Reference),expiresAt=until,meaning="Verified download prepared; receipt or saving is not confirmed."
        }),actor.Party,actor.PartyId);
        DocumentRetentionAccess.Check(deadline,time);
        if(actor.Until<=time.GetUtcNow() || saved.PurgeAfter<=time.GetUtcNow())throw Invalid();
        // An unknown commit outcome returns no grant. Retrying may record another explicit
        // preparation, but cannot regenerate or replace the immutable final packet.
        if(HoldAdmission is not null)await HoldAdmission.OutcomeLockedAsync(db,operation,ct);
        if(actor.Until<=time.GetUtcNow()||until<=time.GetUtcNow())throw Invalid();
        await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,ct);await transaction.DisposeAsync();
        if(HoldAdmission is not null){await HoldAdmission.CompleteAsync(operation,ct);await HoldAdmission.DemandAsync(actor.EnvelopeId,until,ct);}
        var options=Options(http,publicId,actor.Audience); options.MaxAge=until-time.GetUtcNow();
        if(options.MaxAge<=TimeSpan.Zero)return null;
        http.Response.Cookies.Append(Cookie(actor.Audience,selected),encoded,options);
        return new(Path(publicId,actor.Audience)+"/"+kind,until);
    }

    public async Task<FinalDownload?> ReadAsync(HttpContext http,string publicId,PartyType party,string kind,CancellationToken ct=default)
        =>await Read(http,publicId,party,kind,false,ct);
    public async Task<FinalDownload?> ReadReaderAsync(HttpContext http,string publicId,string kind,CancellationToken ct=default)
        =>await Read(http,publicId,PartyType.Recipient,kind,true,ct);
    private async Task<FinalDownload?> Read(HttpContext http,string publicId,PartyType party,string kind,bool reader,CancellationToken ct)
    {
        if(ParseKind(kind) is not { } selected)return null;
        var audience=reader ? "complete" : Audience(party); if(audience is null)return null;
        var proof=ReadProof(http,publicId,audience,selected); if(proof is null)return null;
        var actor=await Authenticate(http,publicId,party,ct,reader); if(!Matches(proof,actor))return null;
        var saved=await CompletionDownloadState.ReadAsync(db,actor!.EnvelopeId,time,ct); if(!Matches(proof,saved))return null;
        var prepared=HoldAdmission is null?null:await HoldAdmission.PrepareAsync(db,new(db,collector,publication,time,pilotBounds),actor.EnvelopeId,ct);
        var verified=HoldAdmission is null?await publication().ReadAsync(actor.EnvelopeId,ct):prepared?.Verified; if(verified is null || !saved!.Matches(verified))throw Invalid();
        var again=await Authenticate(http,publicId,party,ct,reader); if(!Matches(proof,again) || !SameActor(actor,again))return null;
        await using var transaction=await db.Database.BeginTransactionAsync(ct);
        var deadline=await Recheck(saved,actor,http,publicId,ct); if(proof.ExpiresAt<=time.GetUtcNow())return null;
        await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,ct);
        await transaction.DisposeAsync();if(HoldAdmission is not null)await HoldAdmission.DemandAsync(actor.EnvelopeId,proof.ExpiresAt,ct);
        DocumentRetentionAccess.Check(deadline,time);if(proof.ExpiresAt<=time.GetUtcNow())return null;
        // Clearing is a convenience for this browser, not global replay prevention. An
        // authenticated clone can repeat this read until the original short expiry.
        http.Response.Cookies.Delete(Cookie(audience,selected),Options(http,publicId,audience));
        return new(selected==FinalDocumentKind.Executed ? verified.ExecutedBytes : verified.CertificateBytes,FileName(saved.Title,kind));
    }

    private async Task<Actor?> Authenticate(HttpContext http,string publicId,PartyType party,CancellationToken ct,bool reader=false,bool locked=false)
    {
        if(reader) {
            var readerSession=await readers().AuthenticateAsync(http,publicId,ct,locked); if(readerSession is null)return null;
            var i=readerSession.View.Identity;
            return new("complete",i.EnvelopeId,i.Party,i.PartyId,i.Email,readerSession.CookieHash,Hash(readerSession.Receipt),readerSession.Until);
        }
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
            var retained=await RetainedCompleted(identity.Value.Id,publicId,identity.Value.Email,ct);if(retained is null)return null;
            until=new[]{until,retained.Deadline??DateTimeOffset.MaxValue}.Min();
            return until<=time.GetUtcNow() ? null : new("draft",retained.Envelope.Id,party,null,retained.Envelope.SenderEmail,session,null,until);
        }
        var signer=SignerAccessConfiguration.ReadIdentity(authenticated.Principal,now); if(signer?.PublicId!=publicId)return null;
        var receipt=Get(http,SignerReviewBrowser.AcceptedCookie)??Get(http,SignerReviewBrowser.ReviewCookie); if(receipt is null)return null;
        if(await checkpoints.ConfirmAsync(authenticated.Principal,publicId,receipt,ct) is null)return null;
        var completed=await RetainedCompleted(signer.EnvelopeId,publicId,null,ct);if(completed is null)return null;
        until=new[]{until,signer.SessionExpiresAt,completed.Envelope.ExpiresAt??DateTimeOffset.MaxValue,completed.Deadline??DateTimeOffset.MaxValue}.Min();
        return until<=time.GetUtcNow() ? null : new("sign",signer.EnvelopeId,party,signer.SignerId,signer.Email,session,Hash(receipt),until);
    }

    // Called only after exact cookie/party authentication; owner checks precede policy reads.
    private sealed record RetainedScope(Envelope Envelope,DateTimeOffset? Deadline);
    private async Task<RetainedScope?> RetainedCompleted(Guid id,string publicId,string? sender,CancellationToken ct)
    {
        await using var owned=db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e?.PublicId!=publicId || e.Status!=EnvelopeStatus.Completed || e.PurgeAfter<=time.GetUtcNow() ||
            sender is not null && (e.SenderEmail!=sender || e.SenderVerifiedAt is null))return null;
        var deadline=await SenderPreparationRetention.ReadAsync(db,e,time,ct,pilotBounds);
        if(HoldAdmission is not null)await HoldAdmission.DemandLockedAsync(db,id,deadline??time.GetUtcNow().AddMinutes(2),ct);
        if(owned is not null){await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,owned,ct);await owned.DisposeAsync();if(HoldAdmission is not null)await HoldAdmission.DemandAsync(id,deadline??time.GetUtcNow().AddMinutes(2),ct);}
        DocumentRetentionAccess.Check(deadline,time);return new(e,deadline);
    }
    private static DateTimeOffset? Earlier(DateTimeOffset? saved,DateTimeOffset? deadline)=>
        deadline is null ? saved : saved is null || deadline<saved ? deadline : saved;

    private async Task<DateTimeOffset?> Recheck(DownloadPublication saved,Actor actor,HttpContext http,string publicId,CancellationToken ct)
    {
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={saved.EnvelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e is null || actor.Until<=time.GetUtcNow() || e.PurgeAfter<=time.GetUtcNow())throw Invalid();
        var deadline=await SenderPreparationRetention.ReadAsync(db,e,time,ct,pilotBounds);
        if(HoldAdmission is not null)await HoldAdmission.DemandLockedAsync(db,actor.EnvelopeId,actor.Until,ct);
        var current=await CompletionDownloadState.ReadAsync(db,saved.EnvelopeId,time,ct);
        if(current is null || current.Id!=saved.Id || !Same(current.Recipe,saved.Recipe) || !current.Revision.AsSpan().SequenceEqual(saved.Revision))throw Invalid();
        await CompletionDownloadState.RecheckSourceAsync(collector,saved,ct);
        if(actor.Audience=="complete" && !SameActor(actor,await Authenticate(http,publicId,actor.Party,ct,true,true)))throw Invalid();
        if(actor.Until<=time.GetUtcNow() || e.PurgeAfter<=time.GetUtcNow())throw Invalid();
        DocumentRetentionAccess.Check(deadline,time);return deadline;
    }

    private Proof? ReadProof(HttpContext http,string id,string audience,FinalDocumentKind kind)
    {
        var raw=Get(http,Cookie(audience,kind)); if(raw is null)return null;
        try {
            var p=JsonSerializer.Deserialize<Proof>(protector.Unprotect(raw)); var now=time.GetUtcNow();
            return p is not null && p.Version==Version && p.Audience==audience && p.PublicId==id && p.Kind==kind &&
                p.EnvelopeId!=Guid.Empty && p.PublicationId!=Guid.Empty && p.Nonce!=Guid.Empty &&
                (audience=="complete" ? p.Acceptance is {Length:32} && (p.Party==PartyType.Sender ? p.PartyId is null : p.Party is PartyType.Signer or PartyType.Recipient && p.PartyId is { } member && member!=Guid.Empty) :
                    p.Party== (audience=="draft" ? PartyType.Sender : PartyType.Signer) && (p.Party==PartyType.Sender ? p.PartyId is null && p.Acceptance is null : p.PartyId is { } signer && signer!=Guid.Empty && p.Acceptance is {Length:32})) &&
                p.Session is {Length:32} && p.Recipe is {Length:32} && p.Revision is {Length:8} && p.Reference is {Length:32} &&
                p.IssuedAt<=now && p.ExpiresAt>now && p.ExpiresAt>p.IssuedAt && p.ExpiresAt<=p.IssuedAt.AddMinutes(2) ? p : null;
        } catch(Exception e) when(e is CryptographicException or JsonException or ArgumentException) {return null;}
    }
    private bool Matches(Proof proof,Actor? actor)=>actor is not null && proof.Audience==actor.Audience && proof.EnvelopeId==actor.EnvelopeId && proof.Party==actor.Party && proof.PartyId==actor.PartyId &&
        Same(proof.Session,actor.Session) && SameNullable(proof.Acceptance,actor.Acceptance) && proof.ExpiresAt<=actor.Until && proof.ExpiresAt>time.GetUtcNow();
    private bool Matches(Proof proof,DownloadPublication? saved)=>saved is not null && saved.Id==proof.PublicationId && saved.EnvelopeId==proof.EnvelopeId &&
        saved.PublicId==proof.PublicId && Same(proof.Recipe,saved.Recipe) && proof.Revision.AsSpan().SequenceEqual(saved.Revision) && (saved.PurgeAfter is null || saved.PurgeAfter>time.GetUtcNow()) &&
        Same(proof.Reference,DownloadPublication.Reference(proof.Kind==FinalDocumentKind.Executed ? saved.Executed : saved.Certificate));
    private static bool SameActor(Actor actor,Actor? again)=>again is not null && actor.Audience==again.Audience && actor.EnvelopeId==again.EnvelopeId && actor.Party==again.Party && actor.PartyId==again.PartyId &&
        actor.Email==again.Email && actor.Until==again.Until && Same(actor.Session,again.Session) && SameNullable(actor.Acceptance,again.Acceptance);
    private static bool Same(byte[]? a,byte[]? b)=>CompletionEvidenceValidation.Same(a,b);
    private static bool SameNullable(byte[]? a,byte[]? b)=>a is null ? b is null : Same(a,b);
    private static byte[] Hash(string value)=>SHA256.HashData(Encoding.UTF8.GetBytes(value));
    private static string? Get(HttpContext http,string name)=>http.Request.Cookies.TryGetValue(name,out var v) && v.Length is >0 and <=3800 ? v : null;
    private CookieOptions Options(HttpContext http,string id,string audience)=>new() {HttpOnly=true,SameSite=SameSiteMode.Strict,Secure=!environment.IsDevelopment() || http.Request.IsHttps,
        Path=Path(id,audience),IsEssential=true};
    private static string Path(string id,string audience)=>"/"+audience+"/"+id+"/final";
    private static string? Audience(PartyType party)=>party switch {PartyType.Sender=>"draft",PartyType.Signer=>"sign",_=>null};
    private static string Cookie(string audience,FinalDocumentKind kind)=>"QuillSign.Final."+(audience=="draft" ? "Sender" : audience=="sign" ? "Signer" : "Reader")+"."+kind;
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
        services.AddScoped<Func<CompletionReaderBrowser>>(sp=>()=>sp.GetRequiredService<CompletionReaderBrowser>());
        services.AddScoped<Func<CompletionPublication>>(sp=>()=>sp.GetRequiredService<CompletionPublication>()); return services;
    }
}
