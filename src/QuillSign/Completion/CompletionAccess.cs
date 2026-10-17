using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Completion;

public sealed record CompletionReaderView(CompletionReaderIdentity Identity,string Title,DateTimeOffset CompletedAt,DateTimeOffset? RetainedUntil);
public sealed record CompletionReaderFile(byte[] Pdf,string Title,string Sha256,FinalDocumentKind Kind);

// Trusted issuance and readonly authentication. HTTP entry authenticates the dedicated
// scheme and keeps Receipt private; arbitrary claims never replace its protected proof.
public sealed class CompletionAccess(QuillSignDbContext db,CompletionAccessState state,CompletionAccessProtection protection,
    CompletionAccessOptions options,AuditWriter audit,TimeProvider time,Func<CompletionPublication> publication)
{
    public async Task<CompletionAccessLink?> IssueAsync(Guid envelopeId,PartyType party,Guid? partyId,CancellationToken ct=default)
    {
        OwnUnitOfWork();
        try {return await IssueCore(envelopeId,party,partyId,ct);}
        catch {db.ChangeTracker.Clear();throw;}
    }
    private async Task<CompletionAccessLink?> IssueCore(Guid envelopeId,PartyType party,Guid? partyId,CancellationToken ct)
    {
        options.Validate(); var prepared=await state.PrepareAsync(envelopeId,ct); if(prepared is null)return null;
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var link=await PrepareLockedAsync(prepared,party,partyId,ct); if(link is null)return null;
        // Unknown commits return no plaintext transport. An unused hash may expire safely.
        await tx.CommitAsync(ct); return link;
    }

    // Delivery verifies before its transaction and returns raw transport only in memory.
    // The caller owns issuance, submission-intent commit and uncertain-outcome recovery.
    internal Task<CompletionAccessPreparation?> PrepareAsync(Guid envelopeId,CancellationToken ct)=>state.PrepareAsync(envelopeId,ct);
    internal async Task<CompletionAccessLink?> PrepareLockedAsync(CompletionAccessPreparation prepared,PartyType party,Guid? partyId,CancellationToken ct)
    {
        options.Validate(); if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Completion token preparation requires its caller's transaction.");
        if(prepared.Until<=time.GetUtcNow())return null;
        await state.RecheckLockedAsync(prepared.Saved,ct);
        var member=await state.PartyLockedAsync(prepared.Saved,party,partyId,ct); if(member is null)return null;
        var now=time.GetUtcNow(); var until=new[]{now.AddHours(options.LinkHours),prepared.Saved.PurgeAfter??DateTimeOffset.MaxValue}.Min(); if(until<=now)return null;
        var raw=WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var token=new AuthToken {EnvelopeId=prepared.Saved.EnvelopeId,PartyType=party,PartyId=partyId,Email=member.Email,Purpose=TokenPurpose.CompletionAccess,
            CompletionPublicationId=prepared.Saved.Id,CompletionRecipeSha256=prepared.Saved.Recipe.ToArray(),CompletionPartySha256=member.Sha256.ToArray(),
            TokenSha256=SHA256.HashData(Encoding.UTF8.GetBytes(raw)),ExpiresAt=until};
        db.AuthTokens.Add(token); await db.SaveChangesAsync(ct);
        await audit.AppendAsync(prepared.Saved.EnvelopeId,"completion_access_issued",null,null,null,ct,Issued(token),PartyType.System);
        if(until<=time.GetUtcNow() || prepared.Until<=time.GetUtcNow())throw Invalid();
        return new(token.Id,raw,until);
    }

    public async Task<CompletionReaderSession?> RedeemAsync(string? raw,CancellationToken ct=default)
    {
        OwnUnitOfWork();
        try {return await RedeemCore(raw,ct);}
        catch {db.ChangeTracker.Clear();throw;}
    }
    private async Task<CompletionReaderSession?> RedeemCore(string? raw,CancellationToken ct)
    {
        options.Validate(); var hash=SignerInvitationFactory.TokenHash(raw); if(hash is null)return null;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        var located=await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x=>x.TokenSha256==hash,ct);
        if(!Shape(located) || located!.UsedAt is not null || located.ExpiresAt<=time.GetUtcNow())return null;
        var prepared=await state.PrepareAsync(located.EnvelopeId!.Value,ct); if(prepared is null)return null;
        await using var tx=await db.Database.BeginTransactionAsync(ct); await state.RecheckLockedAsync(prepared.Saved,ct);
        var token=await db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={located.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(!Shape(token) || token!.UsedAt is not null || token.ExpiresAt<=time.GetUtcNow() || !Same(token.TokenSha256,hash))return null;
        var member=await Member(token,prepared.Saved,ct); if(member is null || !await Issuance(token,ct))return null;
        var now=time.GetUtcNow(); var until=new[]{now.AddHours(options.SessionHours),prepared.Saved.PurgeAfter??DateTimeOffset.MaxValue}.Min(); if(until<=now)return null;
        var consumed=await db.AuthTokens.Where(x=>x.Id==token.Id && x.UsedAt==null).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.UsedAt,now),ct); if(consumed!=1)return null;
        var revision=await db.AuthTokens.AsNoTracking().Where(x=>x.Id==token.Id).Select(x=>x.RowVersion).SingleAsync(ct);
        var identity=new CompletionReaderIdentity(token.Id,Convert.ToBase64String(revision),prepared.Saved.EnvelopeId,prepared.Saved.PublicId,member.Type,member.Id,member.Email,
            prepared.Saved.Id,Hex(prepared.Saved.Recipe),Hex(member.Sha256),Guid.NewGuid(),now,until);
        await audit.AppendAsync(identity.EnvelopeId,"completion_access_redeemed",member.Email,null,null,ct,Consumed(identity),member.Type,member.Id);
        var receipt=protection.Protect(identity);
        if(prepared.Until<=time.GetUtcNow() || until<=time.GetUtcNow())throw Invalid();
        // Never recover an unknown commit by replaying this consumed link into another session.
        await tx.CommitAsync(ct); return new(identity,receipt);
    }

    public async Task<CompletionReaderView?> AuthenticateAsync(ClaimsPrincipal principal,string publicId,string? receipt,CancellationToken ct=default)
    {
        var i=protection.Read(receipt); if(i?.PublicId!=publicId || !CompletionAccessProtection.Matches(principal,i))return null;
        await SqlResume.RunAsync(()=>db.Database.OpenConnectionAsync(ct),ct);
        await using var tx=await db.Database.BeginTransactionAsync(ct);
        var saved=await SessionLocked(i,ct); if(saved is null)return null;
        await tx.CommitAsync(ct); return new(i,saved.Title,saved.CompletedAt,saved.PurgeAfter);
    }

    // Download transactions already hold the parent lock; never open a nested transaction.
    internal async Task<CompletionReaderView?> AuthenticateLockedAsync(ClaimsPrincipal principal,string publicId,string? receipt,CancellationToken ct)
    {
        if(db.Database.CurrentTransaction is null)throw new InvalidOperationException("Completion session validation requires its parent transaction.");
        var i=protection.Read(receipt); if(i?.PublicId!=publicId || !CompletionAccessProtection.Matches(principal,i))return null;
        var saved=await SessionLocked(i,ct); return saved is null ? null : new(i,saved.Title,saved.CompletedAt,saved.PurgeAfter);
    }

    public async Task<CompletionReaderFile?> ReadAsync(ClaimsPrincipal principal,string publicId,string? receipt,FinalDocumentKind kind,CancellationToken ct=default)
    {
        if(kind is not (FinalDocumentKind.Executed or FinalDocumentKind.Certificate))return null;
        var authenticated=await AuthenticateAsync(principal,publicId,receipt,ct); if(authenticated is null)return null;
        var verified=await publication().ReadAsync(authenticated.Identity.EnvelopeId,ct); if(verified is null)return null;
        if(protection.Read(receipt) is not { } identity || !CompletionAccessProtection.Matches(principal,identity))return null;
        await using var tx=await db.Database.BeginTransactionAsync(ct); var saved=await SessionLocked(identity,ct);
        if(saved is null)return null; if(!saved.Matches(verified))throw Invalid();
        if(identity.ExpiresAt<=time.GetUtcNow())return null;
        await tx.CommitAsync(ct);
        return new(kind==FinalDocumentKind.Executed ? verified.ExecutedBytes : verified.CertificateBytes,saved.Title,
            Hex(kind==FinalDocumentKind.Executed ? verified.Executed.Sha256 : verified.Certificate.Sha256),kind);
    }

    private async Task<DownloadPublication?> SessionLocked(CompletionReaderIdentity i,CancellationToken ct)
    {
        if(i.ExpiresAt<=time.GetUtcNow())return null;
        var e=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={i.EnvelopeId}").AsNoTracking().SingleOrDefaultAsync(ct);
        if(e?.Status!=EnvelopeStatus.Completed || e.PurgeAfter<=time.GetUtcNow())return null;
        var saved=await CompletionDownloadState.ReadAsync(db,i.EnvelopeId,time,ct);
        if(saved is null || saved.PublicId!=i.PublicId || saved.Id!=i.PublicationId || Hex(saved.Recipe)!=i.RecipeSha256 || saved.PurgeAfter<i.ExpiresAt)return null;
        await state.RecheckLockedAsync(saved,ct);
        var token=await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==i.TokenId,ct);
        if(!Shape(token) || token!.UsedAt!=i.RedeemedAt || token.ExpiresAt<=i.RedeemedAt || Convert.ToBase64String(token.RowVersion)!=i.TokenRevision ||
            token.Email!=i.Email || token.PartyType!=i.Party || token.PartyId!=i.PartyId || Hex(token.CompletionPartySha256!)!=i.PartySha256)return null;
        if(await Member(token,saved,ct) is null || !await Issuance(token,ct) || !await Consumption(token,i,ct))return null;
        return i.ExpiresAt>time.GetUtcNow() ? saved : null;
    }
    private async Task<CompletionAccessParty?> Member(AuthToken token,DownloadPublication saved,CancellationToken ct)
    {
        if(token.EnvelopeId!=saved.EnvelopeId || token.CompletionPublicationId!=saved.Id || !Same(token.CompletionRecipeSha256,saved.Recipe))return null;
        var party=await state.PartyLockedAsync(saved,token.PartyType,token.PartyId,ct);
        return party is not null && party.Email==token.Email && Same(party.Sha256,token.CompletionPartySha256) ? party : null;
    }
    private async Task<bool> Issuance(AuthToken token,CancellationToken ct)
    {
        var e=await Evidence(token,"completion_access_issued",ct);
        return e is not null && e.ActorType==PartyType.System && e.ActorId is null && e.ActorEmail is null && e.At<token.ExpiresAt &&
            token.ExpiresAt<=e.At.AddHours(168) && e.DataJson==Issued(token);
    }
    private async Task<bool> Consumption(AuthToken token,CompletionReaderIdentity i,CancellationToken ct)
    {
        var e=await Evidence(token,"completion_access_redeemed",ct);
        return e is not null && e.ActorType==i.Party && e.ActorId==i.PartyId && e.ActorEmail==i.Email && e.At>=i.RedeemedAt && e.DataJson==Consumed(i);
    }
    private async Task<AuditEvent?> Evidence(AuthToken token,string name,CancellationToken ct)
    {
        var id=token.Id.ToString(); var envelope=token.EnvelopeId!.Value;
        // Filter the exact token in SQL. Operational tails need not fit the original
        // certificate's bounded snapshot, and malformed unrelated JSON is not parsed.
        var size=await db.Database.SqlQuery<long>($"SELECT COALESCE(SUM(CONVERT(bigint,DATALENGTH([DataJson]))),0) AS [Value] FROM [AuditEvents] WHERE [EnvelopeId]={envelope} AND [Event]={name} AND JSON_VALUE(CASE WHEN ISJSON([DataJson])=1 THEN [DataJson] ELSE '{{}}' END,'$.tokenId')={id}").SingleAsync(ct);
        if(size>16384)throw Invalid();
        var rows=await db.AuditEvents.FromSqlInterpolated($"SELECT TOP(2) * FROM [AuditEvents] WHERE [EnvelopeId]={envelope} AND [Event]={name} AND JSON_VALUE(CASE WHEN ISJSON([DataJson])=1 THEN [DataJson] ELSE '{{}}' END,'$.tokenId')={id}").AsNoTracking().ToArrayAsync(ct);
        return rows.Length==1 && rows[0].Ip is null && rows[0].UserAgent is null && rows[0].At<=time.GetUtcNow() && Same(rows[0].Hash,AuditHash.Compute(rows[0])) ? rows[0] : null;
    }
    private static string Issued(AuthToken t)=>JsonSerializer.Serialize(new {version=CompletionAccessProtection.Version,tokenId=t.Id,t.EnvelopeId,purpose=t.Purpose.ToString(),
        party=t.PartyType.ToString(),t.PartyId,t.Email,publicationId=t.CompletionPublicationId,recipeSha256=Hex(t.CompletionRecipeSha256!),partySha256=Hex(t.CompletionPartySha256!),
        tokenSha256=Hex(t.TokenSha256),t.ExpiresAt});
    private static string Consumed(CompletionReaderIdentity i)=>JsonSerializer.Serialize(new {version=CompletionAccessProtection.Version,tokenId=i.TokenId,i.EnvelopeId,
        publicationId=i.PublicationId,i.TokenRevision,party=i.Party.ToString(),i.PartyId,i.Email,i.RecipeSha256,i.PartySha256,i.SessionId,i.RedeemedAt,i.ExpiresAt,
        authentication="single_use_party_scoped_link",authority="readonly_published_final_pair"});
    private static bool Shape(AuthToken? t)=>t is not null && t.Id!=Guid.Empty && t.EnvelopeId is { } e && e!=Guid.Empty && t.Purpose==TokenPurpose.CompletionAccess &&
        t.CompletionPublicationId is { } p && p!=Guid.Empty && t.CompletionRecipeSha256 is {Length:32} && t.CompletionPartySha256 is {Length:32} && t.TokenSha256 is {Length:32} &&
        t.RowVersion is {Length:8} && t.DocumentId is null && t.DocumentSha256 is null && t.DisclosureSha256 is null &&
        (t.PartyType==PartyType.Sender ? t.PartyId is null : t.PartyType is PartyType.Signer or PartyType.Recipient && t.PartyId is { } id && id!=Guid.Empty);
    private static bool Same(byte[]? a,byte[]? b)=>CompletionEvidenceValidation.Same(a,b);
    private void OwnUnitOfWork() {
        if(db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())
            throw new InvalidOperationException("Standalone completion access requires a clean unit of work. Caller-owned issuance uses PrepareLockedAsync.");
    }
    private static string Hex(byte[] value)=>Convert.ToHexStringLower(value);
    private static InvalidDataException Invalid()=>CompletionAccessState.Invalid();
}

public static class CompletionAccessConfiguration
{
    public static IServiceCollection AddCompletionAccess(this IServiceCollection services,IConfiguration config)
    {
        var options=config.GetSection("CompletionAccess").Get<CompletionAccessOptions>()??new(); options.Validate(); services.TryAddSingleton(options);
        services.TryAddScoped<CompletionAccessProtection>(); services.TryAddScoped<CompletionAccessState>(); services.TryAddScoped<CompletionAccess>();
        services.TryAddScoped<Func<CompletionPublication>>(sp=>()=>sp.GetRequiredService<CompletionPublication>()); return services;
    }
}
