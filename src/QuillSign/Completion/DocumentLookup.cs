using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;

namespace QuillSign.Completion;

public sealed record DocumentLookupEntry(string PublicId, string Title, DateTimeOffset CompletedAt, DateTimeOffset? RetainedUntil);
public sealed record DocumentLookupPage(IReadOnlyList<DocumentLookupEntry> Entries, string? NextCursor);

// Internal backend only. A future delivery flow must keep issuance transport private and
// authenticate explicit POST redemption; knowing an address is never listing authority.
public sealed class DocumentLookup(QuillSignDbContext db, CompletionAccessState state, DocumentLookupProtection protection,
    DocumentLookupOptions options, TimeProvider time, Email.Pilot.EmailPilotLookupAccess? pilot = null,
    Email.Pilot.EmailPilotCloseoutLookup? closeout = null)
{
    internal bool RequiresCohortExclusion => pilot is not null || closeout is not null;
    internal Task<Email.Pilot.EmailPilotLookupTokenScope> RestrictionAsync(DocumentLookupIdentity identity, CancellationToken ct) =>
        RestrictionCoreAsync(identity.TokenId,identity.Email,ct);
    private async Task<Email.Pilot.EmailPilotLookupTokenScope> RestrictionCoreAsync(Guid token,string email,CancellationToken ct)
    {
        if(closeout is not null && await closeout.TokenAsync(token,email,ct) is {Known:true} c)
            return new(true,c.Allowed,CloseoutRecord:c.RecordId,CloseoutRequest:c.RequestId,CloseoutUntil:c.Until,CloseoutIssuedAt:c.IssuedAt);
        return pilot is null?new(false,true):await pilot.TokenAsync(token,email,ct);
    }
    private bool RestrictionLive(Email.Pilot.EmailPilotLookupTokenScope? r)=>r is null || !r.IsPilot ||
        (r.CloseoutUntil is {} until? r.Allowed && until>time.GetUtcNow():r.Manifest is {} m && pilot?.Live(m)==true);
    private static bool TokenShape(AuthToken? token,Email.Pilot.EmailPilotLookupTokenScope? r)=>Shape(token) ||
        r is {Allowed:true,CloseoutRequest:{} request,CloseoutRecord:not null} && Shape(token,request) &&
        token!.EmailPilotLookupRequestId is null && token.SignerContactRevisionId is null;

    internal async Task<DocumentLookupLink> IssuePilotAsync(Email.Pilot.EmailPilotLookupWorkScope scope, CancellationToken ct)
    {
        OwnUnitOfWork(); options.Validate(); if (pilot is null) throw new EmailDisabledException();
        try
        {
            await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await pilot.DemandBeforeIssueLockedAsync(scope, ct);
            var now = time.GetUtcNow(); var until = new[] { now.AddMinutes(options.LinkMinutes), scope.Request.ExpiresAt, scope.Manifest.ExpiresAt }.Min();
            if (until <= now) throw Email.Pilot.EmailPilotProtection.Invalid();
            var raw = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            var token = new AuthToken { Purpose = TokenPurpose.Lookup, PartyType = PartyType.System, Email = "",
                EmailPilotLookupRequestId = scope.Request.RequestId, TokenSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(raw)), ExpiresAt = until };
            db.AuthTokens.Add(token); await db.SaveChangesAsync(ct);
            await pilot.SaveIssuedLockedAsync(scope, token, now, ct);
            var transport = protection.Link(new LookupIssuance(token.Id, Convert.ToBase64String(token.RowVersion), raw, scope.Manifest.Mailboxes.Sender, now, until));
            if (scope.Until <= time.GetUtcNow() || !pilot.Live(scope.Manifest)) throw Email.Pilot.EmailPilotProtection.Invalid();
            await tx.CommitAsync(ct);
            if (scope.Until <= time.GetUtcNow() || !pilot.Live(scope.Manifest)) throw Email.Pilot.EmailPilotProtection.Invalid();
            return new(token.Id, transport, until);
        }
        catch { db.ChangeTracker.Clear(); throw; }
    }

    public async Task<DocumentLookupLink> IssueAsync(string email, CancellationToken ct = default)
    {
        OwnUnitOfWork(); options.Validate(); email = EmailAddress.Normalize(email);
        try
        {
            await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var now = time.GetUtcNow(); var until = now.AddMinutes(options.LinkMinutes);
            var raw = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
            // No mailbox is stored: even expired, unbound lookup tokens contain no contact data.
            var token = new AuthToken { Purpose = TokenPurpose.Lookup, PartyType = PartyType.System,
                Email = "", TokenSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(raw)), ExpiresAt = until };
            db.AuthTokens.Add(token); await db.SaveChangesAsync(ct);
            var transport = protection.Link(new LookupIssuance(token.Id, Convert.ToBase64String(token.RowVersion), raw, email, now, until));
            await tx.CommitAsync(ct);
            if (until <= time.GetUtcNow()) throw new InvalidDataException("Document lookup issuance expired.");
            return new(token.Id, transport, until);
        }
        catch { db.ChangeTracker.Clear(); throw; }
    }

    public async Task<DocumentLookupSession?> RedeemAsync(string? transport, CancellationToken ct = default)
    {
        OwnUnitOfWork(); options.Validate(); var link = protection.Link(transport); if (link is null) return null;
        try
        {
            await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            var restriction = await RestrictionCoreAsync(link.TokenId,link.Email,ct);
            if (restriction is { IsPilot: true, Allowed: false }) return null;
            var token = await db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={link.TokenId}")
                .AsNoTracking().SingleOrDefaultAsync(ct);
            var hash = Signing.SignerInvitationFactory.TokenHash(link.RawToken)!;
            if (!TokenShape(token,restriction) || restriction.CloseoutIssuedAt is {} issuedAt && link.IssuedAt!=issuedAt ||
                token!.EmailPilotLookupRequestId is not null && restriction?.IsPilot != true || token!.UsedAt is not null || token.ExpiresAt != link.ExpiresAt || Convert.ToBase64String(token.RowVersion) != link.TokenRevision ||
                !CryptographicOperations.FixedTimeEquals(token.TokenSha256, hash) || link.ExpiresAt <= time.GetUtcNow()) return null;
            var now = time.GetUtcNow();
            if (await db.AuthTokens.Where(x => x.Id == token.Id && x.UsedAt == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.UsedAt, now), ct) != 1) return null;
            var revision = await db.AuthTokens.AsNoTracking().Where(x => x.Id == token.Id).Select(x => x.RowVersion).SingleAsync(ct);
            var until = new[] { now.AddMinutes(options.SessionMinutes), restriction?.Deadline ?? DateTimeOffset.MaxValue,
                restriction?.Manifest?.ExpiresAt ?? DateTimeOffset.MaxValue }.Min();
            var identity = new DocumentLookupIdentity(token.Id, Convert.ToBase64String(revision), Convert.ToHexStringLower(hash), link.Email,
                Guid.NewGuid(), link.IssuedAt, link.ExpiresAt, now, until);
            var receipt = protection.Session(identity);
            // Unknown acknowledgement returns no session. Never silently replay a consumed link.
            await tx.CommitAsync(ct);
            if(restriction is {CloseoutRecord:not null}) {
                await tx.DisposeAsync();
                var fresh=await RestrictionCoreAsync(token.Id,link.Email,ct);
                if(fresh!=restriction || !fresh.Allowed)return null;
            }
            if (!RestrictionLive(restriction)) return null;
            return identity.ExpiresAt > time.GetUtcNow() ? new(identity, receipt) : null;
        }
        catch { db.ChangeTracker.Clear(); throw; }
    }

    public Task<DocumentLookupIdentity?> AuthenticateAsync(ClaimsPrincipal principal, string? receipt, CancellationToken ct = default) =>
        AuthenticateCoreAsync(principal, receipt, false, ct);

    internal Task<DocumentLookupIdentity?> AuthenticateLockedAsync(ClaimsPrincipal principal, string? receipt, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Lookup handoff authentication requires its parent transaction.");
        return AuthenticateCoreAsync(principal, receipt, true, ct);
    }

    private async Task<DocumentLookupIdentity?> AuthenticateCoreAsync(ClaimsPrincipal principal, string? receipt, bool locked, CancellationToken ct)
    {
        var i = protection.Session(receipt);
        if (i is null || !DocumentLookupProtection.Matches(principal, i)) return null;
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        var restriction = await RestrictionCoreAsync(i.TokenId,i.Email,ct);
        if (restriction is { IsPilot: true, Allowed: false }) return null;
        var query = locked
            ? db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={i.TokenId}")
            : db.AuthTokens.Where(x => x.Id == i.TokenId);
        var token = await query.AsNoTracking().SingleOrDefaultAsync(ct);
        return TokenShape(token,restriction) && (restriction.CloseoutIssuedAt is null || restriction.CloseoutIssuedAt==i.IssuedAt) &&
            (token!.EmailPilotLookupRequestId is null || restriction?.IsPilot == true) && token!.UsedAt == i.RedeemedAt && token.ExpiresAt == i.LinkExpiresAt &&
            Convert.ToBase64String(token.RowVersion) == i.TokenRevision && Convert.ToHexStringLower(token.TokenSha256) == i.TokenSha256 &&
            i.ExpiresAt > time.GetUtcNow() && (restriction?.Deadline is null || i.ExpiresAt <= restriction.Deadline) && RestrictionLive(restriction) ? i : null;
    }

    public async Task<DocumentLookupPage?> ListAsync(ClaimsPrincipal principal, string? receipt, string? cursor = null, CancellationToken ct = default)
    {
        OwnUnitOfWork(); options.Validate();
        var i = await AuthenticateAsync(principal, receipt, ct); if (i is null) return null;
        var restriction = await RestrictionAsync(i, ct);
        if (!restriction.Allowed || restriction.IsPilot && cursor is not null) return null;
        var after = cursor is null ? null : protection.Cursor(cursor, i); if (cursor is not null && after is null) return null;
        var now = time.GetUtcNow();
        var query = db.Envelopes.AsNoTracking().Where(x => x.Status == EnvelopeStatus.Completed && x.CompletedAt <= i.RedeemedAt &&
            (x.PurgeAfter == null || x.PurgeAfter > now) && (x.SenderEmail == i.Email ||
            db.Signers.Any(s => s.EnvelopeId == x.Id && s.Email == i.Email) || db.Recipients.Any(r => r.EnvelopeId == x.Id && r.Email == i.Email)));
        if (restriction.IsPilot) query = query.Where(x => x.Id == restriction.SelectedRecord);
        else if (RequiresCohortExclusion) query = query.Where(x => !db.EmailPilotEnrollments.Any(p => p.SubjectEnvelopeId == x.Id));
        if (after is not null) query = query.Where(x => x.CompletedAt > after.CompletedAt || x.CompletedAt == after.CompletedAt && x.PublicId.CompareTo(after.PublicId) > 0);
        var candidates = await query.OrderBy(x => x.CompletedAt).ThenBy(x => x.PublicId).Select(x => new { x.Id, x.PublicId, x.CompletedAt })
            .Take(options.PageSize + 1).ToArrayAsync(ct);
        // Retain metadata only; verified PDF buffers from earlier candidates must not
        // accumulate across the page.
        var saved = new List<(DownloadPublication Publication, DateTimeOffset Until, DateTimeOffset? Deadline)>();
        foreach (var candidate in candidates.Take(options.PageSize))
        {
            // Verification reads the exact immutable final pair, never reseals or grants storage access.
            var prepared = await state.PrepareAsync(candidate.Id, ct); if (prepared is null) continue;
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await state.RecheckLockedAsync(prepared.Saved, ct);
            var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == candidate.Id, ct);
            if (!await OwnedLocked(prepared.Saved, i.Email, ct)) throw Invalid();
            var deadline = await SenderPreparationRetention.ReadAsync(db, envelope, time, ct);
            await tx.CommitAsync(ct); saved.Add((prepared.Saved, prepared.Until, deadline));
        }
        // Recheck all returned scopes after the last I/O. A later file read must still
        // independently authorize and verify; these entries are not download capabilities.
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            foreach (var item in saved)
            {
                if (item.Until <= time.GetUtcNow()) throw Invalid();
                await state.RecheckLockedAsync(item.Publication, ct);
                if (!await OwnedLocked(item.Publication, i.Email, ct)) throw Invalid();
                var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == item.Publication.EnvelopeId, ct);
                if (await SenderPreparationRetention.ReadAsync(db, envelope, time, ct) != item.Deadline) throw Invalid();
                DocumentRetentionAccess.Check(item.Deadline, time);
            }
            if (await AuthenticateAsync(principal, receipt, ct) is null) return null;
            await tx.CommitAsync(ct);
        }
        if(restriction.CloseoutRecord is not null && await RestrictionAsync(i,ct)!=restriction)return null;
        if (i.ExpiresAt <= time.GetUtcNow() || restriction.IsPilot &&
            (restriction.Deadline <= time.GetUtcNow() || !RestrictionLive(restriction))) return null;
        var entries = saved.Select(x => new DocumentLookupEntry(x.Publication.PublicId, x.Publication.Title, x.Publication.CompletedAt,
            Min(x.Publication.PurgeAfter, x.Deadline))).ToArray();
        foreach (var entry in entries) DocumentRetentionAccess.Check(entry.RetainedUntil, time);
        var last = candidates.Take(options.PageSize).LastOrDefault();
        var next = candidates.Length > options.PageSize && last?.CompletedAt is { } at
            ? protection.Cursor(new LookupCursor(i.SessionId, i.TokenId, i.TokenRevision, at, last.PublicId)) : null;
        return new(entries, next);
    }

    private async Task<bool> OwnedLocked(DownloadPublication saved, string email, CancellationToken ct)
    {
        var e = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == saved.EnvelopeId, ct);
        if (e.SenderEmail == email && await state.PartyLockedAsync(saved, PartyType.Sender, null, ct) is not null) return true;
        var signer = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == saved.EnvelopeId && x.Email == email).Select(x => (Guid?)x.Id).SingleOrDefaultAsync(ct);
        if (signer is not null && (await state.PartyLockedAsync(saved, PartyType.Signer, signer, ct))?.Email == email) return true;
        var recipient = await db.Recipients.AsNoTracking().Where(x => x.EnvelopeId == saved.EnvelopeId && x.Email == email).Select(x => (Guid?)x.Id).SingleOrDefaultAsync(ct);
        return recipient is not null && (await state.PartyLockedAsync(saved, PartyType.Recipient, recipient, ct))?.Email == email;
    }
    private static DateTimeOffset? Min(DateTimeOffset? a, DateTimeOffset? b) => a is null ? b : b is null || a < b ? a : b;
    private static bool Shape(AuthToken? t,Guid? closeoutRequest=null) => t is not null && t.Id != Guid.Empty && t.Purpose == TokenPurpose.Lookup &&
        t.PartyType == PartyType.System && t.PartyId == closeoutRequest && t.EnvelopeId is null && t.Email == "" && t.Ip is null &&
        t.TokenSha256 is { Length: 32 } && t.RowVersion is { Length: 8 } && t.DocumentId is null && t.DocumentSha256 is null &&
        t.DisclosureSha256 is null && t.CompletionPublicationId is null && t.CompletionPartySha256 is null && t.CompletionRecipeSha256 is null;
    private void OwnUnitOfWork()
    {
        if (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges())
            throw new InvalidOperationException("Document lookup requires a clean standalone unit of work.");
    }
    private static InvalidDataException Invalid() => new("Completed document lookup evidence could not be verified.");
}

public static class DocumentLookupConfiguration
{
    public static IServiceCollection AddDocumentLookup(this IServiceCollection services, IConfiguration config)
    {
        var options = config.GetSection("DocumentLookup").Get<DocumentLookupOptions>() ?? new(); options.Validate();
        services.AddCompletionAccess(config); services.TryAddSingleton(options);
        services.TryAddScoped<DocumentLookupProtection>(); services.TryAddScoped<DocumentLookup>();
        services.TryAddScoped<LookupPacketAccess>(); return services;
    }
}
