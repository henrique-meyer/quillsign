using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public sealed partial class EmailPilotLookupAccess
{
    internal async Task VerifyIssuedLockedAsync(EmailPilotLookupRequestBinding request, LookupIssuedToken issued, int attempt, CancellationToken ct)
    {
        var db = database();
        var row = await db.EmailPilotLookupTokens.AsNoTracking().SingleOrDefaultAsync(x => x.Id == issued.Id, ct) ?? throw EmailPilotProtection.Invalid();
        var saved = Decode(row);
        var token = await db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={issued.Id}").AsNoTracking().SingleOrDefaultAsync(ct);
        if (saved.RunId != request.RunId || saved.RequestId != request.RequestId || saved.Attempt != attempt ||
            saved.IssuedAt < request.RequestedAt || saved.IssuedAt > Now || saved.ExpiresAt > request.ExpiresAt ||
            saved.IssuedRevision != issued.Revision || saved.TokenSha256 != issued.Sha256 || saved.ExpiresAt != issued.ExpiresAt ||
            !TokenShape(token, request) || token!.UsedAt is not null || token.ExpiresAt <= Now ||
            Convert.ToBase64String(token.RowVersion) != saved.IssuedRevision || token.ExpiresAt != saved.ExpiresAt ||
            !CryptographicOperations.FixedTimeEquals(token.TokenSha256, Convert.FromHexString(saved.TokenSha256))) throw EmailPilotProtection.Invalid();
    }

    internal async Task SaveIssuedLockedAsync(EmailPilotLookupWorkScope scope, AuthToken token, DateTimeOffset issuedAt, CancellationToken ct)
    {
        var db = database();
        if (db.Database.CurrentTransaction is null || !Live(scope.Manifest) || scope.Until <= Now ||
            !TokenShape(token, scope.Request) || token.UsedAt is not null || token.ExpiresAt <= Now || token.ExpiresAt > scope.Request.ExpiresAt ||
            issuedAt < scope.Request.RequestedAt || issuedAt > Now || issuedAt.Offset != TimeSpan.Zero ||
            await db.EmailPilotLookupTokens.AnyAsync(x => x.RequestId == scope.Request.RequestId && x.Attempt == scope.Lease.Attempt, ct))
            throw EmailPilotProtection.Invalid();
        var value = new EmailPilotLookupTokenBinding(EmailPilotLookupRules.Version, token.Id, scope.Manifest.RunId,
            scope.Request.RequestId, scope.Lease.Attempt, Convert.ToHexStringLower(token.TokenSha256), Convert.ToBase64String(token.RowVersion), issuedAt, token.ExpiresAt);
        if (!EmailPilotLookupRules.Shape(value)) throw EmailPilotProtection.Invalid();
        db.EmailPilotLookupTokens.Add(new() { Id = token.Id, RunId = value.RunId, RequestId = value.RequestId, Attempt = value.Attempt,
            TokenSha256 = token.TokenSha256.ToArray(), IssuedRevision = value.IssuedRevision, IssuedAt = value.IssuedAt, ExpiresAt = value.ExpiresAt,
            ProtectedBinding = protection().Protect(value.RunId, "lookup-token", value) });
        await db.SaveChangesAsync(ct);
    }

    // Call BEFORE acquiring the lookup token update lock. This takes the exact
    // completion parent first, matching delivery and packet-handoff lock order.
    internal async Task<EmailPilotLookupTokenScope> TokenLockedAsync(Guid tokenId, string email, CancellationToken ct)
    {
        var db = database();
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("Pilot lookup token checks require a transaction.");
        var marker = await db.AuthTokens.AsNoTracking().SingleOrDefaultAsync(x => x.Id == tokenId, ct);
        var row = await db.EmailPilotLookupTokens.AsNoTracking().SingleOrDefaultAsync(x => x.Id == tokenId, ct);
        if (marker?.EmailPilotLookupRequestId is null && row is null) return new(false, true);
        try
        {
            if (row is null) return new(true, false);
            var saved = Decode(row);
            var requestRow = await db.EmailPilotLookupRequests.AsNoTracking().SingleOrDefaultAsync(x => x.RequestId == saved.RequestId, ct);
            if (requestRow is null) return new(true, false);
            var request = Decode(requestRow);
            var current = await ReadRequestLockedAsync(request, ct);
            if (!TokenShape(marker, request) || saved.RunId != request.RunId || saved.IssuedAt < request.RequestedAt || saved.IssuedAt > Now ||
                saved.ExpiresAt > request.ExpiresAt || marker!.ExpiresAt != saved.ExpiresAt || email != current.Run.Mailboxes.Sender ||
                Convert.ToHexStringLower(marker.TokenSha256) != saved.TokenSha256 || current.Payload.Issued is not { } issued ||
                issued.Id != tokenId || issued.Revision != saved.IssuedRevision || issued.Sha256 != saved.TokenSha256 || issued.ExpiresAt != saved.ExpiresAt ||
                marker.UsedAt is null && (marker.ExpiresAt <= Now || Convert.ToBase64String(marker.RowVersion) != saved.IssuedRevision) ||
                marker.UsedAt is not null && (marker.UsedAt < saved.IssuedAt || marker.UsedAt >= saved.ExpiresAt || marker.UsedAt > Now) || !Live(current.Run))
                return new(true, false);
            return new(true, true, request, current.Run);
        }
        catch (Exception e) when (SourceError(e)) { return new(true, false); }
    }

    internal async Task<EmailPilotLookupTokenScope> TokenAsync(Guid tokenId, string email, CancellationToken ct)
    {
        var db = database();
        if (db.Database.CurrentTransaction is not null) return await TokenLockedAsync(tokenId, email, ct);
        if (db.ChangeTracker.HasChanges()) throw new InvalidOperationException("Pilot lookup token checks require a clean context.");
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(ct), ct);
        EmailPilotLookupTokenScope value;
        await using (var tx = await db.Database.BeginTransactionAsync(ct))
        {
            value = await TokenLockedAsync(tokenId, email, ct);
            await tx.CommitAsync(ct);
        }
        return value.IsPilot && value.Allowed && (!Live(value.Manifest!) || value.Request!.ExpiresAt <= Now) ? new(true, false) : value;
    }

    private static bool TokenShape(AuthToken? token, EmailPilotLookupRequestBinding request) => token is not null && token.Id != Guid.Empty &&
        token.Purpose == TokenPurpose.Lookup && token.PartyType == PartyType.System && token.PartyId is null && token.EnvelopeId is null && token.Email == "" && token.Ip is null &&
        token.EmailPilotLookupRequestId == request.RequestId && token.TokenSha256 is { Length: 32 } && token.RowVersion is { Length: 8 } &&
        token.DocumentId is null && token.DocumentSha256 is null && token.DisclosureSha256 is null && token.SignerContactRevisionId is null &&
        token.CompletionPublicationId is null && token.CompletionRecipeSha256 is null && token.CompletionPartySha256 is null;
}
