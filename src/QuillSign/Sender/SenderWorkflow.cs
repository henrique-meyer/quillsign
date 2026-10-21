using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Work;
using QuillSign.Legal;
using QuillSign.Lifecycle;

namespace QuillSign.Sender;

public sealed class SenderOptions
{
    public int SessionHours { get; set; } = 2;
    public int DailyRequests { get; set; } = 5;
    public int RequestsPerWindow { get; set; } = 20;
    public int WindowMinutes { get; set; } = 10;
}

public sealed record VerifiedSender(Guid EnvelopeId, string PublicId, string Email,DateTimeOffset? AccessExpiresAt=null);
public enum SenderRequestOutcome { Neutral, Unavailable }

public sealed class SenderAvailability(EmailOptions email, WorkOptions work, IConfiguration config)
{
    public bool CanVerify => !string.IsNullOrWhiteSpace(config.GetConnectionString("Database")) && config["Storage:Provider"] is "Azure" or "Azurite";
    public bool CanSend => CanVerify && email.Enabled && work.Enabled;
}

public sealed class SenderWorkflow(QuillSignDbContext db, SenderOptions options, SenderAvailability availability,
    Func<EmailOutboxWriter> getOutbox, AuditWriter audit, TimeProvider time,Email.Pilot.EmailPilotReadBounds? pilotBounds=null,
    RecordLifecycleOptions? lifecycle=null,ElectronicRecordOptions? electronicRecords=null)
{
    // Internal opt-in wiring while the complete production mutation surface is
    // being integrated. The public/default constructor preserves demo behavior.
    internal ProductionRecordOperationAdmission? HoldAdmission { get; init; }

    public async Task<SenderRequestOutcome> RequestAsync(string address, string? ip, string? userAgent, CancellationToken cancellationToken = default)
    {
        DemandStandaloneCaller();
        var email = EmailAddress.Normalize(address);
        if (!availability.CanSend) return SenderRequestOutcome.Unavailable;
        if(lifecycle is not null) {
            try {var admission=ProductionRetentionAdmission.Prepare(email,time.GetUtcNow(),lifecycle,electronicRecords??new());
                if(!admission.Envelope.IsDemo&&HoldAdmission?.ProductionAdmissionEnabled==false)return SenderRequestOutcome.Unavailable;}
            catch(Exception error) when(error is InvalidOperationException or InvalidDataException or DisclosureRejectedException or ArgumentException)
            {return SenderRequestOutcome.Unavailable;}
        }
        var outbox = getOutbox();
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(cancellationToken), cancellationToken);
        Guid workId; Guid recordId; bool production;
        await using (var transaction = await db.Database.BeginTransactionAsync(cancellationToken))
        {
            var lockName = "sender-request:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(email)));
            await db.Database.ExecuteSqlInterpolatedAsync($"""
                DECLARE @result int;
                EXEC @result = sys.sp_getapplock @Resource = {lockName}, @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = 5000;
                IF @result < 0 THROW 50002, 'Sender request is temporarily busy.', 1;
                """, cancellationToken);
            var now = time.GetUtcNow();
            var start = new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero);
            if (await db.Envelopes.CountAsync(x => x.SenderEmail == email && x.CreatedAt >= start, cancellationToken) >= options.DailyRequests ||
                await db.Suppressions.AnyAsync(x => x.Email == email, cancellationToken)) return SenderRequestOutcome.Neutral;
            Envelope envelope;
            DemoCreationOrigin? demoOrigin=null;
            if(lifecycle is null) {
                envelope = new Envelope { SenderEmail = email, CreatedAt = now, IsDemo = true };
                db.Envelopes.Add(envelope);
                if(HoldAdmission?.AuthenticatedDemoOrigin==true)demoOrigin=ProductionDemoOrigin.CaptureNew(db,envelope,time);
                await db.SaveChangesAsync(cancellationToken);
            } else {
                var admission=new ProductionRetentionAdmission(db,audit,time,HoldAdmission);
                envelope=await admission.CreateLockedAsync(email,lifecycle,electronicRecords??new(),cancellationToken);
                demoOrigin=admission.OriginalDemoOrigin;
            }
            recordId = envelope.Id; production = !envelope.IsDemo;
            await audit.AppendAsync(envelope.Id, "draft_created", email, ip, userAgent, cancellationToken);
            await audit.AppendAsync(envelope.Id, "sender_verification_requested", email, ip, userAgent, cancellationToken);
            workId = demoOrigin is null ? await outbox.PrepareVerificationAsync(envelope.Id, email, cancellationToken) :
                await outbox.PrepareInitialDemoVerificationAsync(envelope,demoOrigin,cancellationToken);
            await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,cancellationToken);
        }
        // The durable hint may already exist, but a gated worker cannot claim
        // until this exact fresh-record baseline has been witnessed. Never
        // bootstrap an arbitrary legacy/held record from an empty chain.
        if (production && HoldAdmission is not null)
            await HoldAdmission.InitializeAsync(recordId, cancellationToken);
        await outbox.PublishCommittedAsync(workId, cancellationToken);
        return SenderRequestOutcome.Neutral;
    }

    public async Task<VerifiedSender?> VerifyAsync(string? rawToken, string? ip, string? userAgent, CancellationToken cancellationToken = default)
    {
        DemandStandaloneCaller();
        if (rawToken is null || !Regex.IsMatch(rawToken, "^[A-Za-z0-9_-]{43}$", RegexOptions.CultureInvariant)) return null;
        if (HoldAdmission is null) return await VerifyCoreAsync(rawToken, ip, userAgent, cancellationToken);
        var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        var original = await db.AuthTokens.AsNoTracking().Where(x => x.TokenSha256 == tokenHash && x.Purpose == TokenPurpose.SenderVerify && x.PartyType == PartyType.Sender)
            .Select(x => new { x.Id, x.EnvelopeId, x.UsedAt, x.ExpiresAt }).SingleOrDefaultAsync(cancellationToken);
        if (original?.EnvelopeId is not { } recordId || original.UsedAt is not null || original.ExpiresAt <= time.GetUtcNow()) return null;
        var record = await db.Envelopes.AsNoTracking().Where(x => x.Id == recordId).Select(x => new { x.IsDemo, x.Status, x.SenderVerifiedAt }).SingleOrDefaultAsync(cancellationToken);
        if (record is null || record.Status != EnvelopeStatus.Draft || record.SenderVerifiedAt is not null) return null;
        if (record.IsDemo)
        {
            try
            {
                if (await HoldAdmission.IsUnenrolledDemoAsync(db, recordId, cancellationToken))
                    return await VerifyCoreAsync(rawToken, ip, userAgent, cancellationToken);
            }
            catch (Exception error) when (error is InvalidDataException or UnauthorizedAccessException or DocumentConflictException)
            { return null; }
        }
        ProductionRecordOperation operation;
        try { operation = await HoldAdmission.BeginAsync(recordId, Guid.NewGuid(), "sender/verify", original.Id.ToString("N"), cancellationToken); }
        catch (Exception error) when (error is InvalidDataException or UnauthorizedAccessException or DocumentConflictException)
        { return null; }
        // SQL-only verification has no provider dispatch. The core transaction
        // has been disposed before settlement. An exception/unknown commit keeps
        // the original reservation closed for explicit reconciliation.
        var result = await VerifyCoreAsync(rawToken, ip, userAgent, cancellationToken, operation);
        var receipt = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
            { Version = "production-sender-verify-v1", recordId, TokenId = original.Id, Verified = result is not null })));
        await HoldAdmission.CompleteAsync(operation, receipt, cancellationToken);
        return result;
    }

    private async Task<VerifiedSender?> VerifyCoreAsync(string rawToken, string? ip, string? userAgent, CancellationToken cancellationToken, ProductionRecordOperation? operation = null)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(rawToken));
        await SqlResume.RunAsync(() => db.Database.OpenConnectionAsync(cancellationToken), cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        if (operation is not null)
        {
            _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {operation.RecordId}")
                .AsNoTracking().SingleAsync(cancellationToken);
            await HoldAdmission!.DemandStartingLockedAsync(db, operation, cancellationToken);
        }
        var token = await db.AuthTokens.FromSqlInterpolated($"SELECT * FROM [AuthTokens] WITH (UPDLOCK, HOLDLOCK) WHERE [TokenSha256] = {hash}")
            .SingleOrDefaultAsync(cancellationToken);
        var now = time.GetUtcNow();
        if (token is null || token.Purpose != TokenPurpose.SenderVerify || token.PartyType != PartyType.Sender ||
            token.EnvelopeId is null || token.UsedAt is not null || token.ExpiresAt <= now) return null;
        var envelope = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {token.EnvelopeId}")
            .SingleOrDefaultAsync(cancellationToken);
        if (envelope is null || envelope.Status != EnvelopeStatus.Draft || envelope.SenderVerifiedAt is not null ||
            !string.Equals(envelope.SenderEmail, token.Email, StringComparison.OrdinalIgnoreCase)) return null;
        DateTimeOffset? accessEnd=null;
        try {
            accessEnd=await QuillSign.Documents.DocumentRetentionAccess.ReadAsync(db,envelope,time,cancellationToken,pilotBounds);
            QuillSign.Documents.DocumentRetentionAccess.Check(accessEnd,time);
        }
        catch(Email.Pilot.EmailPilotAccessUnavailableException){return null;}
        catch(QuillSign.Documents.DocumentRetentionExpiredException){return null;}
        token.UsedAt = now;
        envelope.SenderVerifiedAt = now;
        await audit.AppendAsync(envelope.Id, "sender_email_verified", token.Email, ip, userAgent, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        if(pilotBounds is not null) {
            var current=await pilotBounds.ReadAsync(envelope,cancellationToken);
            accessEnd=Email.Pilot.EmailPilotReadBounds.Earlier(accessEnd,current);
            if(accessEnd<=time.GetUtcNow())return null;
        }
        if (operation is not null)
        {
            await HoldAdmission!.PrepareOutcomeLockedAsync(db, operation, cancellationToken);
            DocumentRetentionAccess.Check(accessEnd, time);
            if (token.ExpiresAt <= time.GetUtcNow()) throw new DocumentConflictException();
        }
        await QuillSign.Email.Pilot.EmailPilotReadBounds.CommitAsync(pilotBounds,transaction,cancellationToken);
        return accessEnd<=time.GetUtcNow() ? null : new(envelope.Id, envelope.PublicId, token.Email,accessEnd);
    }

    private void DemandStandaloneCaller()
    {
        if (HoldAdmission is not null && (db.Database.CurrentTransaction is not null || db.ChangeTracker.HasChanges()))
            throw new InvalidOperationException("Production sender admission requires a clean standalone context.");
    }
}
