using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Work;

internal sealed record ResendSaved(EmailOutbox Row, WorkItem Work, ResendMail Mail);

internal sealed class InvitationResendRules(QuillSignDbContext db, InvitationResendOptions limits, InvitationResendProtection protection, TimeProvider time,
    InvitationSuccessorProtection? successors=null)
{
    // Damaged index keys must not make latest lookups lose an admission.
    // Return one scalar; never load unbounded historical payloads.
    internal static async Task VerifyIndexAsync(QuillSignDbContext db, Guid envelopeId, CancellationToken ct, TimeProvider? time=null)
    {
        var historicalRecipients=false;
        if(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==envelopeId && x.Event==SignerContactHistory.Event,ct)) {
            if(time is null)throw Invalid();
            var parent=await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH(UPDLOCK,HOLDLOCK) WHERE [Id]={envelopeId}")
                .AsNoTracking().SingleOrDefaultAsync(ct)??throw Invalid();
            var contacts=await new SignerContactState(db,time).ReadHistoryLockedAsync(parent,ct);
            var entries=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==envelopeId && x.Event==InvitationResendProtection.Event)
                .OrderBy(x=>x.Sequence).Take(513).ToArrayAsync(ct);
            if(entries.Length>512)throw Invalid();
            foreach(var entry in entries) {
                var request=InvitationResendProtection.ReadEvidence(entry);
                if(contacts.Resolve(request.SignerId,SignerContactEpoch.Legacy)?.Email!=request.Email)throw Invalid();
            }
            historicalRecipients=true;
        }
        var invalid = await db.Database.SqlQuery<int>($"""
            SELECT CAST(CASE WHEN
                (SELECT COUNT_BIG(*) FROM [AuditEvents] WHERE [EnvelopeId]={envelopeId} AND [Event]='invitation_resend_requested') <>
                (SELECT COUNT_BIG(*) FROM [EmailOutbox] WHERE [EnvelopeId]={envelopeId} AND [Template]='signer-invitation-resend')
                OR EXISTS (
                    SELECT 1 FROM [EmailOutbox] m WHERE m.[EnvelopeId]={envelopeId} AND m.[Template]='signer-invitation-resend'
                    AND NOT EXISTS (SELECT 1 FROM [AuditEvents] a WHERE a.[EnvelopeId]=m.[EnvelopeId] AND a.[Event]='invitation_resend_requested'
                        AND TRY_CONVERT(uniqueidentifier,JSON_VALUE(a.[DataJson],'$.id'))=m.[Id])
                )
                OR EXISTS (
                    SELECT 1 FROM [AuditEvents] a
                    LEFT JOIN [EmailOutbox] m ON m.[Id]=TRY_CONVERT(uniqueidentifier,JSON_VALUE(a.[DataJson],'$.id'))
                        AND m.[EnvelopeId]=a.[EnvelopeId] AND m.[Template]='signer-invitation-resend'
                    LEFT JOIN [Signers] s ON s.[Id]=TRY_CONVERT(uniqueidentifier,JSON_VALUE(a.[DataJson],'$.signerId')) AND s.[EnvelopeId]=a.[EnvelopeId]
                    WHERE a.[EnvelopeId]={envelopeId} AND a.[Event]='invitation_resend_requested' AND (
                        DATALENGTH(a.[DataJson])>24000 OR COALESCE(JSON_VALUE(a.[DataJson],'$.version'),'')<>'resend-admission-v1'
                        OR m.[Id] IS NULL OR s.[Id] IS NULL OR ({historicalRecipients}=0 AND m.[To]<>s.[Email])
                        OR DATALENGTH(m.[PayloadJson])>24000 OR m.[AttachmentsJson]<>'[]'
                        OR COALESCE(JSON_VALUE(a.[DataJson],'$.request.id'),'')<>CONVERT(nvarchar(36),m.[Id])
                        OR COALESCE(JSON_VALUE(a.[DataJson],'$.request.signerId'),'')<>CONVERT(nvarchar(36),s.[Id])
                        OR COALESCE(JSON_VALUE(a.[DataJson],'$.request.envelopeId'),'')<>CONVERT(nvarchar(36),a.[EnvelopeId])
                        OR COALESCE(JSON_VALUE(a.[DataJson],'$.request.email'),'')<>m.[To])
                ) THEN 1 ELSE 0 END AS int) AS [Value]
            """).SingleAsync(ct);
        if (invalid != 0) throw Invalid();
    }

    internal static Task LockAsync(QuillSignDbContext db, CancellationToken ct) => db.Database.ExecuteSqlRawAsync("""
        DECLARE @result int;
        EXEC @result = sys.sp_getapplock @Resource=N'invitation-resend-v1', @LockMode='Exclusive', @LockOwner='Transaction', @LockTimeout=5000;
        IF @result < 0 THROW 50002, 'Invitation resend is temporarily busy.', 1;
        """, ct);

    // Also used by original dispatch under the envelope lock: an old original
    // invitation must never become active again after a replacement was admitted.
    private static IQueryable<AuditEvent> LatestAuditQuery(QuillSignDbContext db, Guid envelopeId, Guid signerId) =>
        db.AuditEvents.FromSqlInterpolated($"""
            SELECT TOP(1) * FROM [AuditEvents] WHERE [EnvelopeId]={envelopeId} AND [Event]='invitation_resend_requested'
            AND JSON_VALUE([DataJson],'$.signerId')={signerId.ToString()} ORDER BY [Sequence] DESC
            """).AsNoTracking();
    internal static async Task<AuditEvent?> LatestAuditAsync(QuillSignDbContext db, Guid envelopeId, Guid signerId, CancellationToken ct)
    {
        var query = LatestAuditQuery(db, envelopeId, signerId);
        var size = await query.Select(x => EF.Functions.DataLength(x.DataJson)).SingleOrDefaultAsync(ct);
        if (size > 24000) throw Invalid();
        return await query.SingleOrDefaultAsync(ct);
    }

    internal async Task<ResendSaved?> LatestAsync(Guid envelopeId, Guid signerId, CancellationToken ct)
    {
        var audit = await LatestAuditAsync(db, envelopeId, signerId, ct);
        return audit is null ? null : await FromAuditAsync(audit, ct);
    }
    internal async Task<ResendSaved?> FindAsync(Guid id, Guid envelopeId, CancellationToken ct)
    {
        var events = await db.AuditEvents.FromSqlInterpolated($"""
            SELECT * FROM [AuditEvents] WHERE [EnvelopeId]={envelopeId} AND [Event]='invitation_resend_requested'
            AND JSON_VALUE([DataJson],'$.id')={id.ToString()}
            """).AsNoTracking().Take(2).ToArrayAsync(ct);
        if (events.Length > 1) throw Invalid();
        return events.Length == 0 ? null : await FromAuditAsync(events[0], ct);
    }
    internal async Task<ResendSaved> FromAuditAsync(AuditEvent audit, CancellationToken ct)
    {
        var p = InvitationResendProtection.ReadEvidence(audit);
        var size = await db.EmailOutbox.Where(x => x.Id == p.Id).Select(x => new { Payload = EF.Functions.DataLength(x.PayloadJson), Attachments = EF.Functions.DataLength(x.AttachmentsJson) }).SingleOrDefaultAsync(ct);
        if (size is null || size.Payload > 24000 || size.Attachments != 4) throw Invalid();
        var row = await db.EmailOutbox.AsNoTracking().SingleOrDefaultAsync(x => x.Id == p.Id, ct) ?? throw Invalid();
        var mail = protection.Read(row);
        var work = await db.WorkItems.AsNoTracking().SingleOrDefaultAsync(x => x.Id == p.Id, ct) ?? throw Invalid();
        if (mail.Request != p || work.EnvelopeId != p.EnvelopeId || work.Kind != WorkKind.Email || !Enum.IsDefined(work.Status) ||
            work.PayloadJson != JsonSerializer.Serialize(new { emailId = p.Id })) throw Invalid();
        return new(row, work, mail);
    }
    internal async Task<bool> WithinCapsAsync(ResendRequest candidate, bool reserved, CancellationToken ct)
    {
        return await new InvitationResendReservations(db,protection,successors,limits,time).WithinAsync(candidate,reserved,ct);
    }
    internal async Task<bool> SettledAsync(EmailOutbox row, WorkItem work, Guid signerId, string documentSha256, string disclosureSha256, Guid? tokenId, CancellationToken ct)
    {
        if (work.Kind != WorkKind.Email || work.EnvelopeId != row.EnvelopeId || work.Id != row.Id ||
            work.LeaseOwner is not null || work.LeaseExpiresAt is not null || work.Status is not (WorkStatus.Completed or WorkStatus.Failed)) return false;
        if (work.Status == WorkStatus.Failed && row.Status == EmailStatus.Failed && row.SubmissionStartedAt is null &&
            row.Provider is null && row.ProviderMessageId is null && row.LastError != "submission-ambiguous" && work.LastError != "submission-ambiguous") return true;
        if (work.Status != WorkStatus.Completed || row.Status is not (EmailStatus.Sent or EmailStatus.Bounced or EmailStatus.Complained) ||
            row.SubmissionStartedAt is null || row.SubmissionStartedAt > time.GetUtcNow() || tokenId is null || string.IsNullOrWhiteSpace(row.Provider) || string.IsNullOrWhiteSpace(row.ProviderMessageId)) return false;
        var name = row.Template switch {
            InvitationResendProtection.Template => "invitation_resend_submitted",
            InvitationSuccessorProtection.Template => InvitationSuccessorProtection.ReceiptEvent,
            "signer-invitation" => "invitation_submitted", _ => throw Invalid()
        };
        var receipts = await db.AuditEvents.FromSqlInterpolated($"""
            SELECT * FROM [AuditEvents] WHERE [EnvelopeId]={row.EnvelopeId} AND [Event]={name}
            AND JSON_VALUE([DataJson],'$.emailId')={row.Id.ToString()}
            """).AsNoTracking().Take(2).ToArrayAsync(ct);
        if (receipts.Length != 1) return false;
        var receipt = receipts[0];
        if (receipt.ActorType != PartyType.System || receipt.ActorId is not null || receipt.ActorEmail is not null || receipt.At < row.SubmissionStartedAt ||
            receipt.At > time.GetUtcNow() || receipt.DataJson.Length > 8000 || !CryptographicOperations.FixedTimeEquals(AuditHash.Compute(receipt), receipt.Hash)) throw Invalid();
        try {
            using var json = JsonDocument.Parse(receipt.DataJson); var root = json.RootElement;
            return root.GetProperty("emailId").GetGuid() == row.Id && root.GetProperty("signerId").GetGuid() == signerId &&
                root.GetProperty("tokenId").GetGuid() == tokenId && root.GetProperty("documentSha256").GetString() == documentSha256 &&
                root.GetProperty("disclosureSha256").GetString() == disclosureSha256 &&
                root.GetProperty("recipient").GetString() == row.To && root.GetProperty("provider").GetString() == row.Provider &&
                root.GetProperty("providerMessageId").GetString() == row.ProviderMessageId &&
                root.GetProperty("meaning").GetString() == "provider_accepted_not_proof_of_delivery";
        } catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException) { throw Invalid(); }
    }
    internal static InvalidDataException Invalid() => InvitationResendProtection.Invalid();
}
