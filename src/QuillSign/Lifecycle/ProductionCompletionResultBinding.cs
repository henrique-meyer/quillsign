using System.Data.SqlTypes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

internal static partial class ProductionCompletionInputRows
{
    private static void BindResult(CompletionInputV1 body, IDataProtectionProvider keys, JsonElement sql, List<CompletionSqlRow> rows)
    {
        var original = body.Publication!; var before = original.Before;
        var envelope = Entity<Envelope>(sql, "Envelopes", body.RecordId.ToString("N"));
        if (envelope.RowVersion.AsSpan().SequenceEqual(before.RowVersion)) throw ProductionCompletionInputCodec.Invalid();
        MatchVersioned(original.Completed, envelope);
        var expected = JsonSerializer.Deserialize<CompletionPublicationResult>(JsonSerializer.SerializeToUtf8Bytes(original.Result, Sql), Sql) ?? throw ProductionCompletionInputCodec.Invalid();
        expected.AfterEnvelopeSha256 = PublishedCompletionSource.Digest(envelope); expected.RecipeSha256 = CompletionPublication.Recipe(expected);
        var actual = Entity<CompletionPublicationResult>(sql, "CompletionPublicationResults", expected.Id.ToString("N"));
        MatchVersioned(expected, actual);
        var intent = Entity<CompletionPublicationIntent>(sql, "CompletionPublicationIntents", original.Intent.Id.ToString("N"));
        if (JsonSerializer.Serialize(intent, Sql) != JsonSerializer.Serialize(original.Intent, Sql)) throw ProductionCompletionInputCodec.Invalid();
        Add(rows, sql, "Envelopes", body.RecordId.ToString("N"), Canonical(JsonSerializer.SerializeToElement(before, Sql), false));
        Add(rows, sql, "CompletionPublicationResults", expected.Id.ToString("N"));

        var policy = Entity<ProductionRetentionPolicyRecord>(sql, "ProductionRetentionPolicies", body.RecordId.ToString("N"));
        var terminal = Entity<ProductionRetentionTerminalRecord>(sql, "ProductionRetentionTerminals", body.RecordId.ToString("N"));
        // Terminal is inserted before its audit rows in selector order, but its
        // proof is derived only from the actual canonical completed audit.
        Add(rows, sql, "ProductionRetentionTerminals", body.RecordId.ToString("N"));
        var completed = Audit(rows, sql, body, body.AuditCut.Sequence + 1, body.AuditCut.Sha256, "completed", CompletionPublication.Evidence(expected));
        var wanted = new ProductionRetentionTerminalRecord { EnvelopeId = body.RecordId, Status = EnvelopeStatus.Completed,
            PolicySha256 = policy.PolicySha256, OriginalAt = body.RecordedAt, ClockAt = ProductionRetentionLedger.Seconds(body.RecordedAt),
            RecordedAt = body.RecordedAt, SourceAuditSequence = completed.Sequence, SourceAuditHash = completed.Hash.ToArray() };
        var anchored = Audit(rows, sql, body, body.AuditCut.Sequence + 2, ProductionCompletionInputCodec.Hex(completed.Hash),
            ProductionRetentionLedger.TerminalEvent, ProductionRetentionLedger.TerminalJson(wanted));
        wanted.AuditSequence = anchored.Sequence; wanted.AuditHash = anchored.Hash.ToArray();
        if (JsonSerializer.Serialize(terminal, Sql) != JsonSerializer.Serialize(wanted, Sql)) throw ProductionCompletionInputCodec.Invalid();
        var members = FrozenMembers(sql, before);
        if (!members.SequenceEqual(original.Notifications)) throw ProductionCompletionInputCodec.Invalid();
        var previous = anchored.Hash; var sequence = anchored.Sequence + 1;
        foreach (var member in members)
        {
            var party = CompletionAccessState.PartyProjection(body.RecordId, actual.Id, actual.RowVersion, member.Type, member.Id, member.Email, member.Name, member.Order);
            var payload = CompletionNotificationJobs.Payload(body.RecordId, actual.Id, actual.RecipeSha256, actual.RowVersion,
                original.Files.Executed, original.Files.Certificate, party, false);
            var id = CompletionNotificationJobs.Id(payload); var mail = Entity<EmailOutbox>(sql, "EmailOutbox", id.ToString("N"));
            var read = ReadPayload(keys, mail.PayloadJson);
            if (JsonSerializer.Serialize(read) != JsonSerializer.Serialize(payload)) throw ProductionCompletionInputCodec.Invalid();
            var expectedMail = new EmailOutbox { Id = id, EnvelopeId = body.RecordId, To = member.Email, Template = CompletionNotificationJobs.Template,
                PayloadJson = mail.PayloadJson, AvailableAt = body.RecordedAt, Status = EmailStatus.Queued };
            MatchVersioned(expectedMail, mail); Add(rows, sql, "EmailOutbox", id.ToString("N"));
            var work = Entity<WorkItem>(sql, "WorkItems", id.ToString("N"));
            var expectedWork = new WorkItem { Id = id, EnvelopeId = body.RecordId, Kind = WorkKind.Email, Status = WorkStatus.Queued,
                PayloadJson = CompletionNotificationJobs.WorkJson(id), AvailableAt = body.RecordedAt };
            MatchVersioned(expectedWork, work); Add(rows, sql, "WorkItems", id.ToString("N"));
            var queued = Audit(rows, sql, body, sequence++, ProductionCompletionInputCodec.Hex(previous), "completion_notification_queued",
                CompletionNotificationJobs.Queued(id, member.Email, payload)); previous = queued.Hash;
        }
    }
    internal static CompletionNotificationPayload ReadPayload(IDataProtectionProvider keys, string raw)
    {
        var options = new JsonSerializerOptions { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
        if (raw is null || raw.Length > 8192 || Encoding.UTF8.GetByteCount(raw) > 32768) throw ProductionCompletionInputCodec.Invalid();
        ProductionCompletionInputCodec.DemandJson(Encoding.UTF8.GetBytes(raw));
        try
        {
            var wrapped = JsonSerializer.Deserialize<ProtectedWorkPayload>(raw, options) ?? throw ProductionCompletionInputCodec.Invalid();
            if (JsonSerializer.Serialize(wrapped) != raw) throw ProductionCompletionInputCodec.Invalid();
            var plain = keys.CreateProtector("QuillSign.CompletionNotification.v1").Unprotect(wrapped.Protected);
            if (plain.Length > 8192 || Encoding.UTF8.GetByteCount(plain) > 32768) throw ProductionCompletionInputCodec.Invalid();
            ProductionCompletionInputCodec.DemandJson(Encoding.UTF8.GetBytes(plain));
            var payload = JsonSerializer.Deserialize<CompletionNotificationPayload>(plain, options) ?? throw ProductionCompletionInputCodec.Invalid();
            if (!CompletionNotificationJobs.Shape(payload) || JsonSerializer.Serialize(payload) != plain) throw ProductionCompletionInputCodec.Invalid();
            return payload;
        }
        catch (Exception error) when (error is System.Security.Cryptography.CryptographicException or JsonException)
        { throw new InvalidDataException("The exact prepared completion notification cannot be authenticated.", error); }
    }
    private static CompletionNotificationRosterMember[] FrozenMembers(JsonElement sql, Envelope before)
    {
        var result = new List<CompletionNotificationRosterMember> { new(PartyType.Sender, null, before.SenderName, before.SenderEmail, null) };
        var signers = Table(sql, "Signers").Select(x => x.Deserialize<Signer>(Sql) ?? throw ProductionCompletionInputCodec.Invalid()).OrderBy(x => x.Order).ToArray();
        var recipients = Table(sql, "Recipients").Select(x => x.Deserialize<Recipient>(Sql) ?? throw ProductionCompletionInputCodec.Invalid()).OrderBy(x => new SqlGuid(x.Id)).ToArray();
        if (signers.Length is < 1 or > 100 || recipients.Length > 100 || signers.Any(x => x.EnvelopeId != before.Id) || recipients.Any(x => x.EnvelopeId != before.Id)) throw ProductionCompletionInputCodec.Invalid();
        result.AddRange(signers.Select(x => new CompletionNotificationRosterMember(PartyType.Signer, x.Id, x.FullName, x.Email, x.Order)));
        result.AddRange(recipients.Select(x => new CompletionNotificationRosterMember(PartyType.Recipient, x.Id, x.Name, x.Email, null)));
        return result.GroupBy(x => x.Email, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).ToArray();
    }
    private static IEnumerable<JsonElement> Table(JsonElement sql, string name) => sql.GetProperty("Tables").EnumerateArray()
        .Single(x => x.GetProperty("Table").GetString() == name).GetProperty("Rows").EnumerateArray();
}
