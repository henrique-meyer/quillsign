using System.Net.Mail;
using System.Text.Json;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal static partial class ProductionCompletionInputCodec
{
    internal sealed record CompletionStages(Guid Id, Guid EnvelopeId, byte[] RecipeSha256, byte[] RowVersion,
        byte[] FrozenStateSha256, long AuditSequence, byte[] AuditAnchor, CompletionStageOutput[] outputs);
    internal sealed record CompletionStageOutput(Guid Id, Guid PdfObjectId, CompletionSealKind Kind, byte[] RecipeSha256,
        byte[] RowVersion, long AuditSequence, byte[] AuditHash, byte[] Sha256);
    private static readonly string[] EnvelopeColumns = ["Id", "PublicId", "Status", "SenderEmail", "SenderName", "SenderVerifiedAt", "Title", "Message", "ReminderDaysJson", "ExpiresAt",
        "ErsdVersion", "ErsdText", "ErsdSha256", "ExclusionsAckAt", "OriginalBlob", "OriginalSha256", "OriginalMime", "PdfBlob", "PdfSha256", "PageCount", "PageSizesJson",
        "PreviewConfirmedAt", "SentPdfBlob", "SentPdfSha256", "CurrentFinishId", "CurrentCopyVersion", "FinalBlob", "FinalSha256", "CertificateBlob", "CertificateSha256",
        "SealCertThumbprint", "SealProvider", "TsaUrl", "AiRolesJson", "AiModel", "CreatedAt", "SentAt", "CompletedAt", "PurgeAfter", "IsDemo", "RowVersion"];
    private static readonly string[] IntentColumns = ["Id", "EnvelopeId", "CandidateId", "ExecutedOutputId", "CertificateOutputId", "ExecutedObjectId", "CertificateObjectId",
        "BeforeEnvelopeJson", "StageBindingsJson", "RetentionDays", "DevelopmentWriteOnce", "PreparedAt", "RecipeSha256", "RowVersion"];
    private static readonly string[] ResultColumns = ["Id", "EnvelopeId", "IntentId", "FinalDocumentsJson", "CompletedAt", "AfterEnvelopeSha256", "IntentRecipeSha256", "RecipeSha256", "AuditSequence", "RowVersion"];
    private static void ValidatePublicationResult(CompletionInputV1 body)
    {
        Shape<Envelope>(EnvelopeColumns); Shape<CompletionPublicationIntent>(IntentColumns); Shape<CompletionPublicationResult>(ResultColumns);
        var value = body.Publication!; var row = value.Result; var intent = value.Intent;
        if (row is null || intent is null || value.Before is null || value.Completed is null || value.Files is null || value.Notifications is null ||
            body.Context.Slot != CompletionSlot.PublicationResult || row.Id == Guid.Empty || row.EnvelopeId != body.RecordId || row.IntentId != intent.Id ||
            value.Files.ResultId != row.Id || row.CompletedAt != body.RecordedAt || row.AuditSequence != body.AuditCut.Sequence + 1 || row.RowVersion is not { Length: 0 } ||
            row.AfterEnvelopeSha256 is not { Length: 0 } || row.RecipeSha256 is not { Length: 0 } ||
            !row.IntentRecipeSha256.AsSpan().SequenceEqual(intent.RecipeSha256) || intent.EnvelopeId != body.RecordId ||
            !CompletionPublication.Recipe(intent).AsSpan().SequenceEqual(intent.RecipeSha256) || value.Before.Id != body.RecordId || value.Before.IsDemo ||
            value.Before.Status != EnvelopeStatus.Sent || value.Completed.Id != body.RecordId || value.Completed.Status != EnvelopeStatus.Completed ||
            value.Completed.CompletedAt != body.RecordedAt || value.Before.RowVersion is not { Length: 8 } ||
            !value.Completed.RowVersion.AsSpan().SequenceEqual(value.Before.RowVersion) ||
            intent.BeforeEnvelopeJson != JsonSerializer.Serialize(value.Before) || value.Notifications.Length is < 1 or > 201 || value.Notifications.Any(x => x is null) ||
            body.AuditCut.Sequence > 512 - 2 - value.Notifications.Length || row.CompletedAt < intent.PreparedAt ||
            value.Notifications.GroupBy(x => x.Email, StringComparer.OrdinalIgnoreCase).Any(x => x.Count() != 1)) throw Invalid();
        _ = DemandIntentFacts(intent);
        Final(value.Files.Executed, intent, FinalDocumentKind.Executed); Final(value.Files.Certificate, intent, FinalDocumentKind.Certificate);
        var documents = JsonSerializer.Serialize(new { value.Files.Executed, value.Files.Certificate });
        if (row.FinalDocumentsJson != documents || value.Completed.FinalBlob != intent.ExecutedObjectId.ToString("N") ||
            value.Completed.CertificateBlob != intent.CertificateObjectId.ToString("N") ||
            !value.Completed.FinalSha256!.AsSpan().SequenceEqual(value.Files.Executed.Sha256) ||
            !value.Completed.CertificateSha256!.AsSpan().SequenceEqual(value.Files.Certificate.Sha256) ||
            value.Completed.PurgeAfter != CompletionRetentionBinding.RequiredUntil(intent, body.RecordedAt)) throw Invalid();
        if (value.Files.Executed.Document.ObjectId != body.Context.Targets.Single(x => x.Effect == CompletionEffect.PublicationExecutedFinal).TargetId ||
            value.Files.Certificate.Document.ObjectId != body.Context.Targets.Single(x => x.Effect == CompletionEffect.PublicationCertificateFinal).TargetId) throw Invalid();
        foreach (var member in value.Notifications)
            if (member is null || member.Type is not (PartyType.Sender or PartyType.Signer or PartyType.Recipient) ||
                member.Email is not { Length: > 0 and <= 320 } || !MailAddress.TryCreate(member.Email, out var parsed) || parsed.Address != member.Email ||
                member.Name is { Length: > 512 } || (member.Type == PartyType.Sender ? member.Id is not null || member.Order is not null : member.Id is null || member.Id == Guid.Empty) ||
                (member.Type == PartyType.Signer ? member.Order is < 1 or > 100 or null : member.Order is not null)) throw Invalid();
        var mutable = new HashSet<string>(["Status", "CompletedAt", "FinalBlob", "FinalSha256", "CertificateBlob", "CertificateSha256", "SealProvider", "SealCertThumbprint", "PurgeAfter"], StringComparer.Ordinal);
        var before = JsonSerializer.SerializeToElement(value.Before); var completed = JsonSerializer.SerializeToElement(value.Completed);
        if (before.EnumerateObject().Where(x => !mutable.Contains(x.Name)).Any(x => !JsonElement.DeepEquals(x.Value, completed.GetProperty(x.Name)))) throw Invalid();
        if (intent.BeforeEnvelopeJson.Length > 262144 || intent.StageBindingsJson.Length > 16384) throw Invalid();
        _ = Nested(intent.StageBindingsJson); _ = Nested(row.FinalDocumentsJson);
    }
    internal static CompletionStages DemandIntentFacts(CompletionPublicationIntent row)
    {
        Shape<Envelope>(EnvelopeColumns); Shape<CompletionPublicationIntent>(IntentColumns);
        var before = JsonSerializer.Deserialize<Envelope>(Nested(row.BeforeEnvelopeJson), Json) ?? throw Invalid();
        if (JsonSerializer.Serialize(before, Json) != row.BeforeEnvelopeJson || before.Id != row.EnvelopeId || before.IsDemo ||
            before.Status != EnvelopeStatus.Sent || before.RowVersion is not { Length: 8 } || before.CompletedAt is not null ||
            before.FinalBlob is not null || before.FinalSha256 is not null || before.CertificateBlob is not null || before.CertificateSha256 is not null ||
            before.SealProvider is not null || before.SealCertThumbprint is not null) throw Invalid();
        var production = ProductionCompletionRetentionBinding.Read(row) ?? throw Invalid();
        var raw = production.Stages.GetRawText();
        var stages = JsonSerializer.Deserialize<CompletionStages>(Nested(raw), Json) ?? throw Invalid();
        // The existing retention producer serializes Stages as a JsonElement.
        // That writer escapes decoded '+' in base64 strings, whereas directly
        // serializing a typed byte[] writes raw '+'. Reproduce the SAME nested
        // writer; preserve every retained recipe byte and the closed schema.
        var canonical = JsonSerializer.Serialize(JsonSerializer.SerializeToElement(stages, Json), Json);
        if (canonical != raw || stages.Id != row.CandidateId || stages.EnvelopeId != row.EnvelopeId ||
            !Hash32(stages.RecipeSha256) || stages.RowVersion is not { Length: 8 } || !Hash32(stages.FrozenStateSha256) ||
            stages.AuditSequence is < 1 or > 512 || !Hash32(stages.AuditAnchor) || stages.outputs is not { Length: 2 } ||
            stages.outputs[0]?.Id != row.ExecutedOutputId || stages.outputs[1]?.Id != row.CertificateOutputId ||
            stages.outputs[0].Kind != CompletionSealKind.Executed || stages.outputs[1].Kind != CompletionSealKind.Certificate ||
            stages.outputs.Any(x => x.Id == Guid.Empty || x.PdfObjectId == Guid.Empty || !Hash32(x.RecipeSha256) || x.RowVersion is not { Length: 8 } ||
                x.AuditSequence is < 1 or > 512 || !Hash32(x.AuditHash) || !Hash32(x.Sha256)) ||
            stages.outputs[0].Id == stages.outputs[1].Id || stages.outputs[0].PdfObjectId == stages.outputs[1].PdfObjectId ||
            stages.AuditSequence >= stages.outputs[0].AuditSequence || stages.outputs[0].AuditSequence >= stages.outputs[1].AuditSequence) throw Invalid();
        return stages;
    }
    private static void Final(FinalStoredDocument file, CompletionPublicationIntent intent, FinalDocumentKind kind)
    {
        if (file is null || file.Document.EnvelopeId != intent.EnvelopeId || file.Document.Kind != kind ||
            file.Document.ObjectId != (kind == FinalDocumentKind.Executed ? intent.ExecutedObjectId : intent.CertificateObjectId) ||
            file.Length is < 1 or > 64 * 1024 * 1024 || !Hash32(file.Sha256) || file.VersionId is not { Length: > 0 and <= 512 } ||
            file.ETag is not { Length: >= 3 and <= 256 } || file.ETag[0] != '"' || file.ETag[^1] != '"' ||
            file.CreatedAt == default || file.CreatedAt.Offset != TimeSpan.Zero || file.Protection is not (FinalProtection.LockedTime or FinalProtection.LegalHold) ||
            file.Protection == FinalProtection.LockedTime && (file.ProtectedUntil is null || file.ProtectedUntil < intent.PreparedAt)) throw Invalid();
    }
}
