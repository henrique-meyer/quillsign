using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

// Owned before any asynchronous publication. This is a frozen local input, not
// participant authority, a generic object capability or permission to retry.
internal sealed class ProductionSignaturePreviewWrite
{
    private readonly byte[] signature, initials;
    internal string PreviewRowJson { get; }
    internal VerifiedSigner Identity { get; }
    internal DateTimeOffset AccessExpiresAt { get; }
    internal Guid PreviewId => ProductionRecordPreviewWriteContract.ReadRow(PreviewRowJson).Id;
    internal ProductionRecordWriteDescriptor Signature { get; }
    internal ProductionRecordWriteDescriptor Initials { get; }
    private ProductionSignaturePreviewWrite(SignaturePreview row, VerifiedSigner identity, DateTimeOffset access,
        NormalizedSignatureImage signature, NormalizedSignatureImage initials)
    {
        PreviewRowJson = ProductionRecordPreviewWriteContract.Row(row); Identity = identity with { }; AccessExpiresAt = access;
        row = ProductionRecordPreviewWriteContract.ReadRow(PreviewRowJson);
        this.signature = signature.Bytes; this.initials = initials.Bytes;
        Signature = new(new(row.EnvelopeId, DocumentBlobKind.Signature, row.SignatureObjectId), this.signature.Length, Convert.ToHexStringLower(SHA256.HashData(this.signature)));
        Initials = new(new(row.EnvelopeId, DocumentBlobKind.Initials, row.InitialsObjectId), this.initials.Length, Convert.ToHexStringLower(SHA256.HashData(this.initials)));
        ProductionRecordPreviewWriteContract.Validate(new(PreviewRowJson, Identity, access, null, null, new('0', 64), Signature, Initials), requireRetention: false);
        if (signature.Width != row.SignatureWidth || signature.Height != row.SignatureHeight || initials.Width != row.InitialsWidth || initials.Height != row.InitialsHeight)
            throw ProductionRecordPreviewWriteContract.Invalid();
    }
    internal static ProductionSignaturePreviewWrite Own(SignaturePreview row, VerifiedSigner identity, DateTimeOffset accessExpiresAt,
        NormalizedSignatureImage signature, NormalizedSignatureImage initials) => new(row, identity, accessExpiresAt, signature, initials);
    internal Stream Open(DocumentBlobKind member) => new MemoryStream((member switch {
        DocumentBlobKind.Signature => signature, DocumentBlobKind.Initials => initials, _ => throw ProductionRecordPreviewWriteContract.Invalid()
    }).ToArray(), false);
}

internal sealed record HoldWitnessPreviewPlan(string PreviewRowJson, VerifiedSigner Identity, DateTimeOffset AccessExpiresAt,
    DateTimeOffset? RetentionDeadline, DateTimeOffset? SigningDeadline, string BaselineProjectionSha256,
    ProductionRecordWriteDescriptor Signature, ProductionRecordWriteDescriptor Initials);
internal sealed record HoldWitnessPreviewWrites(HoldWitnessPreviewPlan Plan, ImmutableHashSet<DocumentBlob> Begun,
    ImmutableDictionary<DocumentBlob, ProductionRecordWriteReceipt> Receipts);

internal static class ProductionRecordPreviewWriteContract
{
    internal const string Version = "production-record-signature-preview-writes-v1", Kind = "signer/preview";
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() } };
    private static readonly string[] Columns = ["Id", "EnvelopeId", "SignerId", "DocumentId", "SignatureObjectId", "InitialsObjectId", "SignatureSha256",
        "InitialsSha256", "DocumentSha256", "DisclosureSha256", "SessionSha256", "BaselineSignerVersion", "SignatureWidth", "SignatureHeight",
        "InitialsWidth", "InitialsHeight", "Method", "TypedName", "TypedInitials", "NormalizationVersion", "AdoptionVersion", "CreatedAt", "ExpiresAt", "UsedAt"];
    internal static string Row(SignaturePreview row)
    {
        if (row.TypedName is { Length: > 200 } || row.TypedInitials is { Length: > 20 } || row.NormalizationVersion is { Length: > 64 } ||
            row.AdoptionVersion is { Length: > 64 } || row.BaselineSignerVersion is not { Length: 8 } ||
            new[] { row.SignatureSha256, row.InitialsSha256, row.DocumentSha256, row.DisclosureSha256, row.SessionSha256 }.Any(x => x is not { Length: 32 })) throw Invalid();
        try { var utf8 = new UTF8Encoding(false, true); if (row.TypedName is not null) _ = utf8.GetByteCount(row.TypedName); if (row.TypedInitials is not null) _ = utf8.GetByteCount(row.TypedInitials); }
        catch (EncoderFallbackException error) { throw new InvalidDataException("The bounded preview descriptor is malformed.", error); }
        var properties = typeof(SignaturePreview).GetProperties();
        if (!properties.Select(x => x.Name).Order(StringComparer.Ordinal).SequenceEqual(Columns.Order(StringComparer.Ordinal))) throw Invalid();
        return JsonSerializer.Serialize(new SortedDictionary<string, object?>(Columns.ToDictionary(x => x, x => properties.Single(p => p.Name == x).GetValue(row)), StringComparer.Ordinal), Json);
    }
    internal static SignaturePreview ReadRow(string json)
    {
        if (json is not { Length: > 0 and <= 8192 }) throw Invalid();
        try { var row = JsonSerializer.Deserialize<SignaturePreview>(json, Json) ?? throw Invalid(); if (Row(row) != json) throw Invalid(); return row; }
        catch (Exception error) when (error is JsonException or NotSupportedException) { throw new InvalidDataException("The frozen preview row is malformed.", error); }
    }
    internal static bool Item(Guid recordId, ProductionRecordWriteDescriptor? item) => item is not null && recordId != Guid.Empty &&
        item.Blob.EnvelopeId == recordId && item.Blob.ObjectId != Guid.Empty && item.Blob.Kind is DocumentBlobKind.Signature or DocumentBlobKind.Initials &&
        item.Length is > 0 and <= SignaturePng.MaximumBytes && Hash(item.Sha256);
    internal static bool Receipt(Guid recordId, ProductionRecordWriteReceipt? receipt) => receipt is not null && Item(recordId, receipt.Item) &&
        Opaque(receipt.VersionId) && Opaque(receipt.ETag);
    internal static bool Member(HoldWitnessPreviewPlan plan, ProductionRecordWriteDescriptor item) => item == plan.Signature || item == plan.Initials;
    internal static void Validate(HoldWitnessPreviewPlan plan, bool requireRetention = true)
    {
        var row = ReadRow(plan.PreviewRowJson); var identity = plan.Identity;
        if (identity is null || row.Id == Guid.Empty || row.EnvelopeId == Guid.Empty || row.SignerId == Guid.Empty || row.DocumentId == Guid.Empty ||
            row.UsedAt is not null || row.EnvelopeId != identity.EnvelopeId || row.SignerId != identity.SignerId || row.DocumentId != identity.DocumentId ||
            identity.SessionId == Guid.Empty || identity.PublicId is not { Length: > 0 and <= 128 } || identity.Email is not { Length: > 0 and <= 320 } ||
            !Hash(identity.DocumentHash) || !Hash(identity.DisclosureHash) || row.BaselineSignerVersion is not { Length: 8 } ||
            row.DocumentSha256 is not { Length: 32 } || Convert.ToHexStringLower(row.DocumentSha256) != identity.DocumentHash ||
            row.DisclosureSha256 is not { Length: 32 } || Convert.ToHexStringLower(row.DisclosureSha256) != identity.DisclosureHash ||
            row.SessionSha256 is not { Length: 32 } || !CryptographicOperations.FixedTimeEquals(row.SessionSha256, SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(identity))) ||
            !Item(row.EnvelopeId, plan.Signature) || !Item(row.EnvelopeId, plan.Initials) || plan.Signature.Blob.Kind != DocumentBlobKind.Signature ||
            plan.Initials.Blob.Kind != DocumentBlobKind.Initials || plan.Signature.Blob.ObjectId == plan.Initials.Blob.ObjectId ||
            plan.Signature.Blob.ObjectId == row.DocumentId || plan.Initials.Blob.ObjectId == row.DocumentId ||
            row.SignatureObjectId != plan.Signature.Blob.ObjectId || row.InitialsObjectId != plan.Initials.Blob.ObjectId ||
            row.SignatureSha256 is not { Length: 32 } || Convert.ToHexStringLower(row.SignatureSha256) != plan.Signature.Sha256 ||
            row.InitialsSha256 is not { Length: 32 } || Convert.ToHexStringLower(row.InitialsSha256) != plan.Initials.Sha256 ||
            row.SignatureWidth is < 1 or > SignaturePng.MaximumWidth || row.InitialsWidth is < 1 or > SignaturePng.MaximumWidth ||
            row.SignatureHeight is < 1 or > SignaturePng.MaximumHeight || row.InitialsHeight is < 1 or > SignaturePng.MaximumHeight ||
            !Enum.IsDefined(row.Method) || row.NormalizationVersion != SignaturePng.Version || row.AdoptionVersion != SignatureAdoptionStatement.Version ||
            row.Method == SignatureMethod.Typed && (!Descriptor(row.TypedName, 200) || !Descriptor(row.TypedInitials, 20)) ||
            row.Method != SignatureMethod.Typed && (row.TypedName is not null || row.TypedInitials is not null) ||
            row.CreatedAt.Offset != TimeSpan.Zero || row.ExpiresAt.Offset != TimeSpan.Zero || identity.SessionExpiresAt.Offset != TimeSpan.Zero ||
            plan.AccessExpiresAt.Offset != TimeSpan.Zero || plan.RetentionDeadline is { Offset: var retentionOffset } && retentionOffset != TimeSpan.Zero ||
            plan.SigningDeadline is { Offset: var signingOffset } && signingOffset != TimeSpan.Zero ||
            row.CreatedAt >= row.ExpiresAt || row.ExpiresAt != Earlier(row.CreatedAt.AddMinutes(SignatureAdoption.PreviewMinutes), plan.AccessExpiresAt) ||
            plan.AccessExpiresAt > identity.SessionExpiresAt || requireRetention && plan.AccessExpiresAt != Earlier(identity.SessionExpiresAt, plan.RetentionDeadline) ||
            plan.SigningDeadline is { } signing && identity.SessionExpiresAt > signing || !Hash(plan.BaselineProjectionSha256)) throw Invalid();
    }
    private static bool Descriptor(string? value, int maximum) => value is { Length: > 0 } && value.Length <= maximum &&
        value == value.Trim() && value.IsNormalized(NormalizationForm.FormC) && !value.EnumerateRunes().Any(r => Rune.GetUnicodeCategory(r) is
            System.Globalization.UnicodeCategory.Control or System.Globalization.UnicodeCategory.Format or System.Globalization.UnicodeCategory.Surrogate);
    internal static DateTimeOffset Earlier(DateTimeOffset first, DateTimeOffset? second) => second is { } end && end < first ? end : first;
    internal static bool Complete(HoldWitnessPreviewWrites writes) => writes.Begun.Count == 2 && writes.Receipts.Count == 2 &&
        new[] { writes.Plan.Signature, writes.Plan.Initials }.All(x => writes.Begun.Contains(x.Blob) &&
            writes.Receipts.TryGetValue(x.Blob, out var receipt) && receipt.Item == x && Receipt(x.Blob.EnvelopeId, receipt));
    // All tables/columns, including old previews and private requests, remain in
    // this bounded fingerprint. Only the exact newly inserted row is removed.
    internal static string Projection(ProductionHoldSqlSnapshot snapshot, IDataProtectionProvider keys, Guid previewId, string? expectedRow)
    {
        using var sql = ProductionHoldSqlInventory.OpenAcknowledgementVerified(snapshot, keys);
        using var expected = expectedRow is null ? null : JsonDocument.Parse(expectedRow);
        var tables = sql.RootElement.GetProperty("Tables").EnumerateArray().Select(table => {
            if (table.GetProperty("Table").GetString() != "SignaturePreviews") return table.Clone();
            if (!table.GetProperty("Columns").EnumerateArray().Select(x => x.GetString()!.Split(':')[0]).Order(StringComparer.Ordinal)
                .SequenceEqual(Columns.Order(StringComparer.Ordinal))) throw Invalid();
            var rows = table.GetProperty("Rows").EnumerateArray().ToArray();
            var own = rows.Where(x => x.GetProperty("Id").GetGuid() == previewId).ToArray();
            if (expectedRow is null ? own.Length != 0 : own.Length != 1 || !JsonElement.DeepEquals(own[0], expected!.RootElement)) throw Invalid();
            var retained = rows.Where(x => x.GetProperty("Id").GetGuid() != previewId).ToArray();
            return JsonSerializer.SerializeToElement(new { Table = "SignaturePreviews", Columns = table.GetProperty("Columns"),
                Count = retained.LongLength, Sha256 = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(retained))), Rows = retained });
        }).ToArray();
        return Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new {
            Version = "production-preview-sql-projection-v1", snapshot.RecordId, snapshot.Revision, snapshot.FenceHash, snapshot.Control,
            PolicySha256 = sql.RootElement.GetProperty("PolicySha256").GetString(), Tables = tables
        })));
    }
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigitLower);
    private static bool Opaque(string? value) => value is { Length: > 0 and <= 256 } && value != "*" && value.All(x => x is >= '!' and <= '~');
    internal static InvalidDataException Invalid() => new("The exact production signature preview and original authority could not be verified.");
}

internal sealed partial class ProductionRecordOperationAdmission
{
    internal async Task PreparePreviewWritesLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionSignaturePreviewWrite write, CancellationToken ct = default)
    {
        if (scope.Kind != ProductionRecordPreviewWriteContract.Kind || scope.Reference != write.PreviewId.ToString("N")) throw Invalid();
        await DemandStartingLockedAsync(db, scope, ct);
        var state = await witness.ReadAsync(scope.RecordId, ct); await DemandControls(db, scope.RecordId, state, ct);
        var requests = await Requests(db, scope.RecordId, ct); var snapshot = await Capture(db, scope.RecordId, requests, ct);
        var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == scope.RecordId, ct);
        var retention = await ProductionRecordRetentionAccess.ReadLockedAsync(db, envelope, time, ct);
        var plan = new HoldWitnessPreviewPlan(write.PreviewRowJson, write.Identity, write.AccessExpiresAt, retention.Deadline,
            envelope.ExpiresAt, ProductionRecordPreviewWriteContract.Projection(snapshot, keys, write.PreviewId, null), write.Signature, write.Initials);
        ProductionRecordPreviewWriteContract.Validate(plan); await DemandPreviewIdentityLocked(db, scope, plan, ct);
        await witness.PreparePreviewWritesAsync(scope.RecordId, state.Operations![scope.OperationId], plan, PreviewId(scope, "plan"), ct);
        DemandPreviewClock(plan);
    }
    internal async Task<bool> BeginPreviewWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor item, CancellationToken ct = default)
    {
        var state = await PreviewAuthorizationLocked(db, scope, item, false, ct);
        var began = await witness.BeginPreviewWriteAsync(scope.RecordId, state.Operations![scope.OperationId], item, PreviewId(scope, "begin", item), ct);
        await DemandPreviewWriteLockedAsync(db, scope, item, ct); return began;
    }
    internal async Task DemandPreviewWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor item, CancellationToken ct = default) => _ = await PreviewAuthorizationLocked(db, scope, item, true, ct);
    internal async Task<ProductionRecordWriteReceipt?> ReadPreviewWriteReceiptLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor item, CancellationToken ct = default)
        => (await PreviewAuthorizationLocked(db, scope, item, false, ct)).PreviewWrites![scope.OperationId].Receipts.GetValueOrDefault(item.Blob);
    internal async Task RecordPreviewWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteReceipt receipt, CancellationToken ct = default)
    {
        if (!ProductionRecordPreviewWriteContract.Receipt(scope.RecordId, receipt)) throw Invalid();
        var state = await PreviewAuthorizationLocked(db, scope, receipt.Item, true, ct);
        await witness.RecordPreviewWriteAsync(scope.RecordId, state.Operations![scope.OperationId], receipt, PreviewId(scope, "receipt", receipt.Item), ct);
        await DemandPreviewWriteLockedAsync(db, scope, receipt.Item, ct);
    }
    private async Task<HoldWitnessState> PreviewAuthorizationLocked(QuillSignDbContext db, ProductionRecordOperation scope,
        ProductionRecordWriteDescriptor item, bool started, CancellationToken ct)
    {
        if (scope.Kind != ProductionRecordPreviewWriteContract.Kind) throw Invalid();
        await DemandStartingLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct);
        await DemandControls(db, scope.RecordId, state, ct); var saved = state.PreviewWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (!ProductionRecordPreviewWriteContract.Member(saved.Plan, item) || started && !saved.Begun.Contains(item.Blob)) throw Invalid();
        await DemandPreviewIdentityLocked(db, scope, saved.Plan, ct); DemandActive(scope, await witness.ReadAsync(scope.RecordId, ct));
        DemandPreviewClock(saved.Plan); return state;
    }
    private async Task DemandPreviewIdentityLocked(QuillSignDbContext db, ProductionRecordOperation scope, HoldWitnessPreviewPlan plan, CancellationToken ct)
    {
        ProductionRecordPreviewWriteContract.Validate(plan); var row = ProductionRecordPreviewWriteContract.ReadRow(plan.PreviewRowJson);
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges() || row.EnvelopeId != scope.RecordId || scope.Reference != row.Id.ToString("N")) throw Invalid();
        var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == scope.RecordId, ct);
        var retention = await ProductionRecordRetentionAccess.ReadLockedAsync(db, envelope, time, ct);
        var signer = await db.Signers.AsNoTracking().SingleOrDefaultAsync(x => x.Id == row.SignerId && x.EnvelopeId == scope.RecordId, ct) ?? throw Invalid();
        var source = await new SignerCheckpointState(db, time).CurrentAsync(envelope, ct) ?? throw Invalid();
        if (retention.Kind != ProductionEnrollmentKind.Enrolled || retention.Stage != ProductionRecordStage.Signing || retention.Deadline != plan.RetentionDeadline ||
            envelope.ExpiresAt != plan.SigningDeadline || envelope.Status != EnvelopeStatus.Sent || envelope.PublicId != plan.Identity.PublicId ||
            envelope.SenderVerifiedAt is null || envelope.ErsdSha256 is not { Length: 32 } || Convert.ToHexStringLower(envelope.ErsdSha256) != plan.Identity.DisclosureHash ||
            signer.Email != plan.Identity.Email || signer.Status != SignerStatus.Viewed || signer.ConsentAt is null || signer.ConsentAt > row.CreatedAt ||
            !signer.RowVersion.SequenceEqual(row.BaselineSignerVersion) || source.ObjectId != plan.Identity.DocumentId ||
            Convert.ToHexStringLower(source.Sha256) != plan.Identity.DocumentHash ||
            await db.Signers.AnyAsync(x => x.EnvelopeId == scope.RecordId && x.Order < signer.Order && x.Status != SignerStatus.Signed, ct) ||
            await db.SignerFinishAcceptances.AnyAsync(x => x.EnvelopeId == scope.RecordId && x.SignerId == signer.Id, ct)) throw Invalid();
        DemandPreviewClock(plan);
    }
    private void DemandPreviewClock(HoldWitnessPreviewPlan plan)
    {
        var row = ProductionRecordPreviewWriteContract.ReadRow(plan.PreviewRowJson);
        if (row.CreatedAt > time.GetUtcNow()) throw Invalid();
        DocumentRetentionAccess.Check(row.ExpiresAt, time); DocumentRetentionAccess.Check(plan.AccessExpiresAt, time);
        DocumentRetentionAccess.Check(plan.RetentionDeadline, time); DocumentRetentionAccess.Check(plan.SigningDeadline, time);
    }
    private async Task DemandPreviewOutcomeLocked(QuillSignDbContext db, ProductionRecordOperation scope, ProductionHoldSqlSnapshot current,
        HoldWitnessState state, CancellationToken ct)
    {
        var saved = state.PreviewWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (!ProductionRecordPreviewWriteContract.Complete(saved)) throw Invalid();
        await DemandPreviewIdentityLocked(db, scope, saved.Plan, ct);
        var row = ProductionRecordPreviewWriteContract.ReadRow(saved.Plan.PreviewRowJson);
        if (ProductionRecordPreviewWriteContract.Projection(current, keys, row.Id, saved.Plan.PreviewRowJson) != saved.Plan.BaselineProjectionSha256) throw Invalid();
        DemandPreviewClock(saved.Plan);
    }
    private static Guid PreviewId(ProductionRecordOperation scope, string phase, ProductionRecordWriteDescriptor? item = null)
        => new(SHA256.HashData(Encoding.ASCII.GetBytes($"production-preview-v1:{scope.RecordId:N}:{scope.OperationId:N}:{phase}:{item?.Blob.Kind}:{item?.Blob.ObjectId:N}")).AsSpan(0, 16));
}
