using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Lifecycle;

internal sealed class ProductionSignerReviewWrite
{
    private readonly byte[] input, pdf;
    private readonly ReviewInputV1 body;
    internal Guid OperationId => body.OperationId;
    internal Guid CandidateId => body.CandidateId;
    internal VerifiedSigner Identity => body.Identity with { };
    internal DateTimeOffset AccessExpiresAt => body.AccessExpiresAt;
    internal string CandidateRowJson => body.CandidateRowJson;
    internal DateTimeOffset PreparedAt => ProductionRecordReviewWriteContract.ReadRow(CandidateRowJson).PreparedAt;
    internal DateTimeOffset ExpiresAt => ProductionRecordReviewWriteContract.ReadRow(CandidateRowJson).ExpiresAt;
    internal DateOnly ProspectiveDate => ProductionRecordReviewWriteContract.ReadRow(CandidateRowJson).ProspectiveDate;
    internal ProductionRecordWriteDescriptor Input { get; }
    internal ProductionRecordWriteDescriptor Pdf { get; }
    private ProductionSignerReviewWrite(IDataProtectionProvider keys, Guid operationId, Guid inputObjectId, SignerReviewCandidate candidate,
        VerifiedSigner identity, DateTimeOffset accessExpiresAt, string snapshot, SignerPdfRequest request, IReadOnlyList<PageGeometry> pages,
        RenderedSignerPdf rendered, long auditId, int auditSequence, byte[] auditHash, string? ip, string? ua)
    {
        if (operationId == Guid.Empty || inputObjectId == Guid.Empty || inputObjectId == candidate.PdfObjectId || inputObjectId == candidate.SourceObjectId ||
            rendered.Bytes is not { Length: > 0 and <= ProductionRecordReviewWriteContract.MaximumPdfBytes } ||
            request.Fields is null || request.Fields.Count > 200 || pages.Count is < 1 or > 200 || request.Marks is not { } marks ||
            marks.Signature is not { Length: > 0 and <= SignaturePng.MaximumBytes } || marks.Initials is not { Length: > 0 and <= SignaturePng.MaximumBytes } ||
            ip is { Length: > 64 }) throw ProductionReviewInputCodec.Invalid();
        // Own every byte before protection or any caller-controlled await. Raw
        // images are verified, then represented only by their exact references.
        var signature = marks.Signature.ToArray(); var initials = marks.Initials.ToArray();
        if (!SignaturePng.Normalize(signature).Bytes.AsSpan().SequenceEqual(signature) || !SignaturePng.Normalize(initials).Bytes.AsSpan().SequenceEqual(initials) ||
            ProductionReviewInputCodec.Hash(signature) != ProductionReviewInputCodec.Hex(marks.SignatureSha256) ||
            ProductionReviewInputCodec.Hash(initials) != ProductionReviewInputCodec.Hex(marks.InitialsSha256)) throw ProductionReviewInputCodec.Invalid();
        pdf = rendered.Bytes.ToArray();
        var render = new ReviewRenderInputV1(request.EnvelopeId, request.SignerId, request.FullName, request.FinishAt, request.AdoptionId,
            request.Fields.Select(x => x with { Revision = x.Revision.ToArray(), ImageSha256 = x.ImageSha256?.ToArray() }).ToArray(),
            new(marks.AdoptionId, marks.SignatureObjectId, marks.InitialsObjectId, marks.SignatureSha256.ToArray(), marks.InitialsSha256.ToArray(), marks.NormalizationVersion));
        body = new(ProductionReviewInputCodec.Version, candidate.EnvelopeId, operationId, candidate.Id, ProductionRecordReviewWriteContract.Row(candidate),
            identity with { }, accessExpiresAt, snapshot, render, pages.Select(x => x with { MediaBox = x.MediaBox.ToArray(), CropBox = x.CropBox.ToArray() }).ToArray(),
            auditId, auditSequence, ProductionReviewInputCodec.Hex(auditHash));
        var plain = ProductionReviewInputCodec.Encode(body);
        body = ProductionReviewInputCodec.Read(plain);
        if (rendered.EnvelopeId != candidate.EnvelopeId || rendered.SignerId != candidate.SignerId || rendered.AdoptionId != candidate.AdoptionId ||
            rendered.FinishAt != candidate.PreparedAt || rendered.RendererVersion != candidate.RendererVersion ||
            ProductionReviewInputCodec.Hash(pdf) != ProductionReviewInputCodec.Hex(candidate.PdfSha256) ||
            !rendered.Sha256.SequenceEqual(candidate.PdfSha256) || !rendered.SourceSha256.SequenceEqual(candidate.SourceSha256) ||
            !rendered.BindingSha256.SequenceEqual(candidate.RecipeSha256)) throw ProductionReviewInputCodec.Invalid();
        input = ProductionReviewInputCodec.Protect(keys, body);
        Input = new(new(candidate.EnvelopeId, DocumentBlobKind.ReviewInput, inputObjectId), input.Length, ProductionReviewInputCodec.Hash(input));
        Pdf = new(new(candidate.EnvelopeId, DocumentBlobKind.Normalized, candidate.PdfObjectId), pdf.Length, ProductionReviewInputCodec.Hash(pdf));
        Ip = ip; UserAgent = ua is { Length: > 2048 } ? ua[..2048] : ua;
    }
    internal string? Ip { get; }
    internal string? UserAgent { get; }
    internal static ProductionSignerReviewWrite Own(IDataProtectionProvider keys, Guid operationId, Guid inputObjectId, SignerReviewCandidate candidate,
        VerifiedSigner identity, DateTimeOffset accessExpiresAt, string originalSnapshotJson, SignerPdfRequest request, IReadOnlyList<PageGeometry> pages,
        RenderedSignerPdf rendered, long auditId, int auditSequence, byte[] auditHash, string? ip = null, string? ua = null)
        => new(keys, operationId, inputObjectId, candidate, identity, accessExpiresAt, originalSnapshotJson, request, pages, rendered, auditId, auditSequence, auditHash, ip, ua);
    internal Stream Open(DocumentBlobKind kind) => new MemoryStream((kind switch {
        DocumentBlobKind.ReviewInput => input, DocumentBlobKind.Normalized => pdf, _ => throw ProductionReviewInputCodec.Invalid() }).ToArray(), false);
    internal HoldWitnessReviewPlan Plan(DateTimeOffset? retention, DateTimeOffset? signing, string baseline, IReadOnlyList<ReviewSupersede> superseded)
        => new(OperationId, CandidateRowJson, Identity, AccessExpiresAt, retention, signing, baseline, superseded.ToImmutableArray(), Input, Pdf,
            ProductionReviewInputCodec.Version, ProductionReviewInputCodec.Hash(ProductionReviewInputCodec.Encode(body)),
            ProductionReviewInputCodec.Hash(Encoding.UTF8.GetBytes(body.OriginalSnapshotJson)), ProductionReviewInputCodec.Hex(ProductionRecordReviewWriteContract.ReadRow(CandidateRowJson).RecipeSha256),
            body.AuditId, body.AuditSequence, body.AuditSha256, Ip, UserAgent);
}

internal sealed record ReviewSupersede(Guid CandidateId, string OriginalRowVersion);
internal sealed record HoldWitnessReviewPlan(Guid OperationId, string CandidateRowJson, VerifiedSigner Identity, DateTimeOffset AccessExpiresAt,
    DateTimeOffset? RetentionDeadline, DateTimeOffset? SigningDeadline, string BaselineProjectionSha256, ImmutableArray<ReviewSupersede> Superseded,
    ProductionRecordWriteDescriptor Input, ProductionRecordWriteDescriptor Pdf, string InputVersion, string InputPlainSha256,
    string SnapshotSha256, string RecipeSha256, long AuditId, int AuditSequence, string AuditSha256, string? Ip, string? UserAgent);
internal sealed record HoldWitnessReviewWrites(HoldWitnessReviewPlan Plan, ImmutableHashSet<DocumentBlob> Begun,
    ImmutableDictionary<DocumentBlob, ProductionRecordWriteReceipt> Receipts);

internal static class ProductionRecordReviewWriteContract
{
    internal const string Version = "production-record-review-writes-v1", Kind = "signer/review-prepare";
    internal const int MaximumPdfBytes = 64 * 1024 * 1024;
    private static readonly JsonSerializerOptions Json = new() { Converters = { new JsonStringEnumConverter() }, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    internal static readonly string[] Columns = ["Id", "EnvelopeId", "SignerId", "AdoptionId", "SourceObjectId", "PdfObjectId", "PdfLength", "SourceSha256", "DisclosureSha256", "SessionSha256", "SnapshotSha256", "PdfSha256", "RecipeSha256", "RendererVersion", "SnapshotVersion", "ProspectiveDate", "PreparedAt", "ExpiresAt", "UsedAt", "SupersededAt", "RowVersion"];
    internal static string Row(SignerReviewCandidate row)
    {
        if (row.RendererVersion is not { Length: > 0 and <= 64 } || row.SnapshotVersion is not { Length: > 0 and <= 64 } ||
            new[] { row.SourceSha256, row.DisclosureSha256, row.SessionSha256, row.SnapshotSha256, row.PdfSha256, row.RecipeSha256 }.Any(x => x is not { Length: 32 }) ||
            row.RowVersion is not { Length: 0 or 8 } || !typeof(SignerReviewCandidate).GetProperties().Select(x => x.Name).Order(StringComparer.Ordinal).SequenceEqual(Columns.Order(StringComparer.Ordinal))) throw Invalid();
        var properties = typeof(SignerReviewCandidate).GetProperties();
        return JsonSerializer.Serialize(new SortedDictionary<string, object?>(Columns.Where(x => x != "RowVersion").ToDictionary(x => x, x => properties.Single(p => p.Name == x).GetValue(row)), StringComparer.Ordinal), Json);
    }
    internal static SignerReviewCandidate ReadRow(string raw)
    {
        if (raw is not { Length: > 0 and <= 8192 }) throw Invalid();
        try { var row = JsonSerializer.Deserialize<SignerReviewCandidate>(raw, Json) ?? throw Invalid(); if (Row(row) != raw) throw Invalid(); return row; }
        catch (JsonException error) { throw new InvalidDataException("The frozen review row is malformed.", error); }
    }
    internal static void Validate(HoldWitnessReviewPlan plan)
    {
        var row = ReadRow(plan.CandidateRowJson); var id = plan.Identity;
        if (plan.OperationId == Guid.Empty || id is null || row.Id == Guid.Empty || row.EnvelopeId == Guid.Empty || row.SignerId == Guid.Empty || row.AdoptionId == Guid.Empty ||
            row.SourceObjectId == Guid.Empty || row.PdfObjectId == Guid.Empty || row.PdfObjectId == row.SourceObjectId || row.UsedAt is not null || row.SupersededAt is not null ||
            id.EnvelopeId != row.EnvelopeId || id.SignerId != row.SignerId || id.DocumentId != row.SourceObjectId || id.SessionId == Guid.Empty ||
            id.PublicId is not { Length: > 0 and <= 128 } || id.Email is not { Length: > 0 and <= 320 } || id.DocumentHash != ProductionReviewInputCodec.Hex(row.SourceSha256) ||
            id.DisclosureHash != ProductionReviewInputCodec.Hex(row.DisclosureSha256) ||
            ProductionReviewInputCodec.Hash(JsonSerializer.SerializeToUtf8Bytes(id)) != ProductionReviewInputCodec.Hex(row.SessionSha256) ||
            row.PdfLength != plan.Pdf.Length || plan.Pdf.Blob.ObjectId != row.PdfObjectId || plan.Pdf.Blob.Kind != DocumentBlobKind.Normalized ||
            plan.Input.Blob.Kind != DocumentBlobKind.ReviewInput || plan.Input.Blob.ObjectId == row.PdfObjectId || plan.Input.Blob.ObjectId == row.SourceObjectId ||
            !Item(row.EnvelopeId, plan.Input) || !Item(row.EnvelopeId, plan.Pdf) || plan.InputVersion != ProductionReviewInputCodec.Version ||
            !ProductionReviewInputCodec.IsHash(plan.InputPlainSha256) || plan.SnapshotSha256 != ProductionReviewInputCodec.Hex(row.SnapshotSha256) ||
            plan.RecipeSha256 != ProductionReviewInputCodec.Hex(row.RecipeSha256) || plan.Pdf.Sha256 != ProductionReviewInputCodec.Hex(row.PdfSha256) ||
            !ProductionReviewInputCodec.IsHash(plan.BaselineProjectionSha256) || plan.AuditId < 1 || plan.AuditSequence < 1 || !ProductionReviewInputCodec.IsHash(plan.AuditSha256) ||
            plan.Ip is { Length: > 64 } || plan.UserAgent is { Length: > 2048 } || plan.Superseded.IsDefault || plan.Superseded.Length > 20 ||
            plan.Superseded.Select(x => x.CandidateId).Distinct().Count() != plan.Superseded.Length ||
            plan.Superseded.Any(x => x.CandidateId == Guid.Empty || x.CandidateId == row.Id || Convert.FromBase64String(x.OriginalRowVersion).Length != 8) ||
            row.RendererVersion != SignerPdfRenderer.Version || row.SnapshotVersion != "signer-review-v1" || row.PreparedAt.Offset != TimeSpan.Zero || row.ExpiresAt.Offset != TimeSpan.Zero ||
            plan.AccessExpiresAt.Offset != TimeSpan.Zero || id.SessionExpiresAt.Offset != TimeSpan.Zero ||
            plan.RetentionDeadline is { Offset: var ro } && ro != TimeSpan.Zero || plan.SigningDeadline is { Offset: var so } && so != TimeSpan.Zero ||
            row.PreparedAt >= row.ExpiresAt || plan.AccessExpiresAt != Earlier(id.SessionExpiresAt, plan.RetentionDeadline) ||
            row.ExpiresAt != Earlier(Earlier(Earlier(row.PreparedAt.AddMinutes(10), plan.AccessExpiresAt), plan.SigningDeadline), new DateTimeOffset(row.PreparedAt.UtcDateTime.Date.AddDays(1), TimeSpan.Zero)) ||
            row.ProspectiveDate != DateOnly.FromDateTime(row.PreparedAt.UtcDateTime) || PlanBytes(plan).Length > 49152) throw Invalid();
    }
    internal static byte[] PlanBytes(HoldWitnessReviewPlan plan) => JsonSerializer.SerializeToUtf8Bytes(plan);
    internal static string PlanSha256(HoldWitnessReviewPlan plan) => ProductionReviewInputCodec.Hash(PlanBytes(plan));
    internal static bool Item(Guid record, ProductionRecordWriteDescriptor? item) => item is not null && item.Blob.EnvelopeId == record && record != Guid.Empty && item.Blob.ObjectId != Guid.Empty &&
        item.Blob.Kind is DocumentBlobKind.ReviewInput or DocumentBlobKind.Normalized && item.Length > 0 &&
        item.Length <= (item.Blob.Kind == DocumentBlobKind.ReviewInput ? ProductionReviewInputCodec.MaximumCipherBytes : MaximumPdfBytes) && ProductionReviewInputCodec.IsHash(item.Sha256);
    internal static bool Member(HoldWitnessReviewPlan plan, ProductionRecordWriteDescriptor item) => item == plan.Input || item == plan.Pdf;
    internal static bool Receipt(Guid record, ProductionRecordWriteReceipt? receipt) => receipt is not null && Item(record, receipt.Item) &&
        Opaque(receipt.VersionId) && Opaque(receipt.ETag);
    private static bool Opaque(string? value) => value is { Length: > 0 and <= 256 } && value != "*" && value.All(x => x is >= '!' and <= '~');
    internal static bool Complete(HoldWitnessReviewWrites saved) => saved.Begun.Count == 2 && saved.Receipts.Count == 2 &&
        new[] { saved.Plan.Input, saved.Plan.Pdf }.All(x => saved.Begun.Contains(x.Blob) && saved.Receipts.TryGetValue(x.Blob, out var r) && r.Item == x && Receipt(x.Blob.EnvelopeId, r));
    internal static DateTimeOffset Earlier(DateTimeOffset first, DateTimeOffset? second) => second is { } end && end < first ? end : first;
    internal static string AuditData(SignerReviewCandidate candidate) => JsonSerializer.Serialize(new {
        candidateId = candidate.Id, candidate.PdfObjectId, candidate.SourceObjectId, candidate.PdfLength, candidate.AdoptionId,
        sourceSha256 = ProductionReviewInputCodec.Hex(candidate.SourceSha256), disclosureSha256 = ProductionReviewInputCodec.Hex(candidate.DisclosureSha256),
        sessionSha256 = ProductionReviewInputCodec.Hex(candidate.SessionSha256), snapshotSha256 = ProductionReviewInputCodec.Hex(candidate.SnapshotSha256),
        pdfSha256 = ProductionReviewInputCodec.Hex(candidate.PdfSha256), recipeSha256 = ProductionReviewInputCodec.Hex(candidate.RecipeSha256),
        candidate.RendererVersion, candidate.SnapshotVersion, candidate.ProspectiveDate, candidate.PreparedAt, candidate.ExpiresAt,
        serverEvidence = "exact_review_pdf_prepared_not_user_review_or_finish" });
    internal static string Projection(ProductionHoldSqlSnapshot snapshot, IDataProtectionProvider keys, HoldWitnessReviewPlan plan, bool outcome)
    {
        using var sql = ProductionHoldSqlInventory.OpenAcknowledgementVerified(snapshot, keys); var candidate = ReadRow(plan.CandidateRowJson);
        var seenSuperseded = new HashSet<Guid>(); var seenCandidate = false; var seenAudit = false;
        var tables = sql.RootElement.GetProperty("Tables").EnumerateArray().Select(table => {
            var name = table.GetProperty("Table").GetString(); if (name is not ("SignerReviewCandidates" or "AuditEvents")) return table.Clone();
            var rows = new List<JsonElement>();
            foreach (var raw in table.GetProperty("Rows").EnumerateArray())
            {
                if (name == "SignerReviewCandidates")
                {
                    if (!table.GetProperty("Columns").EnumerateArray().Select(x => x.GetString()!.Split(':')[0]).Order(StringComparer.Ordinal).SequenceEqual(Columns.Order(StringComparer.Ordinal))) throw Invalid();
                    var row = raw.Deserialize<SignerReviewCandidate>(Json) ?? throw Invalid();
                    if (row.Id == candidate.Id)
                    {
                        if (!outcome || seenCandidate || row.RowVersion.Length != 8 || Row(row) != plan.CandidateRowJson) throw Invalid(); seenCandidate = true; continue;
                    }
                    var original = plan.Superseded.SingleOrDefault(x => x.CandidateId == row.Id);
                    if (original is not null)
                    {
                        if (!seenSuperseded.Add(row.Id) || row.EnvelopeId != candidate.EnvelopeId || row.SignerId != candidate.SignerId || row.UsedAt is not null ||
                            row.ExpiresAt <= candidate.PreparedAt || row.SnapshotSha256.SequenceEqual(candidate.SnapshotSha256) || row.RowVersion.Length != 8 ||
                            (outcome ? row.SupersededAt != candidate.PreparedAt || Convert.ToBase64String(row.RowVersion) == original.OriginalRowVersion :
                                row.SupersededAt is not null || Convert.ToBase64String(row.RowVersion) != original.OriginalRowVersion)) throw Invalid();
                        var node = JsonNode.Parse(raw.GetRawText())!.AsObject(); node["SupersededAt"] = null; node["RowVersion"] = original.OriginalRowVersion;
                        rows.Add(JsonSerializer.SerializeToElement(node)); continue;
                    }
                }
                else if (raw.GetProperty("Sequence").GetInt32() > plan.AuditSequence)
                {
                    var audit = raw.Deserialize<AuditEvent>(Json) ?? throw Invalid();
                    if (!outcome || seenAudit || audit.Id <= plan.AuditId || audit.Sequence != plan.AuditSequence + 1 || audit.Event != "signer_review_prepared" ||
                        audit.EnvelopeId != candidate.EnvelopeId || audit.ActorType != PartyType.Signer || audit.ActorId != candidate.SignerId ||
                        audit.ActorEmail != plan.Identity.Email || audit.Ip != plan.Ip || audit.UserAgent != plan.UserAgent || audit.DataJson != AuditData(candidate) ||
                        audit.At < candidate.PreparedAt || audit.At >= candidate.ExpiresAt || audit.At.Offset != TimeSpan.Zero ||
                        ProductionReviewInputCodec.Hex(audit.PrevHash ?? []) != plan.AuditSha256 || !AuditHash.Compute(audit).SequenceEqual(audit.Hash)) throw Invalid();
                    seenAudit = true; continue;
                }
                rows.Add(raw.Clone());
            }
            return JsonSerializer.SerializeToElement(new { Table = name, Columns = table.GetProperty("Columns"), Count = rows.LongCount(),
                Sha256 = ProductionReviewInputCodec.Hash(JsonSerializer.SerializeToUtf8Bytes(rows)), Rows = rows });
        }).ToArray();
        if (seenSuperseded.Count != plan.Superseded.Length || outcome && (!seenCandidate || !seenAudit)) throw Invalid();
        return ProductionReviewInputCodec.Hash(JsonSerializer.SerializeToUtf8Bytes(new {
            Version = "production-review-sql-projection-v1", snapshot.RecordId, snapshot.Revision, snapshot.FenceHash, snapshot.Control,
            PolicySha256 = sql.RootElement.GetProperty("PolicySha256").GetString(), Tables = tables }));
    }
    internal static InvalidDataException Invalid() => ProductionReviewInputCodec.Invalid();
}

internal sealed partial class ProductionRecordOperationAdmission
{
    internal async Task PrepareReviewWritesLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, ProductionSignerReviewWrite write, CancellationToken ct = default)
    {
        if (scope.Kind != ProductionRecordReviewWriteContract.Kind || scope.OperationId != write.OperationId || scope.Reference != write.CandidateId.ToString("N")) throw Invalid();
        await DemandStartingLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct); await DemandControls(db, scope.RecordId, state, ct);
        var requests = await Requests(db, scope.RecordId, ct); var snapshot = await Capture(db, scope.RecordId, requests, ct);
        var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == scope.RecordId, ct);
        var retention = await ProductionRecordRetentionAccess.ReadLockedAsync(db, envelope, time, ct);
        var row = ProductionRecordReviewWriteContract.ReadRow(write.CandidateRowJson);
        var old = await db.SignerReviewCandidates.AsNoTracking().Where(x => x.EnvelopeId == scope.RecordId && x.SignerId == row.SignerId).ToArrayAsync(ct);
        if (old.Length >= 20 || old.Any(x => x.Id == row.Id || x.PdfObjectId == write.Pdf.Blob.ObjectId || x.PdfObjectId == write.Input.Blob.ObjectId)) throw Invalid();
        var superseded = old.Where(x => x.UsedAt is null && x.SupersededAt is null && x.ExpiresAt > row.PreparedAt && !x.SnapshotSha256.SequenceEqual(row.SnapshotSha256))
            .Select(x => new ReviewSupersede(x.Id, Convert.ToBase64String(x.RowVersion))).OrderBy(x => x.CandidateId).ToArray();
        var plan = write.Plan(retention.Deadline, envelope.ExpiresAt, new('0', 64), superseded);
        plan = plan with { BaselineProjectionSha256 = ProductionRecordReviewWriteContract.Projection(snapshot, keys, plan, false) };
        ProductionRecordReviewWriteContract.Validate(plan); await DemandReviewIdentityLocked(db, scope, plan, ct);
        using var input = write.Open(DocumentBlobKind.ReviewInput); var cipher = new byte[checked((int)write.Input.Length)]; input.ReadExactly(cipher);
        var verified = ProductionReviewInputCodec.OpenVerified(keys, plan, cipher);
        var snap = verified.Snapshot;
        if (!envelope.RowVersion.SequenceEqual(snap.RowVersion) || envelope.PageCount != snap.PageCount || envelope.PageSizesJson != snap.PageSizesJson) throw Invalid();
        var signer = await db.Signers.AsNoTracking().SingleAsync(x => x.Id == row.SignerId && x.EnvelopeId == scope.RecordId, ct);
        if (!signer.RowVersion.SequenceEqual(snap.signerVersion) || signer.FullName != snap.FullName || signer.ConsentAt != snap.ConsentAt) throw Invalid();
        var fields = await db.Fields.AsNoTracking().Where(x => x.EnvelopeId == scope.RecordId && x.SignerId == row.SignerId).OrderBy(x => x.Id).ToArrayAsync(ct);
        if (JsonSerializer.Serialize(fields) != JsonSerializer.Serialize(snap.fields)) throw Invalid();
        var cut = await db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == scope.RecordId).OrderByDescending(x => x.Sequence).FirstOrDefaultAsync(ct) ?? throw Invalid();
        if (cut.Id != plan.AuditId || cut.Sequence != plan.AuditSequence || ProductionReviewInputCodec.Hex(cut.Hash) != plan.AuditSha256) throw Invalid();
        await witness.PrepareReviewWritesAsync(scope.RecordId, state.Operations![scope.OperationId], plan, ReviewId(scope, "plan"), ct); DemandReviewClock(plan);
    }
    internal async Task<bool> BeginReviewWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, ProductionRecordWriteDescriptor item, CancellationToken ct = default)
    {
        var state = await ReviewAuthorizationLocked(db, scope, item, false, ct);
        var began = await witness.BeginReviewWriteAsync(scope.RecordId, state.Operations![scope.OperationId], item, ReviewId(scope, "begin", item), ct);
        await DemandReviewWriteLockedAsync(db, scope, item, ct); return began;
    }
    internal async Task DemandReviewWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, ProductionRecordWriteDescriptor item, CancellationToken ct = default)
        => _ = await ReviewAuthorizationLocked(db, scope, item, true, ct);
    internal async Task<ProductionRecordWriteReceipt?> ReadReviewWriteReceiptLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, ProductionRecordWriteDescriptor item, CancellationToken ct = default)
        => (await ReviewAuthorizationLocked(db, scope, item, false, ct)).ReviewWrites![scope.OperationId].Receipts.GetValueOrDefault(item.Blob);
    internal async Task RecordReviewWriteLockedAsync(QuillSignDbContext db, ProductionRecordOperation scope, ProductionRecordWriteReceipt receipt, CancellationToken ct = default)
    {
        if (!ProductionRecordReviewWriteContract.Receipt(scope.RecordId, receipt)) throw Invalid();
        var state = await ReviewAuthorizationLocked(db, scope, receipt.Item, true, ct);
        await witness.RecordReviewWriteAsync(scope.RecordId, state.Operations![scope.OperationId], receipt, ReviewId(scope, "receipt", receipt.Item), ct);
        await DemandReviewWriteLockedAsync(db, scope, receipt.Item, ct);
    }
    private async Task<HoldWitnessState> ReviewAuthorizationLocked(QuillSignDbContext db, ProductionRecordOperation scope, ProductionRecordWriteDescriptor item, bool started, CancellationToken ct)
    {
        if (scope.Kind != ProductionRecordReviewWriteContract.Kind) throw Invalid();
        await DemandStartingLockedAsync(db, scope, ct); var state = await witness.ReadAsync(scope.RecordId, ct); await DemandControls(db, scope.RecordId, state, ct);
        var saved = state.ReviewWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (!ProductionRecordReviewWriteContract.Member(saved.Plan, item) || started && !saved.Begun.Contains(item.Blob) ||
            item == saved.Plan.Pdf && !saved.Receipts.ContainsKey(saved.Plan.Input.Blob)) throw Invalid();
        await DemandReviewIdentityLocked(db, scope, saved.Plan, ct); DemandActive(scope, await witness.ReadAsync(scope.RecordId, ct)); DemandReviewClock(saved.Plan); return state;
    }
    private async Task DemandReviewIdentityLocked(QuillSignDbContext db, ProductionRecordOperation scope, HoldWitnessReviewPlan plan, CancellationToken ct)
    {
        ProductionRecordReviewWriteContract.Validate(plan); var row = ProductionRecordReviewWriteContract.ReadRow(plan.CandidateRowJson);
        if (db.Database.CurrentTransaction is null || db.ChangeTracker.HasChanges() || scope.OperationId != plan.OperationId || row.EnvelopeId != scope.RecordId || scope.Reference != row.Id.ToString("N")) throw Invalid();
        var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == scope.RecordId, ct);
        var retention = await ProductionRecordRetentionAccess.ReadLockedAsync(db, envelope, time, ct);
        var signer = await db.Signers.AsNoTracking().SingleOrDefaultAsync(x => x.EnvelopeId == scope.RecordId && x.Id == row.SignerId, ct) ?? throw Invalid();
        var source = await new SignerCheckpointState(db, time).CurrentAsync(envelope, ct) ?? throw Invalid();
        if (retention.Kind != ProductionEnrollmentKind.Enrolled || retention.Stage != ProductionRecordStage.Signing || retention.Deadline != plan.RetentionDeadline ||
            envelope.ExpiresAt != plan.SigningDeadline || envelope.Status != EnvelopeStatus.Sent || envelope.PublicId != plan.Identity.PublicId || envelope.SenderVerifiedAt is null ||
            ProductionReviewInputCodec.Hex(envelope.ErsdSha256 ?? []) != plan.Identity.DisclosureHash || signer.Email != plan.Identity.Email || signer.Status != SignerStatus.Viewed ||
            signer.ConsentAt is null || signer.ConsentAt > row.PreparedAt || signer.SignatureAdoptionId != row.AdoptionId || source.ObjectId != row.SourceObjectId ||
            ProductionReviewInputCodec.Hex(source.Sha256) != plan.Identity.DocumentHash ||
            await db.Signers.AnyAsync(x => x.EnvelopeId == scope.RecordId && x.Order < signer.Order && x.Status != SignerStatus.Signed, ct) ||
            await db.SignerFinishAcceptances.AnyAsync(x => x.EnvelopeId == scope.RecordId && x.SignerId == row.SignerId, ct)) throw Invalid();
        DemandReviewClock(plan);
    }
    private void DemandReviewClock(HoldWitnessReviewPlan plan)
    {
        var row = ProductionRecordReviewWriteContract.ReadRow(plan.CandidateRowJson); if (row.PreparedAt > time.GetUtcNow()) throw Invalid();
        DocumentRetentionAccess.Check(row.ExpiresAt, time); DocumentRetentionAccess.Check(plan.AccessExpiresAt, time);
        DocumentRetentionAccess.Check(plan.RetentionDeadline, time); DocumentRetentionAccess.Check(plan.SigningDeadline, time);
    }
    private async Task DemandReviewOutcomeLocked(QuillSignDbContext db, ProductionRecordOperation scope, ProductionHoldSqlSnapshot current, HoldWitnessState state, CancellationToken ct)
    {
        var saved = state.ReviewWrites?.GetValueOrDefault(scope.OperationId) ?? throw Invalid();
        if (!ProductionRecordReviewWriteContract.Complete(saved)) throw Invalid();
        await DemandReviewIdentityLocked(db, scope, saved.Plan, ct);
        if (ProductionRecordReviewWriteContract.Projection(current, keys, saved.Plan, true) != saved.Plan.BaselineProjectionSha256) throw Invalid(); DemandReviewClock(saved.Plan);
    }
    private static Guid ReviewId(ProductionRecordOperation scope, string phase, ProductionRecordWriteDescriptor? item = null)
        => new(SHA256.HashData(Encoding.ASCII.GetBytes($"production-review-v1:{scope.RecordId:N}:{scope.OperationId:N}:{phase}:{item?.Blob.Kind}:{item?.Blob.ObjectId:N}")).AsSpan(0, 16));
}
