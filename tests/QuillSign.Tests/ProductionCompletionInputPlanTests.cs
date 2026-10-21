using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionCompletionInputPlanTests
{
    internal sealed record Example(ProductionCompletionInput Input, CompletionCandidate Row, PreparedCompletionPacket Packet, Envelope Envelope);
    private static byte[] Hash(string value) => SHA256.HashData(Encoding.UTF8.GetBytes(value));
    internal static Example Candidate(Guid? owner = null, HoldWitnessCompletionContext? context = null, IDataProtectionProvider? keys = null, string? unicode = null)
    {
        var now = context?.RecordedAt ?? ProductionCompletionInputCodecTests.Now; var id = owner ?? Guid.NewGuid();
        var envelope = new Envelope { Id = id, SenderEmail = "sender@example.invalid", Status = EnvelopeStatus.Sent, PdfBlob = Guid.NewGuid().ToString("N"), RowVersion = new byte[8] };
        var bytes = Encoding.ASCII.GetBytes("SYNTHETIC METADATA PACKET - NOT A RENDERED PDF"); var source = Hash("source"); var disclosure = Hash("disclosure"); var anchor = Hash("audit");
        var evidence = new CompletionEvidence(Guid.ParseExact(envelope.PublicId, "N"), now, false, true,
            new(Guid.ParseExact(envelope.PdfBlob, "N"), unicode ?? "Synthetic completion", 1, Hash("original"), Hash("converted"), Hash("sent"), source),
            new("Synthetic sender", envelope.SenderEmail, now.AddMinutes(-7)), "synthetic-ersd-v1", disclosure,
            [new(Guid.NewGuid(), 1, "Synthetic signer", "signer@example.invalid", null, now.AddMinutes(-6), now.AddMinutes(-5), now.AddMinutes(-4), now.AddMinutes(-3), now.AddMinutes(-2),
                "synthetic-ersd-v1", disclosure, source, null, null, null, null, null)], [],
            [new(1, now.AddMinutes(-1), "synthetic_event", "System", "Synthetic", null, null, new byte[32], anchor)], anchor);
        evidence = CompletionEvidenceValidation.Own(evidence, default);
        var packet = new PreparedCompletionPacket(bytes, SHA256.HashData(bytes), source, CompletionEvidenceValidation.Digest(evidence), [], 1, 1, CompletionCertificateRenderer.Version);
        var pages = new[] { new PageGeometry(612, 792, 0, 1, [0,0,612,792], [0,0,612,792]) };
        var original = new CompletionMaterialization(id, envelope.PublicId, Hash("state"), evidence, [], pages, Guid.NewGuid(), Guid.NewGuid(), 1, Hash("frozen"));
        var row = CompletionCandidates.Create(original, packet); envelope.CurrentFinishId = row.FinishId; envelope.CurrentCopyVersion = 1;
        var cut = new CompletionInputAuditCut(1, Convert.ToHexStringLower(anchor));
        context ??= ProductionCompletionInputCodecTests.Context(CompletionSlot.Candidate);
        row.PdfObjectId = context.Targets.Single(x => x.Effect == CompletionEffect.CandidatePdf).TargetId; row.RecipeSha256 = CompletionCandidates.Recipe(row);
        context = context with { SqlRows = ProductionCompletionInputRows.Selectors(row, cut).ToImmutableArray() };
        return new(ProductionCompletionInput.OwnCandidate(keys ?? new EphemeralDataProtectionProvider(), id, context, row, packet, now, cut), row, packet, envelope);
    }
    [Fact]
    public void Candidate_owns_exact_original_Unicode_evidence_without_calling_a_renderer_or_guessing_object_UUIDs()
    {
        var f = Candidate(unicode: new string('\u6f22', 512)); var body = f.Input.Verified.Body;
        Assert.Contains(new string('\u6f22', 512), JsonSerializer.Deserialize<CompletionEvidence>(body.Candidate!.EvidenceJson)!.Document.Name);
        Assert.NotEqual(body.RecordId, JsonSerializer.Deserialize<CompletionEvidence>(body.Candidate.EvidenceJson)!.EnvelopeId);
        f.Row.EvidenceSha256[0] ^= 1; f.Packet.Bytes[0] ^= 1;
        Assert.NotEqual(f.Row.EvidenceSha256, f.Input.Verified.Body.Candidate!.EvidenceSha256);
        Assert.Equal(ProductionCompletionInputCodecTests.Now, CompletionOwnedRowPlan.FromInput(new EphemeralDataProtectionProvider(), f.Input).RecordedAt);
    }
    [Theory]
    [InlineData("pages")][InlineData("certificate-pages")][InlineData("pdf")][InlineData("recipe")][InlineData("renderer")]
    [InlineData("source")][InlineData("evidence")][InlineData("audit")][InlineData("row-version")]
    public void Producer_candidate_metadata_cannot_be_rehashed_into_a_different_plan(string fault)
    {
        var f = Candidate(); var body = f.Input.Verified.Body; var row = body.Candidate!;
        switch (fault) {
            case "pages": row.DocumentPages = 200; break; case "certificate-pages": row.CertificatePages = 65; break;
            case "pdf": row.PdfLength = 1; break; case "recipe": row.RecipeSha256[0] ^= 1; break;
            case "renderer": row.RendererVersion = "future"; break; case "source": row.SourceSha256[0] ^= 1; break;
            case "evidence": row.EvidenceJson = row.EvidenceJson.Replace("synthetic_event", "future_event", StringComparison.Ordinal); break;
            case "audit": row.AuditSequence++; break; case "row-version": row.RowVersion = new byte[8]; break; }
        if (fault is not "recipe") row.RecipeSha256 = CompletionCandidates.Recipe(row);
        Assert.Throws<InvalidDataException>(() => ProductionCompletionInputCodec.Encode(body));
    }
    [Theory]
    [InlineData("valid")][InlineData("field")][InlineData("row-version")][InlineData("audit-time")][InlineData("audit-actor")][InlineData("audit-payload")][InlineData("source-owner")]
    public void Deferred_binding_allows_only_generated_rowversion_and_audit_identity_not_semantic_substitution(string fault)
    {
        var f = Candidate(); var saved = f.Input.Verified.Body.Candidate!; saved.RowVersion = [1,2,3,4,5,6,7,8];
        var audit = new AuditEvent { Id = 73, EnvelopeId = f.Envelope.Id, Sequence = 2, At = f.Input.RecordedAt, ActorType = PartyType.System,
            Event = "completion_prepared", DataJson = CompletionCandidates.PreparationJson(saved), PrevHash = f.Row.AuditAnchor.ToArray() };
        audit.Hash = AuditHash.Compute(audit);
        switch (fault) {
            case "field": saved.FrozenStateSha256[0] ^= 1; break; case "row-version": saved.RowVersion = [1]; break;
            case "audit-time": audit.At = audit.At.AddSeconds(1); break; case "audit-actor": audit.ActorEmail = "foreign@example.invalid"; break;
            case "audit-payload": audit.DataJson = "{}"; break; case "source-owner": f.Envelope.PublicId = Guid.NewGuid().ToString("N"); break; }
        audit.Hash = AuditHash.Compute(audit);
        using var sql = Sql(f.Envelope.Id, ("Envelopes", [f.Envelope]), ("CompletionCandidates", [saved]), ("AuditEvents", [audit]));
        if (fault == "valid") {
            var result = ProductionCompletionInputRows.Bind(f.Input.Verified, new EphemeralDataProtectionProvider(), sql.RootElement);
            Assert.Equal(2, result.Length); Assert.DoesNotContain("RowVersion", result[0].AfterJson); Assert.DoesNotContain("\"Id\":", result[1].AfterJson);
        }
        else Assert.Throws<InvalidDataException>(() => ProductionCompletionInputRows.Bind(f.Input.Verified, new EphemeralDataProtectionProvider(), sql.RootElement));
    }
    [Fact]
    public void Prospective_SQL_budget_reserves_all_future_slots_and_notifications_without_refunding_current_bytes()
    {
        var f = Candidate(); using var sql = Sql(f.Envelope.Id, ("Envelopes", [f.Envelope]), ("Signers", [new Signer { EnvelopeId = f.Envelope.Id, Email = "signer@example.invalid" }]), ("Recipients", []));
        ProductionCompletionSqlBudget.Demand(1024, f.Input.Verified.Body, sql.RootElement);
        Assert.Throws<InvalidDataException>(() => ProductionCompletionSqlBudget.Demand(ProductionCompletionSqlBudget.MaximumBytes - 1, f.Input.Verified.Body, sql.RootElement));
        Assert.Throws<InvalidDataException>(() => ProductionCompletionSqlBudget.Demand(ProductionCompletionSqlBudget.MaximumBytes - 1, CompletionSlot.PublicationResult, sql.RootElement));
    }
    internal static JsonDocument Sql(Guid id, params (string Name, object[] Rows)[] tables)
    {
        var options = new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } };
        return JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = id, Tables = tables.Select(x => new { Table = x.Name, x.Rows }) }, options));
    }
}

public sealed class ProductionCompletionInputNativeTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("valid")][InlineData("changed-SQL")][InlineData("changed-context")]
    public async Task Same_parent_pre_effect_preflight_requires_exact_original_ack_and_has_zero_provider_or_SQL_mutation(string fault)
    {
        var r = await ProductionRecordOperationAdmissionTests.Run.Create(fixture);
        await using (var edit = fixture.Open()) await edit.WorkItems.Where(x => x.Id == r.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Kind, WorkKind.Sealing));
        var gate = r.Gate(); await gate.InitializeAsync(r.Id); var operation = Guid.NewGuid();
        var scope = await gate.BeginAsync(r.Id, operation, "work/3", r.Work.ToString("N") + "/attempt/1");
        await using (var claim = fixture.Open()) {
            await using var tx = await claim.Database.BeginTransactionAsync(); var next = await claim.WorkItems.AsNoTracking().SingleAsync(x => x.Id == r.Work);
            next.Status = WorkStatus.Leased; next.Attempts = 1; next.LeaseOwner = operation; next.LeaseExpiresAt = r.Clock.Now.AddMinutes(5);
            var permit = await gate.BeginCompletionClaimLockedAsync(claim, scope, next);
            await claim.WorkItems.Where(x => x.Id == r.Work).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, next.Status).SetProperty(w => w.Attempts, next.Attempts)
                .SetProperty(w => w.LeaseOwner, next.LeaseOwner).SetProperty(w => w.LeaseExpiresAt, next.LeaseExpiresAt));
            await gate.PrepareCompletionClaimExpectedLockedAsync(claim, permit); await tx.CommitAsync(); }
        await gate.AcknowledgeCompletionClaimAsync(scope);
        await using var db = fixture.Open(); await using var parent = await db.Database.BeginTransactionAsync();
        var preliminary = ProductionCompletionInputPlanTests.Candidate(r.Id, keys: r.Keys);
        var context = await gate.CreateCompletionContextLockedAsync(db, scope, CompletionSlot.Candidate, preliminary.Input.Verified.Context.Targets,
            preliminary.Input.Verified.Context.SqlRows, r.Clock.Now);
        var cut = preliminary.Input.Verified.Body.AuditCut;
        var row = preliminary.Input.Verified.Body.Candidate!; row.PreparedAt = r.Clock.Now; row.RecipeSha256 = CompletionCandidates.Recipe(row);
        // The test body is a metadata-only original-plan fact. This does not
        // manufacture a renderer/provider receipt or semantic Finish authority.
        var evidence = JsonSerializer.Deserialize<CompletionEvidence>(row.EvidenceJson)! with { PreparedAt = r.Clock.Now };
        row.EvidenceJson = JsonSerializer.Serialize(evidence); row.EvidenceSha256 = CompletionEvidenceValidation.Digest(evidence); row.RecipeSha256 = CompletionCandidates.Recipe(row);
        var packet = preliminary.Packet with { EvidenceSha256 = row.EvidenceSha256 };
        if (fault == "changed-context") context = context with { PredecessorContentSha256 = new('a',64) };
        var input = ProductionCompletionInput.OwnCandidate(r.Keys, r.Id, context, row, packet, r.Clock.Now, cut);
        var count = r.Store.Rows.Count;
        if (fault == "changed-SQL") await db.Envelopes.Where(x => x.Id == r.Id).ExecuteUpdateAsync(x => x.SetProperty(e => e.Title, "foreign change"));
        if (fault == "valid") await gate.PreflightCompletionInputLockedAsync(db, scope, input.Verified);
        else await Assert.ThrowsAsync<InvalidDataException>(() => gate.PreflightCompletionInputLockedAsync(db, scope, input.Verified));
        Assert.Equal(count, r.Store.Rows.Count); Assert.False(db.ChangeTracker.HasChanges()); await parent.RollbackAsync();
    }
}
