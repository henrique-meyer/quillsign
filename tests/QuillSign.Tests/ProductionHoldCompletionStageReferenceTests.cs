using System.Data.SqlTypes;
using System.Collections.Immutable;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldCompletionStageReferenceTests
{
    [Theory]
    [InlineData("settled")][InlineData("outstanding")][InlineData("unsettled")][InlineData("handler")][InlineData("outcome")]
    [InlineData("missing-slot")][InlineData("missing-ack")][InlineData("changed-ack")][InlineData("unknown-effect")]
    public void Complete_acceptance_requires_all_seven_acknowledged_slots_and_final_settlement(string fault)
    {
        // Factual state-fold unit only: no claim of DP, provider or SQL proof.
        // The connected parent fixture supplies those independently.
        var record=Guid.NewGuid();var operation=Guid.NewGuid();var work=Guid.NewGuid();var hash=Convert.ToHexStringLower(SHA256.HashData([1]));
        var now=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero);var expected=new HoldWitnessOutcome(hash,hash,9);
        var claim=new HoldWitnessCompletionClaim(work,1,now.AddMinutes(5),hash,"{}","{}",hash,Guid.NewGuid());
        var slots=ImmutableDictionary<CompletionSlot,HoldWitnessCompletionSlot>.Empty;
        foreach(var slot in Enum.GetValues<CompletionSlot>())
        {
            var effects=ProductionCompletionProtocol.Effects(slot).Select(x=>new CompletionEffectDescriptor(x,Guid.NewGuid(),20,hash,1,[hash])).ToArray();
            var context=new HoldWitnessCompletionContext(slot,operation,8,hash,hash,work,1,claim.Until,hash,
                effects.Select(x=>new CompletionEffectTarget(x.Effect,x.TargetId)).ToImmutableArray(),[],hash,now);
            slots=slots.Add(slot,new(context,8,effects.ToImmutableDictionary(x=>x.Effect),
                effects.ToImmutableDictionary(x=>x.Effect,x=>new CompletionEffectReceipt(x,hash,null)),
                new(hash,null,hash),hash,expected,Guid.NewGuid(),expected with {Sequence=10}));
        }
        var state=new HoldWitnessState(90,hash,1,hash,null,null,new Dictionary<Guid,HoldWitnessHold>(),hash,
            new Dictionary<Guid,string>{{operation,hash}},true,hash,
            new Dictionary<Guid,HoldWitnessOperation>{{operation,new(operation,"work/3",work.ToString("N")+"/attempt/1",0,null,hash,hash,1)}},
            new Dictionary<Guid,HoldWitnessOutcome>{{operation,expected}},new Dictionary<Guid,HoldWitnessOutcome>{{operation,expected}},
            Completions:new Dictionary<Guid,HoldWitnessCompletionState>{{operation,new(claim,1,expected,expected with {Sequence=10},slots)}});
        switch(fault)
        {
            case "outstanding":state=state with {OutstandingOperation=operation};break;
            case "unsettled":state=state with {SettledOperations=new Dictionary<Guid,string>()};break;
            case "handler":state=state with {HandlerOutcomes=new Dictionary<Guid,HoldWitnessOutcome>()};break;
            case "outcome":state=state with {Outcomes=new Dictionary<Guid,HoldWitnessOutcome>()};break;
            case "missing-slot":slots=slots.Remove(CompletionSlot.WorkFinish);break;
            case "missing-ack":slots=slots.SetItem(CompletionSlot.WorkFinish,slots[CompletionSlot.WorkFinish] with {Acknowledged=null});break;
            case "changed-ack":slots=slots.SetItem(CompletionSlot.WorkFinish,slots[CompletionSlot.WorkFinish] with {Acknowledged=expected with {ContentSha256=new string('a',64)}});break;
            case "unknown-effect":slots=slots.SetItem(CompletionSlot.Candidate,slots[CompletionSlot.Candidate] with {Receipts=slots[CompletionSlot.Candidate].Receipts.Remove(CompletionEffect.CandidatePdf)});break;
        }
        state=state with {Completions=new Dictionary<Guid,HoldWitnessCompletionState>{{operation,state.Completions![operation] with {Slots=slots}}}};
        if(fault=="settled")Assert.Equal(operation,ProductionHoldCompletionStageReferences.DemandSettled(record,state).OperationId);
        else Assert.Throws<InvalidDataException>(()=>ProductionHoldCompletionStageReferences.DemandSettled(record,state));
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Candidate_compares_the_actual_original_checkpoint_frame_with_shared_producer_formulas(bool maximumFields)
    {
        var f = new CandidateFrame(maximumFields); using var sql = f.History.F.Sql();
        ProductionHoldCompletionStageReferences.DemandCandidate(sql.RootElement, f.Candidate, f.History.F.Objects);
        Assert.Equal(maximumFields ? 200 : 6, f.History.F.Fields.Count);
        Assert.Equal(f.OriginalSnapshot, f.History.Inputs.Single().Body.OriginalSnapshotJson);
        Assert.Equal("signer_completed", f.History.F.Audits[^1].Event);
    }

    [Theory]
    [InlineData("valid")][InlineData("executed-candidate")][InlineData("certificate-candidate")][InlineData("executed-evidence")]
    [InlineData("certificate-evidence")][InlineData("source")][InlineData("source-length")][InlineData("executed-bytes")][InlineData("executed-recipe")]
    public void Separate_authenticated_seal_bodies_must_join_the_exact_same_candidate_and_executed_predecessor(string fault)
    {
        byte[] Hash(byte value)=>SHA256.HashData([value]);
        var candidate=new CompletionCandidate{EnvelopeId=Guid.NewGuid(),PdfObjectId=Guid.NewGuid(),PdfLength=40,PdfSha256=Hash(1),RecipeSha256=Hash(2),EvidenceSha256=Hash(3)};
        var executed=new CompletionSealOutput{EnvelopeId=candidate.EnvelopeId,CandidateId=candidate.Id,SourceObjectId=candidate.PdfObjectId,SourceLength=40,
            SourceSha256=candidate.PdfSha256, CandidateRecipeSha256=candidate.RecipeSha256,EvidenceSha256=candidate.EvidenceSha256,PdfSha256=Hash(4),RecipeSha256=Hash(5)};
        var certificate=new CompletionSealOutput{EnvelopeId=candidate.EnvelopeId,CandidateId=candidate.Id,CandidateRecipeSha256=candidate.RecipeSha256,
            EvidenceSha256=candidate.EvidenceSha256,ExecutedSha256=executed.PdfSha256};
        var context=new CompletionSealInputContext(candidate.Id,Convert.ToHexStringLower(candidate.RecipeSha256),Guid.NewGuid(),40,Convert.ToHexStringLower(Hash(6)),
            Guid.NewGuid(),Guid.NewGuid(),1,"synthetic",[],Convert.ToHexStringLower(Hash(7)),new(2030,1,1,12,0,0,TimeSpan.Zero),
            Convert.ToHexStringLower(executed.PdfSha256),Convert.ToHexStringLower(executed.RecipeSha256));
        switch(fault)
        {
            case "executed-candidate":executed.CandidateRecipeSha256=Hash(8);break;
            case "certificate-candidate":certificate.CandidateRecipeSha256=Hash(8);break;
            case "executed-evidence":executed.EvidenceSha256=Hash(8);break;
            case "certificate-evidence":certificate.EvidenceSha256=Hash(8);break;
            case "source":executed.SourceObjectId=Guid.NewGuid();break;
            case "source-length":executed.SourceLength++;break;
            case "executed-bytes":certificate.ExecutedSha256=Hash(8);break;
            case "executed-recipe":context=context with {ExecutedRecipeSha256=Convert.ToHexStringLower(Hash(8))};break;
        }
        if(fault=="valid")ProductionHoldCompletionStageReferences.DemandSealLinks(candidate,executed,certificate,context);
        else Assert.Throws<InvalidDataException>(()=>ProductionHoldCompletionStageReferences.DemandSealLinks(candidate,executed,certificate,context));
    }

    [Theory]
    [InlineData("source")][InlineData("copy")][InlineData("finish")][InlineData("anchor")][InlineData("prefix")][InlineData("frozen")]
    [InlineData("signer-name")][InlineData("signer-role")][InlineData("signer-clock")][InlineData("sender")][InlineData("recipient")]
    [InlineData("document")][InlineData("disclosure")][InlineData("actor")][InlineData("mark")][InlineData("mark-version")]
    [InlineData("geometry")][InlineData("document-pages")]
    public void Authenticated_rehashed_candidate_evidence_does_not_replace_actual_original_business_facts(string fault)
    {
        var f = new CandidateFrame(); var row = f.Candidate;
        var body = JsonSerializer.Deserialize<CompletionEvidence>(row.EvidenceJson)!;
        switch (fault)
        {
            case "source": row.SourceSha256 = SHA256.HashData([9]); break;
            case "copy": row.CopyVersion++; break;
            case "finish": row.FinishId = Guid.NewGuid(); break;
            case "anchor": row.AuditAnchor = SHA256.HashData([9]); break;
            case "prefix": row.AuditSequence--; break;
            case "frozen": row.FrozenStateSha256 = SHA256.HashData([9]); break;
            case "signer-name": body = body with { Signers = [body.Signers[0] with { Name = "Different saved name" }] }; break;
            case "signer-role": body = body with { Signers = [body.Signers[0] with { Role = "Different role" }] }; break;
            case "signer-clock": body = body with { Signers = [body.Signers[0] with { ViewedAt = body.Signers[0].ViewedAt.AddTicks(1), ConsentedAt = body.Signers[0].ConsentedAt.AddTicks(1) }] }; break;
            case "sender": body = body with { Sender = body.Sender with { Name = "Invented sender" } }; break;
            case "recipient": body = body with { Recipients = [body.Recipients[0] with { Name = "Changed historical recipient" }] }; break;
            case "document": body = body with { Document = body.Document with { Name = "Changed saved title" } }; break;
            case "disclosure": body = body with { DisclosureVersion = "future-disclosure", Signers = [body.Signers[0] with { DisclosureVersion = "future-disclosure" }] }; break;
            case "actor": body = body with { Events = body.Events.Select((x, i) => i == body.Events.Count - 1 ? x with { Actor = "foreign@example.invalid" } : x).ToArray() }; break;
            case "mark": f.History.F.Objects.RemoveAll(x => x.Address.Name.EndsWith(f.History.M.P.SignatureObjectId.ToString("N"), StringComparison.Ordinal)); break;
            case "mark-version": body = body with { Signers = [body.Signers[0] with { Signature = body.Signers[0].Signature! with { NormalizationVersion = "future" } }] }; break;
            case "geometry":row.GeometryJson=JsonSerializer.Serialize(new[]{new PageGeometry(613,792,0,1,[0,0,613,792],[0,0,613,792])});break;
            case "document-pages":row.DocumentPages++;break;
        }
        row.EvidenceJson = JsonSerializer.Serialize(body); row.EvidenceSha256 = CompletionEvidenceValidation.Digest(body);
        row.RecipeSha256 = CompletionCandidates.Recipe(row); // A new matching row recipe grants no factual authority.
        using var sql = f.History.F.Sql();
        var error=Record.Exception(()=>ProductionHoldCompletionStageReferences.DemandCandidate(sql.RootElement, row, f.History.F.Objects));
        Assert.True(error is InvalidDataException or DocumentRejectedException, error?.ToString());
        Assert.Equal(f.OriginalSnapshot, f.History.Inputs.Single().Body.OriginalSnapshotJson);
    }

    [Fact]
    public void Private_projection_preserves_original_chain_rows_and_uses_exact_saved_work_without_invented_columns()
    {
        var f = new CandidateFrame(); var frame = f.History.F; using var original = frame.Sql();
        var before = JsonSerializer.Deserialize<Envelope>(JsonSerializer.Serialize(frame.Envelope))!;
        var work = frame.Work.Single(x => x.Kind == WorkKind.Sealing);
        var options = new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } };
        var exact = JsonSerializer.SerializeToElement(work, options); var notice = Guid.NewGuid();
        var method = typeof(ProductionHoldCompletionStageReferences).GetMethod("Project", BindingFlags.Static | BindingFlags.NonPublic)!;
        using var projection = (JsonDocument)method.Invoke(null, [original.RootElement, before, work.Id, exact, f.Candidate.AuditSequence, new HashSet<Guid> { notice }, new HashSet<Guid>()])!;
        var tables = projection.RootElement.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        Assert.True(JsonElement.DeepEquals(exact, tables["WorkItems"].EnumerateArray().Single(x => x.GetProperty("Id").GetGuid() == work.Id)));
        var old = original.RootElement.GetProperty("Tables").EnumerateArray().ToDictionary(x => x.GetProperty("Table").GetString()!, x => x.GetProperty("Rows"));
        foreach (var table in new[] { "Signers", "Fields", "SignerReviewCandidates", "SignerFinishAcceptances", "SignaturePreviews", "AuthTokens", "AuditEvents", "ProductionHoldRequests", "ProductionHoldControls" })
            Assert.True(JsonElement.DeepEquals(old[table], tables[table]), table);
        Assert.Equal("Sent", old["Envelopes"][0].GetProperty("Status").GetString());
        Assert.Single(ProductionHoldReviewCheckpointReferences.ReadVerified(projection.RootElement, frame.Objects, frame.Keys, f.History.Inputs).Reviews);
    }

    internal sealed class CandidateFrame
    {
        internal readonly ProductionHoldReviewCheckpointReferenceTests.Frame History;
        internal readonly CompletionCandidate Candidate;
        internal readonly string OriginalSnapshot;
        internal CandidateFrame(bool maximum = false)
        {
            History = new(large: maximum, parties: 1); History.Review(); History.Accept(); History.Process(); _ = History.Demand();
            OriginalSnapshot = History.Inputs.Single().Body.OriginalSnapshotJson;
            var f = History.F; var e = f.Envelope; var p = History.M.P;
            var signature = SignaturePng.Normalize(SignatureAdoptionTests.Mark(20)); var initials = SignaturePng.Normalize(SignatureAdoptionTests.Mark(60));
            var marks = new Dictionary<Guid, SignerPdfMarks> { [f.Signers[0].Id] = new(p.Id, p.SignatureObjectId, p.InitialsObjectId,
                signature.Bytes, initials.Bytes, signature.Sha256, initials.Sha256, SignaturePng.Version) };
            var signers = f.Signers.OrderBy(x => x.Order).ToArray(); var recipients = f.Recipients.OrderBy(x => new SqlGuid(x.Id)).ToArray();
            var fields = f.Fields.OrderBy(x => new SqlGuid(x.Id)).ToArray(); var finishes = History.Finishes.OrderBy(x => new SqlGuid(x.SignerId)).ToArray();
            var previews = new[] { p }; var at = f.Audits[^1].At.AddSeconds(1);
            var evidence = CompletionEvidenceValidation.Own(CompletionEvidenceCollector.ProjectHistorical(e, signers, recipients, fields, finishes, previews, f.Audits.ToArray(), marks, at), default);
            var bytes = "SYNTHETIC GRAPH METADATA - NOT A NEW PROVIDER PDF"u8.ToArray();
            var packet = new PreparedCompletionPacket(bytes, SHA256.HashData(bytes), finishes[0].PdfSha256, CompletionEvidenceValidation.Digest(evidence), [], 1, 1, CompletionCertificateRenderer.Version);
            var source = new CompletionMaterialization(e.Id, e.PublicId, SHA256.HashData([1]), evidence, [],
                [new(612, 792, 0, 1, [0, 0, 612, 792], [0, 0, 612, 792])], finishes[0].PdfObjectId, finishes[0].Id, 1,
                CompletionEvidenceCollector.FrozenState(e, signers, recipients, fields, finishes, previews));
            Candidate = CompletionCandidates.Create(source, packet);
        }
    }
}
