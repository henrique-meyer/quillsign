using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldReviewCheckpointReferenceTests
{
    [Theory]
    [InlineData(0)][InlineData(1)][InlineData(2)]
    public void Original_expired_review_input_remains_exact_through_acceptance_and_first_checkpoint(int stage)
    {
        var f = new Frame(); f.Review(); if (stage > 0) f.Accept(); if (stage > 1) f.Process();
        var result = f.Demand(); Assert.Single(result.Reviews); Assert.Single(result.Previews);
        Assert.Equal(stage > 1, result.Processed); Assert.True(result.Reviews[0].ExpiresAt < f.F.Captured);
        using var reversed = f.F.Sql(reverse: true); _ = ProductionHoldReviewCheckpointReferences.ReadVerified(reversed.RootElement, f.F.Objects, f.F.Keys, f.Inputs);
        Assert.Equal(stage > 1 ? 1 : 0, f.F.Envelope.CurrentCopyVersion);
    }

    [Fact]
    public void Superseded_reviews_retain_their_exact_old_field_timestamps_and_predecessor_events()
    {
        var f = new Frame(); f.Review(); var first = f.Candidates[0]; var original = f.Inputs[0].Body.OriginalSnapshotJson;
        f.M.Fill(clear: true); f.M.Fill(); f.Review(); f.Accept(); f.Process();
        Assert.Equal(f.Candidates[1].PreparedAt, first.SupersededAt); Assert.Equal(2, f.Demand().Reviews.Count);
        Assert.Equal(original, f.Inputs[0].Body.OriginalSnapshotJson);
    }

    [Fact]
    public void Three_live_candidates_cannot_borrow_a_later_accepted_time_to_excuse_the_original_active_bound()
    {
        var f = new Frame(); f.Review(); f.Review(); f.Review(); f.Accept();
        Assert.Throws<InvalidDataException>(() => f.Demand());
    }

    [Fact]
    public void Actual_SQL_uniqueidentifier_field_order_differs_from_Guid_order_and_remains_exact_through_Finish()
    {
        var f = new Frame(craftedOrder: true); f.Review(); f.Accept(); f.Process();
        var body = f.Demand().Reviews.Single().Input.Snapshot;
        Assert.False(body.fields.Select(x => x.Id).SequenceEqual(body.fields.OrderBy(x => x.Id).Select(x => x.Id)));
        Assert.True(body.fields.Select(x => x.Id).SequenceEqual(body.fields.OrderBy(x => new SqlGuid(x.Id)).Select(x => x.Id)));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Rebound_snapshot_or_accepted_field_array_order_is_not_the_original_SQL_producer(bool accepted)
    {
        var f = new Frame(craftedOrder: true); f.Review(reverseSnapshot: !accepted);
        if (accepted)
        {
            f.Accept(); f.Process(); var a = f.Acceptance!;
            a.FieldsJson = JsonSerializer.Serialize(JsonSerializer.Deserialize<DocumentField[]>(a.FieldsJson)!.OrderBy(x => x.Id));
            a.FieldsSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(a.FieldsJson));
            f.F.Audits.Single(x => x.Event == "signer_finish_accepted").DataJson = SignerFinish.EvidenceJson(a);
            f.F.Audits.Single(x => x.Event == "signer_completed").DataJson = SignerCheckpointState.PublishedJson(a); f.Sync();
        }
        Assert.Throws<InvalidDataException>(() => f.Demand());
    }

    [Fact]
    public void Maximum_owned_field_set_keeps_every_original_Unicode_value_beyond_witness_header_size()
    {
        var f = new Frame(large: true); f.Review(); f.Accept(); f.Process();
        var result = f.Demand(); var snapshot = result.Reviews.Single().Input.Snapshot;
        Assert.Equal(199, snapshot.fields.Length); Assert.Equal(195, snapshot.fields.Count(x => x.Type == FieldType.Text));
        Assert.All(snapshot.fields.Where(x => x.Type == FieldType.Text), x => Assert.Equal(new string('é', 4000), x.Value));
        Assert.True(Encoding.UTF8.GetByteCount(result.Reviews[0].Input.Body.OriginalSnapshotJson) > 65536);
    }

    [Theory]
    [InlineData("SignerReviewCandidates")][InlineData("SignerFinishAcceptances")]
    public void Future_SQL_row_columns_do_not_disappear_in_entity_deserialization(string table)
    {
        var f = new Frame(); f.Review(); f.Accept(); using var sql = f.F.Sql(); var body = JsonNode.Parse(sql.RootElement.GetRawText())!;
        body["Tables"]!.AsArray().Single(x => x!["Table"]!.GetValue<string>() == table)!["Rows"]![0]!["FutureObject"] = Guid.NewGuid();
        using var changed = JsonDocument.Parse(body.ToJsonString());
        Assert.Throws<InvalidDataException>(() => ProductionHoldReviewCheckpointReferences.ReadVerified(changed.RootElement, f.F.Objects, f.F.Keys, f.Inputs));
    }

    [Theory]
    [InlineData("candidate-owner")][InlineData("candidate-party")][InlineData("candidate-source")][InlineData("candidate-pdf")]
    [InlineData("candidate-length")][InlineData("candidate-hash")][InlineData("candidate-recipe")][InlineData("candidate-snapshot")]
    [InlineData("candidate-date")][InlineData("candidate-expiry")][InlineData("candidate-used")][InlineData("candidate-superseded")]
    [InlineData("missing-input")][InlineData("duplicate-input")][InlineData("missing-pdf")][InlineData("pdf-length")]
    [InlineData("prepared-unknown")][InlineData("prepared-order")][InlineData("prepared-actor")][InlineData("prepared-mailbox")]
    [InlineData("prepared-time")][InlineData("prepared-duplicate")][InlineData("unknown-tail")][InlineData("field-after-finish")]
    [InlineData("finish-statement")][InlineData("finish-review")][InlineData("finish-session")][InlineData("finish-time")]
    [InlineData("finish-actor")][InlineData("finish-ip")][InlineData("finish-unknown")][InlineData("server-date")]
    [InlineData("server-filled-at")][InlineData("server-rowversion")][InlineData("current-field")][InlineData("checkpoint-copy")]
    [InlineData("rebound-field-time")]
    [InlineData("checkpoint-current")][InlineData("checkpoint-time")][InlineData("checkpoint-actor")][InlineData("checkpoint-unknown")]
    [InlineData("checkpoint-work")][InlineData("checkpoint-attempt")][InlineData("checkpoint-lease")][InlineData("next-id")]
    [InlineData("next-mailbox")][InlineData("next-template")][InlineData("next-submitted")][InlineData("next-provider")]
    [InlineData("next-work")][InlineData("next-payload")][InlineData("second-consent")][InlineData("second-token")]
    public void Rehashed_current_row_schema_clock_and_next_dispatch_substitutions_cannot_complete_preservation(string fault)
    {
        var f = new Frame(); f.Review(); f.Accept(); f.Process(); var c = f.Candidates[0]; var a = f.Acceptance!;
        var prepared = f.F.Audits.Single(x => x.Event == "signer_review_prepared");
        var accepted = f.F.Audits.Single(x => x.Event == "signer_finish_accepted"); var completed = f.F.Audits.Single(x => x.Event == "signer_completed");
        var next = f.F.Mail[^1]; var work = f.F.Work.Single(x => x.Id == a.Id);
        switch (fault)
        {
            case "candidate-owner": c.EnvelopeId = Guid.NewGuid(); break; case "candidate-party": c.SignerId = f.F.Signers[1].Id; break;
            case "candidate-source": c.SourceObjectId = Guid.NewGuid(); break; case "candidate-pdf": c.PdfObjectId = Guid.NewGuid(); break;
            case "candidate-length": c.PdfLength++; break; case "candidate-hash": c.PdfSha256 = SHA256.HashData([9]); break;
            case "candidate-recipe": c.RecipeSha256 = SHA256.HashData([9]); break; case "candidate-snapshot": c.SnapshotSha256 = SHA256.HashData([9]); break;
            case "candidate-date": c.ProspectiveDate = c.ProspectiveDate.AddDays(1); break; case "candidate-expiry": c.ExpiresAt = c.ExpiresAt.AddSeconds(1); break;
            case "candidate-used": c.UsedAt = null; break; case "candidate-superseded": c.SupersededAt = c.PreparedAt; break;
            case "missing-input": f.Inputs.Clear(); break; case "duplicate-input": f.Inputs.Add(f.Inputs[0]); break;
            case "missing-pdf": f.F.Objects.RemoveAll(x => x.Address.Name.EndsWith('/' + c.PdfObjectId.ToString("N"), StringComparison.Ordinal)); break;
            case "pdf-length": f.F.Objects[^1] = f.F.Objects[^1] with { Address = f.F.Objects[^1].Address with { Length = 17 } }; break;
            case "prepared-unknown": f.F.EditEvent(prepared, x => x["future"] = true); break;
            case "prepared-order": prepared.DataJson = Reorder(prepared.DataJson); break; case "prepared-actor": prepared.ActorType = PartyType.Sender; break;
            case "prepared-mailbox": prepared.ActorEmail = f.F.Envelope.SenderEmail; break; case "prepared-time": prepared.At = c.PreparedAt.AddTicks(-1); break;
            case "prepared-duplicate": f.F.Audits.Insert(f.F.Audits.IndexOf(prepared), Clone(prepared)); break;
            case "unknown-tail": f.M.Event("future_review_event", "{}", completed.At.AddSeconds(1)); break;
            case "field-after-finish": var field = Clone(f.F.Audits.Last(x => x.Event == "field_filled")); field.At = completed.At.AddSeconds(1); f.F.Audits.Add(field); break;
            case "finish-statement": a.Statement = "Different"; break; case "finish-review": a.ReviewCandidateId = Guid.NewGuid(); break;
            case "finish-session": a.SessionSha256 = SHA256.HashData([9]); break; case "finish-time": a.FinishedAt = c.ExpiresAt; break;
            case "finish-actor": accepted.ActorId = f.F.Signers[1].Id; break; case "finish-ip": accepted.Ip = "127.0.0.2"; break;
            case "finish-unknown": f.F.EditEvent(accepted, x => x["future"] = 1); break;
            case "server-date": f.M.Date.Value = "2031-01-01"; break; case "server-filled-at": f.M.Date.FilledAt = a.FinishedAt.AddTicks(1); break;
            case "server-rowversion": f.M.Signature.RowVersion = new byte[7]; break; case "current-field": f.M.Signature.Value = Guid.NewGuid().ToString("N"); break;
            case "checkpoint-copy": f.F.Envelope.CurrentCopyVersion = 2; break; case "checkpoint-current": f.F.Envelope.CurrentFinishId = Guid.NewGuid(); break;
            case "checkpoint-time": a.ProcessedAt = a.FinishedAt.AddTicks(-1); break; case "checkpoint-actor": completed.ActorType = PartyType.System; break;
            case "checkpoint-unknown": f.F.EditEvent(completed, x => x["future"] = true); break;
            case "checkpoint-work": work.Status = WorkStatus.Queued; break; case "checkpoint-attempt": work.Attempts = 2; break;
            case "checkpoint-lease": work.LeaseOwner = Guid.NewGuid(); break; case "next-id": a.NextInvitationId = Guid.NewGuid(); break;
            case "next-mailbox": next.To = f.F.Signers[0].Email; break; case "next-template": next.Template = "future"; break;
            case "next-submitted": next.SubmissionStartedAt = a.ProcessedAt; break; case "next-provider": next.Provider = "unexpected"; break;
            case "next-work": f.F.Work[^1].PayloadJson = "{\"future\":true}"; break;
            case "next-payload": next.PayloadJson = new SignerInvitationProtection(f.F.Keys).Protect(new(f.F.Signers[1].Id, DocumentId: c.SourceObjectId,
                DocumentSha256: Hex(c.SourceSha256), DisclosureSha256: Hex(c.DisclosureSha256))); break;
            case "second-consent": f.F.Signers[1].ConsentAt = a.ProcessedAt; break;
            case "second-token": f.F.Tokens.Add(new() { EnvelopeId = f.F.Envelope.Id, PartyType = PartyType.Signer, PartyId = f.F.Signers[1].Id, Purpose = TokenPurpose.SignerAccess }); break;
            case "rebound-field-time":
                f.M.Signature.FilledAt = f.M.Signature.FilledAt!.Value.AddTicks(1);
                a.FieldsJson = JsonSerializer.Serialize(f.F.Fields.Where(x => x.SignerId == c.SignerId).OrderBy(x => new SqlGuid(x.Id)));
                a.FieldsSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(a.FieldsJson));
                accepted.DataJson = SignerFinish.EvidenceJson(a); completed.DataJson = SignerCheckpointState.PublishedJson(a); break;
        }
        f.Sync(); Assert.Throws<InvalidDataException>(() => f.Demand());
    }

    internal sealed class Frame
    {
        internal readonly ProductionHoldSignaturePreviewReferenceTests.MarksFrame M = new(SignatureMethod.Typed);
        internal ProductionHoldSentAuditReferenceTests.Frame F => M.F;
        internal readonly List<SignerReviewCandidate> Candidates = []; internal readonly List<VerifiedReviewInput> Inputs = [];
        internal SignerFinishAcceptance? Acceptance; internal readonly List<SignerFinishAcceptance> Finishes = [];
        private readonly VerifiedSigner identity;
        internal Frame(bool large = false, bool craftedOrder = false, int parties = 2, bool laterFields = false, int additionalTextFields = 0)
        {
            var first = F.Signers[0]; var e = F.Envelope;
            for (var party = 1; party < parties; party++)
            {
                var later = new Signer { EnvelopeId = e.Id, Order = party + 1, FullName = $"Synthetic later signer {party + 1}", Email = $"party{party + 1}@example.invalid", RowVersion = new byte[8] };
                F.Signers.Add(later);
                var roster = new AuditEvent { EnvelopeId = e.Id, Event = "signer_added", ActorType = PartyType.Sender, ActorEmail = e.SenderEmail,
                    At = F.Audits.First(x => x.Event == "signer_added").At.AddTicks(party),
                    DataJson = JsonSerializer.Serialize(new { signerId = later.Id, signers = F.Signers.Select(x => new SignerListItem(x.Id, x.Order, x.FullName, x.Email, x.Role)).ToArray() }) };
                F.Audits.Insert(F.Audits.FindIndex(x => x.Event == "recipient_added"), roster);
                if (laterFields)
                    foreach (var type in new[] { FieldType.Signature, FieldType.Initials, FieldType.Text, FieldType.FullName, FieldType.DateSigned })
                        F.Fields.Add(new() { EnvelopeId = e.Id, SignerId = later.Id, Type = type, Page = 1, X = .10000000m, Y = .20000000m, Width = .30000000m, Height = .10000000m,
                            DateFormat = type == FieldType.DateSigned ? "yyyy-MM-dd" : null, RowVersion = new byte[8] });
            }
            for (var index = 0; index < additionalTextFields; index++)
                F.Fields.Add(new() { EnvelopeId = e.Id, SignerId = F.Signers[index % parties].Id, Type = FieldType.Text, Page = 1,
                    X = .10000000m, Y = .20000000m, Width = .30000000m, Height = .10000000m, RowVersion = new byte[8] });
            e.PageSizesJson = JsonSerializer.Serialize(new[] { new PageGeometry(612, 792, 0, 1, [0, 0, 612, 792], [0, 0, 612, 792]) });
            if (craftedOrder)
            {
                var owned = F.Fields.Where(x => x.SignerId == first.Id).ToArray();
                owned[0].Id = Guid.Parse("00000001-0000-0000-0000-000000000000");
                owned[1].Id = Guid.Parse("00000000-0000-0000-0000-000000000001");
                for (var n = 2; n < owned.Length; n++) owned[n].Id = Guid.Parse($"0000000{n}-0000-0000-0000-000000000000");
            }
            if (large)
            {
                for (var n = 0; n < 194; n++) F.Fields.Add(new() { EnvelopeId = e.Id, SignerId = first.Id, Type = FieldType.Text, Page = 1,
                    X = .10000000m, Y = .20000000m, Width = .30000000m, Height = .10000000m, RowVersion = new byte[8] });
            }
            if (large || craftedOrder || laterFields || additionalTextFields > 0)
            {
                F.Audits.Single(x => x.Event == "fields_saved").DataJson = JsonSerializer.Serialize(new { documentId = e.PdfBlob,
                    fields = F.Fields.Select(x => new FieldInput(x.Id, x.SignerId, x.Type.ToString(), x.Page, x.X, x.Y, x.Width, x.Height, x.Required, x.Label, x.Value)).ToArray() });
                F.FreezeFields();
            }
            M.Adopt(); M.Fill();
            if (large || additionalTextFields > 0)
                foreach (var field in F.Fields.Where(x => x.SignerId == first.Id && x.Type == FieldType.Text))
                {
                    var at = F.Audits.Last().At.AddTicks(2); field.Value = new string('é', 4000); field.FilledAt = at; field.FilledBy = PartyType.Signer;
                    M.Event("field_filled", JsonSerializer.Serialize(new { fieldId = field.Id, type = "Text", previousValue = (string?)null, value = field.Value,
                        previousAdoptionId = (Guid?)null, adoptionId = (Guid?)null, previousImageSha256 = (string?)null, imageSha256 = (string?)null,
                        valueSha256 = Hex(SHA256.HashData(Encoding.UTF8.GetBytes(field.Value))), documentSha256 = Hex(e.SentPdfSha256!), disclosureSha256 = Hex(e.ErsdSha256!),
                        input = "explicit_owned_field_request" }), at.AddTicks(1));
                }
            identity = new(e.Id, e.PublicId, first.Id, first.Email, Guid.Parse(e.SentPdfBlob!), Hex(e.SentPdfSha256!), Hex(e.ErsdSha256!), F.Audits.Last().At.AddHours(2));
            Sync();
        }
        internal void Review(bool reverseSnapshot = false, int party = 0)
        {
            var e = F.Envelope; var s = F.Signers[party]; var mark = M.Previews.Last(x => x.SignerId == s.Id); var at = F.Audits.Last().At.AddSeconds(1); var cut = F.Audits.Last();
            var reviewIdentity = party == 0 ? identity : new VerifiedSigner(e.Id, e.PublicId, s.Id, s.Email, mark.DocumentId,
                Hex(mark.DocumentSha256), Hex(mark.DisclosureSha256), at.AddHours(2));
            var fields = F.Fields.Where(x => x.SignerId == s.Id).OrderBy(x => new SqlGuid(x.Id)).Select(Clone).ToArray();
            if (reverseSnapshot) fields = fields.OrderBy(x => x.Id).ToArray();
            var snapshot = JsonSerializer.Serialize(new { version = "signer-review-v1", reviewIdentity.EnvelopeId, reviewIdentity.SignerId, reviewIdentity.DocumentId,
                reviewIdentity.DocumentHash, reviewIdentity.DisclosureHash, e.RowVersion, e.PageCount, e.PageSizesJson, s.FullName, s.ConsentAt, signerVersion = s.RowVersion,
                adoptionId = mark.Id, mark.SignatureSha256, mark.InitialsSha256, mark.NormalizationVersion, fields });
            var render = new ReviewRenderInputV1(e.Id, s.Id, s.FullName, at, mark.Id, fields.Select(x => new SignerPdfField(x.Id, x.EnvelopeId, x.SignerId,
                x.RowVersion, x.Type, x.Page, x.X, x.Y, x.Width, x.Height, x.Required, x.Value, x.FilledAt, x.FilledBy, x.SignatureAdoptionId, x.ImageSha256)).ToArray(),
                new(mark.Id, mark.SignatureObjectId, mark.InitialsObjectId, mark.SignatureSha256, mark.InitialsSha256, mark.NormalizationVersion));
            var bytes = Encoding.UTF8.GetBytes("Synthetic retained review PDF bytes");
            var candidate = new SignerReviewCandidate { EnvelopeId = e.Id, SignerId = s.Id, AdoptionId = mark.Id, SourceObjectId = reviewIdentity.DocumentId,
                PdfObjectId = Guid.NewGuid(), PdfLength = bytes.Length, SourceSha256 = mark.DocumentSha256, DisclosureSha256 = e.ErsdSha256!,
                SessionSha256 = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(reviewIdentity)), SnapshotSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(snapshot)),
                PdfSha256 = SHA256.HashData(bytes), RecipeSha256 = Convert.FromHexString(ProductionReviewInputCodec.Binding(render, 1, mark.DocumentSha256)),
                RendererVersion = "signer-pdf-v1", SnapshotVersion = "signer-review-v1", PreparedAt = at, ExpiresAt = at.AddMinutes(10), ProspectiveDate = DateOnly.FromDateTime(at.UtcDateTime) };
            var body = new ReviewInputV1("review-input-v1", e.Id, Guid.NewGuid(), candidate.Id, JsonSerializer.Serialize(candidate), reviewIdentity, reviewIdentity.SessionExpiresAt,
                snapshot, render, JsonSerializer.Deserialize<PageGeometry[]>(e.PageSizesJson!)!, cut.Id, checked((int)cut.Sequence), Hex(cut.Hash));
            Inputs.Add(Seal(body, candidate, bytes));
            foreach (var old in Candidates.Where(x => x.SignerId == s.Id && x.UsedAt is null && x.SupersededAt is null && x.ExpiresAt > at && !x.SnapshotSha256.SequenceEqual(candidate.SnapshotSha256))) old.SupersededAt = at;
            candidate.RowVersion = Enumerable.Repeat((byte)(10 + Candidates.Count), 8).ToArray(); Candidates.Add(candidate);
            F.Objects.Add(new(new("normalized", $"{e.Id:N}/{candidate.PdfObjectId:N}", "synthetic-review-version", "", "\"synthetic-review-etag\"", bytes.Length), Hex(candidate.PdfSha256)));
            PartyEvent(s, "signer_review_prepared", ProductionHoldReviewCheckpointReferences.PreparedJson(candidate), at.AddTicks(1)); Sync();
        }
        private VerifiedReviewInput Seal(ReviewInputV1 body, SignerReviewCandidate candidate, byte[] pdf)
        {
            var mark = M.Previews.Single(x => x.Id == candidate.AdoptionId); var signature = SignaturePng.Normalize(SignatureAdoptionTests.Mark(20)).Bytes;
            var initials = SignaturePng.Normalize(SignatureAdoptionTests.Mark(60)).Bytes;
            var request = new SignerPdfRequest(body.RecordId, candidate.SignerId, body.Render.FullName, candidate.PreparedAt, candidate.AdoptionId,
                body.Render.Fields, new(mark.Id, mark.SignatureObjectId, mark.InitialsObjectId, signature, initials, mark.SignatureSha256, mark.InitialsSha256, mark.NormalizationVersion));
            var rendered = new RenderedSignerPdf(pdf, candidate.PdfSha256, candidate.SourceSha256, candidate.RecipeSha256, candidate.EnvelopeId,
                candidate.SignerId, candidate.AdoptionId, candidate.PreparedAt, candidate.RendererVersion);
            var write = ProductionSignerReviewWrite.Own(F.Keys, body.OperationId, Guid.NewGuid(), candidate, body.Identity, body.AccessExpiresAt,
                body.OriginalSnapshotJson, request, body.Pages, rendered, body.AuditId, body.AuditSequence, Convert.FromHexString(body.AuditSha256));
            using var source = write.Open(DocumentBlobKind.ReviewInput); using var memory = new MemoryStream(); source.CopyTo(memory);
            return ProductionReviewInputCodec.OpenVerified(F.Keys, write.Plan(null, F.Envelope.ExpiresAt, new string('a', 64), []), memory.ToArray());
        }
        internal void Accept()
        {
            var c = Candidates[^1]; var at = F.Audits.Last().At.AddSeconds(1); var date = F.Fields.Single(x => x.SignerId == c.SignerId && x.Type == FieldType.DateSigned);
            date.Value = c.ProspectiveDate.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture); date.FilledAt = at; date.FilledBy = PartyType.Signer; date.RowVersion = Enumerable.Repeat((byte)20, 8).ToArray();
            var json = JsonSerializer.Serialize(F.Fields.Where(x => x.SignerId == c.SignerId).OrderBy(x => new SqlGuid(x.Id)).ToArray()); c.UsedAt = at;
            Acceptance = new() { EnvelopeId = c.EnvelopeId, SignerId = c.SignerId, ReviewCandidateId = c.Id, AdoptionId = c.AdoptionId, SourceObjectId = c.SourceObjectId,
                PdfObjectId = c.PdfObjectId, PdfLength = c.PdfLength, SourceSha256 = c.SourceSha256, DisclosureSha256 = c.DisclosureSha256, SessionSha256 = c.SessionSha256,
                SnapshotSha256 = c.SnapshotSha256, PdfSha256 = c.PdfSha256, RecipeSha256 = c.RecipeSha256, FieldsJson = json, FieldsSha256 = SHA256.HashData(Encoding.UTF8.GetBytes(json)),
                SnapshotVersion = SignerFinish.SnapshotVersion, StatementVersion = SignerFinishStatement.Version, Statement = SignerFinishStatement.Text, StatementSha256 = SignerFinishStatement.Sha256,
                ProspectiveDate = c.ProspectiveDate, ReviewPreparedAt = c.PreparedAt, ReviewExpiresAt = c.ExpiresAt, FinishedAt = at, RowVersion = new byte[8] };
            Finishes.Add(Acceptance); PartyEvent(F.Signers.Single(x => x.Id == c.SignerId), "signer_finish_accepted", SignerFinish.EvidenceJson(Acceptance), at.AddTicks(1));
            F.Work.Add(new() { Id = Acceptance.Id, EnvelopeId = c.EnvelopeId, Kind = WorkKind.Rendering, AvailableAt = at.AddTicks(2),
                PayloadJson = JsonSerializer.Serialize(new SignerCheckpointPayload(SignerCheckpointJobs.Version, Acceptance.Id)) }); Sync();
        }
        internal void Process()
        {
            var f = Acceptance!; var at = F.Audits.Last().At.AddSeconds(1); f.ProcessedAt = at;
            var s = F.Signers.Single(x => x.Id == f.SignerId); var next = F.Signers.SingleOrDefault(x => x.Order == s.Order + 1);
            f.NextInvitationId = next is null ? null : Guid.NewGuid(); s.Status = SignerStatus.Signed; s.SignedAt = f.FinishedAt; s.SignedIp = f.Ip; s.SignedUa = f.UserAgent;
            F.Envelope.CurrentFinishId = f.Id; F.Envelope.CurrentCopyVersion = s.Order;
            PartyEvent(s, "signer_completed", SignerCheckpointState.PublishedJson(f), at.AddTicks(1)); var due = at.AddTicks(2);
            if (next is not null)
            {
                F.Mail.Add(new() { Id = f.NextInvitationId!.Value, EnvelopeId = f.EnvelopeId, Template = "signer-invitation", To = next.Email, AvailableAt = due,
                    PayloadJson = new SignerInvitationProtection(F.Keys).Protect(new(next.Id, DocumentId: f.PdfObjectId, DocumentSha256: Hex(f.PdfSha256), DisclosureSha256: Hex(f.DisclosureSha256))) });
                F.Work.Add(new() { Id = f.NextInvitationId.Value, EnvelopeId = f.EnvelopeId, Kind = WorkKind.Email, AvailableAt = due });
            }
            else F.Work.Add(new() { Id = CompletionJobs.WorkId(f.EnvelopeId), EnvelopeId = f.EnvelopeId, Kind = WorkKind.Sealing, AvailableAt = due,
                PayloadJson = JsonSerializer.Serialize(new CompletionWorkPayload(CompletionJobs.Version, f.Id, F.Signers.Count, Hex(f.PdfSha256), Hex(f.DisclosureSha256))) });
            var work = F.Work.Single(x => x.Id == f.Id); work.Status = WorkStatus.Completed; work.Attempts = 1; work.AvailableAt = due.AddTicks(1); Sync();
        }
        internal void PartyEvent(Signer signer, string name, string json, DateTimeOffset at) => F.Audits.Add(new() { EnvelopeId = F.Envelope.Id, Event = name,
            ActorType = PartyType.Signer, ActorId = signer.Id, ActorEmail = signer.Email, DataJson = json, At = at });
        internal void Sync() { F.Other["SignerReviewCandidates"] = Candidates.Cast<object>().ToArray(); F.Other["SignerFinishAcceptances"] = Finishes.Cast<object>().ToArray(); M.Sync(); }
        internal HoldReviewCheckpointHistory Demand() { using var sql = F.Sql(); return ProductionHoldReviewCheckpointReferences.ReadVerified(sql.RootElement, F.Objects, F.Keys, Inputs); }
    }
    private static string Reorder(string json) => "{" + string.Join(',', JsonNode.Parse(json)!.AsObject().Reverse().Select(x => JsonSerializer.Serialize(x.Key) + ":" + x.Value!.ToJsonString())) + "}";
    private static T Clone<T>(T value) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(value))!;
    private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
}
