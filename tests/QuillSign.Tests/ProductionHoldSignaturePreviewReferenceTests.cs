using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionHoldSignaturePreviewReferenceTests
{
    [Theory]
    [InlineData("source")][InlineData("disclosure")][InlineData("session")][InlineData("baseline")][InlineData("missing-mark")]
    [InlineData("hash")][InlineData("width")][InlineData("method")][InlineData("descriptor")][InlineData("normalizer")]
    [InlineData("statement")][InlineData("before-consent")][InlineData("long-expiry")][InlineData("future")][InlineData("source-alias")]
    public void An_unused_preview_without_an_adoption_event_still_requires_complete_exact_metadata_and_mark_facts(string fault)
    {
        var f = new MarksFrame(SignatureMethod.Typed); var p = f.P;
        switch (fault)
        {
            case "source": p.DocumentId = Guid.NewGuid(); break; case "disclosure": p.DisclosureSha256 = SHA256.HashData([9]); break;
            case "session": p.SessionSha256 = new byte[31]; break; case "baseline": p.BaselineSignerVersion = new byte[7]; break;
            case "missing-mark": f.Remove(p.InitialsObjectId); break; case "hash": p.SignatureSha256 = SHA256.HashData([9]); break;
            case "width": p.SignatureWidth = 1; break; case "method": p.Method = (SignatureMethod)999; break;
            case "descriptor": p.TypedName = "Synthetic\tName"; break; case "normalizer": p.NormalizationVersion = "future"; break;
            case "statement": p.AdoptionVersion = "future"; break; case "before-consent": p.CreatedAt = f.F.Signers[0].ConsentAt!.Value; break;
            case "long-expiry": p.ExpiresAt = p.CreatedAt.AddMinutes(11); break; case "future": p.CreatedAt = f.F.Captured.AddDays(1); break;
            case "source-alias": p.SignatureObjectId = Guid.Parse(f.F.Envelope.OriginalBlob!); break;
        }
        f.Sync(); using var sql = f.F.Sql(); Assert.Throws<InvalidDataException>(() => f.F.Demand(sql));
    }

    [Fact]
    public void Expiry_after_capture_does_not_excuse_a_sixth_concurrent_unused_preview()
    {
        var f = new MarksFrame(SignatureMethod.Drawn); for (var n = 0; n < 5; n++) f.AddPreview(SignatureMethod.Drawn);
        using var sql = f.F.Sql(); Assert.Throws<InvalidDataException>(() => f.F.Demand(sql));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public void Future_or_missing_preview_columns_are_refused_even_without_adoption(bool removeKnown)
    {
        var f = new MarksFrame(SignatureMethod.Drawn); using var sql = f.F.Sql(); var body = JsonNode.Parse(sql.RootElement.GetRawText())!;
        var row = body["Tables"]!.AsArray().Single(x => x!["Table"]!.GetValue<string>() == "SignaturePreviews")!["Rows"]![0]!.AsObject();
        if (removeKnown) row.Remove("TypedName"); else row["FutureObject"] = Guid.NewGuid();
        using var changed = JsonDocument.Parse(body.ToJsonString()); Assert.Throws<InvalidDataException>(() => f.F.Demand(changed));
    }

    [Theory]
    [InlineData("Typed", false)][InlineData("Drawn", false)][InlineData("Uploaded", false)]
    [InlineData("Typed", true)][InlineData("Drawn", true)][InlineData("Uploaded", true)]
    public void Exact_prepared_adopted_and_editable_stages_retain_expired_proof_and_return_immutable_facts(string method, bool adopt)
    {
        var f = new MarksFrame(Enum.Parse<SignatureMethod>(method)); if (adopt) { f.Adopt(); f.Fill(); }
        using var sql = f.F.Sql(); var saved = ProductionHoldSentAuditReferences.ReadVerified(sql.RootElement, f.F.Objects, f.F.Keys).Single();
        Assert.Equal(f.P.Id, saved.Id); Assert.Equal(f.P.ExpiresAt, saved.ExpiresAt); Assert.True(saved.ExpiresAt < f.F.Captured);
        Assert.Equal(Convert.ToHexStringLower(f.P.SignatureSha256), saved.SignatureSha256); Assert.Equal(f.P.UsedAt, saved.UsedAt);
        using var reversed = f.F.Sql(reverse: true); f.F.Demand(reversed);
    }

    [Fact]
    public void Replaced_adoption_keeps_old_applied_mark_until_explicit_clear_and_reapply_and_retains_unused_old_preview()
    {
        var f = new MarksFrame(SignatureMethod.Drawn); var unused = f.P; f.AddPreview(SignatureMethod.Uploaded); f.Adopt(); f.Fill();
        var previous = f.P; f.AddPreview(SignatureMethod.Typed); f.Adopt();
        using (var stale = f.F.Sql()) f.F.Demand(stale);
        Assert.Equal(previous.SignatureObjectId.ToString("N"), f.Signature.Value);
        f.Fill(clear: true); f.Fill();
        using var sql = f.F.Sql(); var saved = ProductionHoldSentAuditReferences.ReadVerified(sql.RootElement, f.F.Objects, f.F.Keys);
        Assert.Equal(3, saved.Count); Assert.Null(saved.Single(x => x.Id == unused.Id).UsedAt); Assert.Equal(f.P.SignatureObjectId.ToString("N"), f.Signature.Value);
    }

    [Theory]
    [InlineData("owner")][InlineData("party")][InlineData("id")][InlineData("duplicate")][InlineData("bound")]
    [InlineData("source")][InlineData("source-hash")][InlineData("disclosure")][InlineData("session")][InlineData("baseline")]
    [InlineData("signature-id")][InlineData("initials-id")][InlineData("same-id")][InlineData("source-id")][InlineData("missing-signature")][InlineData("missing-initials")]
    [InlineData("signature-hash")][InlineData("initials-hash")][InlineData("foreign-object")][InlineData("length")][InlineData("oversize")]
    [InlineData("width")][InlineData("height")][InlineData("initials-width")][InlineData("initials-height")]
    [InlineData("method")][InlineData("typed-name")][InlineData("typed-initials")][InlineData("typed-control")][InlineData("typed-nfc")]
    [InlineData("normalizer")][InlineData("statement")][InlineData("created-offset")][InlineData("created-before-consent")][InlineData("created-future")]
    [InlineData("expiry-offset")][InlineData("expiry-before-created")][InlineData("expiry-long")][InlineData("used-no-audit")]
    [InlineData("used-before-created")][InlineData("used-expired")][InlineData("adoption-missing")][InlineData("adoption-unknown")][InlineData("adoption-actor")]
    [InlineData("adoption-before-consent")][InlineData("adoption-prior")][InlineData("field-unknown")][InlineData("field-prior")][InlineData("field-actor")]
    [InlineData("field-current")][InlineData("field-generic")][InlineData("field-date")][InlineData("field-definition")][InlineData("later-preview")][InlineData("future-tail")]
    [InlineData("missing-preparation")][InlineData("rehashed-saved-field")][InlineData("new-dispatch")][InlineData("contact")][InlineData("review")][InlineData("finish")]
    public void Correctly_rehashed_metadata_object_and_closed_projection_faults_are_refused(string fault)
    {
        var f = new MarksFrame(SignatureMethod.Typed); f.Adopt(); f.Fill(); var p = f.P; var first = f.F.Signers[0];
        var adoption = f.F.Audits.Single(x => x.Event == "signature_adopted"); var field = f.F.Audits.Last(x => x.Event == "field_filled");
        switch (fault)
        {
            case "owner": p.EnvelopeId = Guid.NewGuid(); break; case "party": p.SignerId = Guid.NewGuid(); break; case "id": p.Id = Guid.Empty; break;
            case "duplicate": f.Previews.Add(p); break; case "bound": while (f.Previews.Count <= SignatureAdoption.MaximumPreviewsPerSigner) f.Previews.Add(p); break;
            case "source": p.DocumentId = Guid.Parse(f.F.Envelope.PdfBlob!); break; case "source-hash": p.DocumentSha256 = SHA256.HashData([9]); break;
            case "disclosure": p.DisclosureSha256 = SHA256.HashData([9]); break; case "session": p.SessionSha256 = new byte[31]; break;
            case "baseline": p.BaselineSignerVersion = new byte[7]; break; case "signature-id": p.SignatureObjectId = Guid.Empty; break;
            case "initials-id": p.InitialsObjectId = Guid.Empty; break; case "same-id": p.InitialsObjectId = p.SignatureObjectId; break;
            case "source-id": p.SignatureObjectId = p.DocumentId; break; case "missing-signature": f.Remove(p.SignatureObjectId); break;
            case "missing-initials": f.Remove(p.InitialsObjectId); break; case "signature-hash": p.SignatureSha256 = SHA256.HashData([9]); break;
            case "initials-hash": p.InitialsSha256 = SHA256.HashData([9]); break;
            case "foreign-object": f.F.Objects[^1] = f.F.Objects[^1] with { Address = f.F.Objects[^1].Address with { Name = $"{Guid.NewGuid():N}/{p.InitialsObjectId:N}" } }; break;
            case "length": f.F.Objects[^1] = f.F.Objects[^1] with { Address = f.F.Objects[^1].Address with { Length = 0 } }; break;
            case "oversize": f.F.Objects[^1] = f.F.Objects[^1] with { Address = f.F.Objects[^1].Address with { Length = SignaturePng.MaximumBytes + 1 } }; break;
            case "width": p.SignatureWidth = 0; break; case "height": p.SignatureHeight = SignaturePng.MaximumHeight + 1; break;
            case "initials-width": p.InitialsWidth = SignaturePng.MaximumWidth + 1; break; case "initials-height": p.InitialsHeight = 0; break;
            case "method": p.Method = (SignatureMethod)999; break; case "typed-name": p.TypedName = null; break; case "typed-initials": p.TypedInitials = new('X', 21); break;
            case "typed-control": p.TypedName = "Synthetic\tName"; break; case "typed-nfc": p.TypedName = "Cafe\u0301"; break;
            case "normalizer": p.NormalizationVersion = "future"; break; case "statement": p.AdoptionVersion = "future"; break;
            case "created-offset": p.CreatedAt = p.CreatedAt.ToOffset(TimeSpan.FromHours(1)); break;
            case "created-before-consent": p.CreatedAt = first.ConsentAt!.Value.AddTicks(-1); break; case "created-future": p.CreatedAt = f.F.Captured.AddDays(1); break;
            case "expiry-offset": p.ExpiresAt = p.ExpiresAt.ToOffset(TimeSpan.FromHours(1)); break;
            case "expiry-before-created": p.ExpiresAt = p.CreatedAt; break; case "expiry-long": p.ExpiresAt = p.CreatedAt.AddMinutes(11); break;
            case "used-no-audit": f.F.Audits.Remove(adoption); break; case "used-before-created": p.UsedAt = p.CreatedAt.AddTicks(-1); break;
            case "used-expired": p.UsedAt = p.ExpiresAt; break; case "adoption-missing": p.UsedAt = null; break;
            case "adoption-unknown": f.F.EditEvent(adoption, x => x["hiddenObject"] = Guid.NewGuid()); break;
            case "adoption-actor": adoption.ActorType = PartyType.Sender; break;
            case "adoption-before-consent": f.F.Audits.Remove(adoption); adoption.At = f.F.Audits.Single(x => x.Event == "consent_given").At; f.F.Audits.Insert(f.F.Audits.FindIndex(x => x.Event == "consent_given"), adoption); break;
            case "adoption-prior": f.F.EditEvent(adoption, x => x["replacedAdoptionId"] = Guid.NewGuid()); break;
            case "field-unknown": f.F.EditEvent(field, x => x["hiddenObject"] = Guid.NewGuid()); break;
            case "field-prior": f.F.EditEvent(field, x => x["previousValue"] = "unrecorded"); break; case "field-actor": field.ActorType = PartyType.Sender; break;
            case "field-current": f.Signature.Value = Guid.NewGuid().ToString("N"); break; case "field-generic": f.F.Fields[0].Value = "Changed after Send"; break;
            case "field-date": f.Date.Value = "2030-01-01"; f.Date.FilledAt = p.UsedAt; f.Date.FilledBy = PartyType.Signer; break;
            case "field-definition": f.Signature.X = .50000000m; break;
            case "later-preview": f.F.Signers.Add(new() { EnvelopeId = f.F.Envelope.Id, Order = 2, Email = "other@example.invalid", FullName = "Other" }); p.SignerId = f.F.Signers[1].Id; break;
            case "future-tail": f.Event("future_signature_event", "{}", p.ExpiresAt); break;
            case "missing-preparation": f.F.Audits.RemoveAll(x => x.Event == "fields_saved"); break;
            case "rehashed-saved-field": f.F.EditEvent(f.F.Audits.Single(x => x.Event == "fields_saved"), x => x["fields"]![1]!["X"] = .50000000m); break;
            case "new-dispatch": f.Event("invitation_submitted", "{}", p.ExpiresAt); break;
            case "contact": f.F.Other["SignerContactRevisions"] = [new { Id = Guid.NewGuid() }]; break;
            case "review": f.F.Other["SignerReviewCandidates"] = [new { Id = Guid.NewGuid() }]; break;
            case "finish": f.F.Other["SignerFinishAcceptances"] = [new { Id = Guid.NewGuid() }]; break;
        }
        f.Sync(); using var sql = f.F.Sql(); Assert.Throws<InvalidDataException>(() => f.F.Demand(sql));
    }

    private sealed class MarksFrame
    {
        internal readonly ProductionHoldSentAuditReferenceTests.Frame F = new(); internal readonly List<SignaturePreview> Previews = [];
        internal SignaturePreview P => Previews[^1]; internal DocumentField Signature => F.Fields.Single(x => x.Type == FieldType.Signature);
        internal DocumentField Date => F.Fields.Single(x => x.Type == FieldType.DateSigned);
        internal MarksFrame(SignatureMethod method)
        {
            var e = F.Envelope; var signer = F.Signers[0]; signer.RowVersion = Enumerable.Repeat((byte)3, 8).ToArray();
            foreach (var type in new[] { FieldType.Signature, FieldType.Initials, FieldType.Text, FieldType.FullName, FieldType.DateSigned })
                F.Fields.Add(new() { EnvelopeId = e.Id, SignerId = signer.Id, Type = type, Page = 1, X = .10000000m, Y = .20000000m, Width = .30000000m, Height = .10000000m,
                    DateFormat = type == FieldType.DateSigned ? "yyyy-MM-dd" : null, RowVersion = new byte[8] });
            var before = new List<AuditEvent>();
            void Sender(string name, object data, DateTimeOffset at) => before.Add(new() { EnvelopeId = e.Id, Event = name, ActorType = PartyType.Sender, ActorEmail = e.SenderEmail, At = at, DataJson = JsonSerializer.Serialize(data) });
            Sender("document_uploaded", new { filename = "synthetic.pdf", originalSha256 = Hex(e.OriginalSha256!), pdfSha256 = Hex(e.PdfSha256!), pageCount = 1, previousDocument = (string?)null, retentionSha256 = (string?)null }, e.SenderVerifiedAt!.Value.AddSeconds(10));
            Sender("preview_confirmed", new { document = e.PdfBlob, pdfSha256 = Hex(e.PdfSha256!) }, e.PreviewConfirmedAt!.Value.AddTicks(1));
            Sender("signer_added", new { signerId = signer.Id, signers = new[] { new SignerListItem(signer.Id, 1, signer.FullName, signer.Email, signer.Role) } }, e.PreviewConfirmedAt.Value.AddSeconds(10));
            var r = F.Recipients[0]; Sender("recipient_added", new { recipientId = r.Id, recipients = new[] { new RecipientItem(r.Id, r.Name!, r.Email) } }, e.PreviewConfirmedAt.Value.AddSeconds(20));
            Sender("fields_saved", new { documentId = e.PdfBlob, fields = F.Fields.Select(x => new FieldInput(x.Id, x.SignerId, x.Type.ToString(), x.Page, x.X, x.Y, x.Width, x.Height, x.Required, x.Label, x.Value)).ToArray() }, e.PreviewConfirmedAt.Value.AddMinutes(2));
            F.Audits.InsertRange(4, before); F.FreezeFields(); F.Progress(HoldInitialSignerStage.Consented); AddPreview(method);
        }
        internal void AddPreview(SignatureMethod method)
        {
            var signer = F.Signers[0]; var at = Previews.Count == 0 ? signer.ConsentAt!.Value.AddMinutes(1) : F.Audits.Last().At.AddMinutes(1);
            var signature = SignaturePng.Normalize(SignatureAdoptionTests.Mark((byte)(20 + Previews.Count))); var initials = SignaturePng.Normalize(SignatureAdoptionTests.Mark(60));
            var p = new SignaturePreview { EnvelopeId = F.Envelope.Id, SignerId = signer.Id, DocumentId = Guid.Parse(F.Envelope.SentPdfBlob!),
                SignatureObjectId = Guid.NewGuid(), InitialsObjectId = Guid.NewGuid(), SignatureSha256 = signature.Sha256, InitialsSha256 = initials.Sha256,
                DocumentSha256 = F.Envelope.SentPdfSha256!, DisclosureSha256 = F.Envelope.ErsdSha256!, SessionSha256 = SHA256.HashData("Synthetic saved original session"u8),
                BaselineSignerVersion = signer.RowVersion.ToArray(), SignatureWidth = signature.Width, SignatureHeight = signature.Height,
                InitialsWidth = initials.Width, InitialsHeight = initials.Height, Method = method, TypedName = method == SignatureMethod.Typed ? "Synthetic signer" : null,
                TypedInitials = method == SignatureMethod.Typed ? "SS" : null, NormalizationVersion = SignaturePng.Version, AdoptionVersion = SignatureAdoptionStatement.Version,
                CreatedAt = at, ExpiresAt = at.AddMinutes(10) };
            Previews.Add(p); Add(p.SignatureObjectId, signature.Bytes); Add(p.InitialsObjectId, initials.Bytes); Sync();
        }
        internal void Adopt()
        {
            var p = P; var signer = F.Signers[0]; var previous = signer.SignatureAdoptionId; p.UsedAt = p.CreatedAt.AddSeconds(1);
            signer.SignatureAdoptionId = p.Id; signer.SignatureAdoptedAt = p.UsedAt; signer.SignatureImageBlob = p.SignatureObjectId.ToString("N"); signer.InitialsImageBlob = p.InitialsObjectId.ToString("N");
            signer.SignatureImageSha256 = p.SignatureSha256; signer.InitialsImageSha256 = p.InitialsSha256; signer.SignatureMethod = p.Method;
            signer.SignatureTypedName = p.TypedName; signer.SignatureTypedInitials = p.TypedInitials; signer.SignatureNormalizationVersion = p.NormalizationVersion; signer.SignatureAdoptionVersion = p.AdoptionVersion;
            signer.RowVersion = Enumerable.Repeat((byte)(4 + Previews.Count), 8).ToArray();
            Event("signature_adopted", JsonSerializer.Serialize(new { adoptionId = p.Id, replacedAdoptionId = previous, statementVersion = p.AdoptionVersion,
                statement = SignatureAdoptionStatement.Text, statementSha256 = Hex(SignatureAdoptionStatement.Sha256), acknowledged = true, method = p.Method.ToString(),
                reportedTypedName = p.TypedName, reportedTypedInitials = p.TypedInitials, normalizationVersion = p.NormalizationVersion, signatureObjectId = p.SignatureObjectId,
                initialsObjectId = p.InitialsObjectId, signatureSha256 = Hex(p.SignatureSha256), initialsSha256 = Hex(p.InitialsSha256), documentSha256 = Hex(p.DocumentSha256),
                disclosureSha256 = Hex(p.DisclosureSha256), serverEvidence = "previewed_assets_bound_to_explicit_adoption_request", identityEvidence = "email_link_session_with_prior_consent" }), p.UsedAt.Value.AddTicks(1)); Sync();
        }
        internal void Fill(bool clear = false)
        {
            var field = Signature; var old = field.Value; var oldAdoption = field.SignatureAdoptionId; var oldHash = field.ImageSha256;
            var at = F.Audits.Last().At.AddSeconds(1); field.Value = clear ? null : P.SignatureObjectId.ToString("N"); field.SignatureAdoptionId = clear ? null : P.Id;
            field.ImageSha256 = clear ? null : P.SignatureSha256; field.FilledAt = clear ? null : at; field.FilledBy = clear ? null : PartyType.Signer;
            Event(clear ? "field_cleared" : "field_filled", JsonSerializer.Serialize(new { fieldId = field.Id, type = field.Type.ToString(), previousValue = old, value = field.Value,
                previousAdoptionId = oldAdoption, adoptionId = field.SignatureAdoptionId, previousImageSha256 = oldHash is null ? null : Hex(oldHash),
                imageSha256 = field.ImageSha256 is null ? null : Hex(field.ImageSha256), valueSha256 = field.Value is null ? null : Hex(SHA256.HashData(Encoding.UTF8.GetBytes(field.Value))),
                documentSha256 = Hex(P.DocumentSha256), disclosureSha256 = Hex(P.DisclosureSha256), input = "explicit_owned_field_request" }), at.AddTicks(1)); Sync();
        }
        internal void Event(string name, string data, DateTimeOffset at) => F.Audits.Add(new() { EnvelopeId = F.Envelope.Id, Event = name, ActorType = PartyType.Signer,
            ActorId = F.Signers[0].Id, ActorEmail = F.Signers[0].Email, DataJson = data, At = at });
        private void Add(Guid id, byte[] bytes) => F.Objects.Add(new(new("normalized", $"{F.Envelope.Id:N}/{id:N}", "synthetic-mark-version", "", "\"synthetic-mark-etag\"", bytes.LongLength), Hex(SHA256.HashData(bytes))));
        internal void Remove(Guid id) => F.Objects.RemoveAll(x => x.Address.Name.EndsWith('/' + id.ToString("N"), StringComparison.Ordinal));
        internal void Sync() { F.Other["SignaturePreviews"] = Previews.Cast<object>().ToArray(); F.Rehash(); }
        private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    }
}
