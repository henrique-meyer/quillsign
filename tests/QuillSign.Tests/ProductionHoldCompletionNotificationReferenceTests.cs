using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldCompletionNotificationReferenceTests
{
    [Theory]
    [InlineData(PartyType.Sender)][InlineData(PartyType.Signer)][InlineData(PartyType.Recipient)]
    public void Historical_completion_binds_publication_revision_and_both_original_versions_after_access_expiry(PartyType party)
    {
        var f = new Frame(party); using var sql = f.Sql(); f.Demand(sql);
        Assert.NotEqual(f.Envelope.RowVersion, f.Result.RowVersion);
        Assert.True(f.At.AddYears(1) < DateTimeOffset.UtcNow);
        var historical = f.Objects[0]; f.Objects[0] = historical with { Address = historical.Address with { VersionId = "newer-current-version" } };
        Assert.Throws<InvalidDataException>(() => f.Demand(sql));
        f.Objects.Add(historical); f.Demand(sql);
    }

    [Theory]
    [InlineData(PartyType.Sender)][InlineData(PartyType.Signer)][InlineData(PartyType.Recipient)]
    public void Issued_used_expired_completion_tokens_remain_exact_evidence_without_deadline_renewal(PartyType party)
    {
        var f = new Frame(party); f.Issue(); var original = JsonSerializer.Serialize(f.Tokens);
        using var sql = f.Sql(); f.Demand(sql); Assert.Equal(original, JsonSerializer.Serialize(f.Tokens));
        f.Tokens[0].CompletionPartySha256 = new byte[32]; using var changed = f.Sql();
        Assert.Throws<InvalidDataException>(() => f.Demand(changed));
    }

    [Theory]
    [InlineData("mail-owner")][InlineData("mailbox")][InlineData("attachment")][InlineData("payload-owner")]
    [InlineData("publication")][InlineData("revision")][InlineData("party-hash")][InlineData("party-id")]
    [InlineData("recipe")][InlineData("executed-ref")][InlineData("certificate-ref")][InlineData("demo")]
    [InlineData("missing-certificate")][InlineData("final-hash")][InlineData("final-area")][InlineData("final-prefix")]
    [InlineData("final-etag")][InlineData("final-length")][InlineData("final-snapshot")]
    [InlineData("queue-missing")][InlineData("queue-duplicate")][InlineData("queue-actor")][InlineData("queue-hash")]
    [InlineData("completed-sequence")][InlineData("prepared-proof")][InlineData("result-intent")][InlineData("result-recipe")]
    [InlineData("intent-recipe")][InlineData("after-source")][InlineData("before-owner")]
    [InlineData("envelope-final")][InlineData("reserved-target")]
    public void Foreign_partial_changed_or_rehashed_history_is_not_verified(string fault)
    {
        var f = new Frame(PartyType.Signer);
        switch (fault)
        {
            case "mail-owner": f.Mail.EnvelopeId = Guid.NewGuid(); break;
            case "mailbox": f.Mail.To = "other@example.invalid"; break;
            case "attachment": f.Mail.AttachmentsJson = "[{}]"; break;
            case "payload-owner": f.Payload = f.Payload with { EnvelopeId = Guid.NewGuid() }; break;
            case "publication": f.Payload = f.Payload with { PublicationId = Guid.NewGuid() }; break;
            case "revision": f.Payload = f.Payload with { Revision = Convert.ToBase64String(f.Envelope.RowVersion) }; break;
            case "party-hash": f.Payload = f.Payload with { PartyHash = new string('0', 64) }; break;
            case "party-id": f.Payload = f.Payload with { PartyId = Guid.NewGuid() }; break;
            case "recipe": f.Payload = f.Payload with { Recipe = new string('0', 64) }; break;
            case "executed-ref": f.Payload = f.Payload with { ExecutedReference = new string('0', 64) }; break;
            case "certificate-ref": f.Payload = f.Payload with { CertificateReference = new string('0', 64) }; break;
            case "demo": f.Payload = f.Payload with { IsDemo = true }; break;
            case "missing-certificate": f.Objects.RemoveAt(1); break;
            case "final-hash": f.Objects[0] = f.Objects[0] with { Sha256 = new string('0', 64) }; break;
            case "final-area": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Area = "normalized" } }; break;
            case "final-prefix": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Name = $"{Guid.NewGuid():N}/executed/{f.Executed.Document.ObjectId:N}" } }; break;
            case "final-etag": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { ETag = "\"changed\"" } }; break;
            case "final-length": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Length = 33 } }; break;
            case "final-snapshot": f.Objects[0] = f.Objects[0] with { Address = f.Objects[0].Address with { Snapshot = "unexpected-snapshot" } }; break;
            case "queue-missing": f.Audits.RemoveAt(2); break;
            case "queue-duplicate": f.Audits.Add(f.Audits[2]); break;
            case "queue-actor": f.Audits[2].ActorEmail = "unexpected@example.invalid"; f.Audits[2].Hash = AuditHash.Compute(f.Audits[2]); break;
            case "queue-hash": f.Audits[2].Hash = new byte[32]; break;
            case "completed-sequence": f.Audits[1].Sequence++; f.Audits[1].Hash = AuditHash.Compute(f.Audits[1]); break;
            case "prepared-proof": f.Audits[0].DataJson = "{}"; f.Audits[0].Hash = AuditHash.Compute(f.Audits[0]); break;
            case "result-intent": f.Result.IntentId = Guid.NewGuid(); break;
            case "result-recipe": f.Result.RecipeSha256 = new byte[32]; break;
            case "intent-recipe": f.Intent.RecipeSha256 = new byte[32]; break;
            case "after-source": f.Result.AfterEnvelopeSha256 = new byte[32]; f.RebuildPublication(); break;
            case "envelope-final": f.Envelope.FinalBlob = Guid.NewGuid().ToString("N"); f.Result.AfterEnvelopeSha256 = PublishedCompletionSource.Digest(f.Envelope); f.RebuildPublication(); break;
            case "reserved-target": f.Intent.ExecutedObjectId = Guid.NewGuid(); f.RebuildPublication(); break;
            case "before-owner":
                var before = JsonSerializer.Deserialize<Envelope>(f.Intent.BeforeEnvelopeJson)!; before.Id = Guid.NewGuid();
                f.Intent.BeforeEnvelopeJson = JsonSerializer.Serialize(before); f.RebuildPublication(); break;
        }
        // Scope mutations use valid ciphertext and regenerated queue evidence;
        // integrity must still bind the exact original publication and party.
        if (fault is "payload-owner" or "publication" or "revision" or "party-hash" or "party-id" or "recipe" or "executed-ref" or "certificate-ref" or "demo") f.Protect(true);
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Theory]
    [InlineData("wrapper")][InlineData("payload")][InlineData("duplicate")][InlineData("documents")][InlineData("before")]
    public void Correctly_protected_unknown_or_duplicate_fields_cannot_hide_additional_file_references(string fault)
    {
        var f = new Frame(PartyType.Sender);
        if (fault == "wrapper") f.Mail.PayloadJson = f.Mail.PayloadJson[..^1] + ",\"HiddenObject\":\"synthetic\"}";
        else if (fault is "documents" or "before")
        {
            if (fault == "documents") f.Result.FinalDocumentsJson = f.Result.FinalDocumentsJson[..^1] + ",\"HiddenObject\":\"synthetic\"}";
            else f.Intent.BeforeEnvelopeJson = f.Intent.BeforeEnvelopeJson[..^1] + ",\"HiddenObject\":\"synthetic\"}";
            f.RebuildPublication();
        }
        else
        {
            var p = f.Keys.CreateProtector("QuillSign.CompletionNotification.v1");
            var plain = p.Unprotect(JsonSerializer.Deserialize<ProtectedWorkPayload>(f.Mail.PayloadJson)!.Protected);
            plain = fault == "duplicate" ? plain[..^1] + "," + plain[1..] : plain[..^1] + ",\"HiddenObject\":\"synthetic\"}";
            f.Mail.PayloadJson = JsonSerializer.Serialize(new ProtectedWorkPayload(p.Protect(plain)));
        }
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Theory]
    [InlineData("missing")][InlineData("owner")][InlineData("party")][InlineData("publication")][InlineData("recipe")][InlineData("document")]
    public void A_submission_cannot_substitute_or_omit_its_issued_token(string fault)
    {
        var f = new Frame(PartyType.Recipient); f.Issue();
        switch (fault)
        {
            case "missing": f.Tokens.Clear(); break;
            case "owner": f.Tokens[0].EnvelopeId = Guid.NewGuid(); break;
            case "party": f.Tokens[0].PartyId = Guid.NewGuid(); break;
            case "publication": f.Tokens[0].CompletionPublicationId = Guid.NewGuid(); break;
            case "recipe": f.Tokens[0].CompletionRecipeSha256 = new byte[32]; break;
            case "document": f.Tokens[0].DocumentId = Guid.NewGuid(); break;
        }
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    private sealed class Frame
    {
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider();
        internal readonly DateTimeOffset At = new(2020, 1, 1, 12, 0, 0, TimeSpan.Zero);
        internal readonly Envelope Envelope;
        internal readonly Signer Signer;
        internal readonly Recipient Recipient;
        internal readonly CompletionPublicationIntent Intent;
        internal readonly CompletionPublicationResult Result;
        internal readonly FinalStoredDocument Executed, Certificate;
        internal readonly List<AuditEvent> Audits = [];
        internal readonly List<AuthToken> Tokens = [];
        internal readonly List<HoldObjectEvidence> Objects = [];
        internal readonly EmailOutbox Mail;
        internal CompletionNotificationPayload Payload;
        internal Frame(PartyType party)
        {
            Envelope = new() { SenderName = "Synthetic sender", SenderEmail = "sender@example.invalid", Status = EnvelopeStatus.Completed,
                Title = "Synthetic - NO AGREEMENT", CreatedAt = At.AddHours(-2), SenderVerifiedAt = At.AddHours(-2), SentAt = At.AddHours(-1),
                CompletedAt = At, RowVersion = [9,0,0,0,0,0,0,0] };
            Signer = new() { EnvelopeId = Envelope.Id, FullName = "Synthetic signer", Email = "signer@example.invalid", Status = SignerStatus.Signed };
            Recipient = new() { EnvelopeId = Envelope.Id, Name = "Synthetic recipient", Email = "recipient@example.invalid" };
            Executed = Document(FinalDocumentKind.Executed); Certificate = Document(FinalDocumentKind.Certificate);
            Envelope.FinalBlob = Executed.Document.ObjectId.ToString("N"); Envelope.FinalSha256 = Executed.Sha256;
            Envelope.CertificateBlob = Certificate.Document.ObjectId.ToString("N"); Envelope.CertificateSha256 = Certificate.Sha256;
            var before = JsonSerializer.Deserialize<Envelope>(JsonSerializer.Serialize(Envelope))!; before.Status = EnvelopeStatus.Sent; before.CompletedAt = null;
            before.FinalBlob = null; before.FinalSha256 = null; before.CertificateBlob = null; before.CertificateSha256 = null;
            Intent = new() { EnvelopeId = Envelope.Id, CandidateId = Guid.NewGuid(), ExecutedOutputId = Guid.NewGuid(), CertificateOutputId = Guid.NewGuid(),
                ExecutedObjectId = Executed.Document.ObjectId, CertificateObjectId = Certificate.Document.ObjectId,
                BeforeEnvelopeJson = JsonSerializer.Serialize(before), StageBindingsJson = "{}", RetentionDays = 365, PreparedAt = At.AddMinutes(-1) };
            Result = new() { EnvelopeId = Envelope.Id, IntentId = Intent.Id, FinalDocumentsJson = JsonSerializer.Serialize(new { Executed, Certificate }),
                CompletedAt = At, AuditSequence = 2, RowVersion = [3,0,0,0,0,0,0,0], AfterEnvelopeSha256 = PublishedCompletionSource.Digest(Envelope) };
            string? name; string email; int? order = null; Guid? member = null;
            if (party == PartyType.Sender) { name = Envelope.SenderName; email = Envelope.SenderEmail; }
            else if (party == PartyType.Signer) { name = Signer.FullName; email = Signer.Email; member = Signer.Id; order = Signer.Order; }
            else { name = Recipient.Name; email = Recipient.Email; member = Recipient.Id; }
            var hash = SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { version = CompletionAccessProtection.Version,
                EnvelopeId = Envelope.Id, publicationId = Result.Id, publicationRevision = Result.RowVersion, type = party, id = member, name, email, order }));
            Payload = new(CompletionNotificationJobs.Version, Envelope.Id, Result.Id, "", "", party, member, Hex(hash),
                Hex(DownloadPublication.Reference(Executed)), Hex(DownloadPublication.Reference(Certificate)), false);
            Mail = new() { EnvelopeId = Envelope.Id, Template = CompletionNotificationJobs.Template, To = email, AvailableAt = At };
            RebuildPublication();
        }
        private FinalStoredDocument Document(FinalDocumentKind kind)
        {
            var hash = SHA256.HashData(new[] { (byte)kind }); var target = new FinalDocument(Envelope.Id, kind, Guid.NewGuid());
            var value = new FinalStoredDocument(target, 32, hash, "historical-" + kind, "\"etag-" + kind + "\"", FinalProtection.LockedTime, At.AddYears(1), At);
            Objects.Add(new(new("final", $"{Envelope.Id:N}/{kind.ToString().ToLowerInvariant()}/{target.ObjectId:N}", value.VersionId, "", value.ETag, value.Length), Hex(hash))); return value;
        }
        internal void RebuildPublication()
        {
            Intent.RecipeSha256 = CompletionPublication.Recipe(Intent); Result.IntentRecipeSha256 = Intent.RecipeSha256;
            Result.RecipeSha256 = CompletionPublication.Recipe(Result); Payload = Payload with { Recipe = Hex(Result.RecipeSha256), Revision = Convert.ToBase64String(Result.RowVersion) };
            Audits.Clear(); Add("completion_publication_prepared", CompletionPublication.Evidence(Intent), Intent.PreparedAt);
            Add("completed", CompletionPublication.Evidence(Result), At); Protect(true);
        }
        internal void Protect(bool queue = false)
        {
            Mail.Id = CompletionNotificationJobs.Id(Payload); Mail.PayloadJson = new CompletionNotificationProtection(Keys).Protect(Payload);
            if (queue) { if (Audits.Count > 2) Audits.RemoveRange(2, Audits.Count - 2); Add("completion_notification_queued", CompletionNotificationJobs.Queued(Mail.Id, Mail.To, Payload), At); }
        }
        private void Add(string kind, string raw, DateTimeOffset at)
        {
            var value = new AuditEvent { Id = Audits.Count + 1, EnvelopeId = Envelope.Id, Sequence = Audits.Count + 1, Event = kind, At = at,
                ActorType = PartyType.System, PrevHash = Audits.LastOrDefault()?.Hash, DataJson = raw };
            value.Hash = AuditHash.Compute(value); Audits.Add(value);
        }
        internal void Issue()
        {
            var id = Guid.NewGuid(); Payload = Payload with { LastTokenId = id }; Protect(); Mail.Status = EmailStatus.Sent; Mail.SubmissionStartedAt = At;
            Tokens.Add(new() { Id = id, EnvelopeId = Envelope.Id, Purpose = TokenPurpose.CompletionAccess, PartyType = Payload.Party, PartyId = Payload.PartyId,
                Email = Mail.To, CompletionPublicationId = Result.Id, CompletionRecipeSha256 = Result.RecipeSha256, CompletionPartySha256 = Convert.FromHexString(Payload.PartyHash),
                TokenSha256 = SHA256.HashData("Synthetic token hash - NO AGREEMENT"u8), ExpiresAt = At.AddMinutes(5), UsedAt = At.AddMinutes(1) });
        }
        internal void Demand(JsonDocument sql) => ProductionHoldCompletionNotificationReferences.Demand(sql.RootElement, Objects, Keys);
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "Signers", Rows = new[] { Signer } }, new { Table = "Recipients", Rows = new[] { Recipient } },
            new { Table = "CompletionPublicationIntents", Rows = new[] { Intent } }, new { Table = "CompletionPublicationResults", Rows = new[] { Result } },
            new { Table = "EmailOutbox", Rows = new[] { Mail } }, new { Table = "AuthTokens", Rows = Tokens }, new { Table = "AuditEvents", Rows = Audits }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    }
}

public sealed class ProductionHoldCompletionNotificationSqlTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Actual_sequential_signing_publication_and_four_queued_notifications_bind_exact_retained_pair()
    {
        var local = new Azure.Storage.Blobs.BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"));
        Assert.True(local.Uri.IsLoopback || local.Uri.Host == "azurite", "Only disposable local storage is allowed.");
        // Existing local fixtures use captured mail, a loopback timestamp test
        // authority and an in-memory final store; no real provider is called.
        await using var f = await CompletionDownloadTests.Flow.Create(fixture, completionNotifications: true);
        var keys = f.App.Services.GetRequiredService<IDataProtectionProvider>();
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        _ = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={f.Id}").AsNoTracking().SingleAsync();
        var mail = await db.EmailOutbox.AsNoTracking().Where(x => x.EnvelopeId == f.Id).ToArrayAsync();
        Assert.Equal(4, mail.Count(x => x.Template == CompletionNotificationJobs.Template));
        var tokens = await db.AuthTokens.AsNoTracking().Where(x => x.EnvelopeId == f.Id).ToArrayAsync();
        Assert.DoesNotContain(tokens, x => x.Purpose == TokenPurpose.CompletionAccess);
        using var sql = JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = f.Id, Tables = new object[] {
            new { Table = "Envelopes", Rows = await db.Envelopes.AsNoTracking().Where(x => x.Id == f.Id).ToArrayAsync() },
            new { Table = "Signers", Rows = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == f.Id).ToArrayAsync() },
            new { Table = "Recipients", Rows = await db.Recipients.AsNoTracking().Where(x => x.EnvelopeId == f.Id).ToArrayAsync() },
            new { Table = "CompletionPublicationIntents", Rows = await db.CompletionPublicationIntents.AsNoTracking().Where(x => x.EnvelopeId == f.Id).ToArrayAsync() },
            new { Table = "CompletionPublicationResults", Rows = await db.CompletionPublicationResults.AsNoTracking().Where(x => x.EnvelopeId == f.Id).ToArrayAsync() },
            new { Table = "EmailOutbox", Rows = mail }, new { Table = "AuthTokens", Rows = tokens },
            new { Table = "AuditEvents", Rows = await db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == f.Id).ToArrayAsync() }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        var objects = new List<HoldObjectEvidence>();
        foreach (var (stored, bytes) in new[] { (f.Published.Executed, f.Published.ExecutedBytes), (f.Published.Certificate, f.Published.CertificateBytes) })
        {
            var hash = SHA256.HashData(bytes); Assert.Equal(stored.Length, bytes.LongLength); Assert.Equal(stored.Sha256, hash);
            objects.Add(new(new("final", $"{f.Id:N}/{stored.Document.Kind.ToString().ToLowerInvariant()}/{stored.Document.ObjectId:N}", stored.VersionId, "", stored.ETag, bytes.LongLength), Convert.ToHexStringLower(hash)));
        }
        ProductionHoldCompletionNotificationReferences.Demand(sql.RootElement, objects, keys);
        objects.RemoveAt(1);
        Assert.Throws<InvalidDataException>(() => ProductionHoldCompletionNotificationReferences.Demand(sql.RootElement, objects, keys));
        Assert.Equal(tokens.Length, await db.AuthTokens.CountAsync(x => x.EnvelopeId == f.Id));
        Assert.Equal(4, await db.EmailOutbox.CountAsync(x => x.EnvelopeId == f.Id && x.Template == CompletionNotificationJobs.Template && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null));
    }
}
