using System.Data.SqlTypes;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldVoidNotificationReferenceTests
{
    internal static readonly Guid SqlFirst = Guid.Parse("00000001-0000-0000-0000-000000000000");
    internal static readonly Guid SqlSecond = Guid.Parse("00000000-0000-0000-0000-000000000001");

    [Theory]
    [InlineData(false, PartyType.Sender)][InlineData(false, PartyType.Signer)]
    [InlineData(true, PartyType.Sender)][InlineData(true, PartyType.Signer)]
    public void Expired_historical_void_binds_original_sent_or_processed_checkpoint_copy(bool checkpoint, PartyType party)
    {
        var f = new Frame(checkpoint, party); using var sql = f.Sql(); f.Demand(sql);
        Assert.True(f.At.AddDays(1) < DateTimeOffset.UtcNow); Assert.NotEqual(f.Action.Id, f.Action.Sequence);
        Assert.NotEqual(Convert.ToBase64String(f.Envelope.RowVersion), f.Evidence.ReviewedVersion);
        f.Objects.RemoveAt(f.Objects.Count - 1); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Fact]
    public void Recipient_roster_uses_SQL_Server_uniqueidentifier_order_and_never_adds_a_recipient_destination()
    {
        var f = new Frame(false, PartyType.Sender);
        Assert.NotEqual(f.Recipients.OrderBy(x => x.Id).First().Id, f.Recipients.OrderBy(x => new SqlGuid(x.Id)).First().Id);
        using var sql = f.Sql(); f.Demand(sql);
        f.Payload = f.Payload with { RosterHash = f.Roster(false) }; f.Protect(); using var wrongOrder = f.Sql();
        Assert.Throws<InvalidDataException>(() => f.Demand(wrongOrder));
        f.Payload = f.Payload with { Party = PartyType.Recipient, PartyId = f.Recipients[0].Id }; f.Mail.To = f.Recipients[0].Email; f.Protect();
        using var recipient = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(recipient));
    }

    [Fact]
    public void Sender_also_signing_is_one_destination_and_cannot_claim_a_second_signer_notification()
    {
        var f = new Frame(false, PartyType.Sender); f.Signer.Email = f.Envelope.SenderEmail; f.Rebind(); using var sql = f.Sql(); f.Demand(sql);
        f.Payload = f.Payload with { Party = PartyType.Signer, PartyId = f.Signer.Id }; f.Protect(); using var duplicate = f.Sql();
        Assert.Throws<InvalidDataException>(() => f.Demand(duplicate));
    }

    [Theory]
    [InlineData("mail-owner")][InlineData("mailbox")][InlineData("attachment")][InlineData("payload-owner")]
    [InlineData("audit-id")][InlineData("audit-hash")][InlineData("pre-review-version")][InlineData("roster")][InlineData("party")][InlineData("demo")]
    [InlineData("missing-source")][InlineData("source-hash")][InlineData("source-area")][InlineData("source-prefix")]
    [InlineData("missing-finish")][InlineData("foreign-finish")][InlineData("late-finish")][InlineData("changed-prior")]
    [InlineData("current-copy")][InlineData("current-finish")][InlineData("saved-source")][InlineData("statement")][InlineData("reason")]
    [InlineData("audit-actor")][InlineData("previous-hash")][InlineData("queue-missing")][InlineData("queue-duplicate")][InlineData("queue-actor")]
    public void Wrong_scope_missing_history_and_rehashed_mutations_do_not_authenticate_void_work(string fault)
    {
        var f = new Frame(true, PartyType.Signer);
        switch (fault)
        {
            case "mail-owner": f.Mail.EnvelopeId = Guid.NewGuid(); break;
            case "mailbox": f.Mail.To = "other@example.invalid"; break;
            case "attachment": f.Mail.AttachmentsJson = "[{}]"; break;
            case "payload-owner": f.Payload = f.Payload with { EnvelopeId = Guid.NewGuid() }; f.Protect(); break;
            case "audit-id": f.Payload = f.Payload with { VoidAuditId = f.Action.Sequence }; f.Protect(); break;
            case "audit-hash": f.Payload = f.Payload with { VoidHash = new string('0', 64) }; f.Protect(); break;
            case "pre-review-version": f.Payload = f.Payload with { Revision = f.Evidence.ReviewedVersion }; f.Protect(); break;
            case "roster": f.Payload = f.Payload with { RosterHash = new string('0', 64) }; f.Protect(); break;
            case "party": f.Payload = f.Payload with { PartyId = Guid.NewGuid() }; f.Protect(); break;
            case "demo": f.Payload = f.Payload with { IsDemo = true }; f.Protect(); break;
            case "missing-source": f.Objects.RemoveAt(1); break;
            case "source-hash": f.Objects[1] = f.Objects[1] with { Sha256 = new string('0', 64) }; break;
            case "source-area": f.Objects[1] = f.Objects[1] with { Address = f.Objects[1].Address with { Area = "originals" } }; break;
            case "source-prefix": f.Objects[1] = f.Objects[1] with { Address = f.Objects[1].Address with { Name = $"{Guid.NewGuid():N}/{f.Source.ObjectId:N}" } }; break;
            case "missing-finish": f.Finishes.Clear(); break;
            case "foreign-finish": f.Finishes[0].EnvelopeId = Guid.NewGuid(); break;
            case "late-finish": f.Finishes[0].ProcessedAt = f.At.AddSeconds(1); break;
            case "changed-prior": f.Finishes[0].SourceSha256 = new byte[32]; break;
            case "current-copy": f.Envelope.CurrentCopyVersion++; break;
            case "current-finish": f.Envelope.CurrentFinishId = Guid.NewGuid(); break;
            case "saved-source": f.Evidence = f.Evidence with { SourceObjectId = Guid.NewGuid() }; f.RewriteAction(); break;
            case "statement": f.Evidence = f.Evidence with { Statement = "Changed statement" }; f.RewriteAction(); break;
            case "reason": f.Evidence = f.Evidence with { Reason = " noncanonical reason " }; f.RewriteAction(); break;
            case "audit-actor": f.Action.ActorEmail = "other@example.invalid"; f.RewriteAction(); break;
            case "previous-hash": f.Audits[0].Hash = new byte[32]; break;
            case "queue-missing": f.Audits.RemoveAt(2); break;
            case "queue-duplicate": f.Audits.Add(f.Audits[2]); break;
            case "queue-actor": f.Audits[2].ActorEmail = "other@example.invalid"; f.Audits[2].Hash = AuditHash.Compute(f.Audits[2]); break;
        }
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(sql));
    }

    [Theory]
    [InlineData("wrapper")][InlineData("payload")][InlineData("duplicate")][InlineData("action")][InlineData("key")]
    public void Correct_ciphertext_or_recomputed_hashes_cannot_hide_unknown_future_references(string fault)
    {
        var f = new Frame(false, PartyType.Sender); IDataProtectionProvider keys = f.Keys;
        if (fault == "wrapper") f.Mail.PayloadJson = f.Mail.PayloadJson[..^1] + ",\"HiddenObject\":\"synthetic\"}";
        else if (fault == "key") keys = new EphemeralDataProtectionProvider();
        else if (fault == "action")
        {
            f.Action.DataJson = f.Action.DataJson[..^1] + ",\"HiddenObject\":\"synthetic\"}";
            f.Action.Hash = AuditHash.Compute(f.Action); f.Rebind();
        }
        else
        {
            var p = f.Keys.CreateProtector("QuillSign.VoidNotification.v1");
            var raw = p.Unprotect(JsonSerializer.Deserialize<ProtectedWorkPayload>(f.Mail.PayloadJson)!.Protected);
            raw = fault == "duplicate" ? raw[..^1] + "," + raw[1..] : raw[..^1] + ",\"HiddenObject\":\"synthetic\"}";
            f.Mail.PayloadJson = JsonSerializer.Serialize(new ProtectedWorkPayload(p.Protect(raw)));
        }
        using var sql = f.Sql(); Assert.Throws<InvalidDataException>(() => ProductionHoldNotificationReferences.Demand(sql.RootElement, f.Objects, keys));
    }

    [Fact]
    public void Unprocessed_Finish_is_preserved_separately_and_cannot_become_the_void_current_copy()
    {
        var f = new Frame(true, PartyType.Sender);
        var next = new Signer { EnvelopeId = f.Envelope.Id, FullName = "Synthetic pending signer", Email = "pending@example.invalid", Order = 2, Status = SignerStatus.Viewed };
        f.Signers.Add(next);
        f.Finishes.Add(new() { EnvelopeId = f.Envelope.Id, SignerId = next.Id, SourceObjectId = f.Source.ObjectId, SourceSha256 = f.Source.Sha256,
            PdfObjectId = Guid.NewGuid(), PdfSha256 = SHA256.HashData("Synthetic pending copy"u8), FinishedAt = f.At.AddSeconds(-1) });
        f.Rebind(); using var sql = f.Sql(); f.Demand(sql);
        f.Envelope.CurrentFinishId = f.Finishes[1].Id; using var substituted = f.Sql(); Assert.Throws<InvalidDataException>(() => f.Demand(substituted));
    }

    private sealed class Frame
    {
        internal readonly IDataProtectionProvider Keys = new EphemeralDataProtectionProvider();
        internal readonly DateTimeOffset At = new(2020, 1, 1, 12, 0, 0, TimeSpan.Zero);
        internal readonly Envelope Envelope;
        internal readonly Signer Signer;
        internal readonly List<Signer> Signers = [];
        internal readonly List<Recipient> Recipients = [];
        internal readonly List<SignerFinishAcceptance> Finishes = [];
        internal readonly List<AuditEvent> Audits = [];
        internal readonly List<HoldObjectEvidence> Objects = [];
        internal readonly AuditEvent Action;
        internal readonly EmailOutbox Mail;
        internal readonly SignerCurrentSource Source;
        internal SenderVoidEvidence Evidence;
        internal VoidNotificationPayload Payload;
        internal Frame(bool checkpoint, PartyType party)
        {
            var sent = Guid.NewGuid(); var sentHash = SHA256.HashData("Synthetic sent source - NO AGREEMENT"u8);
            Envelope = new() { SenderName = "Synthetic sender", SenderEmail = "sender@example.invalid", Status = EnvelopeStatus.Voided,
                CreatedAt = At.AddHours(-2), SenderVerifiedAt = At.AddHours(-2), SentAt = At.AddHours(-1), ExpiresAt = At.AddDays(1),
                SentPdfBlob = sent.ToString("N"), SentPdfSha256 = sentHash, ErsdSha256 = SHA256.HashData("Synthetic disclosure"u8), RowVersion = [9,0,0,0,0,0,0,0] };
            Signer = new() { EnvelopeId = Envelope.Id, FullName = "Synthetic signer", Email = "signer@example.invalid", Order = 1, Status = checkpoint ? SignerStatus.Signed : SignerStatus.Viewed };
            Signers.Add(Signer);
            Recipients.AddRange(new[] { new Recipient { Id = SqlSecond, EnvelopeId = Envelope.Id, Name = "Synthetic second", Email = "second@example.invalid" },
                new Recipient { Id = SqlFirst, EnvelopeId = Envelope.Id, Name = "Synthetic first", Email = "first@example.invalid" } });
            Object(sent, sentHash); Source = new(sent, sentHash, 0, null);
            if (checkpoint)
            {
                var finish = new SignerFinishAcceptance { EnvelopeId = Envelope.Id, SignerId = Signer.Id, SourceObjectId = sent, SourceSha256 = sentHash,
                    DisclosureSha256 = Envelope.ErsdSha256, PdfObjectId = Guid.NewGuid(), PdfSha256 = SHA256.HashData("Synthetic checkpoint copy"u8),
                    FinishedAt = At.AddMinutes(-2), ProcessedAt = At.AddMinutes(-1) };
                Finishes.Add(finish); Signer.SignedAt = finish.FinishedAt;
                Source = new(finish.PdfObjectId, finish.PdfSha256, 1, finish.Id); Envelope.CurrentCopyVersion = 1; Envelope.CurrentFinishId = finish.Id;
                Object(Source.ObjectId, Source.Sha256);
            }
            var previous = new AuditEvent { Id = 77, EnvelopeId = Envelope.Id, Sequence = 1, At = At.AddMinutes(-1), ActorType = PartyType.System, Event = "synthetic_prior", DataJson = "{}" };
            previous.Hash = AuditHash.Compute(previous); Audits.Add(previous);
            Evidence = SenderVoidState.Bind(Envelope, Source, Convert.ToBase64String([8,0,0,0,0,0,0,0]), "Synthetic void", At);
            Action = new() { Id = 1234, EnvelopeId = Envelope.Id, Sequence = 2, At = At, ActorType = PartyType.Sender, ActorEmail = Envelope.SenderEmail,
                Event = "voided", DataJson = JsonSerializer.Serialize(Evidence), PrevHash = previous.Hash };
            Action.Hash = AuditHash.Compute(Action); Audits.Add(Action);
            Payload = new(VoidNotificationJobs.Version, Envelope.Id, Action.Id, Hex(Action.Hash), Convert.ToBase64String(Envelope.RowVersion), party,
                party == PartyType.Sender ? null : Signer.Id, "", "", false);
            Mail = new() { EnvelopeId = Envelope.Id, Template = VoidNotificationJobs.Template, To = party == PartyType.Sender ? Envelope.SenderEmail : Signer.Email, AvailableAt = At };
            Rebind();
        }
        internal string Roster(bool sql = true)
        {
            var ordered = sql ? Recipients.OrderBy(x => new SqlGuid(x.Id)).ToArray() : Recipients.OrderBy(x => x.Id).ToArray();
            return Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { Envelope.SenderName, Envelope.SenderEmail,
                signers = Signers.OrderBy(x => x.Order).Select(x => new { x.Id, x.Order, x.FullName, x.Email, x.Role }), recipients = ordered.Select(x => new { x.Id, x.Name, x.Email }) })));
        }
        internal void Rebind()
        {
            string? name; string email; string? role = null; int? order = null;
            if (Payload.Party == PartyType.Sender) { name = Envelope.SenderName; email = Envelope.SenderEmail; } else { name = Signer.FullName; email = Signer.Email; role = Signer.Role; order = Signer.Order; }
            var hash = Hex(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { version = VoidNotificationJobs.Version, envelopeId = Envelope.Id,
                voidAuditId = Action.Id, voidHash = Hex(Action.Hash), type = Payload.Party, id = Payload.PartyId, name, email, role, order })));
            Payload = Payload with { VoidHash = Hex(Action.Hash), PartyHash = hash, RosterHash = Roster() }; Mail.To = email; Protect();
        }
        internal void RewriteAction() { Action.DataJson = JsonSerializer.Serialize(Evidence); Action.Hash = AuditHash.Compute(Action); Rebind(); }
        internal void Protect()
        {
            Mail.Id = VoidNotificationJobs.Id(Payload); Mail.PayloadJson = new VoidNotificationProtection(Keys).Protect(Payload);
            if (Audits.Count > 2) Audits.RemoveRange(2, Audits.Count - 2);
            var audit = new AuditEvent { Id = 1235, EnvelopeId = Envelope.Id, Sequence = 3, At = At, ActorType = PartyType.System, Event = "void_notification_queued",
                PrevHash = Action.Hash, DataJson = VoidNotificationJobs.Queued(Mail.Id, Mail.To, Payload) };
            audit.Hash = AuditHash.Compute(audit); Audits.Add(audit);
        }
        private void Object(Guid id, byte[] hash) => Objects.Add(new(new("normalized", $"{Envelope.Id:N}/{id:N}", "historical", "", "\"etag\"", 32), Hex(hash)));
        internal void Demand(JsonDocument sql) => ProductionHoldNotificationReferences.Demand(sql.RootElement, Objects, Keys);
        internal JsonDocument Sql() => JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = Envelope.Id, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { Envelope } }, new { Table = "EmailOutbox", Rows = new[] { Mail } }, new { Table = "Signers", Rows = Signers },
            new { Table = "Recipients", Rows = Recipients }, new { Table = "SignerFinishAcceptances", Rows = Finishes }, new { Table = "AuditEvents", Rows = Audits }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        private static string Hex(byte[] bytes) => Convert.ToHexStringLower(bytes);
    }
}

public sealed class ProductionHoldVoidNotificationSqlTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Actual_local_void_history_binds_SQL_roster_order_and_processed_checkpoint_sources(bool checkpoint)
    {
        var local = new Azure.Storage.Blobs.BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"));
        Assert.True(local.Uri.IsLoopback || local.Uri.Host == "azurite", "Only disposable local storage is allowed.");
        await using var signed = checkpoint ? await CompletionEvidenceCollectorTests.Run.Create(fixture, demo: true, finishLast: false) : null;
        await using var fresh = checkpoint ? null : await SendDraftWorkflowTests.Harness.Create(fixture, browser: true, productionRetention: ProductionRetentionLedgerTests.Policy());
        var h = signed?.H ?? fresh!;
        if (!checkpoint)
        {
            await using var setup = fixture.Open();
            setup.Recipients.AddRange(new Recipient { Id = ProductionHoldVoidNotificationReferenceTests.SqlFirst, EnvelopeId = h.Envelope.Id, Name = "Synthetic first", Email = "first-recipient@example.invalid" },
                new Recipient { Id = ProductionHoldVoidNotificationReferenceTests.SqlSecond, EnvelopeId = h.Envelope.Id, Name = "Synthetic second", Email = "second-recipient@example.invalid" });
            await setup.SaveChangesAsync(); Assert.NotNull(await h.Send());
        }
        var recordId = signed?.Envelope.Id ?? h.Envelope.Id;
        Envelope e; await using (var before = fixture.Open()) e = await before.Envelopes.AsNoTracking().SingleAsync(x => x.Id == recordId);
        using var services = h.App.Services.CreateScope();
        var result = await services.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(signed?.Sender ?? h.Principal, e.PublicId,
            h.Clock.GetUtcNow().AddHours(1), e.RowVersion, true, SenderVoidStatement.Version, "Synthetic void - NO AGREEMENT", null, null);
        Assert.Equal(SenderVoidOutcome.Voided, result.Outcome);
        var keys = services.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        e = await db.Envelopes.FromSqlInterpolated($"SELECT * FROM [Envelopes] WITH (UPDLOCK,HOLDLOCK) WHERE [Id]={recordId}").AsNoTracking().SingleAsync();
        var audits = await db.AuditEvents.AsNoTracking().Where(x => x.EnvelopeId == e.Id).ToArrayAsync();
        var action = audits.Single(x => x.Event == "voided"); var evidence = JsonSerializer.Deserialize<SenderVoidEvidence>(action.DataJson)!;
        var mail = await db.EmailOutbox.AsNoTracking().Where(x => x.EnvelopeId == e.Id).ToArrayAsync();
        Assert.Equal(3, mail.Count(x => x.Template == VoidNotificationJobs.Template));
        var recipients = await db.Recipients.AsNoTracking().Where(x => x.EnvelopeId == e.Id).ToArrayAsync();
        Assert.DoesNotContain(mail.Where(x => x.Template == VoidNotificationJobs.Template), x => recipients.Any(r => r.Email == x.To));
        if (!checkpoint)
        {
            var sqlOrder = await db.Recipients.Where(x => x.EnvelopeId == e.Id).OrderBy(x => x.Id).Select(x => x.Id).ToArrayAsync();
            Assert.Equal(recipients.OrderBy(x => new SqlGuid(x.Id)).Select(x => x.Id), sqlOrder);
            Assert.NotEqual(recipients.OrderBy(x => x.Id).Select(x => x.Id).ToArray(), sqlOrder);
        }
        var tokensBefore = await db.AuthTokens.CountAsync(x => x.EnvelopeId == e.Id);
        using var sql = JsonDocument.Parse(JsonSerializer.Serialize(new { RecordId = e.Id, Tables = new object[] {
            new { Table = "Envelopes", Rows = new[] { e } }, new { Table = "EmailOutbox", Rows = mail }, new { Table = "AuditEvents", Rows = audits },
            new { Table = "Signers", Rows = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == e.Id).ToArrayAsync() },
            new { Table = "Recipients", Rows = recipients }, new { Table = "SignerFinishAcceptances", Rows = await db.SignerFinishAcceptances.AsNoTracking().Where(x => x.EnvelopeId == e.Id).ToArrayAsync() }
        } }, new JsonSerializerOptions { Converters = { new JsonStringEnumConverter() } }));
        var objects = new List<HoldObjectEvidence>();
        foreach (var source in new[] { Guid.ParseExact(e.SentPdfBlob!, "N"), evidence.SourceObjectId }.Distinct())
        {
            using var content = new MemoryStream();
            await h.Blobs.Inner.CopyToAsync(signed?.Sender ?? h.Principal, new(e.Id, DocumentBlobKind.Normalized, source), content);
            var bytes = content.ToArray();
            objects.Add(new(new("normalized", $"{e.Id:N}/{source:N}", "local-version", "", "\"local-etag\"", bytes.LongLength), Convert.ToHexStringLower(SHA256.HashData(bytes))));
        }
        ProductionHoldVoidNotificationReferences.Demand(sql.RootElement, objects, keys);
        objects.RemoveAt(objects.Count - 1);
        Assert.Throws<InvalidDataException>(() => ProductionHoldVoidNotificationReferences.Demand(sql.RootElement, objects, keys));
        Assert.Equal(tokensBefore, await db.AuthTokens.CountAsync(x => x.EnvelopeId == e.Id));
        Assert.Equal(3, await db.EmailOutbox.CountAsync(x => x.EnvelopeId == e.Id && x.Template == VoidNotificationJobs.Template && x.Status == EmailStatus.Queued && x.SubmissionStartedAt == null));
    }
}
