using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionCompletionMailCarrierTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public void Original_pair_retains_exact_ciphertext_rowversions_and_UTC_deadline_without_authority()
    {
        var f = new Frame(); var baseline = f.Baseline();
        ProductionCompletionMailBaselineContract.Demand(baseline, f.Keys);
        using var mail = JsonDocument.Parse(baseline.MailRowJson); using var work = JsonDocument.Parse(baseline.WorkRowJson);
        Assert.Equal(f.Mail.PayloadJson, mail.RootElement.GetProperty("PayloadJson").GetString());
        Assert.Equal(Convert.ToBase64String(f.Mail.RowVersion), mail.RootElement.GetProperty("RowVersion").GetString());
        Assert.Equal(Convert.ToBase64String(f.Work.RowVersion), work.RootElement.GetProperty("RowVersion").GetString());
        Assert.NotEqual(mail.RootElement.GetProperty("RowVersion").GetString(), work.RootElement.GetProperty("RowVersion").GetString());
        Assert.Equal(f.Clock.Now.AddMinutes(5), baseline.ClaimUntil);
        Assert.DoesNotContain(typeof(HoldWitnessCompletionMailBaseline).GetMethods(), x => x.Name.Contains("Demand", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("foreign-record")][InlineData("foreign-work")][InlineData("attempt")][InlineData("publication")]
    [InlineData("recipe")][InlineData("revision")][InlineData("request")][InlineData("control")]
    [InlineData("sql")][InlineData("content")][InlineData("deadline-offset")][InlineData("deadline-default")]
    [InlineData("mail-rv")][InlineData("work-rv")][InlineData("mail-leased")][InlineData("work-leased")]
    [InlineData("mail-attempt")][InlineData("work-attempt")][InlineData("provider")][InlineData("submitted")]
    [InlineData("attachments")][InlineData("work-payload")][InlineData("work-kind")][InlineData("due")]
    [InlineData("future-column")][InlineData("duplicate-column")][InlineData("column-order")]
    [InlineData("payload-future")][InlineData("wrapper-future")][InlineData("payload-token")]
    [InlineData("payload-demo")][InlineData("oversized")]
    [InlineData("null-mailbox")]
    public void Changed_original_facts_or_unknown_shapes_are_refused(string fault)
    {
        var f = new Frame(); var b = f.Baseline();
        b = fault switch {
            "foreign-record" => b with { RecordId = Guid.NewGuid() }, "foreign-work" => b with { WorkId = Guid.NewGuid() },
            "attempt" => b with { Attempt = 2 }, "publication" => b with { PublicationId = Guid.NewGuid() },
            "recipe" => b with { RecipeSha256 = new string('a', 64) }, "revision" => b with { PublicationRevision = "invalid" },
            "request" => b with { RequestRevision = 1 }, "control" => b with { ControlSequence = 1 },
            "sql" => b with { SqlStateSha256 = "invalid" }, "content" => b with { ContentSha256 = "invalid" },
            "deadline-offset" => b with { ClaimUntil = b.ClaimUntil.ToOffset(TimeSpan.FromHours(1)) },
            "deadline-default" => b with { ClaimUntil = default }, "oversized" => b with { MailRowJson = b.MailRowJson + new string(' ', 32768) }, _ => b };
        if (fault == "mail-rv") f.Mail.RowVersion = [1];
        if (fault == "work-rv") f.Work.RowVersion = [1];
        if (fault == "mail-leased") f.Mail.LeaseOwner = Guid.NewGuid();
        if (fault == "work-leased") f.Work.LeaseExpiresAt = f.Clock.Now.AddMinutes(5);
        if (fault == "mail-attempt") f.Mail.Attempts = 1;
        if (fault == "work-attempt") f.Work.Attempts = 1;
        if (fault == "provider") f.Mail.Provider = "synthetic";
        if (fault == "submitted") f.Mail.SubmissionStartedAt = f.Clock.Now;
        if (fault == "attachments") f.Mail.AttachmentsJson = "[{}]";
        if (fault == "work-payload") f.Work.PayloadJson = "{}";
        if (fault == "work-kind") f.Work.Kind = WorkKind.Sealing;
        if (fault == "due") f.Work.AvailableAt = f.Work.AvailableAt.AddTicks(1);
        if (fault == "null-mailbox") f.Mail.To = null!;
        if (fault is "payload-future" or "payload-token" or "payload-demo") {
            var p = fault == "payload-token" ? f.Payload with { LastTokenId = Guid.NewGuid() } : fault == "payload-demo" ? f.Payload with { IsDemo = true } : f.Payload;
            var plain = JsonSerializer.Serialize(p); if (fault == "payload-future") plain = plain[..^1] + ",\"future\":true}";
            f.Mail.PayloadJson = JsonSerializer.Serialize(new ProtectedWorkPayload(f.Keys.CreateProtector("QuillSign.CompletionNotification.v1").Protect(plain)));
        }
        if (fault == "wrapper-future") f.Mail.PayloadJson = f.Mail.PayloadJson[..^1] + ",\"future\":true}";
        if (fault is "mail-rv" or "work-rv" or "mail-leased" or "work-leased" or "mail-attempt" or "work-attempt" or "provider" or "submitted" or "attachments" or "work-payload" or "work-kind" or "due" or "payload-future" or "payload-token" or "payload-demo" or "wrapper-future" or "null-mailbox") b = b with { MailRowJson = Frame.Row(f.Mail), WorkRowJson = Frame.Row(f.Work) };
        if (fault == "future-column") b = b with { MailRowJson = b.MailRowJson[..^1] + ",\"future\":true}" };
        if (fault == "duplicate-column") b = b with { MailRowJson = b.MailRowJson[..^1] + ",\"Id\":\"" + b.WorkId + "\"}" };
        if (fault == "column-order") b = b with { MailRowJson = JsonSerializer.Serialize(f.Mail, Frame.Options) };
        Assert.Throws<InvalidDataException>(() => ProductionCompletionMailBaselineContract.Demand(b, f.Keys));
    }

    [Fact]
    public async Task Lost_reservation_ack_keeps_same_original_pair_ciphertext_time_and_event_without_recapture()
    {
        var f = new Frame(); var b = f.Baseline(); var journal = f.Journal();
        await journal.InitializeAsync(b.RecordId, b.ContentSha256, b.SqlStateSha256, Guid.NewGuid());
        var eventId = Guid.NewGuid(); f.Store.LostAck = true;
        await Assert.ThrowsAsync<IOException>(() => journal.ReserveCompletionMailOperationAsync(b, new(0, null, []), eventId));
        var bytes = f.Store.Rows[1].ProtectedPayload.ToArray(); f.Clock.Now = f.Clock.Now.AddMinutes(1);
        var replay = await f.Journal().ReserveCompletionMailOperationAsync(b, new(0, null, []), eventId);
        Assert.Equal(2, f.Store.Rows.Count); Assert.Equal(bytes, f.Store.Rows[1].ProtectedPayload);
        Assert.Equal(b, replay.CompletionMailBaselines![b.OperationId]);
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Journal().ReserveCompletionMailOperationAsync(b with { ClaimUntil = b.ClaimUntil.AddSeconds(1) }, new(0, null, []), eventId));
        Assert.Equal(bytes, f.Store.Rows[1].ProtectedPayload);
    }

    [Theory]
    [InlineData(-1)][InlineData(0)][InlineData(3601)]
    public async Task Original_reservation_rejects_elapsed_or_over_one_hour_deadline_before_append(int seconds)
    {
        var f = new Frame(); var b = f.Baseline() with { ClaimUntil = f.Clock.Now.AddSeconds(seconds) };
        await f.Journal().InitializeAsync(b.RecordId, b.ContentSha256, b.SqlStateSha256, Guid.NewGuid());
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Journal().ReserveCompletionMailOperationAsync(b, new(0, null, []), Guid.NewGuid()));
        Assert.Single(f.Store.Rows);
    }

    [Fact]
    public async Task Existing_encrypted_event_limit_is_checked_after_raw_pair_bound_and_before_store_create()
    {
        var f = new Frame(); var b = f.Baseline();
        var count = ProductionCompletionMailBaselineContract.MaximumRawBytes - Encoding.UTF8.GetByteCount(b.MailRowJson) - Encoding.UTF8.GetByteCount(b.WorkRowJson);
        b = b with { MailRowJson = b.MailRowJson + new string('\n', count) };
        ProductionCompletionMailBaselineContract.Demand(b, f.Keys);
        await f.Journal().InitializeAsync(b.RecordId, b.ContentSha256, b.SqlStateSha256, Guid.NewGuid());
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Journal().ReserveCompletionMailOperationAsync(b, new(0, null, []), Guid.NewGuid()));
        Assert.Single(f.Store.Rows);
    }

    [Fact]
    public async Task Old_events_omit_the_new_property_and_authenticate_identical_plaintext_bytes()
    {
        var f = new Frame(); var b = f.Baseline(); await f.Journal().InitializeAsync(b.RecordId, b.ContentSha256, b.SqlStateSha256, Guid.NewGuid());
        await f.Journal().ReserveOperationAsync(b.RecordId, b.OperationId, "sender/edit", "unchanged-old-event", new(0, null, []), b.ContentSha256, b.SqlStateSha256, Guid.NewGuid());
        foreach (var row in f.Store.Rows) {
            var plain = f.Keys.CreateProtector(ProductionHoldWitnessJournal.Version, ProductionHoldWitnessJournalTests.Installation, b.RecordId.ToString("N")).Unprotect(row.ProtectedPayload);
            var value = JsonSerializer.Deserialize<HoldWitnessEvent>(plain)!;
            Assert.Null(value.CompletionMailBaseline); Assert.DoesNotContain("CompletionMailBaseline", Encoding.UTF8.GetString(plain), StringComparison.Ordinal);
            Assert.Equal(plain, JsonSerializer.SerializeToUtf8Bytes(value));
        }
        Assert.Empty((await f.Journal().ReadAsync(b.RecordId)).CompletionMailBaselines!);
    }

    [Fact]
    public async Task Native_generated_row_pair_survives_rollback_and_claim_without_becoming_new_SQL_authority()
    {
        // This intentionally Draft synthetic fixture proves carrier/kernel SQL mechanics;
        // it is NOT a completed-publication admission or provider test.
        var run = await ProductionRecordOperationAdmissionTests.Run.Create(fixture, work: false); var f = new Frame(run.Keys, run.Clock, run.Id);
        await using (var db = fixture.Open()) { db.AddRange(f.Mail, f.Work); await db.SaveChangesAsync(); }
        HoldWitnessCompletionMailBaseline baseline;
        await using (var db = fixture.Open()) {
            await using var tx = await db.Database.BeginTransactionAsync();
            var snapshot = await new ProductionHoldSqlInventory(db, run.Keys, run.Clock).CaptureAcknowledgementLockedAsync(run.Id, 0, null);
            using var raw = ProductionHoldSqlInventory.OpenAcknowledgementVerified(snapshot, run.Keys);
            baseline = f.Baseline() with { MailRowJson = ProductionCompletionMailBaselineContract.Select(raw.RootElement, "EmailOutbox", f.Work.Id).GetRawText(),
                WorkRowJson = ProductionCompletionMailBaselineContract.Select(raw.RootElement, "WorkItems", f.Work.Id).GetRawText(),
                SqlStateSha256 = snapshot.StateSha256, ContentSha256 = ProductionRecordOperationAdmission.ContentDigest(snapshot, run.Keys),
                ControlSequence = snapshot.Control!.Sequence, ControlHash = snapshot.Control.Hash };
            await tx.RollbackAsync();
        }
        ProductionCompletionMailBaselineContract.Demand(baseline, run.Keys);
        await run.Journal().InitializeAsync(run.Id, baseline.ContentSha256, baseline.SqlStateSha256, Guid.NewGuid());
        var before = await run.Journal().ReadAsync(run.Id);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginAsync(run.Id, baseline.OperationId, ProductionCompletionMailBaselineContract.Kind, ProductionCompletionMailBaselineContract.Reference(f.Work.Id, 1)));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().BeginCompletionNotificationAsync(run.Id, baseline.OperationId, f.Work.Id, 1, baseline.ClaimUntil));
        Assert.Equal(before.HeadHash, (await run.Journal().ReadAsync(run.Id)).HeadHash);
        var state = await run.Journal().ReserveCompletionMailOperationAsync(baseline, new(0, null, []), Guid.NewGuid());
        var op = state.Operations![baseline.OperationId]; var scope = new ProductionRecordOperation(run.Id, op.OperationId, op.Kind, op.Reference, op.RequestRevision, op.RequestFenceHash, op.ContentSha256, op.SqlStateSha256, op.ReservationSequence);
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().CompleteAsync(scope, new string('c', 64)));
        await using (var db = fixture.Open()) {
            await using var tx = await db.Database.BeginTransactionAsync(); await run.Gate().DemandStartingLockedAsync(db, scope);
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().PrepareHandlerOutcomeLockedAsync(db, scope));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().PrepareOutcomeLockedAsync(db, scope));
            await db.WorkItems.Where(x => x.Id == f.Work.Id).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, WorkStatus.Leased).SetProperty(w => w.Attempts, 1)
                .SetProperty(w => w.LeaseOwner, baseline.OperationId).SetProperty(w => w.LeaseExpiresAt, baseline.ClaimUntil));
            await tx.RollbackAsync();
        }
        await using (var db = fixture.Open()) {
            await using var tx = await db.Database.BeginTransactionAsync(); await run.Gate().DemandStartingLockedAsync(db, scope);
            await db.WorkItems.Where(x => x.Id == f.Work.Id).ExecuteUpdateAsync(x => x.SetProperty(w => w.Status, WorkStatus.Leased).SetProperty(w => w.Attempts, 1)
                .SetProperty(w => w.LeaseOwner, baseline.OperationId).SetProperty(w => w.LeaseExpiresAt, baseline.ClaimUntil)); await tx.CommitAsync();
        }
        Assert.Equal(baseline, await run.Gate().ReadCompletionMailBaselineAsync(run.Id, baseline.OperationId));
        await using (var db = fixture.Open()) { await using var tx = await db.Database.BeginTransactionAsync(); await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().DemandStartingLockedAsync(db, scope)); }
        await using (var db = fixture.Open()) {
            await using var tx = await db.Database.BeginTransactionAsync();
            await db.WorkItems.Where(x => x.Id == f.Work.Id).ExecuteUpdateAsync(x => x.SetProperty(w => w.LeaseExpiresAt, baseline.ClaimUntil.AddTicks(1)));
            await db.EmailOutbox.Where(x => x.Id == f.Work.Id).ExecuteUpdateAsync(x => x.SetProperty(m => m.Attempts, 1).SetProperty(m => m.SubmissionStartedAt, run.Clock.Now));
            await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().PrepareDispatchLockedAsync(db, scope));
            Assert.Empty((await run.Journal().ReadAsync(run.Id)).DispatchStarts!); await tx.RollbackAsync();
        }
        run.Clock.Now = baseline.ClaimUntil;
        await Assert.ThrowsAsync<InvalidDataException>(() => run.Gate().DemandAsync(scope));
        Assert.Equal(baseline, await run.Gate().ReadCompletionMailBaselineAsync(run.Id, baseline.OperationId));
        Assert.Equal(baseline.OperationId, (await run.Journal().ReadAsync(run.Id)).OutstandingOperation);
    }

    private sealed class Frame
    {
        internal static readonly JsonSerializerOptions Options = new() { Converters = { new JsonStringEnumConverter() } };
        internal readonly IDataProtectionProvider Keys; internal readonly ProductionHoldWitnessJournalTests.Clock Clock;
        internal readonly ProductionHoldWitnessJournalTests.Store Store = new();
        internal readonly CompletionNotificationPayload Payload; internal readonly EmailOutbox Mail; internal readonly WorkItem Work;
        private readonly Guid operation = Guid.NewGuid();
        internal Frame(IDataProtectionProvider? keys = null, ProductionHoldWitnessJournalTests.Clock? clock = null, Guid? record = null)
        {
            Keys = keys ?? new EphemeralDataProtectionProvider(); Clock = clock ?? new(); var id = record ?? Guid.NewGuid();
            Payload = new(CompletionNotificationJobs.Version, id, Guid.NewGuid(), new string('b', 64), Convert.ToBase64String(new byte[] { 1,2,3,4,5,6,7,8 }), PartyType.Sender, null,
                new string('c', 64), new string('d', 64), new string('e', 64), false);
            var work = CompletionNotificationJobs.Id(Payload);
            Mail = new() { Id = work, EnvelopeId = id, Template = CompletionNotificationJobs.Template, To = "synthetic-carrier@example.invalid", AvailableAt = Clock.Now,
                PayloadJson = new CompletionNotificationProtection(Keys).Protect(Payload), RowVersion = [1,2,3,4,5,6,7,8] };
            Work = new() { Id = work, EnvelopeId = id, Kind = WorkKind.Email, Status = WorkStatus.Queued, PayloadJson = CompletionNotificationJobs.WorkJson(work), AvailableAt = Clock.Now, RowVersion = [8,7,6,5,4,3,2,1] };
        }
        internal HoldWitnessCompletionMailBaseline Baseline() => new(ProductionCompletionMailBaselineContract.Version, Payload.EnvelopeId, operation, Work.Id, 1,
            Payload.PublicationId, Payload.Recipe, Payload.Revision, 0, null, 0, null, new string('a', 64), new string('f', 64), Row(Mail), Row(Work), Clock.Now.AddMinutes(5));
        internal ProductionHoldWitnessJournal Journal() => new(Store, Keys, Clock, ProductionHoldWitnessJournalTests.Installation);
        internal static string Row<T>(T value)
        {
            var raw = JsonSerializer.SerializeToElement(value, Options);
            return JsonSerializer.Serialize(raw.EnumerateObject().OrderBy(x => x.Name, StringComparer.Ordinal).ToDictionary(x => x.Name, x => x.Value));
        }
    }
}
