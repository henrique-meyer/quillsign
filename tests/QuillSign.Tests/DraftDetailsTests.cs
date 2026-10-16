using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;

namespace QuillSign.Tests;

public sealed class DraftDetailsTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Details_and_recipient_lifecycle_normalize_data_advance_versions_and_preserve_signers_and_fields()
    {
        var draft = await SeedAsync(); var initial = await ReadAsync(draft);
        await using var original = fixture.Open();
        var signer = await original.Signers.AsNoTracking().SingleAsync(x => x.EnvelopeId == draft.Id);
        var field = await original.Fields.AsNoTracking().SingleAsync(x => x.EnvelopeId == draft.Id);
        Assert.Equal(DetailsError.None, (await ChangeAsync(draft, new(DetailsChangeKind.SaveDetails, initial.Version,
            Title: "  Synthetic agreement  ", Message: "  Please review.\nSecond paragraph.  "))).Error);
        var named = await ReadAsync(draft); Assert.NotEqual(initial.Version, named.Version);
        Assert.Equal("Synthetic agreement", named.Title); Assert.Equal("Please review.\nSecond paragraph.", named.Message);
        Assert.Equal(DetailsError.None, (await ChangeAsync(draft, new(DetailsChangeKind.SaveRecipient, named.Version,
            Name: "  Synthetic reviewer  ", Email: "  REVIEWER@EXAMPLE.INVALID  "))).Error);
        var added = await ReadAsync(draft); var recipient = Assert.Single(added.Recipients);
        Assert.Equal("Synthetic reviewer", recipient.Name); Assert.Equal("reviewer@example.invalid", recipient.Email);
        Assert.Equal(DetailsError.None, (await ChangeAsync(draft, new(DetailsChangeKind.SaveRecipient, added.Version,
            recipient.Id, Name: "Updated reviewer", Email: recipient.Email))).Error);
        var edited = await ReadAsync(draft); Assert.Equal(recipient.Id, Assert.Single(edited.Recipients).Id);
        Assert.Equal(DetailsError.None, (await ChangeAsync(draft, new(DetailsChangeKind.SaveRecipient, edited.Version,
            Name: "Sender copy", Email: draft.SenderEmail))).Error); // Cross-role overlap is allowed.
        var overlap = await ReadAsync(draft);
        Assert.Equal(DetailsError.None, (await ChangeAsync(draft, new(DetailsChangeKind.RemoveRecipient, overlap.Version, recipient.Id))).Error);
        var remaining = await ReadAsync(draft); Assert.Equal(draft.SenderEmail, Assert.Single(remaining.Recipients).Email);
        Assert.Equal(DetailsError.None, (await ChangeAsync(draft, new(DetailsChangeKind.SaveDetails, remaining.Version,
            Title: remaining.Title, Message: "   "))).Error);
        Assert.Null((await ReadAsync(draft)).Message);
        await using var inspect = fixture.Open();
        Assert.Equal(signer.RowVersion, (await inspect.Signers.SingleAsync(x => x.Id == signer.Id)).RowVersion);
        Assert.Equal(field.RowVersion, (await inspect.Fields.SingleAsync(x => x.Id == field.Id)).RowVersion);
        var events = await inspect.AuditEvents.Where(x => x.EnvelopeId == draft.Id).OrderBy(x => x.Sequence).ToListAsync();
        Assert.Equal(new[] { "envelope_details_updated", "recipient_added", "recipient_updated", "recipient_added", "recipient_removed", "envelope_details_updated" }, events.Select(x => x.Event));
        for (var i = 0; i < events.Count; i++)
        { Assert.Equal(i + 1, events[i].Sequence); Assert.Equal(i == 0 ? null : events[i - 1].Hash, events[i].PrevHash); Assert.Equal(AuditHash.Compute(events[i]), events[i].Hash); }
        Assert.False(await inspect.EmailOutbox.AnyAsync(x => x.EnvelopeId == draft.Id));
        Assert.False(await inspect.WorkItems.AnyAsync(x => x.EnvelopeId == draft.Id));
    }

    [Fact]
    public async Task Invalid_duplicate_capped_and_foreign_changes_do_not_modify_the_draft()
    {
        var draft = await SeedAsync(); var before = await ReadAsync(draft);
        foreach (var change in new[]
        {
            new DetailsChange(DetailsChangeKind.SaveDetails, before.Version, Title: " "),
            new DetailsChange(DetailsChangeKind.SaveDetails, before.Version, Title: new string('x', 513)),
            new DetailsChange(DetailsChangeKind.SaveDetails, before.Version, Title: "bad\ntitle"),
            new DetailsChange(DetailsChangeKind.SaveDetails, before.Version, Title: "Good", Message: new string('x', 4001)),
            new DetailsChange(DetailsChangeKind.SaveDetails, before.Version, Title: "Good", Message: "bad\0message"),
            new DetailsChange(DetailsChangeKind.SaveRecipient, before.Version, Name: " ", Email: "recipient@example.invalid"),
            new DetailsChange(DetailsChangeKind.SaveRecipient, before.Version, Name: "Name", Email: "bad\n@example.invalid"),
            new DetailsChange(DetailsChangeKind.SaveRecipient, before.Version, Name: "bad\nname", Email: "recipient@example.invalid"),
            new DetailsChange((DetailsChangeKind)999, before.Version)
        }) Assert.Equal(DetailsError.Invalid, (await ChangeAsync(draft, change)).Error);
        Assert.Equal(before.Version, (await ReadAsync(draft)).Version);
        Assert.Equal(DetailsError.None, (await ChangeAsync(draft, new(DetailsChangeKind.SaveRecipient, before.Version,
            Name: "Reviewer", Email: "reviewer@example.invalid"))).Error);
        var added = await ReadAsync(draft);
        Assert.Equal(DetailsError.Duplicate, (await ChangeAsync(draft, new(DetailsChangeKind.SaveRecipient, added.Version,
            Name: "Duplicate", Email: "REVIEWER@EXAMPLE.INVALID"))).Error);
        Assert.Equal(DetailsError.Limit, (await ChangeAsync(draft, new(DetailsChangeKind.SaveRecipient, added.Version,
            Name: "Other", Email: "other@example.invalid"), maximum: 1)).Error);
        var other = await SeedAsync(); var otherBefore = await ReadAsync(other);
        Assert.Equal(DetailsError.None, (await ChangeAsync(other, new(DetailsChangeKind.SaveRecipient, otherBefore.Version,
            Name: "Foreign", Email: "foreign@example.invalid"))).Error);
        var foreignId = Assert.Single((await ReadAsync(other)).Recipients).Id;
        Assert.Equal(DetailsError.NotFound, (await ChangeAsync(draft, new(DetailsChangeKind.RemoveRecipient, added.Version, foreignId))).Error);
        Assert.Equal(DetailsError.NotFound, (await ChangeAsync(draft, new(DetailsChangeKind.SaveRecipient, added.Version, foreignId,
            Name: "Taken", Email: "taken@example.invalid"))).Error);
        Assert.Equal(DetailsError.Conflict, (await ChangeAsync(draft, new(DetailsChangeKind.SaveDetails, before.Version, Title: "Stale"))).Error);
        Assert.Equal(added.Version, (await ReadAsync(draft)).Version);
    }

    [Fact]
    public async Task Authorization_current_confirmation_and_draft_state_are_required()
    {
        var draft = await SeedAsync(); var other = await SeedAsync(); var before = await ReadAsync(draft);
        await using (var db = fixture.Open())
        {
            Assert.Null(await Service(db).GetAsync(Principal(other), draft.PublicId));
            Assert.Null(await Service(db).GetAsync(new ClaimsPrincipal(new ClaimsIdentity()), draft.PublicId));
            Assert.Equal(DetailsError.NotFound, (await Service(db).ChangeAsync(Principal(other), draft.PublicId,
                new(DetailsChangeKind.SaveDetails, before.Version, Title: "Foreign"), null, null)).Error);
        }
        await using (var db = fixture.Open())
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == draft.Id); envelope.PreviewConfirmedAt = null; await db.SaveChangesAsync();
        }
        Assert.False((await ReadAsync(draft)).PreviewConfirmed);
        Assert.Equal(DetailsError.PreviewRequired, (await ChangeAsync(draft, new(DetailsChangeKind.SaveDetails, before.Version, Title: "Unconfirmed"))).Error);
        await using (var db = fixture.Open())
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == draft.Id); envelope.Status = EnvelopeStatus.Sent; await db.SaveChangesAsync();
        }
        await using var inspect = fixture.Open(); Assert.Null(await Service(inspect).GetAsync(Principal(draft), draft.PublicId));
        Assert.Equal(DetailsError.NotFound, (await ChangeAsync(draft, new(DetailsChangeKind.SaveDetails, before.Version, Title: "Sent"))).Error);
    }

    [Fact]
    public async Task Concurrent_recipient_additions_have_one_winner_and_respect_the_cap()
    {
        var draft = await SeedAsync(); var before = await ReadAsync(draft);
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 4).Select(i => ChangeAsync(draft,
            new(DetailsChangeKind.SaveRecipient, before.Version, Name: "Recipient " + i, Email: $"recipient-{i}@example.invalid"), maximum: 1)));
        Assert.Single(outcomes, x => x.Error == DetailsError.None); Assert.Equal(3, outcomes.Count(x => x.Error == DetailsError.Conflict));
        Assert.Single((await ReadAsync(draft)).Recipients);
        await using var inspect = fixture.Open(); Assert.Single(await inspect.AuditEvents.Where(x => x.EnvelopeId == draft.Id).ToListAsync());
    }

    [Fact]
    public async Task Audit_failure_rolls_back_details_and_recipients_and_read_refreshes_tracked_stale_versions()
    {
        var draft = await SeedAsync(); var before = await ReadAsync(draft);
        foreach (var change in new[]
        {
            new DetailsChange(DetailsChangeKind.SaveDetails, before.Version, Title: "Rolled back", Message: "Rolled back message"),
            new DetailsChange(DetailsChangeKind.SaveRecipient, before.Version, Name: "Rolled back", Email: "rollback@example.invalid")
        })
        {
            await using var original = fixture.Open();
            await using var failing = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
                .UseSqlServer(original.Database.GetConnectionString()).AddInterceptors(new RejectAudit()).Options);
            await Assert.ThrowsAsync<DbUpdateException>(() => Service(failing).ChangeAsync(Principal(draft), draft.PublicId, change, null, null));
        }
        var after = await ReadAsync(draft); Assert.Equal(before.Version, after.Version); Assert.Empty(after.Recipients); Assert.Equal(before.Title, after.Title);
        await using var staleContext = fixture.Open(); var service = Service(staleContext);
        await staleContext.Envelopes.SingleAsync(x => x.Id == draft.Id); // A tracked old revision must not contaminate subsequent snapshots.
        Assert.Equal(DetailsError.None, (await ChangeAsync(draft, new(DetailsChangeKind.SaveDetails, after.Version, Title: "New saved title"))).Error);
        var refreshed = await service.GetAsync(Principal(draft), draft.PublicId);
        Assert.Equal("New saved title", refreshed!.Title); Assert.NotEqual(after.Version, refreshed.Version);
    }

    private DraftDetails Service(QuillSignDbContext db, int maximum = 20) => new(db, new AuditWriter(db, TimeProvider.System), new PreparationOptions { MaximumRecipients = maximum });
    private static ClaimsPrincipal Principal(Envelope draft) => SenderConfiguration.Principal(new VerifiedSender(draft.Id, draft.PublicId, draft.SenderEmail));
    private async Task<DraftDetailsSnapshot> ReadAsync(Envelope draft) { await using var db = fixture.Open(); return (await Service(db).GetAsync(Principal(draft), draft.PublicId))!; }
    private async Task<DetailsResult> ChangeAsync(Envelope draft, DetailsChange change, int maximum = 20)
    { await using var db = fixture.Open(); return await Service(db, maximum).ChangeAsync(Principal(draft), draft.PublicId, change, "127.0.0.1", "synthetic-test"); }
    private async Task<Envelope> SeedAsync()
    {
        await using var db = fixture.Open();
        var envelope = new Envelope { SenderEmail = "sender-" + Guid.NewGuid().ToString("N") + "@example.invalid", Title = "Synthetic PDF",
            SenderVerifiedAt = DateTimeOffset.UtcNow, PreviewConfirmedAt = DateTimeOffset.UtcNow,
            PdfBlob = Guid.NewGuid().ToString("N"), PdfSha256 = SHA256.HashData([1]), PageCount = 1 };
        var signer = new Signer { EnvelopeId = envelope.Id, FullName = "Synthetic signer", Email = "signer@example.invalid" };
        db.Envelopes.Add(envelope); db.Signers.Add(signer);
        db.Fields.Add(new DocumentField { EnvelopeId = envelope.Id, SignerId = signer.Id, Type = FieldType.Signature,
            X = .1m, Y = .1m, Width = .2m, Height = .1m });
        await db.SaveChangesAsync(); return envelope;
    }
    private sealed class RejectAudit : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context!.ChangeTracker.Entries<AuditEvent>().Any(x => x.State == EntityState.Added)) throw new DbUpdateException("Synthetic audit failure");
            return ValueTask.FromResult(result);
        }
    }
}
