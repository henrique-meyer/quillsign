using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class SignerSetupTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Add_edit_reorder_remove_preserve_identity_consecutive_order_and_audit_history()
    {
        var draft = await SeedAsync();
        var initial = await ReadAsync(draft);
        Assert.Equal(SignerSetupError.None, (await ChangeAsync(draft, new(SignerChangeKind.Save, initial.Version,
            FullName: "  First signer  ", Email: "  FIRST@EXAMPLE.INVALID  ", Role: " Buyer "))).Error);
        var one = await ReadAsync(draft);
        Assert.NotEqual(initial.Version, one.Version);
        var first = Assert.Single(one.Signers);
        Assert.Equal("First signer", first.FullName);
        Assert.Equal("first@example.invalid", first.Email);
        Assert.Equal("Buyer", first.Role);
        Assert.Equal(SignerSetupError.None, (await ChangeAsync(draft, new(SignerChangeKind.Save, one.Version,
            FullName: "Second signer", Email: "second@example.invalid"))).Error);
        var two = await ReadAsync(draft);
        var second = two.Signers[1];
        Assert.Equal(SignerSetupError.None, (await ChangeAsync(draft, new(SignerChangeKind.MoveUp, two.Version, second.Id))).Error);
        var reordered = await ReadAsync(draft);
        Assert.Equal(new[] { second.Id, first.Id }, reordered.Signers.Select(x => x.Id));
        Assert.Equal(new[] { 1, 2 }, reordered.Signers.Select(x => x.Order));
        Assert.Equal(SignerSetupError.None, (await ChangeAsync(draft, new(SignerChangeKind.Save, reordered.Version,
            first.Id, "Updated name", first.Email, "   "))).Error);
        var edited = await ReadAsync(draft);
        Assert.Null(edited.Signers[1].Role);
        Assert.Equal(SignerSetupError.None, (await ChangeAsync(draft, new(SignerChangeKind.Remove, edited.Version, second.Id))).Error);
        var remaining = Assert.Single((await ReadAsync(draft)).Signers);
        Assert.Equal(first.Id, remaining.Id);
        Assert.Equal(1, remaining.Order);
        Assert.Equal("Updated name", remaining.FullName);

        await using var db = fixture.Open();
        var events = await db.AuditEvents.Where(x => x.EnvelopeId == draft.Id).OrderBy(x => x.Sequence).ToListAsync();
        Assert.Equal(new[] { "signer_added", "signer_added", "signers_reordered", "signer_updated", "signer_removed" }, events.Select(x => x.Event));
        for (var i = 0; i < events.Count; i++)
        {
            Assert.Equal(i + 1, events[i].Sequence);
            Assert.Equal(i == 0 ? null : events[i - 1].Hash, events[i].PrevHash);
            Assert.Equal(AuditHash.Compute(events[i]), events[i].Hash);
            Assert.Contains("signers", events[i].DataJson);
        }
        var envelope = await db.Envelopes.SingleAsync(x => x.Id == draft.Id);
        Assert.Equal(EnvelopeStatus.Draft, envelope.Status);
        Assert.Null(envelope.SentPdfBlob);
        Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == draft.Id));
    }

    [Fact]
    public async Task Invalid_duplicate_capped_and_stale_changes_do_not_change_the_draft()
    {
        var draft = await SeedAsync(1);
        var before = await ReadAsync(draft);
        var signer = Assert.Single(before.Signers);
        foreach (var change in new[]
        {
            new SignerChange(SignerChangeKind.Save, before.Version, FullName: " ", Email: "valid@example.invalid"),
            new SignerChange(SignerChangeKind.Save, before.Version, FullName: "Name", Email: "bad\n@example.invalid"),
            new SignerChange(SignerChangeKind.Save, before.Version, FullName: "Name", Email: "valid@example.invalid", Role: "bad\nrole"),
            new SignerChange(SignerChangeKind.MoveUp, before.Version, signer.Id),
            new SignerChange((SignerChangeKind)999, before.Version)
        }) Assert.Equal(SignerSetupError.Invalid, (await ChangeAsync(draft, change)).Error);
        Assert.Equal(SignerSetupError.Duplicate, (await ChangeAsync(draft, new(SignerChangeKind.Save, before.Version,
            FullName: "Duplicate", Email: signer.Email.ToUpperInvariant()))).Error);
        Assert.Equal(SignerSetupError.Limit, (await ChangeAsync(draft, new(SignerChangeKind.Save, before.Version,
            FullName: "Another", Email: "another@example.invalid"), maximum: 1)).Error);
        Assert.Equal(SignerSetupError.Conflict, (await ChangeAsync(draft, new(SignerChangeKind.Remove, "invalid", signer.Id))).Error);
        var after = await ReadAsync(draft);
        Assert.Equal(before.Version, after.Version);
        Assert.Equal(before.Signers, after.Signers);
        await using var db = fixture.Open();
        Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == draft.Id));
    }

    [Fact]
    public async Task Authorization_draft_state_and_current_preview_confirmation_are_required()
    {
        var draft = await SeedAsync(1);
        var other = await SeedAsync(1);
        var before = await ReadAsync(draft);
        await using (var db = fixture.Open())
        {
            var service = Service(db);
            Assert.Null(await service.GetAsync(Principal(other), draft.PublicId));
            Assert.Null(await service.GetAsync(new ClaimsPrincipal(new ClaimsIdentity()), draft.PublicId));
            Assert.Equal(SignerSetupError.NotFound, (await service.ChangeAsync(Principal(other), draft.PublicId,
                new(SignerChangeKind.Remove, before.Version, before.Signers[0].Id), null, null)).Error);
        }
        Assert.Equal(SignerSetupError.NotFound, (await ChangeAsync(draft, new(SignerChangeKind.Remove, before.Version,
            (await ReadAsync(other)).Signers[0].Id))).Error);
        await using (var db = fixture.Open())
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == draft.Id);
            envelope.PreviewConfirmedAt = null;
            await db.SaveChangesAsync();
        }
        var unconfirmed = await ReadAsync(draft);
        Assert.False(unconfirmed.PreviewConfirmed);
        Assert.Equal(SignerSetupError.PreviewRequired, (await ChangeAsync(draft,
            new(SignerChangeKind.Remove, unconfirmed.Version, unconfirmed.Signers[0].Id))).Error);
        await using (var db = fixture.Open())
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == draft.Id);
            envelope.Status = EnvelopeStatus.Sent;
            await db.SaveChangesAsync();
        }
        await using var inspect = fixture.Open();
        Assert.Null(await Service(inspect).GetAsync(Principal(draft), draft.PublicId));
        Assert.Equal(SignerSetupError.NotFound, (await ChangeAsync(draft,
            new(SignerChangeKind.Remove, unconfirmed.Version, unconfirmed.Signers[0].Id))).Error);
    }

    [Fact]
    public async Task Concurrent_mutations_have_one_winner_and_do_not_exceed_the_signer_cap()
    {
        var draft = await SeedAsync();
        var snapshot = await ReadAsync(draft);
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 5).Select(i => ChangeAsync(draft,
            new(SignerChangeKind.Save, snapshot.Version, FullName: "Signer " + i, Email: $"concurrent-{i}@example.invalid"), maximum: 1)));
        Assert.Single(outcomes, x => x.Error == SignerSetupError.None);
        Assert.Equal(4, outcomes.Count(x => x.Error == SignerSetupError.Conflict));
        var after = await ReadAsync(draft);
        Assert.Equal(1, Assert.Single(after.Signers).Order);
        await using var db = fixture.Open();
        Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == draft.Id).ToListAsync());
    }

    [Fact]
    public async Task Assigned_fields_block_removal_and_email_transfer_but_keep_their_owner_when_reordering()
    {
        var draft = await SeedAsync(2);
        var before = await ReadAsync(draft);
        var first = before.Signers[0];
        await using (var db = fixture.Open())
        {
            db.Fields.Add(new DocumentField { EnvelopeId = draft.Id, SignerId = first.Id,
                Type = FieldType.Signature, Page = 1, X = .1m, Y = .1m, Width = .2m, Height = .1m });
            await db.SaveChangesAsync();
        }
        Assert.Equal(SignerSetupError.ReferencedFields, (await ChangeAsync(draft,
            new(SignerChangeKind.Remove, before.Version, first.Id))).Error);
        Assert.Equal(SignerSetupError.ReferencedFields, (await ChangeAsync(draft,
            new(SignerChangeKind.Save, before.Version, first.Id, first.FullName, "replacement@example.invalid"))).Error);
        Assert.Equal(SignerSetupError.None, (await ChangeAsync(draft,
            new(SignerChangeKind.MoveDown, before.Version, first.Id))).Error);
        await using var inspect = fixture.Open();
        Assert.Equal(first.Id, (await inspect.Fields.SingleAsync(x => x.EnvelopeId == draft.Id)).SignerId);
        Assert.Equal(first.Id, (await ReadAsync(draft)).Signers[1].Id);
    }

    [Fact]
    public async Task Audit_failure_rolls_back_temporary_orders_and_draft_version()
    {
        var draft = await SeedAsync(3);
        var before = await ReadAsync(draft);
        await using (var original = fixture.Open())
        await using (var failing = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(original.Database.GetConnectionString()).AddInterceptors(new RejectAudit()).Options))
        {
            await Assert.ThrowsAsync<DbUpdateException>(() => Service(failing).ChangeAsync(Principal(draft), draft.PublicId,
                new(SignerChangeKind.MoveDown, before.Version, before.Signers[0].Id), null, null));
        }
        var after = await ReadAsync(draft);
        Assert.Equal(before.Version, after.Version);
        Assert.Equal(before.Signers, after.Signers);
        Assert.Equal(SignerSetupError.None, (await ChangeAsync(draft,
            new(SignerChangeKind.MoveDown, before.Version, before.Signers[0].Id))).Error);
    }

    private SignerSetup Service(QuillSignDbContext db, int maximum = 10) =>
        new(db, new AuditWriter(db, TimeProvider.System), new SignerSetupOptions { MaximumSigners = maximum });

    private static ClaimsPrincipal Principal(Envelope draft) => SenderConfiguration.Principal(new VerifiedSender(draft.Id, draft.PublicId, draft.SenderEmail));

    private async Task<SignerSetupSnapshot> ReadAsync(Envelope draft)
    {
        await using var db = fixture.Open();
        return (await Service(db).GetAsync(Principal(draft), draft.PublicId))!;
    }

    private async Task<SignerChangeResult> ChangeAsync(Envelope draft, SignerChange change, int maximum = 10)
    {
        await using var db = fixture.Open();
        return await Service(db, maximum).ChangeAsync(Principal(draft), draft.PublicId, change, "127.0.0.1", "synthetic-test");
    }

    private async Task<Envelope> SeedAsync(int count = 0)
    {
        await using var db = fixture.Open();
        var draft = new Envelope
        {
            SenderEmail = "sender-" + Guid.NewGuid().ToString("N") + "@example.invalid",
            SenderVerifiedAt = DateTimeOffset.UtcNow, PreviewConfirmedAt = DateTimeOffset.UtcNow,
            PdfBlob = Guid.NewGuid().ToString("N"), PdfSha256 = SHA256.HashData([1]), PageCount = 1
        };
        db.Envelopes.Add(draft);
        for (var i = 0; i < count; i++) db.Signers.Add(new Signer
        {
            EnvelopeId = draft.Id, Order = i + 1, FullName = "Signer " + (i + 1), Email = $"signer-{i + 1}@example.invalid"
        });
        await db.SaveChangesAsync();
        return draft;
    }

    private sealed class RejectAudit : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context!.ChangeTracker.Entries<AuditEvent>().Any(x => x.State == EntityState.Added))
                throw new DbUpdateException("Synthetic audit failure", new IOException("Synthetic audit failure"));
            return ValueTask.FromResult(result);
        }
    }
}
