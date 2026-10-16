using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;

namespace QuillSign.Tests;

public sealed class DraftReviewTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Review_is_read_only_preserves_false_checkboxes_and_reports_signature_absence_as_warning_only()
    {
        var draft = await SeedAsync();
        await using var db = fixture.Open();
        var before = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == draft.Id);
        var result = (await new DraftReview(db).GetAsync(Principal(draft), draft.PublicId))!;
        Assert.True(result.ChecksPassed); Assert.Single(result.Warnings); Assert.Contains("no Signature field", result.Warnings[0].Message);
        Assert.Equal("false", result.Fields.Single(f => f.Type == "Checkbox").Value);
        Assert.Equal(2, result.Signers.Count); Assert.Equal("First signer", result.Signers[0].FullName); Assert.Single(result.Recipients);
        var after = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == draft.Id);
        Assert.Equal(before.RowVersion, after.RowVersion); Assert.Equal(before.Status, after.Status);
        Assert.Empty(db.ChangeTracker.Entries());
        Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == draft.Id));
        Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == draft.Id));
        Assert.False(await db.WorkItems.AnyAsync(x => x.EnvelopeId == draft.Id));
    }

    [Fact]
    public async Task Review_enforces_scheme_claims_owner_verification_and_draft_status()
    {
        var draft = await SeedAsync(); await using var db = fixture.Open(); var service = new DraftReview(db);
        Assert.Null(await service.GetAsync(new ClaimsPrincipal(), draft.PublicId));
        var wrongEmail = SenderConfiguration.Principal(new VerifiedSender(draft.Id, draft.PublicId, "wrong@example.invalid"));
        Assert.Null(await service.GetAsync(wrongEmail, draft.PublicId));
        Assert.Null(await service.GetAsync(Principal(draft), Guid.NewGuid().ToString("N")));
        var duplicate = Principal(draft); ((ClaimsIdentity)duplicate.Identity!).AddClaim(new Claim(ClaimTypes.Email, draft.SenderEmail));
        Assert.Null(await service.GetAsync(duplicate, draft.PublicId));
        var stored = await db.Envelopes.SingleAsync(x => x.Id == draft.Id); stored.SenderVerifiedAt = null; await db.SaveChangesAsync();
        Assert.Null(await service.GetAsync(Principal(draft), draft.PublicId));
        stored.SenderVerifiedAt = DateTimeOffset.UtcNow; stored.Status = EnvelopeStatus.Sent; await db.SaveChangesAsync();
        Assert.Null(await service.GetAsync(Principal(draft), draft.PublicId));
    }

    [Fact]
    public async Task Missing_pdf_confirmation_title_and_signers_are_actionable_and_do_not_throw()
    {
        var draft = await SeedAsync(); await using var db = fixture.Open();
        await db.Fields.Where(x => x.EnvelopeId == draft.Id).ExecuteDeleteAsync();
        await db.Signers.Where(x => x.EnvelopeId == draft.Id).ExecuteDeleteAsync();
        var stored = await db.Envelopes.SingleAsync(x => x.Id == draft.Id);
        stored.PdfBlob = null; stored.PdfSha256 = null; stored.PageCount = null; stored.PageSizesJson = null;
        stored.PreviewConfirmedAt = null; stored.Title = " "; await db.SaveChangesAsync();
        var result = (await new DraftReview(db).GetAsync(Principal(draft), draft.PublicId))!;
        Assert.False(result.ChecksPassed); Assert.False(result.HasPdf); Assert.Equal(5, result.Errors.Count);
        Assert.Contains(result.Errors, x => x.Step == "signers"); Assert.Contains(result.Errors, x => x.Step == "details");
        Assert.Contains(result.Errors, x => x.Step == "" && x.Message.Contains("confirm"));
    }

    [Theory]
    [InlineData("not-json")]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("[null]")]
    [InlineData("[{}]")]
    [InlineData("[1]")]
    public async Task Malformed_page_metadata_blocks_review_instead_of_crashing(string json)
    {
        var draft = await SeedAsync(); await using var db = fixture.Open();
        var current = (await new DraftReview(db).GetAsync(Principal(draft), draft.PublicId))!;
        draft.PageSizesJson = json;
        var result = DraftReview.CheckPreparation(draft, current.Signers, [], current.Recipients);
        Assert.Contains(result.Errors, x => x.Message.Contains("page information"));
    }

    [Fact]
    public async Task Invalid_sender_values_field_geometry_type_owner_and_assignment_block_preparation()
    {
        var draft = await SeedAsync(); var other = await SeedAsync(); await using var db = fixture.Open();
        var foreign = await db.Signers.FirstAsync(x => x.EnvelopeId == other.Id);
        var current = (await new DraftReview(db).GetAsync(Principal(draft), draft.PublicId))!;
        var field = await db.Fields.SingleAsync(x => x.EnvelopeId == draft.Id && x.Type == FieldType.Text);
        var originalOwner = (await db.Signers.FirstAsync(x => x.EnvelopeId == draft.Id)).Id;
        var changes = new Action<DocumentField>[]
        {
            f => f.Value = null, f => f.Value = " ", f => f.Value = "bad\0value", f => f.Value = new string('x',4001),
            f => { f.Type = FieldType.Date; f.Value = "2026-02-29"; },
            f => { f.Type = FieldType.Checkbox; f.Value = "yes"; },
            f => { f.Type = FieldType.Signature; f.Value = null; },
            f => f.Type = (FieldType)999, f => f.Page = 2, f => f.X = .95m,
            f => { f.SignerId = foreign.Id; f.Value = null; },
            f => { f.SignerId = originalOwner; f.Value = "sender forged signer value"; }
        };
        foreach (var change in changes)
        {
            field.Type = FieldType.Text; field.Page = 1; field.X = .1m; field.SignerId = null; field.Value = "Valid value";
            change(field);
            var result = DraftReview.CheckPreparation(draft, current.Signers, [field], current.Recipients);
            Assert.False(result.ChecksPassed); Assert.Contains(result.Errors, x => x.Step == "fields");
        }
        field.Type = FieldType.Date; field.Page = 1; field.X = .1m; field.SignerId = null; field.Value = "2028-02-29";
        Assert.True(DraftReview.CheckPreparation(draft, current.Signers, [field], current.Recipients).ChecksPassed);
    }

    [Fact]
    public async Task Review_refreshes_old_tracked_envelope_and_collection_after_another_context_changes_the_revision()
    {
        var draft = await SeedAsync(); await using var stale = fixture.Open();
        await stale.Envelopes.SingleAsync(x => x.Id == draft.Id); await stale.Recipients.Where(x => x.EnvelopeId == draft.Id).ToListAsync();
        var before = (await new DraftReview(stale).GetAsync(Principal(draft), draft.PublicId))!;
        await using (var writer = fixture.Open())
        {
            var changed = await writer.Envelopes.SingleAsync(x => x.Id == draft.Id); changed.Title = "New saved title";
            var recipient = await writer.Recipients.SingleAsync(x => x.EnvelopeId == draft.Id); recipient.Name = "New recipient";
            await writer.SaveChangesAsync();
        }
        var after = (await new DraftReview(stale).GetAsync(Principal(draft), draft.PublicId))!;
        Assert.Equal("New saved title", after.Title); Assert.NotEqual(before.Version, after.Version);
        Assert.Equal("New recipient", Assert.Single(after.Recipients).Name);
    }

    [Fact]
    public async Task A_concurrent_writer_cannot_mix_new_details_with_old_recipients_in_one_review()
    {
        var draft = await SeedAsync(); await using var connectionSource = fixture.Open();
        var pause = new PauseEnvelopeRead();
        await using var reader = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(connectionSource.Database.GetConnectionString()).AddInterceptors(pause).Options);
        var reviewTask = new DraftReview(reader).GetAsync(Principal(draft), draft.PublicId);
        await pause.Reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await using var writer = fixture.Open(); await writer.Database.OpenConnectionAsync();
        // A finite SQL lock timeout makes this a database-observed contention check, without sleeps.
        // The transaction changes both details and recipients if it can acquire the envelope lock.
        var blocked = await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(() => writer.Database.ExecuteSqlInterpolatedAsync($"SET LOCK_TIMEOUT 250; UPDATE [Envelopes] SET [Title] = N'Concurrent title' WHERE [Id] = {draft.Id}"));
        Assert.Equal(1222, blocked.Number);
        pause.Release.TrySetResult();
        var before = (await reviewTask)!; Assert.Equal("Synthetic review", before.Title); Assert.Equal("Synthetic observer", before.Recipients[0].Name);
        await writer.Database.ExecuteSqlRawAsync("SET LOCK_TIMEOUT -1");
        await using (var transaction = await writer.Database.BeginTransactionAsync())
        {
            var changed = await writer.Envelopes.SingleAsync(x => x.Id == draft.Id); changed.Title = "Concurrent title";
            var recipient = await writer.Recipients.SingleAsync(x => x.EnvelopeId == draft.Id); recipient.Name = "Concurrent recipient";
            await writer.SaveChangesAsync(); await transaction.CommitAsync();
        }
        var after = (await new DraftReview(reader).GetAsync(Principal(draft), draft.PublicId))!;
        Assert.Equal("Concurrent title", after.Title); Assert.Equal("Concurrent recipient", after.Recipients[0].Name);
    }

    private sealed class PauseEnvelopeRead : DbCommandInterceptor
    {
        public TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
            DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("UPDLOCK, HOLDLOCK", StringComparison.Ordinal) && !Reached.Task.IsCompleted)
            { Reached.TrySetResult(); await Release.Task.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken); }
            return result;
        }
    }

    private static ClaimsPrincipal Principal(Envelope draft) => SenderConfiguration.Principal(new VerifiedSender(draft.Id, draft.PublicId, draft.SenderEmail));
    private async Task<Envelope> SeedAsync()
    {
        await using var db = fixture.Open();
        var draft = new Envelope { SenderEmail = "review-" + Guid.NewGuid().ToString("N") + "@example.invalid", Title = "Synthetic review",
            SenderVerifiedAt = DateTimeOffset.UtcNow, PreviewConfirmedAt = DateTimeOffset.UtcNow,
            PdfBlob = Guid.NewGuid().ToString("N"), PdfSha256 = SHA256.HashData([1]), PageCount = 1,
            PageSizesJson = JsonSerializer.Serialize(new[] { new PageGeometry(612,792,0,1,[0,0,612,792],[0,0,612,792]) }) };
        var first = new Signer { EnvelopeId = draft.Id, Order = 1, FullName = "First signer", Email = "first@example.invalid" };
        var second = new Signer { EnvelopeId = draft.Id, Order = 2, FullName = "Second signer", Email = "second@example.invalid" };
        db.Envelopes.Add(draft); db.Signers.AddRange(first, second);
        foreach (var field in new[] {
            new DocumentField { Type = FieldType.Signature, SignerId = first.Id },
            new DocumentField { Type = FieldType.Text, Value = "Valid sender value" },
            new DocumentField { Type = FieldType.Checkbox, Value = "false" },
            new DocumentField { Type = FieldType.Date, Value = "2028-02-29" } })
        { field.EnvelopeId = draft.Id; field.X = .1m; field.Y = .2m; field.Width = .2m; field.Height = .1m; db.Fields.Add(field); }
        db.Recipients.Add(new Recipient { EnvelopeId = draft.Id, Name = "Synthetic observer", Email = "observer@example.invalid" });
        await db.SaveChangesAsync(); return draft;
    }
}
