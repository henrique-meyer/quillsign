using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Legal;

namespace QuillSign.Tests;

public sealed class DisclosurePersistenceTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Migration_preserves_legacy_nulls_and_roundtrips_full_disclosure_beyond_old_string_limit()
    {
        await using var db = fixture.Open(); var draft = new Envelope { SenderEmail = "sender@example.invalid" };
        db.Envelopes.Add(draft); await db.SaveChangesAsync(); db.ChangeTracker.Clear();
        var stored = await db.Envelopes.SingleAsync(x => x.Id == draft.Id); Assert.Null(stored.ErsdText);
        var snapshot = new ElectronicRecordDisclosure(ElectronicRecordDisclosureTests.Policy()).Build(stored.PublicId,"Synthetic agreement",stored.SenderEmail);
        Assert.True(snapshot.Text.Length > 512); stored.Title = snapshot.Title;
        stored.ErsdVersion = snapshot.Version; stored.ErsdText = snapshot.Text; stored.ErsdSha256 = snapshot.Sha256;
        await db.SaveChangesAsync(); db.ChangeTracker.Clear();
        var reloaded = await db.Envelopes.SingleAsync(x => x.Id == draft.Id);
        Assert.True(ElectronicRecordDisclosure.Verify(new(reloaded.ErsdVersion!,reloaded.PublicId,reloaded.Title!,reloaded.SenderEmail,reloaded.ErsdText!,reloaded.ErsdSha256!)));
        Assert.False(db.Database.HasPendingModelChanges());
        reloaded.ErsdText = new string('x',ElectronicRecordDisclosure.MaximumTextCharacters + 1);
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }
}
