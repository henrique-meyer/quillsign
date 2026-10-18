using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using System.Security.Cryptography;

namespace QuillSign.Tests;

public sealed class PersistenceTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private static Envelope Draft() => new() { SenderEmail = "sender@example.invalid" };
    private static Signer Party(Envelope envelope, int order = 1) => new()
    {
        EnvelopeId = envelope.Id, Order = order, Email = "signer@example.invalid", FullName = "Synthetic Signer"
    };
    private static DocumentField Field(Envelope envelope, Guid? signer = null) => new()
    {
        EnvelopeId = envelope.Id, SignerId = signer, Type = FieldType.Text,
        X = 0.1m, Y = 0.1m, Width = 0.2m, Height = 0.1m
    };

    [Fact]
    public async Task MigrationsApplyToFreshSqlServerAndMatchTheModel()
    {
        await using var db = fixture.Open();
        Assert.False(db.Database.HasPendingModelChanges());
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        Assert.Equal(20, db.Model.GetEntityTypes().Count());
    }

    [Fact]
    public async Task SignerEmailUniquenessIsCaseInsensitiveWithinEachEnvelope()
    {
        await using var db = fixture.Open();
        var envelope = Draft();
        db.AddRange(envelope, Party(envelope));
        await db.SaveChangesAsync();
        var duplicate = Party(envelope, 2);
        duplicate.Email = "SIGNER@example.invalid";
        db.Add(duplicate);
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        var other = Draft();
        db.AddRange(other, Party(other));
        await db.SaveChangesAsync();
    }

    [Fact]
    public async Task RecipientAndSuppressionEmailsAreCaseInsensitive()
    {
        await using var db = fixture.Open();
        var envelope = Draft();
        db.AddRange(envelope, new Recipient { EnvelopeId = envelope.Id, Email = "cc@example.invalid" });
        await db.SaveChangesAsync();
        db.Add(new Recipient { EnvelopeId = envelope.Id, Email = "CC@example.invalid" });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        var address = Guid.NewGuid().ToString("N") + "@example.invalid";
        db.Add(new Suppression { Email = address });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        db.Add(new Suppression { Email = address.ToUpperInvariant() });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task FieldsCannotReferenceASignerFromAnotherEnvelope()
    {
        await using var db = fixture.Open();
        var first = Draft();
        var second = Draft();
        var signer = Party(first);
        db.AddRange(first, second, signer);
        await db.SaveChangesAsync();
        db.Add(Field(second, signer.Id));
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task ValidSignerFieldsAndSenderDatesRoundTrip()
    {
        await using var db = fixture.Open();
        var envelope = Draft(); var signer = Party(envelope);
        var signature = Field(envelope, signer.Id); signature.Type = FieldType.Signature;
        var date = Field(envelope); date.Type = FieldType.Date;
        db.AddRange(envelope, signer, signature, date);
        await db.SaveChangesAsync(); db.ChangeTracker.Clear();
        Assert.Equal(2, await db.Fields.CountAsync(x => x.EnvelopeId == envelope.Id));
        Assert.Equal(0.1m, (await db.Fields.SingleAsync(x => x.Id == signature.Id)).X);
    }

    [Theory]
    [InlineData(-0.1, 0.1, 0.2, 0.1, 1)]
    [InlineData(0.9, 0.1, 0.2, 0.1, 1)]
    [InlineData(0.1, 0.9, 0.1, 0.2, 1)]
    [InlineData(0.1, 0.1, 0, 0.1, 1)]
    [InlineData(0.1, 0.1, 0.1, 0.1, 0)]
    public async Task FieldsMustHavePositiveSizeAndFitWithinAPage(double x, double y, double width, double height, int page)
    {
        await using var db = fixture.Open();
        var envelope = Draft();
        db.Add(envelope);
        await db.SaveChangesAsync();
        var field = Field(envelope);
        field.X = (decimal)x; field.Y = (decimal)y; field.Width = (decimal)width;
        field.Height = (decimal)height; field.Page = page;
        db.Add(field);
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Theory]
    [InlineData(FieldType.Signature)]
    [InlineData(FieldType.Initials)]
    [InlineData(FieldType.FullName)]
    [InlineData(FieldType.DateSigned)]
    public async Task SignerFieldsCannotBeAssignedToTheSenderBucket(FieldType type)
    {
        await using var db = fixture.Open();
        var envelope = Draft();
        db.Add(envelope);
        await db.SaveChangesAsync();
        var field = Field(envelope); field.Type = type;
        db.Add(field);
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task InvalidJsonAndUnknownStatusesAreRejected()
    {
        await using var db = fixture.Open();
        var envelope = Draft(); envelope.ReminderDaysJson = "not-json";
        db.Add(envelope);
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        envelope = Draft(); envelope.Status = (EnvelopeStatus)999;
        db.Add(envelope);
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task TokensHaveUniqueFullLengthHashesAndExplicitEnvelopeScope()
    {
        await using var db = fixture.Open();
        var envelope = Draft(); db.Add(envelope); await db.SaveChangesAsync();
        var hash = SHA256.HashData(RandomNumberGenerator.GetBytes(32));
        db.Add(new AuthToken { EnvelopeId = envelope.Id, TokenSha256 = hash });
        await db.SaveChangesAsync();
        db.Add(new AuthToken { EnvelopeId = envelope.Id, TokenSha256 = hash });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        db.Add(new AuthToken { EnvelopeId = envelope.Id, TokenSha256 = [1] });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        db.Add(new AuthToken { TokenSha256 = RandomNumberGenerator.GetBytes(32) });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task ConcurrentEnvelopeChangesAndTokenUseCannotBothWin()
    {
        await using var db = fixture.Open();
        var envelope = Draft();
        var token = new AuthToken { EnvelopeId = envelope.Id, TokenSha256 = RandomNumberGenerator.GetBytes(32) };
        db.AddRange(envelope, token); await db.SaveChangesAsync();
        await using var other = fixture.Open();
        var staleEnvelope = await other.Envelopes.SingleAsync(x => x.Id == envelope.Id);
        envelope.Title = "first"; await db.SaveChangesAsync();
        staleEnvelope.Title = "second";
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => other.SaveChangesAsync());
        other.ChangeTracker.Clear();
        var staleToken = await other.AuthTokens.SingleAsync(x => x.Id == token.Id);
        token.UsedAt = DateTimeOffset.UtcNow; await db.SaveChangesAsync();
        staleToken.UsedAt = DateTimeOffset.UtcNow;
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => other.SaveChangesAsync());
    }

    [Fact]
    public async Task WorkLeasesArePairedAndCompetingClaimsDetectConflicts()
    {
        await using var db = fixture.Open();
        var work = new WorkItem(); db.Add(work); await db.SaveChangesAsync();
        await using var other = fixture.Open();
        var competing = await other.WorkItems.SingleAsync(x => x.Id == work.Id);
        work.LeaseOwner = Guid.NewGuid(); work.LeaseExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1); work.Status = WorkStatus.Leased;
        await db.SaveChangesAsync();
        competing.LeaseOwner = Guid.NewGuid(); competing.LeaseExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1); competing.Status = WorkStatus.Leased;
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => other.SaveChangesAsync());
        db.Add(new WorkItem { LeaseOwner = Guid.NewGuid() });
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task AuditSequencesAreUniqueAndSavedEventsCannotBeEditedOrDeletedThroughTheContext()
    {
        await using var db = fixture.Open();
        var envelope = Draft(); db.Add(envelope); await db.SaveChangesAsync();
        var audit = new AuditEvent { EnvelopeId = envelope.Id, Sequence = 1, At = DateTimeOffset.UtcNow, Event = "created" };
        audit.Hash = AuditHash.Compute(audit);
        db.Add(audit); await db.SaveChangesAsync();
        var duplicate = new AuditEvent { EnvelopeId = envelope.Id, Sequence = 1, Event = "created" };
        duplicate.Hash = AuditHash.Compute(duplicate);
        db.Add(duplicate);
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        audit = await db.AuditEvents.SingleAsync(x => x.Id == audit.Id);
        audit.Event = "changed";
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        audit = await db.AuditEvents.SingleAsync(x => x.Id == audit.Id);
        db.Remove(audit);
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task AuditChainPersistsAndRejectsMissingPredecessorsOrIncorrectHashes()
    {
        await using var db = fixture.Open();
        var envelope = Draft(); db.Add(envelope); await db.SaveChangesAsync();
        var first = new AuditEvent { EnvelopeId = envelope.Id, Sequence = 1, Event = "created" };
        first.Hash = AuditHash.Compute(first); db.Add(first); await db.SaveChangesAsync();
        var next = new AuditEvent { EnvelopeId = envelope.Id, Sequence = 2, Event = "verified", PrevHash = first.Hash };
        next.Hash = AuditHash.Compute(next); db.Add(next); await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        Assert.Equal(first.Hash, (await db.AuditEvents.SingleAsync(x => x.Id == next.Id)).PrevHash);
        var broken = new AuditEvent { EnvelopeId = envelope.Id, Sequence = 3, Event = "uploaded" };
        broken.Hash = AuditHash.Compute(broken); db.Add(broken);
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear();
        broken.PrevHash = next.Hash; broken.Hash = new byte[32]; db.Add(broken);
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }
}
