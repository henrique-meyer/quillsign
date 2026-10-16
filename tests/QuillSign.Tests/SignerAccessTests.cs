using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Legal;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class SignerAccessTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    private readonly Clock clock = new();
    [Fact]
    public async Task Concurrent_redemption_consumes_once_with_signer_attribution_and_bound_non_sliding_context()
    {
        var seed = await Seed();
        var results = await Task.WhenAll(Enumerable.Range(0,4).Select(async _ =>
        { await using var db = fixture.Open(); return await Service(db).RedeemAsync(seed.Invitation.RawToken,"127.0.0.1","synthetic-access-test"); }));
        var verified = Assert.Single(results,x => x is not null)!;
        Assert.Equal(seed.First.Id,verified.SignerId); Assert.Equal(seed.Envelope.Id,verified.EnvelopeId);
        var principal = SignerAccessConfiguration.Principal(verified);
        await using var inspect = fixture.Open();
        var audit = await inspect.AuditEvents.SingleAsync(x => x.EnvelopeId == seed.Envelope.Id);
        Assert.Equal("link_opened",audit.Event); Assert.Equal(PartyType.Signer,audit.ActorType); Assert.Equal(seed.First.Id,audit.ActorId);
        Assert.Equal(seed.First.Email,audit.ActorEmail); Assert.Equal(AuditHash.Compute(audit),audit.Hash);
        Assert.DoesNotContain(seed.Invitation.RawToken,audit.DataJson);
        var context = (await Service(inspect).GetContextAsync(principal,seed.Envelope.PublicId))!;
        Assert.Equal(Guid.Parse(seed.Envelope.SentPdfBlob!),context.Document.ObjectId); Assert.NotEqual(Guid.Parse(seed.Envelope.PdfBlob!),context.Document.ObjectId);
        Assert.True(ElectronicRecordDisclosure.Verify(context.Disclosure)); Assert.Equal(EnvelopeStatus.Sent,(await inspect.Envelopes.SingleAsync(x => x.Id == seed.Envelope.Id)).Status);
        Assert.Null(await Service(inspect).RedeemAsync(seed.Invitation.RawToken,null,null));
        clock.Advance(TimeSpan.FromHours(1));
        Assert.Equal(verified.SessionExpiresAt,(await Service(inspect).GetContextAsync(principal,seed.Envelope.PublicId))!.Identity.SessionExpiresAt);
        clock.Advance(TimeSpan.FromHours(1)); Assert.Null(await Service(inspect).GetContextAsync(principal,seed.Envelope.PublicId));
    }

    [Fact]
    public async Task A_later_signers_token_is_not_consumed_before_a_verified_prior_checkpoint_exists()
    {
        var seed = await Seed(); var later = new SignerInvitationFactory(new(),clock).Create(seed.Envelope.Id,seed.Second.Id,seed.Second.Email,seed.Envelope.ExpiresAt,Guid.Parse(seed.Envelope.SentPdfBlob!),seed.Envelope.SentPdfSha256!,seed.Envelope.ErsdSha256!);
        await using var db = fixture.Open(); db.AuthTokens.Add(later.Record); await db.SaveChangesAsync();
        Assert.Null(await Service(db).RedeemAsync(later.RawToken,null,null));
        Assert.Null((await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == later.Record.Id)).UsedAt);
        var first = await db.Signers.SingleAsync(x => x.Id == seed.First.Id); first.Status = SignerStatus.Signed; await db.SaveChangesAsync();
        Assert.Null(await Service(db).RedeemAsync(later.RawToken,null,null)); Assert.Null((await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==later.Record.Id)).UsedAt);
    }

    [Theory]
    [InlineData("purpose")][InlineData("party")][InlineData("email")][InlineData("expired-token")][InlineData("used")]
    [InlineData("draft")][InlineData("expired-envelope")][InlineData("signed")][InlineData("declined")]
    [InlineData("foreign-signer")][InlineData("missing-document")][InlineData("disclosure")][InlineData("unverified-sender")]
    public async Task Wrong_or_ineligible_tokens_fail_without_consumption_or_audit(string kind)
    {
        var seed = await Seed(); await using var db = fixture.Open();
        var token = await db.AuthTokens.SingleAsync(x => x.Id == seed.Invitation.Record.Id);
        var envelope = await db.Envelopes.SingleAsync(x => x.Id == seed.Envelope.Id);
        var signer = await db.Signers.SingleAsync(x => x.Id == seed.First.Id);
        switch (kind)
        {
            case "purpose": token.Purpose = TokenPurpose.SenderVerify; break;
            case "party": token.PartyType = PartyType.Recipient; break;
            case "email": token.Email = "other@example.invalid"; break;
            case "expired-token": token.ExpiresAt = clock.GetUtcNow(); break;
            case "used": token.UsedAt = clock.GetUtcNow(); break;
            case "draft": envelope.Status = EnvelopeStatus.Draft; break;
            case "expired-envelope": envelope.ExpiresAt = clock.GetUtcNow(); break;
            case "signed": signer.Status = SignerStatus.Signed; break;
            case "declined": signer.Status = SignerStatus.Declined; break;
            case "foreign-signer": token.PartyId = Guid.NewGuid(); break;
            case "missing-document": envelope.SentPdfBlob = null; break;
            case "disclosure": envelope.ErsdText += "changed"; break;
            case "unverified-sender": envelope.SenderVerifiedAt = null; break;
        }
        await db.SaveChangesAsync(); var before = token.UsedAt;
        Assert.Null(await Service(db).RedeemAsync(seed.Invitation.RawToken,null,null));
        Assert.Equal(before,(await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == token.Id)).UsedAt);
        Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == envelope.Id));
    }

    [Fact]
    public async Task Context_rejects_changed_identity_document_disclosure_and_state_bindings()
    {
        var seed = await Seed(); await using var db = fixture.Open();
        var verified = (await Service(db).RedeemAsync(seed.Invitation.RawToken,null,null))!;
        var principal = SignerAccessConfiguration.Principal(verified);
        Assert.Null(await Service(db).GetContextAsync(principal,new string('a',32)));
        var duplicate = SignerAccessConfiguration.Principal(verified); ((ClaimsIdentity)duplicate.Identity!).AddClaim(new Claim(SignerAccessConfiguration.SignerClaim,Guid.NewGuid().ToString("N")));
        Assert.Null(await Service(db).GetContextAsync(duplicate,seed.Envelope.PublicId));
        var mixed = SignerAccessConfiguration.Principal(verified); mixed.AddIdentity((ClaimsIdentity)BlobStorageTests.Sender(seed.Envelope.Id).Identity!);
        Assert.Null(await Service(db).GetContextAsync(mixed,seed.Envelope.PublicId));
        Assert.Null(await Service(db).GetContextAsync(BlobStorageTests.Sender(seed.Envelope.Id),seed.Envelope.PublicId));
        var stored = await db.Envelopes.SingleAsync(x => x.Id == seed.Envelope.Id);
        foreach (var change in new Action[] { () => stored.SentPdfSha256 = SHA256.HashData([2]), () => stored.SentPdfBlob = Guid.NewGuid().ToString("N"),
            () => stored.ErsdSha256 = SHA256.HashData([3]), () => stored.Status = EnvelopeStatus.Voided })
        {
            stored.SentPdfSha256 = seed.Envelope.SentPdfSha256; stored.SentPdfBlob = seed.Envelope.SentPdfBlob;
            stored.ErsdSha256 = seed.Envelope.ErsdSha256; stored.Status = EnvelopeStatus.Sent;
            change(); await db.SaveChangesAsync(); Assert.Null(await Service(db).GetContextAsync(principal,seed.Envelope.PublicId));
        }
    }

    [Fact]
    public async Task Audit_failure_rolls_back_token_consumption_and_retry_succeeds()
    {
        var seed = await Seed(); await using var original = fixture.Open();
        await using (var failing = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(original.Database.GetConnectionString()).AddInterceptors(new RejectAudit()).Options))
            await Assert.ThrowsAsync<DbUpdateException>(() => Service(failing).RedeemAsync(seed.Invitation.RawToken,null,null));
        Assert.Null((await original.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == seed.Invitation.Record.Id)).UsedAt);
        Assert.False(await original.AuditEvents.AnyAsync(x => x.EnvelopeId == seed.Envelope.Id));
        Assert.NotNull(await Service(original).RedeemAsync(seed.Invitation.RawToken,null,null));
    }

    [Fact]
    public void Factory_starts_expiry_at_creation_uses_256_bits_and_clamps_to_envelope_end()
    {
        var factory = new SignerInvitationFactory(new(),clock); var queued = clock.GetUtcNow(); clock.Advance(TimeSpan.FromDays(3));
        var documentId=Guid.NewGuid(); var documentHash=SHA256.HashData([1]); var disclosureHash=SHA256.HashData([2]);
        var invite = factory.Create(Guid.NewGuid(),Guid.NewGuid(),"SIGNER@EXAMPLE.INVALID",null,documentId,documentHash,disclosureHash);
        Assert.Equal(clock.GetUtcNow().AddHours(24),invite.Record.ExpiresAt); Assert.True(invite.Record.ExpiresAt > queued.AddHours(24));
        Assert.Equal(43,invite.RawToken.Length); Assert.Equal(32,Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(invite.RawToken).Length);
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(invite.RawToken)),invite.Record.TokenSha256);
        Assert.Equal("signer@example.invalid",invite.Record.Email);
        var end = clock.GetUtcNow().AddMinutes(30);
        Assert.Equal(end,factory.Create(Guid.NewGuid(),Guid.NewGuid(),"signer@example.invalid",end,documentId,documentHash,disclosureHash).Record.ExpiresAt);
        Assert.Throws<InvalidOperationException>(() => factory.Create(Guid.NewGuid(),Guid.NewGuid(),"signer@example.invalid",clock.GetUtcNow(),documentId,documentHash,disclosureHash));
    }

    private SignerAccess Service(QuillSignDbContext db) => new(db,new AuditWriter(db,clock),new(),clock);
    private async Task<(Envelope Envelope,Signer First,Signer Second,SignerInvitation Invitation)> Seed()
    {
        await using var db = fixture.Open();
        var envelope = new Envelope { SenderEmail = "sender@example.invalid",Title = "Synthetic signer access",Status = EnvelopeStatus.Sent,
            SenderVerifiedAt = clock.GetUtcNow(),SentAt = clock.GetUtcNow(),ExpiresAt = clock.GetUtcNow().AddDays(30),
            PdfBlob = Guid.NewGuid().ToString("N"),SentPdfBlob = Guid.NewGuid().ToString("N"),SentPdfSha256 = SHA256.HashData([1]) };
        var disclosure = new ElectronicRecordDisclosure(ElectronicRecordDisclosureTests.Policy()).Build(envelope.PublicId,envelope.Title,envelope.SenderEmail);
        envelope.ErsdVersion = disclosure.Version; envelope.ErsdText = disclosure.Text; envelope.ErsdSha256 = disclosure.Sha256;
        var first = new Signer { EnvelopeId = envelope.Id,FullName = "First synthetic signer",Email = "first@example.invalid",Order = 1 };
        var second = new Signer { EnvelopeId = envelope.Id,FullName = "Second synthetic signer",Email = "second@example.invalid",Order = 2 };
        var invitation = new SignerInvitationFactory(new(),clock).Create(envelope.Id,first.Id,first.Email,envelope.ExpiresAt,Guid.Parse(envelope.SentPdfBlob),envelope.SentPdfSha256,disclosure.Sha256);
        db.AddRange(envelope,first,second,invitation.Record); await db.SaveChangesAsync(); return (envelope,first,second,invitation);
    }
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan span) => now += span;
    }
    private sealed class RejectAudit : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,InterceptionResult<int> result,CancellationToken cancellationToken = default)
        {
            if (eventData.Context!.ChangeTracker.Entries<AuditEvent>().Any(x => x.State == EntityState.Added)) throw new DbUpdateException("Synthetic audit failure");
            return ValueTask.FromResult(result);
        }
    }
}
