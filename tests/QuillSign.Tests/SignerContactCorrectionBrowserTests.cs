using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Sender;

namespace QuillSign.Tests;

public sealed class SignerContactCorrectionBrowserTests
{
    private readonly EphemeralDataProtectionProvider keys = new();
    private readonly Clock clock = new(new(2026, 10, 18, 12, 0, 0, TimeSpan.Zero));
    private readonly VerifiedSender owner = new(Guid.NewGuid(), Guid.NewGuid().ToString("N"), "sender@example.invalid");
    private static SignerContactCorrectionReview Review() => new(Guid.NewGuid(), "Synthetic signer NO AGREEMENT",
        "old@example.invalid", "corrected@example.invalid", Convert.ToBase64String([1, 2, 3, 4, 5, 6, 7, 8]),
        Convert.ToBase64String([8, 7, 6, 5, 4, 3, 2, 1]), Guid.Empty, 0, Guid.NewGuid(), new('a', 64), new('b', 64));
    private ClaimsPrincipal Principal => SenderConfiguration.Principal(owner);

    [Fact]
    public void Exact_review_is_stable_on_reread_and_each_explicit_review_has_a_new_command()
    {
        var service = new SignerContactCorrectionBrowser(keys, clock); var until = clock.Now.AddHours(2);
        var preview = new SignerContactCorrectionPreview("Synthetic NO AGREEMENT", Review(), null);
        var proof = service.Create(Principal, owner.PublicId, until, preview);
        var saved = Assert.IsType<SignerContactCorrectionConfirmation>(service.Read(proof, Principal, owner.PublicId, until));
        Assert.Equal(preview.Review, saved.Review); Assert.Equal(preview.Title, saved.Title);
        Assert.Equal(clock.Now.AddMinutes(10), saved.ExpiresAt); Assert.Equal(until, saved.TicketExpiresAt);
        Assert.Equal(SignerContactCorrectionStatement.Version, saved.StatementVersion);
        Assert.Equal(SignerContactCorrectionStatement.Sha256, saved.StatementSha256);
        Assert.Equal(saved, service.Read(proof, Principal, owner.PublicId, until));
        var next = service.Read(service.Create(Principal, owner.PublicId, until, preview), Principal, owner.PublicId, until)!;
        Assert.NotEqual(saved.Id, next.Id); Assert.NotEqual(Guid.Empty, saved.Id);
        Assert.DoesNotContain(preview.Review.NewEmail, proof);
    }

    [Fact]
    public void Review_cannot_cross_sender_envelope_public_id_ticket_or_protection_purpose()
    {
        var service = new SignerContactCorrectionBrowser(keys, clock); var until = clock.Now.AddHours(2);
        var proof = service.Create(Principal, owner.PublicId, until, new("Synthetic", Review(), null));
        Assert.Null(service.Read(proof, SenderConfiguration.Principal(owner with { Email = "other@example.invalid" }), owner.PublicId, until));
        Assert.Null(service.Read(proof, SenderConfiguration.Principal(owner with { EnvelopeId = Guid.NewGuid() }), owner.PublicId, until));
        Assert.Null(service.Read(proof, Principal, Guid.NewGuid().ToString("N"), until));
        Assert.Null(service.Read(proof, Principal, owner.PublicId, until.AddTicks(1)));
        Assert.Null(service.Read(proof + "tampered", Principal, owner.PublicId, until));
        var saved = service.Read(proof, Principal, owner.PublicId, until)!;
        var foreign = keys.CreateProtector("QuillSign.SenderInvitationResend.Review.v1").Protect(JsonSerializer.Serialize(saved));
        Assert.Null(service.Read(foreign, Principal, owner.PublicId, until));
        Assert.Null(service.Read(new string('a', SignerContactCorrectionBrowser.MaximumProofLength + 1), Principal, owner.PublicId, until));
    }

    [Theory]
    [InlineData("ten-minutes")][InlineData("ticket")][InlineData("midnight")][InlineData("future-clock")]
    public void Expiry_is_bounded_without_renewing_the_original_ticket(string boundary)
    {
        if (boundary == "midnight") clock.Now = new(2026, 10, 18, 23, 59, 30, TimeSpan.Zero);
        var until = clock.Now.AddHours(2); if (boundary == "ticket") until = clock.Now.AddSeconds(20);
        var service = new SignerContactCorrectionBrowser(keys, clock);
        var proof = service.Create(Principal, owner.PublicId, until, new("Synthetic", Review(), null));
        clock.Now = boundary switch {
            "ticket" => until, "midnight" => clock.Now.AddSeconds(30), "future-clock" => clock.Now.AddSeconds(-1),
            _ => clock.Now.AddMinutes(10)
        };
        Assert.Null(service.Read(proof, Principal, owner.PublicId, until));
    }

    [Theory]
    [InlineData("envelope-version")][InlineData("signer-version")][InlineData("source")][InlineData("disclosure")]
    [InlineData("same-address")][InlineData("noncanonical-address")][InlineData("epoch-id")][InlineData("epoch-number")]
    public void Invalid_or_ambiguous_saved_review_cannot_be_minted(string kind)
    {
        var r = Review();
        r = kind switch {
            "envelope-version" => r with { Version = "not-a-version" }, "signer-version" => r with { SignerVersion = "" },
            "source" => r with { DocumentSha256 = new('A', 64) }, "disclosure" => r with { DisclosureSha256 = "" },
            "same-address" => r with { NewEmail = r.OldEmail }, "noncanonical-address" => r with { NewEmail = "UPPER@example.invalid" },
            "epoch-id" => r with { ContactRevisionId = Guid.NewGuid() }, _ => r with { ContactRevisionNumber = 1 }
        };
        Assert.Throws<InvalidOperationException>(() => new SignerContactCorrectionBrowser(keys, clock)
            .Create(Principal, owner.PublicId, clock.Now.AddHours(2), new("Synthetic", r, null)));
    }

    [Theory][InlineData("statement")][InlineData("hash")][InlineData("unknown-field")]
    public void Previously_protected_wrong_statement_or_shape_is_not_current_review_authority(string kind)
    {
        var service = new SignerContactCorrectionBrowser(keys, clock); var until = clock.Now.AddHours(2);
        var saved = service.Read(service.Create(Principal, owner.PublicId, until, new("Synthetic", Review(), null)), Principal, owner.PublicId, until)!;
        var changed = kind == "statement" ? saved with { StatementVersion = "old" } : saved with { StatementSha256 = new('c', 64) };
        var json = JsonSerializer.Serialize(kind == "unknown-field" ? saved : changed);
        if (kind == "unknown-field") json = json[..^1] + ",\"unexpected\":true}";
        var proof = keys.CreateProtector("QuillSign.SenderContactCorrection.Review.v1").Protect(json);
        Assert.Null(service.Read(proof, Principal, owner.PublicId, until));
    }

    [Fact]
    public void Maximum_escaped_title_and_name_fit_the_bounded_body_and_blocked_review_never_mints()
    {
        var service = new SignerContactCorrectionBrowser(keys, clock); var until = clock.Now.AddHours(2);
        var preview = new SignerContactCorrectionPreview(new('\u263a', 512), Review() with { Name = new('\u263a', 512) }, null);
        var proof = service.Create(Principal, owner.PublicId, until, preview);
        Assert.InRange(proof.Length, 1, SignerContactCorrectionBrowser.MaximumProofLength);
        Assert.NotNull(service.Read(proof, Principal, owner.PublicId, until));
        Assert.Throws<InvalidOperationException>(() => service.Create(Principal, owner.PublicId, until, preview with { Blocked = SignerContactCorrectionOutcome.Closed }));
    }

    private sealed class Clock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
