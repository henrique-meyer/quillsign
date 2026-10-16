using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using QuillSign.Legal;

namespace QuillSign.Tests;

public sealed class ElectronicRecordDisclosureTests
{
    private const string Id = "11111111111111111111111111111111";
    [Fact]
    public void Versioned_snapshot_has_stable_canonical_bytes_context_and_hash_without_changing_options()
    {
        var options = Policy(); var before = JsonSerializer.Serialize(options);
        var disclosure = new ElectronicRecordDisclosure(options);
        var snapshot = disclosure.Build(Id,"  Cafe\u0301 synthetic agreement  "," SENDER@EXAMPLE.INVALID ");
        Assert.Equal("2026-10-16.1",snapshot.Version); Assert.Equal("Café synthetic agreement",snapshot.Title);
        Assert.Equal("sender@example.invalid",snapshot.SenderContact); Assert.Equal(Id,snapshot.PublicId);
        Assert.DoesNotContain('\r',snapshot.Text); Assert.EndsWith("\n",snapshot.Text); Assert.True(ElectronicRecordDisclosure.Verify(snapshot));
        Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(snapshot.Text)),snapshot.Sha256);
        // Changing the versioned template requires an intentional version/golden update.
        Assert.Equal("72eaa5b9b332b22b9cda8611c171c7fed024381d9efc838c8402e8a0b8e21782",Convert.ToHexStringLower(snapshot.Sha256));
        Assert.Equal(before,JsonSerializer.Serialize(options));
        options.PaperCopyInstructions = "  Synthetic paper procedure.\r\n ";
        var equivalent = disclosure.Build(Id,"Café synthetic agreement","sender@example.invalid");
        Assert.Equal(snapshot.Text,equivalent.Text); Assert.Equal(snapshot.Sha256,equivalent.Sha256);
    }

    [Fact]
    public void Stored_snapshot_verification_binds_version_envelope_title_contact_and_exact_text()
    {
        var snapshot = Build();
        foreach (var tampered in new[] { snapshot with { Text = snapshot.Text + "changed" }, snapshot with { Version = "changed" },
            snapshot with { PublicId = new string('2',32) }, snapshot with { Title = "Changed title" },
            snapshot with { SenderContact = "other@example.invalid" }, snapshot with { Sha256 = new byte[31] },
            snapshot with { Text = snapshot.Text + "\ud800" } }) Assert.False(ElectronicRecordDisclosure.Verify(tampered));
        // Verification of a stored older version is independent of today's mutable template/policy.
        var olderText = snapshot.Text.Replace("Version: 2026-10-16.1\n","Version: earlier-version\n",StringComparison.Ordinal);
        var older = snapshot with { Version = "earlier-version",Text = olderText,Sha256 = SHA256.HashData(Encoding.UTF8.GetBytes(olderText)) };
        Assert.True(ElectronicRecordDisclosure.Verify(older));
        Assert.False(ElectronicRecordDisclosure.Verify(null));
    }

    [Fact]
    public void Each_context_or_policy_change_produces_a_different_bound_hash()
    {
        var original = Build();
        var options = Policy(); options.PaperCopyFees += " Changed.";
        foreach (var changed in new[] {
            new ElectronicRecordDisclosure(Policy()).Build(new string('2',32),original.Title,original.SenderContact),
            new ElectronicRecordDisclosure(Policy()).Build(Id,"Changed title",original.SenderContact),
            new ElectronicRecordDisclosure(Policy()).Build(Id,original.Title,"other@example.invalid"),
            new ElectronicRecordDisclosure(options).Build(Id,original.Title,original.SenderContact) })
        { Assert.NotEqual(original.Sha256,changed.Sha256); Assert.True(ElectronicRecordDisclosure.Verify(changed)); }
    }

    [Fact]
    public void Inserted_title_and_policy_placeholders_or_markup_remain_literal_in_a_single_pass()
    {
        var options = Policy(); options.PaperCopyInstructions = "Literal {{version}} <script>synthetic</script>";
        var snapshot = new ElectronicRecordDisclosure(options).Build(Id,"{{sender_contact}}","sender@example.invalid");
        Assert.Contains("Document: {{sender_contact}}\n",snapshot.Text);
        Assert.Contains("Literal {{version}} <script>synthetic</script>",snapshot.Text);
        Assert.True(ElectronicRecordDisclosure.Verify(snapshot)); // This is plain text; future UI must encode it.
    }

    [Theory]
    [InlineData(nameof(ElectronicRecordOptions.PaperCopyInstructions))]
    [InlineData(nameof(ElectronicRecordOptions.PaperCopyFees))]
    [InlineData(nameof(ElectronicRecordOptions.WithdrawalInstructions))]
    [InlineData(nameof(ElectronicRecordOptions.WithdrawalConsequences))]
    [InlineData(nameof(ElectronicRecordOptions.ContactUpdateInstructions))]
    [InlineData(nameof(ElectronicRecordOptions.AccessRequirements))]
    [InlineData(nameof(ElectronicRecordOptions.RetentionNotice))]
    public void Missing_oversized_or_hidden_control_policy_is_rejected_instead_of_supplying_promises(string name)
    {
        foreach (var value in new[] { "", " ", new string('x',4001), "bad\0value", "\ttrimmed control", "hidden\u202evalue", "\ud800" })
        {
            var options = Policy(); typeof(ElectronicRecordOptions).GetProperty(name)!.SetValue(options,value);
            Assert.Throws<DisclosureRejectedException>(() => new ElectronicRecordDisclosure(options).Build(Id,"Synthetic agreement","sender@example.invalid"));
        }
        Assert.Throws<DisclosureRejectedException>(() => new ElectronicRecordDisclosure(new()).Build(Id,"Synthetic agreement","sender@example.invalid"));
    }

    [Theory]
    [InlineData(null,"Title","sender@example.invalid")]
    [InlineData("bad","Title","sender@example.invalid")]
    [InlineData(Id,null,"sender@example.invalid")]
    [InlineData(Id,"Title\nnext line","sender@example.invalid")]
    [InlineData(Id,"\tTitle","sender@example.invalid")]
    [InlineData(Id,"Title",null)]
    [InlineData(Id,"Title","not an address")]
    public void Invalid_context_is_rejected(string? publicId,string? title,string? contact) =>
        Assert.Throws<DisclosureRejectedException>(() => new ElectronicRecordDisclosure(Policy()).Build(publicId,title,contact));

    internal static DisclosureSnapshot Build() => new ElectronicRecordDisclosure(Policy()).Build(Id,"Café synthetic agreement","sender@example.invalid");
    internal static ElectronicRecordOptions Policy() => new()
    {
        PaperCopyInstructions = "Synthetic paper procedure.", PaperCopyFees = "Synthetic copy fee policy.",
        WithdrawalInstructions = "Synthetic withdrawal procedure.", WithdrawalConsequences = "Synthetic withdrawal consequences and fees.",
        ContactUpdateInstructions = "Synthetic contact update procedure.", AccessRequirements = "Synthetic browser, PDF, email and retention requirements.",
        RetentionNotice = "Synthetic retention notice."
    };
}
