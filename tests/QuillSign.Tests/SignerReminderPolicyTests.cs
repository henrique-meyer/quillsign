using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class SignerReminderPolicyTests
{
    private static SignerReminderOptions Enabled(int[]? days = null) => new() {
        Enabled = true, Days = days ?? [3, 7], DailyRequests = 10, DailyAddressRequests = 2, DailySenderRequests = 4
    };

    [Fact]
    public void Default_off_and_demo_freeze_no_reminders_and_do_not_expose_mutable_configuration()
    {
        Assert.Empty(new SignerReminderOptions().Freeze(false).Days);
        var options = Enabled(); var policy = options.Freeze(false);
        Assert.Equal(new[] { 3, 7 }, policy.Days.ToArray()); Assert.Empty(options.Freeze(true).Days);
        options.Enabled = false; options.Days[0] = 1; options.Days = [2, 9];
        Assert.Equal(new[] { 3, 7 }, policy.Days.ToArray());
        Assert.Equal(policy.CanonicalJson, SignerReminderPolicy.Read(policy.CanonicalJson, policy.Sha256).CanonicalJson);
    }

    [Theory]
    [InlineData("[]")][InlineData("[1]")][InlineData("[3,7]")][InlineData("[1,30]")]
    public void Allowed_days_roundtrip_with_stable_canonical_hash(string days)
    {
        var values = System.Text.Json.JsonSerializer.Deserialize<int[]>(days)!;
        var policy = Enabled(values).Freeze(false);
        Assert.Equal("{\"version\":\"signer-reminder-policy-v1\",\"days\":" + days + "}", policy.CanonicalJson);
        Assert.Equal(Digest(policy.CanonicalJson), policy.Sha256);
        Assert.Equal(policy.Sha256, SignerReminderPolicy.Read(policy.CanonicalJson, policy.Sha256).Sha256);
    }

    public static TheoryData<int[]?> InvalidDays => new() { null, new[] { 0 }, new[] { -1 }, new[] { 31 }, new[] { 7, 3 }, new[] { 3, 3 }, new[] { 1, 2, 3 } };
    [Theory][MemberData(nameof(InvalidDays))]
    public void Invalid_configuration_cannot_be_frozen_even_when_disabled_or_demo(int[]? days)
    {
        var options = new SignerReminderOptions { Days = days! };
        Assert.Throws<InvalidOperationException>(() => options.Freeze(false));
        Assert.Throws<InvalidOperationException>(() => options.Freeze(true));
    }

    [Theory]
    [InlineData(null, 1, 1)][InlineData(0, 1, 1)][InlineData(1001, 1, 1)]
    [InlineData(2, null, 1)][InlineData(2, 1, null)][InlineData(2, 0, 1)]
    [InlineData(2, 1, 0)][InlineData(2, 3, 1)][InlineData(2, 1, 3)]
    public void Enabled_requires_explicit_bounded_daily_limits(int? global, int? sender, int? address)
    {
        var options = Enabled(); options.DailyRequests = global; options.DailySenderRequests = sender; options.DailyAddressRequests = address;
        Assert.Throws<InvalidOperationException>(() => options.Freeze(false));
        options.Enabled = false; Assert.Empty(options.Freeze(false).Days);
    }

    [Theory]
    [InlineData("[3,7]")]
    [InlineData("{\"version\":\"signer-reminder-policy-v1\",\"days\":[7,3]}")]
    [InlineData("{\"version\":\"signer-reminder-policy-v1\",\"days\":[3,3]}")]
    [InlineData("{\"version\":\"signer-reminder-policy-v1\",\"days\":[3.0,7]}")]
    [InlineData("{\"version\":\"signer-reminder-policy-v1\",\"days\":[\"3\",7]}")]
    [InlineData("{\"version\":\"signer-reminder-policy-v1\",\"days\":[3,7],\"days\":[3,7]}")]
    [InlineData("{\"version\":\"signer-reminder-policy-v1\",\"days\":[3,7],\"extra\":true}")]
    [InlineData("{\"version\":\"signer-reminder-policy-v2\",\"days\":[3,7]}")]
    [InlineData("{ \"version\":\"signer-reminder-policy-v1\",\"days\":[3,7]}")]
    [InlineData("{\"days\":[3,7],\"version\":\"signer-reminder-policy-v1\"}")]
    [InlineData("{\"version\":\"signer-reminder-policy-v1\",\"days\":null}")]
    [InlineData("null")][InlineData("{")]
    public void Reader_rejects_noncanonical_or_malformed_evidence_even_with_matching_hash(string text)
        => Assert.Throws<InvalidDataException>(() => SignerReminderPolicy.Read(text, Digest(text)));

    [Fact]
    public void Reader_rejects_wrong_hash_unknown_hash_encoding_and_oversized_payload()
    {
        var p = Enabled().Freeze(false);
        Assert.Throws<InvalidDataException>(() => SignerReminderPolicy.Read(p.CanonicalJson, new string('0', 64)));
        Assert.Throws<InvalidDataException>(() => SignerReminderPolicy.Read(p.CanonicalJson, p.Sha256.ToUpperInvariant()));
        Assert.Throws<InvalidDataException>(() => SignerReminderPolicy.Read(new string(' ', 257), p.Sha256));
    }

    private static readonly Guid Envelope = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Signer = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly Guid Invitation = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid Contact = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid Document = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly DateTimeOffset Anchor = new(2026, 3, 7, 23, 59, 0, TimeSpan.FromHours(-5));
    private static SignerReminderEpoch Epoch(DateTimeOffset? anchor = null, DateTimeOffset? end = null, DateTimeOffset? cutoff = null,
        Guid? envelope = null, Guid? signer = null, Guid? invitation = null, Guid? contact = null, Guid? document = null,
        string recipient = "signer@example.invalid", string? source = null, string? disclosure = null, SignerReminderPolicy? policy = null)
        => new(envelope ?? Envelope, signer ?? Signer, invitation ?? Invitation, contact ?? Contact, recipient, document ?? Document,
            source ?? new string('a', 64), disclosure ?? new string('b', 64), policy ?? Enabled().Freeze(false), anchor ?? Anchor, end, cutoff);

    [Fact]
    public void Schedule_uses_elapsed_utc_days_across_dst_and_equivalent_offsets_have_same_identity()
    {
        var p = Epoch(); var utc = Anchor.ToUniversalTime();
        Assert.Equal(utc.AddDays(3), p.Schedule[0].DueAt); Assert.Equal(utc.AddDays(7), p.Schedule[1].DueAt);
        Assert.All(p.Schedule, x => Assert.Equal(TimeSpan.Zero, x.DueAt.Offset));
        Assert.Equal(p.CanonicalJson, Epoch(utc).CanonicalJson); Assert.Equal(p.Schedule.ToArray(), Epoch(utc).Schedule.ToArray());
        Assert.NotEqual(p.Schedule[0].WorkId, p.Schedule[1].WorkId);
    }

    [Theory][InlineData(3, 0)][InlineData(4, 1)][InlineData(7, 1)][InlineData(8, 2)]
    public void Exact_signing_or_retention_cutoff_excludes_due_work(int days, int count)
    {
        Assert.Equal(count, Epoch(end: Anchor.AddDays(days)).Schedule.Length);
        Assert.Equal(count, Epoch(cutoff: Anchor.AddDays(days)).Schedule.Length);
        Assert.Equal(Math.Min(count, 1), Epoch(end: Anchor.AddDays(days), cutoff: Anchor.AddDays(5)).Schedule.Length);
    }

    [Fact]
    public void One_tick_after_a_due_time_is_eligible_but_one_tick_before_is_not()
    {
        var due = Anchor.AddDays(3);
        Assert.Single(Epoch(end: due.AddTicks(1)).Schedule);
        Assert.Empty(Epoch(end: due.AddTicks(-1)).Schedule);
        Assert.Single(Epoch(cutoff: due.AddTicks(1)).Schedule);
        Assert.Empty(Epoch(cutoff: due.AddTicks(-1)).Schedule);
    }

    [Fact]
    public void Each_later_signer_epoch_anchors_to_its_own_invitation_and_never_the_original_send()
    {
        var first = Epoch(); var second = Epoch(anchor: Anchor.AddDays(10), signer: Guid.NewGuid(), invitation: Guid.NewGuid());
        Assert.Equal(first.Schedule[0].DueAt.AddDays(10), second.Schedule[0].DueAt);
        Assert.NotEqual(first.Schedule[0].WorkId, second.Schedule[0].WorkId);
    }

    [Theory]
    [InlineData("envelope")][InlineData("signer")][InlineData("invitation")][InlineData("contact")][InlineData("document")]
    [InlineData("recipient")][InlineData("source")][InlineData("disclosure")][InlineData("policy")][InlineData("deadline")][InlineData("retention")]
    public void Identity_binds_every_scope_and_old_address_return_does_not_reuse_an_epoch(string change)
    {
        var p = Epoch();
        var changed = change switch {
            "envelope" => Epoch(envelope: Guid.NewGuid()), "signer" => Epoch(signer: Guid.NewGuid()),
            "invitation" => Epoch(invitation: Guid.NewGuid()), "contact" => Epoch(contact: Guid.NewGuid()),
            "document" => Epoch(document: Guid.NewGuid()), "recipient" => Epoch(recipient: "other@example.invalid"),
            "source" => Epoch(source: new string('c', 64)), "disclosure" => Epoch(disclosure: new string('d', 64)),
            "policy" => Epoch(policy: Enabled([3, 9]).Freeze(false)), "deadline" => Epoch(end: Anchor.AddDays(10)),
            _ => Epoch(cutoff: Anchor.AddDays(10))
        };
        Assert.NotEqual(p.Sha256, changed.Sha256); Assert.NotEqual(p.Schedule[0].WorkId, changed.Schedule[0].WorkId);
    }

    [Fact]
    public void Disabled_policy_has_no_schedules_and_bad_scope_or_deadline_cannot_create_work_identity()
    {
        Assert.Empty(Epoch(policy: Enabled().Freeze(true)).Schedule);
        Assert.Throws<ArgumentException>(() => Epoch(envelope: Guid.Empty));
        Assert.Throws<ArgumentException>(() => Epoch(contact: Guid.Empty));
        Assert.Throws<ArgumentException>(() => Epoch(document: Guid.Empty));
        Assert.Throws<ArgumentException>(() => Epoch(source: new string('A', 64)));
        Assert.Throws<ArgumentException>(() => Epoch(recipient: "Signer <signer@example.invalid>"));
        Assert.Throws<ArgumentException>(() => Epoch(recipient: "SIGNER@example.invalid"));
        Assert.Throws<ArgumentException>(() => Epoch(end: Anchor));
        Assert.Throws<ArgumentException>(() => Epoch(cutoff: Anchor.AddTicks(-1)));
        Assert.Throws<ArgumentOutOfRangeException>(() => Epoch(anchor: DateTimeOffset.MaxValue.AddDays(-2)));
    }

    [Fact]
    public void Process_culture_does_not_change_persisted_identity()
    {
        var p = Epoch(); var prior = CultureInfo.CurrentCulture;
        try { CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("ar-SA"); Assert.Equal(p.Schedule.ToArray(), Epoch().Schedule.ToArray()); }
        finally { CultureInfo.CurrentCulture = prior; }
    }
    private static string Digest(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
