using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class SignerContactHistoryTests
{
    [Fact]
    public void Legacy_history_preserves_roster_and_never_mutates_its_input()
    {
        var f = new Fixture(); var original = f.Original.ToArray();
        Assert.Equal(original, SignerContactHistory.Verify(f.Scope, f.Original, [], f.Original));
        Assert.Equal(original, f.Original);
    }

    [Fact]
    public void Address_cycle_keeps_distinct_epochs_and_missing_history_cannot_look_legacy()
    {
        var f = new Fixture(); var first = f.Revision(); var second = f.Revision(first, f.Original[0].Email);
        var current = f.Current(second); var events = new[] { f.Event(first), f.Event(second, 12) };
        var result = SignerContactHistory.Verify(f.Scope, f.Original, events, current);
        Assert.Equal(f.Original[0].Email, result[0].Email);
        Assert.NotEqual(first.Id, result[0].Epoch.RevisionId); Assert.NotEqual(SignerContactEpoch.Legacy, result[0].Epoch);
        Assert.Equal(2, result[0].Epoch.Number); Assert.Equal(f.Original[1], result[1]);
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [], current));
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, events, f.Original));
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [events[1]], current));
    }

    [Fact]
    public void Different_slot_revisions_fold_independently_in_global_audit_order()
    {
        var f = new Fixture(); var first = f.Revision(); var other = f.Revision() with
        { SignerId = f.Original[1].Id, OldEmail = f.Original[1].Email, NewEmail = Address("third"), ChangedAt = f.Scope.SentAt.AddMinutes(2) };
        var current = f.Current(first); current[1] = current[1] with { Email = other.NewEmail, Epoch = new(other.Id, 1) };
        Assert.Equal(current, SignerContactHistory.Verify(f.Scope, f.Original, [f.Event(first), f.Event(other, 13)], current));
    }

    [Theory]
    [InlineData("same-address")]
    [InlineData("mixed-case")]
    [InlineData("display-address")]
    [InlineData("duplicate-address")]
    [InlineData("empty-command")]
    [InlineData("cross-envelope")]
    [InlineData("other-slot")]
    [InlineData("branch")]
    [InlineData("missing-predecessor")]
    [InlineData("wrong-previous-hash")]
    [InlineData("wrong-envelope-version")]
    [InlineData("wrong-signer-version")]
    [InlineData("expired-ticket")]
    [InlineData("wrong-source-hash")]
    [InlineData("wrong-disclosure-hash")]
    [InlineData("wrong-retirement-hash")]
    [InlineData("wrong-statement")]
    [InlineData("wrong-statement-hash")]
    [InlineData("non-utc")]
    [InlineData("before-sent")]
    [InlineData("future")]
    public void Self_consistent_but_semantically_invalid_revision_is_rejected(string change)
    {
        var f = new Fixture(); var r = f.Revision(); var bad = change switch
        {
            "same-address" => r with { NewEmail = r.OldEmail },
            "mixed-case" => r with { NewEmail = r.NewEmail.ToUpperInvariant() },
            "display-address" => r with { NewEmail = "Someone <" + r.NewEmail + ">" },
            "duplicate-address" => r with { NewEmail = f.Original[1].Email },
            "empty-command" => r with { Id = Guid.Empty },
            "cross-envelope" => r with { EnvelopeId = Guid.NewGuid() },
            "other-slot" => r with { SignerId = Guid.NewGuid() },
            "branch" => r with { OldEmail = Address("unrelated") },
            "missing-predecessor" => r with { Number = 2 },
            "wrong-previous-hash" => r with { PreviousCorrectionSha256 = Hash("unrelated") },
            "wrong-envelope-version" => r with { ReviewedEnvelopeVersion = "not-version" },
            "wrong-signer-version" => r with { ReviewedSignerVersion = "not-version" },
            "expired-ticket" => r with { SenderTicketExpiresAt = r.ChangedAt },
            "wrong-source-hash" => r with { DocumentSha256 = "0" },
            "wrong-disclosure-hash" => r with { DisclosureSha256 = "0" },
            "wrong-retirement-hash" => r with { RetirementSha256 = "0" },
            "wrong-statement" => r with { StatementVersion = "unrecognized" },
            "wrong-statement-hash" => r with { StatementSha256 = Hash("unrelated") },
            "non-utc" => r with { ChangedAt = r.ChangedAt.ToOffset(TimeSpan.FromHours(1)) },
            "before-sent" => r with { ChangedAt = f.Scope.SentAt.AddTicks(-1) },
            "future" => r with { ChangedAt = f.Scope.Now.AddTicks(1) },
            _ => throw new InvalidOperationException()
        };
        var entry = f.EventUnchecked(bad);
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [entry], f.Current(bad)));
    }

    [Theory]
    [InlineData("actor")]
    [InlineData("party")]
    [InlineData("actor-id")]
    [InlineData("event")]
    [InlineData("time")]
    [InlineData("sequence")]
    [InlineData("hash")]
    [InlineData("extra-json")]
    [InlineData("duplicate-json")]
    [InlineData("whitespace")]
    [InlineData("invalid-json")]
    [InlineData("oversized-json")]
    [InlineData("predecessor-length")]
    public void Invalid_canonical_event_or_audit_binding_is_rejected(string change)
    {
        var f = new Fixture(); var r = f.Revision(); var e = f.Event(r);
        switch (change)
        {
            case "actor": e.ActorEmail = Address("unrelated"); break;
            case "party": e.ActorType = PartyType.System; break;
            case "actor-id": e.ActorId = r.SignerId; break;
            case "event": e.Event = "sent"; break;
            case "time": e.At = e.At.AddTicks(1); break;
            case "sequence": e.Sequence = f.Scope.SentSequence; break;
            case "hash": e.Hash = RandomNumberGenerator.GetBytes(32); break;
            case "extra-json": var node = JsonNode.Parse(e.DataJson)!; node["unexpected"] = true; e.DataJson = node.ToJsonString(); break;
            case "duplicate-json": e.DataJson = e.DataJson[..^1] + ",\"number\":1}"; break;
            case "whitespace": e.DataJson = " " + e.DataJson; break;
            case "invalid-json": e.DataJson = "{"; break;
            case "oversized-json": e.DataJson = JsonSerializer.Serialize(new { text = new string('x', 8193) }); break;
            case "predecessor-length": e.PrevHash = [1]; break;
        }
        if (change is not ("hash" or "invalid-json")) e.Hash = AuditHash.Compute(e);
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [e], f.Current(r)));
    }

    [Fact]
    public void Duplicate_reordered_branched_and_missing_middle_events_are_rejected()
    {
        var f = new Fixture(); var first = f.Revision(); var second = f.Revision(first, Address("later"));
        var last = f.Revision(second, Address("last")); var events = new[] { f.Event(first), f.Event(second, 12), f.Event(last, 13) };
        var current = f.Current(last);
        Assert.Equal(current, SignerContactHistory.Verify(f.Scope, f.Original, events, current));
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [events[1], events[0], events[2]], current));
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [events[0], events[0], events[2]], current));
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [events[0], events[2]], current));
        var branch = second with { Id = first.Id }; var bad = f.EventUnchecked(branch, 12);
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [events[0], bad], f.Current(branch)));
    }

    [Fact]
    public void Effective_roster_cannot_change_names_roles_order_or_signing_slot_identity()
    {
        var f = new Fixture(); var r = f.Revision(); var current = f.Current(r);
        foreach (var changed in new[] { current[0] with { Name = "Other person" }, current[0] with { Role = "Other role" },
                     current[0] with { Id = Guid.NewGuid() }, current[0] with { Order = 2 }, current[0] with { Epoch = new(Guid.NewGuid(), 1) } })
        {
            var bad = current.ToArray(); bad[0] = changed;
            Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [f.Event(r)], bad));
        }
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, [f.Event(r)], current.Reverse().ToArray()));
    }

    [Fact]
    public void History_and_roster_bounds_are_enforced_before_enumeration()
    {
        var f = new Fixture(); var r = f.Revision();
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, [], [], []));
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, Enumerable.Repeat(f.Original[0], 101).ToArray(), [], Enumerable.Repeat(f.Original[0], 101).ToArray()));
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, f.Original, Enumerable.Repeat(f.Event(r), 101).ToArray(), f.Current(r)));
        var duplicate = f.Original.ToArray(); duplicate[1] = duplicate[1] with { Email = duplicate[0].Email };
        Assert.Throws<InvalidDataException>(() => SignerContactHistory.Verify(f.Scope, duplicate, [], duplicate));
    }

    private static string Address(string local) => local + "@" + "example.invalid";
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private sealed class Fixture
    {
        internal SignerContactScope Scope { get; } = new(Guid.NewGuid(), Address("sender"), 10,
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2026, 1, 1, 2, 0, 0, TimeSpan.Zero));
        internal SignerContactParty[] Original { get; } = [new(Guid.NewGuid(), 1, "Synthetic signer", Address("original"), "Role", SignerContactEpoch.Legacy),
            new(Guid.NewGuid(), 2, "Other synthetic signer", Address("other"), null, SignerContactEpoch.Legacy)];
        internal SignerContactRevision Revision(SignerContactRevision? previous = null, string? email = null) => new(SignerContactHistory.Version,
            Guid.NewGuid(), Scope.EnvelopeId, Original[0].Id, previous?.Id ?? Guid.Empty, (previous?.Number ?? 0) + 1,
            previous?.NewEmail ?? Original[0].Email, email ?? Address("corrected"), (previous?.ChangedAt ?? Scope.SentAt).AddMinutes(1), Scope.Now,
            Convert.ToBase64String(new byte[8]), Convert.ToBase64String(new byte[8]), Guid.NewGuid(), Hash("source"), Hash("disclosure"), Hash("retired"),
            previous is null ? null : SignerContactHistory.Digest(previous), SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
        internal AuditEvent Event(SignerContactRevision r, long sequence = 11)
        { var e = EventUnchecked(r, sequence); Assert.Equal(SignerContactHistory.Canonical(r), e.DataJson); return e; }
        internal AuditEvent EventUnchecked(SignerContactRevision r, long sequence = 11)
        {
            var e = new AuditEvent { EnvelopeId = Scope.EnvelopeId, Sequence = sequence, At = r.ChangedAt,
                ActorType = PartyType.Sender, ActorEmail = Scope.SenderEmail, Event = SignerContactHistory.Event,
                DataJson = JsonSerializer.Serialize(r, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase }), PrevHash = new byte[32] };
            e.Hash = AuditHash.Compute(e); return e;
        }
        internal SignerContactParty[] Current(SignerContactRevision r) => [Original[0] with { Email = r.NewEmail, Epoch = new(r.Id, r.Number) }, Original[1]];
    }
}
