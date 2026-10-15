using QuillSign.Data;

namespace QuillSign.Tests;

public sealed class AuditHashTests
{
    [Fact]
    public void PropertyOrderWhitespaceAndTimeZoneDoNotChangeTheCanonicalHash()
    {
        var audit = new AuditEvent
        {
            EnvelopeId = Guid.NewGuid(), Sequence = 1,
            At = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            Event = "created", DataJson = "{\"b\":{\"z\":2,\"a\":1},\"a\":true}"
        };
        var original = AuditHash.Compute(audit);
        audit.DataJson = "{ \"a\": true, \"b\": { \"a\":1, \"z\":2 } }";
        audit.At = audit.At.ToOffset(TimeSpan.FromHours(-5));
        Assert.Equal(original, AuditHash.Compute(audit));
        audit.PrevHash = new byte[32]; audit.PrevHash[0] = 1;
        Assert.NotEqual(original, AuditHash.Compute(audit));
        audit.Event = "modified";
        Assert.NotEqual(original, AuditHash.Compute(audit));
    }
}
