using System.Security.Cryptography;
using System.Text.Json;

namespace QuillSign.Lifecycle;

internal enum ProductionHoldOperation { Place, Release }

// Private command material. Never include the reason, reference or operator subject
// in a participant-visible audit payload or publication recipe.
internal sealed record ProductionHoldCommand(Guid CommandId, Guid RecordId, Guid HoldId, long ExpectedRevision,
    ProductionHoldOperation Operation, string Purpose, string Reason, string Reference)
{
    internal const string Version = "production-hold-command-v1";
    internal ProductionOperatorPermission Permission => Operation switch
    {
        ProductionHoldOperation.Place => ProductionOperatorPermission.PlaceHold,
        ProductionHoldOperation.Release => ProductionOperatorPermission.ReleaseHold,
        _ => throw new InvalidDataException("Invalid production hold operation.")
    };

    // The future protected one-use confirmation and durable receipt must bind this
    // digest plus the exact operator and expiry. A digest alone grants no authority.
    internal string Digest()
    {
        if (CommandId == Guid.Empty || RecordId == Guid.Empty || HoldId == Guid.Empty || ExpectedRevision < 0 ||
            ExpectedRevision == long.MaxValue || !Enum.IsDefined(Operation) ||
            Operation == ProductionHoldOperation.Release && ExpectedRevision == 0 ||
            !ProductionOperatorAuthority.Text(Purpose, 256) || !ProductionOperatorAuthority.Text(Reason, 2048) ||
            !ProductionOperatorAuthority.Text(Reference, 512)) throw new InvalidDataException("Invalid production hold command.");
        return Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
            { Version, CommandId, RecordId, HoldId, ExpectedRevision, Operation, Purpose, Reason, Reference })));
    }
}
