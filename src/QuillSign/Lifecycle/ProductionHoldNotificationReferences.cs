using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

// Closed dispatch registry: adding an owned template must add historical
// reference coverage here. Global lookup/simulator work is not record evidence.
internal static class ProductionHoldNotificationReferences
{
    internal static void Demand(JsonElement sql, IReadOnlyList<HoldObjectEvidence> objects, IDataProtectionProvider keys)
    {
        try
        {
            var id = sql.GetProperty("RecordId").GetGuid();
            var rows = sql.GetProperty("Tables").EnumerateArray().Single(x => x.GetProperty("Table").GetString() == "EmailOutbox").GetProperty("Rows");
            if (id == Guid.Empty || rows.GetArrayLength() > 4096) throw Invalid();
            var identities = new HashSet<Guid>();
            foreach (var row in rows.EnumerateArray())
            {
                var mailId = row.GetProperty("Id").GetGuid();
                if (mailId == Guid.Empty || !identities.Add(mailId) || row.GetProperty("EnvelopeId").GetGuid() != id) throw Invalid();
                // Each arm maps to the actual verifier below, rather than an
                // open-ended list of names accepted without a payload codec.
                _ = row.GetProperty("Template").GetString() switch
                {
                    "signer-invitation" or InvitationResendProtection.Template or InvitationSuccessorProtection.Template => 1,
                    "sender-verification" or "signer-declined" => 2,
                    CompletionNotificationJobs.Template => 3,
                    VoidNotificationJobs.Template => 4,
                    _ => throw Invalid()
                };
            }
            ProductionHoldInvitationReferences.Demand(sql, objects, keys);
            ProductionHoldDecisionNotificationReferences.Demand(sql, objects, keys);
            ProductionHoldCompletionNotificationReferences.Demand(sql, objects, keys);
            ProductionHoldVoidNotificationReferences.Demand(sql, objects, keys);
        }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or ArgumentException or FormatException)
        { throw Invalid(); }
    }
    private static InvalidDataException Invalid() => new("The owned notification reference coverage could not be verified.");
}
