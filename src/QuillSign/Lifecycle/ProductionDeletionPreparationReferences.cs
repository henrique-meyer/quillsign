using System.Text.Json;
using System.Text.Json.Serialization;
using QuillSign.Data;

namespace QuillSign.Lifecycle;

// Only a proven inert technical job is projected for the older business graph.
// The ORIGINAL full SQL snapshot, all rows, hashes and archive remain unchanged.
internal static class ProductionDeletionPreparationReferences
{
    internal static JsonDocument ProjectVerified(JsonElement sql,HoldWitnessState state)
    {
        var record=sql.GetProperty("RecordId").GetGuid();
        var tables=sql.GetProperty("Tables").EnumerateArray().ToDictionary(t=>t.GetProperty("Table").GetString()!,t=>t.GetProperty("Rows"));
        var rows=tables["WorkItems"].EnumerateArray().Where(r=>r.GetProperty("Kind").GetString()=="ProductionPurge").ToArray();
        if(rows.Length==0)return JsonDocument.Parse(sql.GetRawText());
        var deletion=ProductionDeletionCoordinator.DeletionId(record);var work=ProductionDeletionCoordinator.WorkId(record,deletion);
        var operation=ProductionDeletionCoordinator.PreparationOperationId(record);
        if(rows.Length!=1||state.Deletion?.Reserved==true||state.Operations?.GetValueOrDefault(operation) is not{} original||
            original.Kind!="maintenance/production-deletion-prepare"||original.Reference!=deletion.ToString("N")||state.Outcomes?.ContainsKey(operation)!=true||
            !state.SettledOperations.TryGetValue(operation,out var receipt)||receipt!=ProductionDeletionCoordinator.PreparationReceipt(record))throw ProductionDeletionProtocol.Invalid();
        var row=rows[0];var e=tables["Envelopes"].EnumerateArray().Single();var policy=tables["ProductionRetentionPolicies"].EnumerateArray().Single();
        var saved=ProductionRetentionPolicyContract.Read(policy.GetProperty("PolicyJson").GetString()!,policy.GetProperty("PolicySha256").GetString()!);
        var eligible=e.GetProperty("Status").GetString()=="Draft"?ProductionRetentionPolicyContract.AddDays(policy.GetProperty("OriginalCreatedAt").GetDateTimeOffset(),saved.Policy.AbandonedDraftDays):
            e.GetProperty("PurgeAfter").ValueKind==JsonValueKind.String?e.GetProperty("PurgeAfter").GetDateTimeOffset():throw ProductionDeletionProtocol.Invalid();
        if(saved.RecordId!=record||saved.CreatedAt!=ProductionRetentionLedger.Seconds(policy.GetProperty("OriginalCreatedAt").GetDateTimeOffset())||
            policy.GetProperty("OriginalCreatedAt").GetDateTimeOffset()!=e.GetProperty("CreatedAt").GetDateTimeOffset()||e.GetProperty("Id").GetGuid()!=record||e.GetProperty("IsDemo").GetBoolean()||row.GetProperty("Id").GetGuid()!=work||
            row.GetProperty("EnvelopeId").GetGuid()!=record||row.GetProperty("Status").GetString()!="Queued"||row.GetProperty("Attempts").GetInt32()!=0||
            row.GetProperty("LeaseOwner").ValueKind!=JsonValueKind.Null||row.GetProperty("LeaseExpiresAt").ValueKind!=JsonValueKind.Null||
            row.GetProperty("LastError").ValueKind!=JsonValueKind.Null||row.GetProperty("AvailableAt").GetDateTimeOffset()!=eligible||
            row.GetProperty("PayloadJson").GetString()!=ProductionDeletionProtocol.Payload(record,deletion))throw ProductionDeletionProtocol.Invalid();
        using var bytes=new MemoryStream();using(var writer=new Utf8JsonWriter(bytes)){
            writer.WriteStartObject();foreach(var property in sql.EnumerateObject()){
                writer.WritePropertyName(property.Name);if(property.Name!="Tables"){writer.WriteRawValue(property.Value.GetRawText());continue;}
                writer.WriteStartArray();foreach(var table in property.Value.EnumerateArray()){
                    if(table.GetProperty("Table").GetString()!="WorkItems"){writer.WriteRawValue(table.GetRawText());continue;}
                    writer.WriteStartObject();foreach(var part in table.EnumerateObject()){
                        writer.WritePropertyName(part.Name);if(part.Name!="Rows"){writer.WriteRawValue(part.Value.GetRawText());continue;}
                        writer.WriteStartArray();foreach(var kept in part.Value.EnumerateArray())if(kept.GetProperty("Id").GetGuid()!=work)writer.WriteRawValue(kept.GetRawText());writer.WriteEndArray();
                    }writer.WriteEndObject();
                }writer.WriteEndArray();
            }writer.WriteEndObject();
        }return JsonDocument.Parse(bytes.ToArray());
    }
}
