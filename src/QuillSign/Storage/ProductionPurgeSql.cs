using System.Data;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Storage;

// Private bridge only. The authenticated external deletion scope is authority;
// a SQL absence/count/hash or procedure success never proves provider cleanup.
internal static class ProductionPurgeSql
{
    internal static readonly IReadOnlyList<string> Tables=Array.AsReadOnly(new[] {
        "AuditEvents","AuthTokens","CompletionCandidates","CompletionPublicationIntents","CompletionPublicationResults",
        "CompletionSealOutputs","DocumentRetentionSnapshots","EmailOutbox","Envelopes","Fields","LookupContactRetentionSnapshots",
        "ProductionHoldControls","ProductionHoldRequests","ProductionRetentionPolicies","ProductionRetentionTerminals","Recipients",
        "SignaturePreviews","SignerContactRevisions","SignerContactSessions","SignerFinishAcceptances","SignerReviewCandidates","Signers","WorkItems" });

    internal static async Task<bool> RemoveLockedAsync(QuillSignDbContext db,ProductionDeletionSqlScope scope,CancellationToken ct=default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        // Own mutable data BEFORE the first asynchronous demand.
        var version=scope.ParentRowVersion.ToArray();var lease=scope.Lease;
        var counts=new SortedDictionary<string,long>(StringComparer.Ordinal);
        foreach(var entry in scope.Counts)counts.Add(entry.Key,entry.Value);
        if(db.Database.CurrentTransaction is not{} transaction||db.ChangeTracker.HasChanges()||
            transaction.GetDbTransaction() is not SqlTransaction physical||physical.Connection is not{} connection||
            !ReferenceEquals(connection,db.Database.GetDbConnection())||lease.Kind!=WorkKind.ProductionPurge||
            scope.RecordId==Guid.Empty||scope.DeletionId==Guid.Empty||lease.Id==Guid.Empty||lease.Owner==Guid.Empty||lease.Attempt<1||
            version.Length!=8||scope.EligibleAt.Offset!=TimeSpan.Zero||!Hex(scope.PolicySha256)||!Hex(scope.PlanSha256)||
            !Hex(scope.StorageReceiptSha256)||!Hex(scope.SqlStateSha256)||!Hex(scope.ContentSha256)||
            scope.RequestRevision is <0 or >512||scope.Control.Sequence is <0 or >16384||
            (scope.RequestRevision==0?scope.FenceHash is not null:!Hex(scope.FenceHash))||
            (scope.Control.Sequence==0?scope.Control.Hash is not null:!Hex(scope.Control.Hash))||
            !Tables.SequenceEqual(counts.Keys)||counts.Values.Any(x=>x<0)||
            counts.Where(x=>x.Key!="ProductionHoldControls").Sum(x=>x.Value)>4096||counts["ProductionHoldControls"]>16384||
            counts["Envelopes"]!=1||counts["ProductionRetentionPolicies"]!=1||counts["DocumentRetentionSnapshots"]!=0||
            counts["ProductionHoldControls"]!=scope.Control.Sequence||counts["ProductionHoldRequests"]!=scope.RequestRevision)throw Invalid();
        var json=JsonSerializer.Serialize(counts);if(json.Length>4096)throw Invalid();
        await scope.DemandAsync(db,ct);
        if(!ReferenceEquals(db.Database.CurrentTransaction?.GetDbTransaction(),physical)||physical.Connection is null)throw Invalid();
        await using var command=connection.CreateCommand();command.Transaction=physical;command.CommandType=CommandType.StoredProcedure;
        command.CommandText="dbo.RemoveExpiredProductionPrivateRecords";command.CommandTimeout=60;
        command.Parameters.Add(new("@EnvelopeId",SqlDbType.UniqueIdentifier){Value=scope.RecordId});
        command.Parameters.Add(new("@DeletionId",SqlDbType.UniqueIdentifier){Value=scope.DeletionId});
        command.Parameters.Add(new("@WorkId",SqlDbType.UniqueIdentifier){Value=lease.Id});
        command.Parameters.Add(new("@Owner",SqlDbType.UniqueIdentifier){Value=lease.Owner});
        command.Parameters.Add(new("@Attempt",SqlDbType.Int){Value=lease.Attempt});
        command.Parameters.Add(new("@Until",SqlDbType.DateTimeOffset){Value=lease.Until});
        command.Parameters.Add(new("@ParentRowVersion",SqlDbType.VarBinary,8){Value=version});
        command.Parameters.Add(new("@PolicySha256",SqlDbType.VarChar,64){Value=scope.PolicySha256});
        command.Parameters.Add(new("@EligibleAt",SqlDbType.DateTimeOffset){Value=scope.EligibleAt});
        command.Parameters.Add(new("@RequestRevision",SqlDbType.BigInt){Value=scope.RequestRevision});
        command.Parameters.Add(new("@FenceHash",SqlDbType.VarChar,64){Value=(object?)scope.FenceHash??DBNull.Value});
        command.Parameters.Add(new("@ControlSequence",SqlDbType.BigInt){Value=scope.Control.Sequence});
        command.Parameters.Add(new("@ControlHash",SqlDbType.VarChar,64){Value=(object?)scope.Control.Hash??DBNull.Value});
        command.Parameters.Add(new("@CountsJson",SqlDbType.NVarChar,-1){Value=json});
        command.Parameters.Add(new("@PlanSha256",SqlDbType.VarChar,64){Value=scope.PlanSha256});
        command.Parameters.Add(new("@StorageReceiptSha256",SqlDbType.VarChar,64){Value=scope.StorageReceiptSha256});
        var removed=Convert.ToBoolean(await command.ExecuteScalarAsync(ct));
        await scope.DemandAsync(db,ct);
        if(!ReferenceEquals(db.Database.CurrentTransaction?.GetDbTransaction(),physical)||physical.Connection is null||db.ChangeTracker.HasChanges())throw Invalid();
        // Caller still owns the exact physical transaction, commit and unknown-ack reconciliation.
        return removed;
    }
    private static bool Hex(string? value)=>value is {Length:64}&&value.All(char.IsAsciiHexDigitLower);
    private static InvalidDataException Invalid()=>new("The current exact production deletion SQL scope is unavailable.");
}