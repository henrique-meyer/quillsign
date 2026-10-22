using System.Data;
using System.Text;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Email.Pilot;

namespace QuillSign.Data;

// Fixed factual projections shared by the authenticated live receipt and later
// due cleanup. No caller SQL, column schema, path or provider callback exists.
internal static class HostedCloseoutReceiptState
{
    internal static string HeaderHash(EmailPilotCloseoutHeaderRecord h)=>Convert.ToHexStringLower(EmailPilotCanonical.Hash(new {
        h.Id,h.CreatedAt,h.Until,h.DeleteAfter,h.CapabilitySha256,h.ManifestSha256}));
    internal static string OperationsHash(EmailPilotCloseoutOperationRecord[] rows)=>Convert.ToHexStringLower(EmailPilotCanonical.Hash(
        rows.OrderBy(x=>x.Id.ToString("N"),StringComparer.Ordinal).ToArray()));
    internal static async Task<EmailPilotCloseoutOperationRecord[]> OperationsAsync(QuillSignDbContext db,Guid id,CancellationToken ct)
    {
        _=Transaction(db);var rows=await db.EmailPilotCloseoutOperations.AsNoTracking().Where(x=>x.CloseoutId==id).Take(15).ToArrayAsync(ct);
        if(rows.Length>14||rows.Any(x=>x.ProtectedReceipt.Length>8192||x.RequestSha256.Length!=32))throw Invalid();return rows;
    }
    internal static SqlTransaction Transaction(QuillSignDbContext db)
    {
        if(db.Database.CurrentTransaction?.GetDbTransaction() is not SqlTransaction tx||tx.Connection is null||tx.IsolationLevel!=IsolationLevel.Serializable||
            !ReferenceEquals(tx.Connection,db.Database.GetDbConnection())||tx.Connection.State!=ConnectionState.Open||db.ChangeTracker.HasChanges())throw Invalid();
        return tx;
    }
    internal static async Task<(string Mail,string Work)> OriginalsAsync(QuillSignDbContext db,Guid[] ids,CancellationToken ct)
        =>(await FingerprintAsync(db,10,ids,6,ct),await FingerprintAsync(db,11,ids,6,ct));
    internal static async Task<string> OriginalAccountingAsync(QuillSignDbContext db,Guid[] ids,CancellationToken ct)
    {
        if(ids.Length!=5||ids.Any(x=>x==Guid.Empty)||ids.Distinct().Count()!=5)throw Invalid();_=Transaction(db);
        var known=await db.EmailPilotRuns.AsNoTracking().Select(x=>x.Id).Take(9).ToArrayAsync(ct);
        if(!known.ToHashSet().SetEquals(ids))throw Invalid();
        var runs=await FingerprintAsync(db,2,ids,5,ct);var reservations=await FingerprintAsync(db,5,ids,20,ct);
        return Convert.ToHexStringLower(EmailPilotCanonical.Hash(new{Version="closeout-original-accounting-v1",Runs=runs,Reservations=reservations}));
    }
    private static async Task<string> FingerprintAsync(QuillSignDbContext db,int index,Guid[] ids,int count,CancellationToken ct)
    {
        var parent=index is 2 or 5;var idCount=parent?5:6;
        if(index is not(2 or 5 or 10 or 11)||ids.Length!=idCount||ids.Any(x=>x==Guid.Empty)||ids.Distinct().Count()!=idCount)throw Invalid();
        var tx=Transaction(db);
        {
            var schema=HostedCloseoutStoredStateFingerprint.Schema(index);
            await using var command=HostedCloseoutStateVerification.Command(tx.Connection!,HostedCloseoutStateVerification.Query(index),tx);
            for(var n=0;n<idCount;n++)command.Parameters.Add((parent?"@p":"@w")+n,SqlDbType.UniqueIdentifier).Value=ids[n];
            await using var reader=await command.ExecuteReaderAsync(CommandBehavior.SequentialAccess,ct);
            if(reader.FieldCount!=schema.Columns.Length)throw Invalid();
            var rows=new List<IReadOnlyList<object?>>();
            while(await reader.ReadAsync(ct)) {
                if(rows.Count>=count)throw Invalid();var values=new object?[reader.FieldCount];
                for(var n=0;n<values.Length;n++) {
                    if(reader.GetName(n)!=schema.Columns[n].Name||reader.GetDataTypeName(n)!=schema.Columns[n].SqlType)throw Invalid();
                    if(await reader.IsDBNullAsync(n,ct)){values[n]=null;continue;}
                    if(schema.Columns[n].SqlType=="nvarchar") {
                        var length=reader.GetChars(n,0,null,0,0);if(length>HostedCloseoutStoredStateFingerprint.MaximumCellBytes/2)throw Invalid();
                        var data=new char[(int)length];if(reader.GetChars(n,0,data,0,data.Length)!=length)throw Invalid();values[n]=new string(data);
                    } else if(schema.Columns[n].SqlType is "varbinary" or "timestamp") {
                        var length=reader.GetBytes(n,0,null,0,0);if(length>HostedCloseoutStoredStateFingerprint.MaximumCellBytes)throw Invalid();
                        var data=new byte[(int)length];if(reader.GetBytes(n,0,data,0,data.Length)!=length)throw Invalid();values[n]=data;
                    } else values[n]=reader.GetValue(n);
                }
                rows.Add(values);
            }
            if(rows.Count!=count)throw Invalid();return HostedCloseoutStoredStateFingerprint.Compute(index,rows).Sha256.ToLowerInvariant();
        }
    }
    internal static async Task<DateTimeOffset> DatabaseUtcAsync(QuillSignDbContext db,CancellationToken ct)
    {
        var tx=Transaction(db);await using var cmd=HostedCloseoutStateVerification.Command(tx.Connection!,"SELECT SYSUTCDATETIME()",tx);
        return await cmd.ExecuteScalarAsync(ct) is DateTime utc?new(DateTime.SpecifyKind(utc,DateTimeKind.Utc)):throw Invalid();
    }
    internal static InvalidDataException Invalid()=>new("The exact committed closeout receipt is unavailable.");
}
