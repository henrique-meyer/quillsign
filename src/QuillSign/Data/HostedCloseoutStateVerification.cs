using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.SqlClient;

namespace QuillSign.Data;

internal sealed record HostedCloseoutExpectedSet(int Index,string SchemaSha256,string Sha256,int Count);
internal sealed record HostedCloseoutVerificationConfiguration(string Version,Guid VerificationRunId,string SourceRevision,string ApplicationSha256,
    string Server,string Database,Guid RuntimeClientId,Guid WorkerClientId,string RuntimeSqlSid,string WorkerSqlSid,
    Guid[] ParentRunIds,Guid[] EnvelopeIds,Guid[] OriginalWorkIds,HostedCloseoutExpectedSet[] ExpectedSets,string VisibleSchemaSha256);
internal sealed record HostedCloseoutVerificationSetResult(int Index,int Count,string Sha256);

// SELECT-only factual inspection. These hashes never decrypt a manifest or admit
// an operation. Actual Create still authenticates current DP/source authority.
internal static class HostedCloseoutStateVerification
{
    internal static readonly int[] SetIndices=[1,2,3,4,5,7,8,9,10,11,13,14,15,16,17,18,19];
    internal const int MaximumBytes=16*1024*1024;
    private static readonly string[] ImmutableTables=["AuditEvents","DocumentRetentionSnapshots","LookupContactRetentionSnapshots","SignerContactRevisions","SignerContactSessions",
        "EmailPilotRuns","EmailPilotSecrets","EmailPilotEnrollments","EmailPilotReservations","EmailPilotLookupRequests","EmailPilotLookupTokens",
        "EmailPilotCloseouts","EmailPilotCloseoutOperations","CompletionCandidates","CompletionSealOutputs","CompletionPublicationIntents","CompletionPublicationResults"];
    internal static async Task DemandCallerAsync(SqlConnection connection,HostedCloseoutVerificationConfiguration cfg,bool worker,CancellationToken ct,SqlTransaction? transaction=null)
    {
        await using(var command=Command(connection,"SELECT USER_NAME(),p.[type],p.[sid],DB_NAME() FROM sys.database_principals p WHERE p.principal_id=USER_ID()",transaction)) {
            await using var reader=await command.ExecuteReaderAsync(ct);
            if(!await reader.ReadAsync(ct)||reader.IsDBNull(0)||reader.IsDBNull(1)||reader.IsDBNull(2)||reader.IsDBNull(3)||
                reader.GetString(0)!=(worker?"app_worker":"app_runtime")||reader.GetString(1)!="E"||
                !CryptographicOperations.FixedTimeEquals((byte[])reader.GetValue(2),Convert.FromBase64String(worker?cfg.WorkerSqlSid:cfg.RuntimeSqlSid))||
                !string.Equals(reader.GetString(3),cfg.Database,StringComparison.Ordinal)||await reader.ReadAsync(ct))throw Invalid();
        }
        await DemandPermissionsAsync(connection,worker,ct,transaction);
    }
    internal static async Task DemandPermissionsAsync(SqlConnection connection,bool worker,CancellationToken ct,SqlTransaction? transaction=null)
    {
        foreach(var table in ImmutableTables)foreach(var permission in new[]{"SELECT","INSERT","UPDATE","DELETE","ALTER"})
            await Permission(connection,"dbo."+table,permission,null,permission is "SELECT" or "INSERT"?1:0,ct,transaction);
        foreach(var permission in new[]{"SELECT","INSERT","UPDATE","DELETE","ALTER"})
            await Permission(connection,"dbo.__EFMigrationsHistory",permission,null,permission=="SELECT"?1:0,ct,transaction);
        foreach(var (table,column,expected) in new[]{("AuthTokens","UsedAt",1),("AuthTokens","SignerContactRevisionId",0),("AuthTokens","EmailPilotLookupRequestId",0),
            ("SignaturePreviews","UsedAt",1),("SignaturePreviews","SignatureSha256",0),("SignerReviewCandidates","UsedAt",1),
            ("SignerReviewCandidates","SupersededAt",1),("SignerReviewCandidates","PdfSha256",0),("SignerFinishAcceptances","ProcessedAt",1),("SignerFinishAcceptances","NextInvitationId",1),("SignerFinishAcceptances","FieldsSha256",0)})
            await Permission(connection,"dbo."+table,"UPDATE",column,expected,ct,transaction);
        foreach(var procedure in new[]{"RemoveExpiredEmailPilotSecrets","RemoveExpiredEmailPilotCloseoutSecret"})
            await Permission(connection,"dbo."+procedure,"EXECUTE",null,worker?1:0,ct,transaction);
        await using var roles=Command(connection,"SELECT IS_ROLEMEMBER('db_owner'),IS_ROLEMEMBER('db_ddladmin'),IS_ROLEMEMBER('db_datawriter')",transaction);
        await using var r=await roles.ExecuteReaderAsync(ct);if(!await r.ReadAsync(ct))throw Invalid();
        for(var n=0;n<3;n++)if(r.IsDBNull(n)||r.GetInt32(n)!=0)throw Invalid();
        await r.DisposeAsync();
        foreach(var role in new[]{"app_runtime_role","app_email_pilot_retention_role","app_demo_purge_role","app_lookup_retention_role"}) {
            await using var roleCommand=Command(connection,"SELECT IS_ROLEMEMBER(@role)",transaction);roleCommand.Parameters.Add("@role",SqlDbType.NVarChar,128).Value=role;
            if(await roleCommand.ExecuteScalarAsync(ct) is not int member||member!=(role=="app_runtime_role"||worker?1:0))throw Invalid();
        }
    }
    private static async Task Permission(SqlConnection connection,string name,string permission,string? column,int expected,CancellationToken ct,SqlTransaction? transaction)
    {
        await using var cmd=Command(connection,column is null?"SELECT HAS_PERMS_BY_NAME(@name,'OBJECT',@permission)":"SELECT HAS_PERMS_BY_NAME(@name,'OBJECT',@permission,@column,'COLUMN')",transaction);
        cmd.Parameters.Add("@name",SqlDbType.NVarChar,256).Value=name;cmd.Parameters.Add("@permission",SqlDbType.NVarChar,20).Value=permission;
        if(column is not null)cmd.Parameters.Add("@column",SqlDbType.NVarChar,128).Value=column;
        var value=await cmd.ExecuteScalarAsync(ct);if(value is not int actual||actual!=expected)throw Invalid();
    }
    internal static async Task<HostedCloseoutVerificationSetResult[]> ReadSetsAsync(SqlConnection connection,HostedCloseoutVerificationConfiguration cfg,CancellationToken ct,SqlTransaction? transaction=null)
    {
        var results=new List<HostedCloseoutVerificationSetResult>();var bytes=0L;
        var selected=new Dictionary<int,List<IReadOnlyList<object?>>>();
        foreach(var index in SetIndices) {
            var schema=HostedCloseoutStoredStateFingerprint.Schema(index);
            await using var cmd=Command(connection,Query(index),transaction);Scope(cmd,cfg);
            await using var reader=await cmd.ExecuteReaderAsync(CommandBehavior.SequentialAccess,ct);
            if(reader.FieldCount!=schema.Columns.Length)throw Invalid();
            for(var n=0;n<reader.FieldCount;n++)if(reader.GetName(n)!=schema.Columns[n].Name||reader.GetDataTypeName(n)!=schema.Columns[n].SqlType)throw Invalid();
            var rows=new List<IReadOnlyList<object?>>();
            while(await reader.ReadAsync(ct)) {
                if(rows.Count>=4096)throw Invalid();var values=new object?[reader.FieldCount];
                for(var n=0;n<values.Length;n++) {
                    if(await reader.IsDBNullAsync(n,ct)){values[n]=null;continue;}
                    object value;
                    if(schema.Columns[n].SqlType=="nvarchar") {
                        var length=reader.GetChars(n,0,null,0,0);if(length>HostedCloseoutStoredStateFingerprint.MaximumCellBytes/2)throw Invalid();
                        var chars=new char[(int)length];if(reader.GetChars(n,0,chars,0,chars.Length)!=length)throw Invalid();value=new string(chars);bytes+=Encoding.UTF8.GetByteCount((string)value);
                    } else if(schema.Columns[n].SqlType is "varbinary" or "timestamp") {
                        var length=reader.GetBytes(n,0,null,0,0);if(length>HostedCloseoutStoredStateFingerprint.MaximumCellBytes)throw Invalid();
                        var data=new byte[(int)length];if(reader.GetBytes(n,0,data,0,data.Length)!=length)throw Invalid();value=data;bytes+=length;
                    } else {value=reader.GetValue(n);bytes+=32;}
                    if(bytes>MaximumBytes)throw Invalid();values[n]=value;
                }
                rows.Add(values);
            }
            var hash=HostedCloseoutStoredStateFingerprint.Compute(index,rows);var expected=cfg.ExpectedSets.Single(x=>x.Index==index);
            if(hash.Rows.Length!=expected.Count||!SameHash(hash.Sha256,expected.Sha256)||!SameHash(hash.SchemaSha256,expected.SchemaSha256))throw Invalid();
            results.Add(new(index,rows.Count,hash.Sha256.ToLowerInvariant()));
            if(index is 5 or 10 or 11)selected.Add(index,rows);
        }
        DemandOriginalState(selected[10],selected[11]);DemandCounters(selected[5]);
        await using var empty=Command(connection,"SELECT (SELECT COUNT_BIG(1) FROM dbo.EmailPilotCloseouts),(SELECT COUNT_BIG(1) FROM dbo.EmailPilotCloseoutOperations)",transaction);
        await using var er=await empty.ExecuteReaderAsync(ct);if(!await er.ReadAsync(ct)||er.GetInt64(0)!=0||er.GetInt64(1)!=0)throw Invalid();
        return results.ToArray();
    }
    internal static string Query(int index)
    {
        var schema=HostedCloseoutStoredStateFingerprint.Schema(index);
        var where=index switch {1=>"1=1",2=>"[Id] IN(@p0,@p1,@p2,@p3,@p4)",3 or 4 or 5=>"[RunId] IN(@p0,@p1,@p2,@p3,@p4)",7=>"[Id] IN(@r0,@r1,@r2)",
            10 or 11=>"[Id] IN(@w0,@w1,@w2,@w3,@w4,@w5)",19=>"[Email] IN (SELECT [SenderEmail] FROM dbo.Envelopes WHERE [Id] IN(@r0,@r1,@r2) UNION SELECT [Email] FROM dbo.Signers WHERE [EnvelopeId] IN(@r0,@r1,@r2) UNION SELECT [Email] FROM dbo.Recipients WHERE [EnvelopeId] IN(@r0,@r1,@r2))",
            _=>"[EnvelopeId] IN(@r0,@r1,@r2)"};
        return "SELECT TOP(4097) "+string.Join(",",schema.Columns.Select(c=>"["+c.Name+"]"))+" FROM [dbo].["+schema.Table+"] WHERE "+where;
    }
    private static void Scope(SqlCommand command,HostedCloseoutVerificationConfiguration cfg)
    {foreach(var (prefix,values) in new[]{("p",cfg.ParentRunIds),("r",cfg.EnvelopeIds),("w",cfg.OriginalWorkIds)})for(var n=0;n<values.Length;n++)command.Parameters.Add("@"+prefix+n,SqlDbType.UniqueIdentifier).Value=values[n];}
    private static void DemandOriginalState(List<IReadOnlyList<object?>> mails,List<IReadOnlyList<object?>> works)
    {
        if(mails.Count!=6||works.Count!=6)throw Invalid();var completion=0;var terminal=0;
        foreach(var m in mails) {
            var w=works.Single(x=>Equals(x[0],m[0]));var template=(string)m[3]!;
            if(template=="completion-ready")completion++;else if(template=="envelope-voided")terminal++;else throw Invalid();
            if(!Equals(m[1],w[1])||m[1] is null||m[6] is not string mailStatus||mailStatus!="Failed"||m[9] is not int mailAttempts||mailAttempts!=0||(string?)m[10]!="pilot-delivery-unavailable"||
                m[7] is not null||m[8] is not null||m[12] is not null||m[13] is not null||m[15] is not null||
                w[2] is not string workKind||workKind!="Email"||w[3] is not string workStatus||workStatus!="Failed"||w[5] is not int workAttempts||workAttempts!=1||(string?)w[6]!="pilot-delivery-unavailable"||w[8] is not null||w[9] is not null)throw Invalid();
        }
        if(completion!=4||terminal!=2)throw Invalid();
    }
    private static void DemandCounters(List<IReadOnlyList<object?>> rows)
    {if(rows.Count!=20||rows.Count(r=>Equals(r[4],"Application"))!=12||rows.Count(r=>Equals(r[4],"Simulator"))!=4||rows.Count(r=>Equals(r[4],"Timestamp"))!=4||rows.Sum(r=>(long)(int)r[6]!)!=27918)throw Invalid();}

    // Stable visible catalog projection only; no object IDs/collation/module or
    // hidden constraint definitions, and never another principal's role graph.
    internal const string VisibleSchemaQuery="""
        SELECT N'column' AS Kind,t.name AS TableName,c.name AS Name,CONVERT(nvarchar(20),c.column_id) AS Position,
          CONCAT(ty.name,N'|',c.max_length,N'|',c.precision,N'|',c.scale,N'|',c.is_nullable,N'|',c.is_identity,N'|',c.is_computed) AS Detail
        FROM sys.tables t JOIN sys.columns c ON c.object_id=t.object_id JOIN sys.types ty ON ty.user_type_id=c.user_type_id
        WHERE t.schema_id=SCHEMA_ID(N'dbo') AND t.name IN(N'EmailPilotCloseouts',N'EmailPilotCloseoutOperations')
        UNION ALL SELECT N'index',t.name,i.name,CONVERT(nvarchar(20),ic.key_ordinal),CONCAT(c.name,N'|',i.type,N'|',i.is_unique,N'|',i.is_primary_key,N'|',i.has_filter,N'|',ic.is_descending_key,N'|',ic.is_included_column)
        FROM sys.tables t JOIN sys.indexes i ON i.object_id=t.object_id JOIN sys.index_columns ic ON ic.object_id=t.object_id AND ic.index_id=i.index_id JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id
        WHERE t.schema_id=SCHEMA_ID(N'dbo') AND t.name IN(N'EmailPilotCloseouts',N'EmailPilotCloseoutOperations')
        UNION ALL SELECT N'foreign',t.name,f.name,CONVERT(nvarchar(20),fc.constraint_column_id),CONCAT(rt.name,N'|',c.name,N'|',rc.name,N'|',f.delete_referential_action,N'|',f.update_referential_action,N'|',f.is_disabled,N'|',f.is_not_trusted)
        FROM sys.tables t JOIN sys.foreign_keys f ON f.parent_object_id=t.object_id JOIN sys.foreign_key_columns fc ON fc.constraint_object_id=f.object_id JOIN sys.tables rt ON rt.object_id=f.referenced_object_id JOIN sys.columns c ON c.object_id=t.object_id AND c.column_id=fc.parent_column_id JOIN sys.columns rc ON rc.object_id=rt.object_id AND rc.column_id=fc.referenced_column_id
        WHERE t.schema_id=SCHEMA_ID(N'dbo') AND t.name IN(N'EmailPilotCloseouts',N'EmailPilotCloseoutOperations')
        UNION ALL SELECT N'check',t.name,c.name,N'0',CONCAT(c.is_disabled,N'|',c.is_not_trusted) FROM sys.tables t JOIN sys.check_constraints c ON c.parent_object_id=t.object_id
        WHERE t.schema_id=SCHEMA_ID(N'dbo') AND t.name IN(N'EmailPilotCloseouts',N'EmailPilotCloseoutOperations')
        UNION ALL SELECT N'default',t.name,d.name,N'0',c.name FROM sys.tables t JOIN sys.default_constraints d ON d.parent_object_id=t.object_id JOIN sys.columns c ON c.object_id=t.object_id AND c.column_id=d.parent_column_id
        WHERE t.schema_id=SCHEMA_ID(N'dbo') AND t.name IN(N'EmailPilotCloseouts',N'EmailPilotCloseoutOperations')
        """;
    internal static async Task<(string Sha256,string[][] Projection)> ReadVisibleSchemaAsync(SqlConnection connection,CancellationToken ct,SqlTransaction? transaction=null)
    {
        await using var cmd=Command(connection,VisibleSchemaQuery,transaction);await using var reader=await cmd.ExecuteReaderAsync(ct);var rows=new List<string[]>();
        while(await reader.ReadAsync(ct)) {if(rows.Count>=128)throw Invalid();var row=new string[5];for(var n=0;n<5;n++){if(reader.IsDBNull(n))throw Invalid();row[n]=reader.GetString(n);if(row[n].Length>1024)throw Invalid();}rows.Add(row);}
        string[] checks=["CK_EmailPilotCloseoutHeaderRecord_CapabilitySha256","CK_EmailPilotCloseoutHeaderRecord_ManifestSha256","CK_PilotCloseout_Header","CK_PilotCloseout_Secret",
            "CK_EmailPilotCloseoutOperationRecord_RequestSha256","CK_PilotCloseout_Accounting","CK_PilotCloseout_Operation"];
        if(rows.Count(x=>x[0]=="column")!=17||!rows.Where(x=>x[0]=="check").Select(x=>x[2]).Order(StringComparer.Ordinal).SequenceEqual(checks.Order(StringComparer.Ordinal))||rows.Count(x=>x[0]=="foreign")!=1)throw Invalid();
        var ordered=rows.OrderBy(x=>JsonSerializer.Serialize(x),StringComparer.Ordinal).ToArray();
        return (Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes("closeout-visible-schema-v1\0"+JsonSerializer.Serialize(ordered)))),ordered);
    }
    internal static bool SameHash(string a,string b)=>CryptographicOperations.FixedTimeEquals(Convert.FromHexString(a),Convert.FromHexString(b));
    internal static SqlCommand Command(SqlConnection connection,string sql,SqlTransaction? transaction=null)=>new(sql,connection,transaction){CommandType=CommandType.Text,CommandTimeout=15};
    internal static InvalidDataException Invalid()=>new("Hosted closeout verification refused.");
}
