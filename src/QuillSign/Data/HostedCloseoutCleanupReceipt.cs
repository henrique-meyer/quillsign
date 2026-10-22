using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Email.Pilot;

namespace QuillSign.Data;

internal sealed record HostedCloseoutCleanupProofConfiguration(string Version,string Database,string WorkerSqlSid,
    EmailPilotCloseoutCommittedReceipt FinalReceipt);
internal sealed record HostedCloseoutCleanupReceiptResult(string Version,Guid AuthorizationId,DateTimeOffset DatabaseReadAt,
    string ManifestSha256,string HeaderFactsSha256,DateTimeOffset DeleteAfter,bool ProtectedManifestBefore,bool ProtectedManifestAfter,
    bool RemovedByThisCall,bool AlreadyAbsent,int NewApplication,long NewEncodedBytes,int OperationCount,string OperationsSha256,
    string OriginalMailSha256,string OriginalWorkSha256,string OriginalAccountingSha256,bool ImmutableFactsUnchanged,bool WorkerIdentityVerified,
    string ApplicationSha256,string ConfigurationSha256);

internal static class HostedCloseoutCleanupReceipt
{
    internal const string Prefix="QUILLSIGN_CLOSEOUT_CLEANUP_RECEIPT:",Version="closeout-cleanup-receipt-v1";
    private static readonly JsonSerializerOptions Json=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=8};
    internal static HostedCloseoutCleanupProofConfiguration Capture(IConfiguration config,out string sha)
    {
        if(config["EmailPilot:Closeout:EmitCleanupReceipt"]!="true"||config["Email:Enabled"]!="false"||
            config["EmailPilot:Enabled"]!="false"||config["EmailPilot:Closeout:Enabled"]!="false"||config["Work:Enabled"]!="true")throw Invalid();
        var raw=config["EmailPilot:Closeout:CleanupProofBase64"];
        if(raw is not {Length:>0 and <=32768})throw Invalid();var bytes=Convert.FromBase64String(raw);
        if(bytes.Length>24576||Convert.ToBase64String(bytes)!=raw)throw Invalid();
        using(var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=8}))Unique(doc.RootElement);
        var expected=JsonSerializer.Deserialize<HostedCloseoutCleanupProofConfiguration>(bytes,Json)??throw Invalid();
        if(expected.Version!="closeout-cleanup-proof-v1"||expected.Database is not {Length:>0 and <=128}||expected.FinalReceipt is null||
            Convert.FromBase64String(expected.WorkerSqlSid).Length!=16||
            !Guid.TryParseExact(config["EmailPilot:Closeout:AuthorizationId"],"N",out var id)||id==Guid.Empty||id!=expected.FinalReceipt.AuthorizationId)throw Invalid();
        Validate(expected.FinalReceipt);sha=Convert.ToHexStringLower(SHA256.HashData(bytes));return expected;
    }
    internal static async Task<HostedCloseoutCleanupReceiptResult> RunAsync(QuillSignDbContext db,IConfiguration config)
    {
        var expected=Capture(config,out var configurationSha);if(db.Database.CurrentTransaction is not null||db.ChangeTracker.HasChanges())throw Invalid();
        if(!Same(expected.FinalReceipt.ApplicationSha256,HostedCloseoutStateVerificationCommand.ApplicationHash()))throw Invalid();
        using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(90));var ct=stop.Token;
        await db.Database.OpenConnectionAsync(ct);
        await using var tx=await db.Database.BeginTransactionAsync(IsolationLevel.Serializable,ct);
        var committed=false;
        try {
            await db.Database.ExecuteSqlRawAsync("SET LOCK_TIMEOUT 5000",ct);
            await DemandWorkerAsync(db,expected.Database,Convert.FromBase64String(expected.WorkerSqlSid),ct);
            var result=await ApplyLockedAsync(db,expected.FinalReceipt,ct);
            await tx.CommitAsync(ct);committed=true;
            return result with{WorkerIdentityVerified=true,ConfigurationSha256=configurationSha};
        } finally {if(!committed)await tx.RollbackAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));}
    }
    internal static async Task DemandWorkerAsync(QuillSignDbContext db,string database,byte[] actualSavedSid,CancellationToken ct)
    {
        if(actualSavedSid.Length!=16)throw Invalid();var tx=HostedCloseoutReceiptState.Transaction(db);
        await using var command=HostedCloseoutStateVerification.Command(tx.Connection!,
            "SELECT USER_NAME(),p.[type],p.[sid],DB_NAME() FROM sys.database_principals p WHERE p.principal_id=USER_ID()",tx);
        await using(var reader=await command.ExecuteReaderAsync(ct)) {
            if(!await reader.ReadAsync(ct)||reader.IsDBNull(0)||reader.IsDBNull(1)||reader.IsDBNull(2)||reader.IsDBNull(3)||
                reader.GetString(0)!="app_worker"||reader.GetString(1)!="E"||reader.GetString(3)!=database||
                !CryptographicOperations.FixedTimeEquals((byte[])reader.GetValue(2),actualSavedSid)||await reader.ReadAsync(ct))throw Invalid();
        }
        await HostedCloseoutStateVerification.DemandPermissionsAsync(tx.Connection!,true,ct,tx);
    }
    // Native S-principal tests exercise this exact fixed procedure/state stage;
    // the command always performs the independent strict E/SID/database check
    // above first. This factual stage does not manufacture identity evidence.
    internal static async Task<HostedCloseoutCleanupReceiptResult> ApplyLockedAsync(QuillSignDbContext db,EmailPilotCloseoutCommittedReceipt expected,CancellationToken ct)
    {
        Validate(expected);_=HostedCloseoutReceiptState.Transaction(db);
        if(await db.EmailPilotCloseouts.CountAsync(ct)!=1)throw Invalid();
        var before=await db.EmailPilotCloseouts.AsNoTracking().SingleOrDefaultAsync(x=>x.Id==expected.AuthorizationId,ct)??throw Invalid();
        DemandHeader(before,expected);
        var now=await HostedCloseoutReceiptState.DatabaseUtcAsync(db,ct);if(now<before.DeleteAfter||expected.ObservedAt>now)throw Invalid();
        var operations=await HostedCloseoutReceiptState.OperationsAsync(db,before.Id,ct);
        var originals=await HostedCloseoutReceiptState.OriginalsAsync(db,expected.OriginalWorkIds,ct);
        var originalAccounting=await HostedCloseoutReceiptState.OriginalAccountingAsync(db,expected.OriginalParentIds,ct);
        if(!Same(originalAccounting,expected.OriginalAccountingSha256))throw Invalid();
        DemandAccounting(expected,operations,originals);
        var wasPresent=before.ProtectedManifest is not null;
        if(wasPresent)await db.Database.ExecuteSqlInterpolatedAsync($"EXEC dbo.RemoveExpiredEmailPilotCloseoutSecret @Id={before.Id}",ct);
        var after=await db.EmailPilotCloseouts.AsNoTracking().SingleAsync(x=>x.Id==before.Id,ct);DemandHeader(after,expected);
        if(after.ProtectedManifest is not null)throw Invalid();
        var afterOperations=await HostedCloseoutReceiptState.OperationsAsync(db,before.Id,ct);
        var afterOriginals=await HostedCloseoutReceiptState.OriginalsAsync(db,expected.OriginalWorkIds,ct);
        if(!Same(await HostedCloseoutReceiptState.OriginalAccountingAsync(db,expected.OriginalParentIds,ct),originalAccounting))throw Invalid();
        DemandAccounting(expected,afterOperations,afterOriginals);
        var finalNow=await HostedCloseoutReceiptState.DatabaseUtcAsync(db,ct);
        return new(Version,before.Id,finalNow,expected.ManifestSha256,expected.HeaderFactsSha256,before.DeleteAfter,
            wasPresent,false,wasPresent,!wasPresent,expected.NewApplication,expected.NewEncodedBytes,expected.OperationCount,
            expected.OperationsSha256,expected.OriginalMailSha256,expected.OriginalWorkSha256,originalAccounting,true,false,
            HostedCloseoutStateVerificationCommand.ApplicationHash(),"");
    }
    private static void DemandHeader(EmailPilotCloseoutHeaderRecord row,EmailPilotCloseoutCommittedReceipt expected)
    {
        if(row.Id!=expected.AuthorizationId||row.CreatedAt!=expected.CreatedAt||row.Until!=expected.Until||row.DeleteAfter!=expected.DeleteAfter||
            !Same(Convert.ToHexStringLower(row.CapabilitySha256),expected.CapabilitySha256)||!Same(Convert.ToHexStringLower(row.ManifestSha256),expected.ManifestSha256)||
            !Same(HostedCloseoutReceiptState.HeaderHash(row),expected.HeaderFactsSha256))throw Invalid();
    }
    private static void DemandAccounting(EmailPilotCloseoutCommittedReceipt expected,EmailPilotCloseoutOperationRecord[] rows,(string Mail,string Work) originals)
    {
        if(rows.Length!=expected.OperationCount||rows.Count(x=>x.Kind==0)!=expected.StepBoundCount||rows.Count(x=>x.Kind==1)!=expected.NewApplication||
            rows.Any(x=>x.Kind is not(0 or 1)||x.Step is <0 or >9||x.CloseoutId!=expected.AuthorizationId||x.At<expected.CreatedAt||x.At>=expected.Until||
                (x.Kind==0?(x.Step<6||x.EncodedBytes!=0):(x.EncodedBytes is <1 or >1048576)))||
            rows.GroupBy(x=>(x.Kind,x.Step)).Any(x=>x.Count()!=1)||rows.Where(x=>x.Kind==1).Sum(x=>(long)x.EncodedBytes)!=expected.NewEncodedBytes||
            !Same(HostedCloseoutReceiptState.OperationsHash(rows),expected.OperationsSha256)||!Same(originals.Mail,expected.OriginalMailSha256)||!Same(originals.Work,expected.OriginalWorkSha256))throw Invalid();
    }
    internal static void Validate(EmailPilotCloseoutCommittedReceipt r)
    {
        if(r.Version!=EmailPilotCloseout.CommittedReceiptVersion||r.AuthorizationId==Guid.Empty||!r.ProtectedManifestPresent||!r.OriginalPairsPreserved||
            r.CreatedAt.Offset!=TimeSpan.Zero||r.Until.Offset!=TimeSpan.Zero||r.DeleteAfter.Offset!=TimeSpan.Zero||r.ObservedAt.Offset!=TimeSpan.Zero||
            r.CreatedAt==default||r.Until<=r.CreatedAt||r.Until>r.CreatedAt.AddMinutes(30)||r.DeleteAfter<=r.Until||r.ObservedAt<r.CreatedAt||r.ObservedAt>=r.Until||
            r.ActualOriginalParentDeleteAfterMinimum!=r.DeleteAfter||!Ids(r.OriginalParentIds,5)||!Ids(r.OriginalWorkIds,6)||
            r.OriginalApplication!=12||r.OriginalSimulator!=4||r.OriginalTimestamp!=4||r.OriginalEncodedBytes!=27918||r.NewApplication is <0 or >10||
            r.NewSimulator!=0||r.NewTimestamp!=0||r.NewEncodedBytes<0||r.NewEncodedBytes>31429362||r.StepBoundCount is <0 or >4||
            r.OperationCount!=r.StepBoundCount+r.NewApplication||r.OperationCount>14||
            new[]{r.CapabilitySha256,r.ManifestSha256,r.OperationsSha256,r.OriginalMailSha256,r.OriginalWorkSha256,r.OriginalAccountingSha256,r.HeaderFactsSha256,r.ApplicationSha256}.Any(x=>!Hex(x)))throw Invalid();
    }
    private static bool Ids(Guid[]? ids,int count)=>ids is not null&&ids.Length==count&&ids.All(x=>x!=Guid.Empty)&&ids.Distinct().Count()==count;
    private static bool Hex(string? x)=>x is {Length:64}&&x.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Same(string a,string b)=>HostedCloseoutStateVerification.SameHash(a,b);
    private static void Unique(JsonElement v)
    {if(v.ValueKind==JsonValueKind.Object){var names=new HashSet<string>(StringComparer.Ordinal);foreach(var p in v.EnumerateObject()){if(!names.Add(p.Name))throw Invalid();Unique(p.Value);}}else if(v.ValueKind==JsonValueKind.Array)foreach(var x in v.EnumerateArray())Unique(x);}
    private static InvalidDataException Invalid()=>HostedCloseoutReceiptState.Invalid();
}
