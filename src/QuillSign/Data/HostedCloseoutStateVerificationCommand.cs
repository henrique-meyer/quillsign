using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Identity;
using Microsoft.Data.SqlClient;

namespace QuillSign.Data;

internal sealed class HostedCloseoutVerificationOutput
{
    public string Version {get;init;}=HostedCloseoutStateVerificationCommand.Version;
    public string? VerificationRunId {get;set;}
    public string? SourceRevision {get;set;}
    public string? LoadedApplicationSha256 {get;set;}
    public string? ConfigurationSha256 {get;set;}
    public string Status {get;set;}="refused";
    public bool Complete {get;set;}
    public string Reason {get;set;}="configuration";
    public int WorkerOpenAttempts {get;set;}
    public int? FirstWorkerOpenSqlError {get;set;}
    public int? FailureSqlErrorNumber {get;set;}
    public string? FailureKind {get;set;}
    public bool QueriesStarted {get;set;}
    public int RuntimeOpenAttempts {get;set;}
    public bool WorkerIdentityVerified {get;set;}
    public bool RuntimeIdentityVerified {get;set;}
    public bool PermissionsVerified {get;set;}
    public bool VisibleSchemaVerified {get;set;}
    public bool OriginalPairsVerified {get;set;}
    public bool CountersVerified {get;set;}
    public string? VisibleSchemaSha256 {get;set;}
    public DateTimeOffset? DatabaseReadAt {get;set;}
    public string FingerprintVersion {get;init;}=HostedCloseoutStoredStateFingerprint.Version;
    public HostedCloseoutVerificationSetResult[] Sets {get;set;}=[];
    public DateTimeOffset StartedAt {get;init;}=DateTimeOffset.UtcNow;
    public DateTimeOffset FinishedAt {get;set;}
}

internal static class HostedCloseoutStateVerificationCommand
{
    internal const string Version="hosted-closeout-verification-v1",Prefix="QUILLSIGN_HOSTED_CLOSEOUT_VERIFICATION:";
    internal static readonly string[] GateKeys=["Work__Enabled","Email__Enabled","EmailPilot__Enabled","EmailPilot__Closeout__Enabled"];
    private static readonly JsonSerializerOptions Json=new(){UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow,MaxDepth=8};
    internal static async Task<int> RunAsync(string[] args)
    {
        var output=new HostedCloseoutVerificationOutput();
        try {
            if(args.Length!=1||args[0]!="verify-hosted-closeout-state"){output.Reason="arguments";throw Refused();}
            output.LoadedApplicationSha256=ApplicationHash();
            var cfg=Capture(Environment.GetEnvironmentVariable("HostedCloseoutVerification__Enabled"),Environment.GetEnvironmentVariable("HostedCloseoutVerification__ConfigurationBase64"),
                GateKeys.Select(Environment.GetEnvironmentVariable).ToArray(),out var configHash);
            output.ConfigurationSha256=configHash;output.VerificationRunId=cfg.VerificationRunId.ToString("N");output.SourceRevision=cfg.SourceRevision;
            if(!HostedCloseoutStateVerification.SameHash(cfg.ApplicationSha256,output.LoadedApplicationSha256))throw Refused();
            using var stop=new CancellationTokenSource(TimeSpan.FromSeconds(270));var ct=stop.Token;
            // Explicit managed identities only. No shared/default credential chain,
            // inherited SQL authentication, password, admin token or retry provider.
            output.Reason="worker-open";
            var workerCredential=Credential(cfg.WorkerClientId);
            await using var worker=Connection(cfg);
            worker.AccessToken=(await workerCredential.GetTokenAsync(new TokenRequestContext(["https://database.windows.net/.default"]),ct)).Token;
            await OpenWorkerAsync(worker.OpenAsync,output,Task.Delay,ct);
            output.Reason="worker-caller";
            await using(var workerTransaction=(SqlTransaction)await worker.BeginTransactionAsync(System.Data.IsolationLevel.Serializable,ct)) {
                try {
                    output.QueriesStarted=true;await LockTimeout(worker,workerTransaction,ct);
                    await HostedCloseoutStateVerification.DemandCallerAsync(worker,cfg,true,ct,workerTransaction);output.WorkerIdentityVerified=true;
                } finally {await workerTransaction.RollbackAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));}
            }
            output.Reason="runtime-open";
            var runtimeCredential=Credential(cfg.RuntimeClientId);await using var runtime=Connection(cfg);
            runtime.AccessToken=(await runtimeCredential.GetTokenAsync(new TokenRequestContext(["https://database.windows.net/.default"]),ct)).Token;
            output.RuntimeOpenAttempts=1;await runtime.OpenAsync(ct);
            await using(var transaction=(SqlTransaction)await runtime.BeginTransactionAsync(System.Data.IsolationLevel.Serializable,ct)) {
                try {
                    await LockTimeout(runtime,transaction,ct);
                    output.Reason="runtime-caller";await HostedCloseoutStateVerification.DemandCallerAsync(runtime,cfg,false,ct,transaction);
                    output.RuntimeIdentityVerified=true;output.PermissionsVerified=true;
                    output.Reason="stored-state";output.Sets=await HostedCloseoutStateVerification.ReadSetsAsync(runtime,cfg,ct,transaction);
                    output.OriginalPairsVerified=true;output.CountersVerified=true;
                    output.Reason="schema";var schema=await HostedCloseoutStateVerification.ReadVisibleSchemaAsync(runtime,ct,transaction);output.VisibleSchemaSha256=schema.Sha256;
                    if(!HostedCloseoutStateVerification.SameHash(schema.Sha256,cfg.VisibleSchemaSha256))throw Refused();
                    output.VisibleSchemaVerified=true;
                    await using var clock=HostedCloseoutStateVerification.Command(runtime,"SELECT SYSUTCDATETIME()",transaction);
                    var observed=await clock.ExecuteScalarAsync(ct);if(observed is not DateTime utc)throw Refused();
                    output.DatabaseReadAt=new DateTimeOffset(DateTime.SpecifyKind(utc,DateTimeKind.Utc));
                } finally {var observedPhase=output.Reason;output.Reason="rollback";await transaction.RollbackAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5));output.Reason=observedPhase;}
            }
            output.Complete=true;output.Status="passed";output.Reason="verified";
        }
        catch(Exception failure){RecordFailure(output,failure);}
        output.FinishedAt=DateTimeOffset.UtcNow;
        var encoded=JsonSerializer.Serialize(output,Json);if(Encoding.UTF8.GetByteCount(encoded)>16384)throw Refused();
        Console.WriteLine(Prefix+encoded);return output.Complete?0:1;
    }
    // Closed diagnostic facts only. These never authorize a retry or reveal
    // exception text, stack, type names, endpoints, identity or protected cells.
    internal static void RecordFailure(HostedCloseoutVerificationOutput output,Exception failure)
    {
        output.Complete=false;output.Status="refused";
        output.FailureSqlErrorNumber=failure is SqlException sql?sql.Number:null;
        output.FailureKind=failure switch {
            SqlException=>"sql",
            AuthenticationFailedException=>"credential",
            OperationCanceledException=>"cancelled",
            InvalidDataException=>"refused",
            _=>"other"
        };
        if(failure is OperationCanceledException)output.Reason="cancelled";
    }
    internal static async Task OpenWorkerAsync(Func<CancellationToken,Task> open,HostedCloseoutVerificationOutput state,
        Func<TimeSpan,CancellationToken,Task> delay,CancellationToken ct)
    {
        if(state.WorkerOpenAttempts!=0||state.QueriesStarted)throw Refused();state.WorkerOpenAttempts=1;
        try {await open(ct);}
        catch(SqlException e)when(e.Number==40613&&!state.QueriesStarted) {
            state.FirstWorkerOpenSqlError=40613;
            await delay(TimeSpan.FromSeconds(120),ct);ct.ThrowIfCancellationRequested();state.WorkerOpenAttempts=2;await open(ct);
        }
    }
    private static ManagedIdentityCredential Credential(Guid clientId)
    {
        var options=new ManagedIdentityCredentialOptions(ManagedIdentityId.FromUserAssignedClientId(clientId.ToString("D")));
        options.Retry.MaxRetries=0;options.Retry.NetworkTimeout=TimeSpan.FromSeconds(15);
        options.Diagnostics.IsLoggingEnabled=false;options.Diagnostics.IsLoggingContentEnabled=false;options.Diagnostics.IsDistributedTracingEnabled=false;
        return new(options);
    }
    private static async Task LockTimeout(SqlConnection connection,SqlTransaction transaction,CancellationToken ct)
    {await using var command=HostedCloseoutStateVerification.Command(connection,"SET LOCK_TIMEOUT 5000",transaction);await command.ExecuteNonQueryAsync(ct);}
    internal static SqlConnection Connection(HostedCloseoutVerificationConfiguration cfg)=>new(new SqlConnectionStringBuilder{
        DataSource="tcp:"+cfg.Server+",1433",InitialCatalog=cfg.Database,Encrypt=true,TrustServerCertificate=false,
        ConnectTimeout=60,ConnectRetryCount=0,Pooling=false,MultipleActiveResultSets=false,ApplicationName="QuillSign.HostedCloseoutVerification"}.ConnectionString);
    internal static string ApplicationHash()=>Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(typeof(DatabaseCommands).Assembly.Location)));
    internal static HostedCloseoutVerificationConfiguration Capture(string? enabled,string? packet,string?[] gates,out string hash)
    {
        if(enabled!="true"||gates.Length!=4||gates.Any(x=>x!="false")||packet is not {Length:>0 and <=87384})throw Refused();
        var bytes=Convert.FromBase64String(packet);if(bytes.Length>65536||Convert.ToBase64String(bytes)!=packet)throw Refused();
        // JsonSerializer normally accepts duplicate property names. Reject them
        // throughout this one closed packet before constructing typed options.
        using(var doc=JsonDocument.Parse(bytes,new JsonDocumentOptions{MaxDepth=8}))DemandUnique(doc.RootElement);
        var cfg=JsonSerializer.Deserialize<HostedCloseoutVerificationConfiguration>(bytes,Json)??throw Refused();
        if(cfg.Version!=Version||cfg.VerificationRunId==Guid.Empty||!Hex(cfg.SourceRevision,40)||!Hex(cfg.ApplicationSha256,64)||!Hex(cfg.VisibleSchemaSha256,64)||
            cfg.RuntimeClientId==Guid.Empty||cfg.WorkerClientId==Guid.Empty||cfg.RuntimeClientId==cfg.WorkerClientId||
            cfg.Server is null||!System.Text.RegularExpressions.Regex.IsMatch(cfg.Server,@"^[a-z0-9][a-z0-9-]{0,61}\.database\.windows\.net$",System.Text.RegularExpressions.RegexOptions.CultureInvariant)||
            cfg.Database is null||!System.Text.RegularExpressions.Regex.IsMatch(cfg.Database,@"^[A-Za-z0-9_-]{1,128}$",System.Text.RegularExpressions.RegexOptions.CultureInvariant)||
            !Ids(cfg.ParentRunIds,5)||!Ids(cfg.EnvelopeIds,3)||!Ids(cfg.OriginalWorkIds,6)||
            cfg.ExpectedSets is null||cfg.ExpectedSets.Length!=17||cfg.ExpectedSets.Any(x=>x is null)||!cfg.ExpectedSets.Select(x=>x.Index).Order().SequenceEqual(HostedCloseoutStateVerification.SetIndices))throw Refused();
        var runtimeSid=Convert.FromBase64String(cfg.RuntimeSqlSid);var workerSid=Convert.FromBase64String(cfg.WorkerSqlSid);
        if(runtimeSid.Length!=16||workerSid.Length!=16||runtimeSid.SequenceEqual(workerSid))throw Refused();
        foreach(var set in cfg.ExpectedSets)if(!Hex(set.Sha256,64)||!Hex(set.SchemaSha256,64)||set.Count is <0 or >4096||(set.Index switch {
            1=>set.Count!=23,2 or 3=>set.Count!=5,4=>set.Count!=8,5=>set.Count!=20,7=>set.Count!=3,10 or 11=>set.Count!=6,_=>false}))throw Refused();
        hash=Convert.ToHexStringLower(SHA256.HashData(bytes));return cfg;
    }
    private static void DemandUnique(JsonElement value)
    {
        if(value.ValueKind==JsonValueKind.Object){var keys=new HashSet<string>(StringComparer.Ordinal);foreach(var p in value.EnumerateObject()){if(!keys.Add(p.Name))throw Refused();DemandUnique(p.Value);}}
        else if(value.ValueKind==JsonValueKind.Array)foreach(var item in value.EnumerateArray())DemandUnique(item);
    }
    private static bool Ids(Guid[]? ids,int count)=>ids is not null&&ids.Length==count&&ids.All(x=>x!=Guid.Empty)&&ids.Distinct().Count()==count;
    private static bool Hex(string? value,int length)=>value is not null&&value.Length==length&&value.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
    private static InvalidDataException Refused()=>new("Hosted closeout verification refused.");
}
