using System.Diagnostics;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Azure.Identity;
using Microsoft.Data.SqlClient;
using QuillSign.Data;

namespace QuillSign.Tests;

public sealed class HostedCloseoutStateVerificationCommandTests
{
    [Fact]
    public void Closed_packet_has_distinct_MI_and_saved_SQL_identity_and_no_inherited_connection_options()
    {
        var cfg=HostedCloseoutStateVerificationTests.Configuration();var packet=Packet(cfg);
        var parsed=HostedCloseoutStateVerificationCommand.Capture("true",packet,["false","false","false","false"],out var hash);
        Assert.Equal(cfg.RuntimeClientId,parsed.RuntimeClientId);Assert.Equal(cfg.RuntimeSqlSid,parsed.RuntimeSqlSid);Assert.Equal(64,hash.Length);
        var sql=new SqlConnectionStringBuilder(HostedCloseoutStateVerificationCommand.Connection(cfg).ConnectionString);
        Assert.Equal(0,sql.ConnectRetryCount);Assert.False(sql.Pooling);Assert.False(sql.TrustServerCertificate);Assert.Equal(60,sql.ConnectTimeout);
        Assert.Empty(sql.UserID);Assert.Empty(sql.Password);Assert.Equal(SqlAuthenticationMethod.NotSpecified,sql.Authentication);
        Assert.NotEqual(new Guid(Convert.FromBase64String(cfg.RuntimeSqlSid)),cfg.RuntimeClientId);
    }
    [Theory]
    [InlineData("disabled")][InlineData("gate")][InlineData("duplicate")][InlineData("unknown")][InlineData("wrongcount")][InlineData("sameidentity")][InlineData("badserver")][InlineData("oversize")]
    public void Ambiguous_unbounded_or_live_packet_refuses_before_connection(string fault)
    {
        var cfg=HostedCloseoutStateVerificationTests.Configuration();var enabled="true";string?[] gates=["false","false","false","false"];
        if(fault=="sameidentity")cfg=cfg with{WorkerClientId=cfg.RuntimeClientId};if(fault=="badserver")cfg=cfg with{Server="server;Password=private-value"};
        if(fault=="wrongcount")cfg=cfg with{EnvelopeIds=[Guid.NewGuid()]};var raw=JsonSerializer.Serialize(cfg);
        if(fault=="duplicate")raw="{\"Version\":\"duplicate\","+raw[1..];if(fault=="unknown")raw="{\"Query\":\"private-value\","+raw[1..];
        if(fault=="oversize")raw=new string('x',65537);if(fault=="disabled")enabled="false";if(fault=="gate")gates[0]="true";
        var packet=Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
        Assert.ThrowsAny<Exception>(()=>HostedCloseoutStateVerificationCommand.Capture(enabled,packet,gates,out _));
    }
    [Theory]
    [InlineData(40613,false,2,1)][InlineData(40613,true,2,1)][InlineData(18456,false,1,0)]
    public async Task Only_first_prequery_40613_has_one_fixed_delay_and_one_open(int number,bool secondFails,int attempts,int waits)
    {
        var state=new HostedCloseoutVerificationOutput();var called=0;var delayed=0;
        Task Open(CancellationToken _){called++;if(called==1||secondFails)throw SqlError(number);return Task.CompletedTask;}
        Task Delay(TimeSpan duration,CancellationToken ct){Assert.Equal(TimeSpan.FromSeconds(120),duration);Assert.False(ct.IsCancellationRequested);delayed++;return Task.CompletedTask;}
        if(number!=40613||secondFails)await Assert.ThrowsAsync<SqlException>(()=>HostedCloseoutStateVerificationCommand.OpenWorkerAsync(Open,state,Delay,default));
        else await HostedCloseoutStateVerificationCommand.OpenWorkerAsync(Open,state,Delay,default);
        Assert.Equal(attempts,called);Assert.Equal(attempts,state.WorkerOpenAttempts);Assert.Equal(waits,delayed);Assert.False(state.QueriesStarted);
        Assert.Equal(number==40613?40613:(int?)null,state.FirstWorkerOpenSqlError);
    }
    [Fact]
    public async Task Query_started_and_cancelled_delay_never_grant_another_open()
    {
        var state=new HostedCloseoutVerificationOutput{QueriesStarted=true};var calls=0;
        await Assert.ThrowsAsync<InvalidDataException>(()=>HostedCloseoutStateVerificationCommand.OpenWorkerAsync(_=>{calls++;return Task.CompletedTask;},state,Task.Delay,default));Assert.Equal(0,calls);
        state=new();using var cancel=new CancellationTokenSource();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>HostedCloseoutStateVerificationCommand.OpenWorkerAsync(_=>{calls++;throw SqlError(40613);},state,
            (_,_)=>{cancel.Cancel();return Task.CompletedTask;},cancel.Token));Assert.Equal(1,calls);Assert.Equal(1,state.WorkerOpenAttempts);
    }
    [Theory]
    [InlineData(-2)][InlineData(18456)][InlineData(0)][InlineData(int.MinValue)][InlineData(int.MaxValue)]
    public async Task Actual_caught_SQL_open_error_exports_only_number_and_closed_kind_without_retry(int number)
    {
        var state=new HostedCloseoutVerificationOutput{Reason="worker-open"};var calls=0;var delays=0;
        try {await HostedCloseoutStateVerificationCommand.OpenWorkerAsync(_=>{calls++;throw SqlError(number);},state,
            (_,_)=>{delays++;return Task.CompletedTask;},default);throw new Exception("Expected SQL failure.");}
        catch(SqlException failure){HostedCloseoutStateVerificationCommand.RecordFailure(state,failure);}
        Assert.Equal(1,calls);Assert.Equal(0,delays);Assert.Equal(1,state.WorkerOpenAttempts);Assert.Null(state.FirstWorkerOpenSqlError);
        Assert.False(state.QueriesStarted);Assert.Equal(0,state.RuntimeOpenAttempts);Assert.Equal("worker-open",state.Reason);
        Assert.Equal(number,state.FailureSqlErrorNumber);Assert.Equal("sql",state.FailureKind);NoExceptionDetails(state);
    }
    [Fact]
    public async Task Failed_second_open_reports_actual_final_number_and_preserves_original_40613_fact()
    {
        var state=new HostedCloseoutVerificationOutput{Reason="worker-open"};var calls=0;var delays=0;
        try {await HostedCloseoutStateVerificationCommand.OpenWorkerAsync(_=>throw SqlError(++calls==1?40613:18456),state,
            (duration,_)=>{Assert.Equal(TimeSpan.FromSeconds(120),duration);delays++;return Task.CompletedTask;},default);throw new Exception("Expected SQL failure.");}
        catch(SqlException failure){HostedCloseoutStateVerificationCommand.RecordFailure(state,failure);}
        Assert.Equal(2,calls);Assert.Equal(1,delays);Assert.Equal(2,state.WorkerOpenAttempts);Assert.Equal(40613,state.FirstWorkerOpenSqlError);
        Assert.Equal(18456,state.FailureSqlErrorNumber);Assert.Equal("sql",state.FailureKind);Assert.False(state.QueriesStarted);NoExceptionDetails(state);
    }
    [Theory]
    [InlineData("credential")][InlineData("cancelled")][InlineData("refused")][InlineData("other")]
    public void Non_SQL_failures_have_only_closed_category_and_preserve_phase_except_existing_cancellation(string kind)
    {
        Exception failure=kind switch {
            "credential"=>new AuthenticationFailedException("synthetic-private-message"),
            "cancelled"=>new OperationCanceledException("synthetic-private-message"),
            "refused"=>new InvalidDataException("synthetic-private-message"),
            _=>new InvalidOperationException("synthetic-private-message")
        };
        var state=new HostedCloseoutVerificationOutput{Reason="worker-open"};
        HostedCloseoutStateVerificationCommand.RecordFailure(state,failure);
        Assert.Equal(kind,state.FailureKind);Assert.Null(state.FailureSqlErrorNumber);Assert.Equal(kind=="cancelled"?"cancelled":"worker-open",state.Reason);
        Assert.Equal(0,state.WorkerOpenAttempts);Assert.Null(state.FirstWorkerOpenSqlError);Assert.False(state.QueriesStarted);NoExceptionDetails(state);
    }
    [Fact]
    public void Success_has_no_failure_number_or_kind()
    {
        var state=new HostedCloseoutVerificationOutput{Status="passed",Complete=true,Reason="verified"};
        using var json=JsonDocument.Parse(JsonSerializer.Serialize(state));
        Assert.Equal(JsonValueKind.Null,json.RootElement.GetProperty("FailureKind").ValueKind);
        Assert.Equal(JsonValueKind.Null,json.RootElement.GetProperty("FailureSqlErrorNumber").ValueKind);
    }
    private static void NoExceptionDetails(HostedCloseoutVerificationOutput state)
    {
        Assert.False(state.Complete);Assert.Equal("refused",state.Status);var json=JsonSerializer.Serialize(state);
        foreach(var secret in new[]{"synthetic-private-message","synthetic-server","synthetic-procedure","synthetic-version","SqlException","AuthenticationFailedException","InvalidOperationException","StackTrace"})Assert.DoesNotContain(secret,json);
        Assert.True(Encoding.UTF8.GetByteCount(json)<16384);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Actual_early_CLI_never_bootstraps_web_DP_providers_or_prints_poisoned_private_config(bool malformed)
    {
        var start=new ProcessStartInfo("dotnet"){RedirectStandardOutput=true,RedirectStandardError=true,UseShellExecute=false};
        start.ArgumentList.Add(typeof(DatabaseCommands).Assembly.Location);start.ArgumentList.Add("database");start.ArgumentList.Add("verify-hosted-closeout-state");
        foreach(var key in start.Environment.Keys.ToArray())if(key.StartsWith("AZURE",StringComparison.OrdinalIgnoreCase)||key.StartsWith("IDENTITY",StringComparison.OrdinalIgnoreCase)||key.StartsWith("MSI",StringComparison.OrdinalIgnoreCase)||key.Contains("ConnectionStrings",StringComparison.OrdinalIgnoreCase)||key.StartsWith("HostedCloseoutVerification",StringComparison.OrdinalIgnoreCase))start.Environment.Remove(key);
        const string secret="synthetic-private-value-must-not-appear";
        start.Environment["ConnectionStrings__Database"]=secret;start.Environment["DataProtection__KeyVaultKeyIdentifier"]=secret;start.Environment["Email__Provider"]=secret;start.Environment["Storage__Provider"]=secret;
        start.Environment["HostedCloseoutVerification__Enabled"]=malformed?"true":"false";start.Environment["HostedCloseoutVerification__ConfigurationBase64"]=malformed?Packet(HostedCloseoutStateVerificationTests.Configuration() with{ApplicationSha256=new string('0',64)}):"";
        foreach(var key in HostedCloseoutStateVerificationCommand.GateKeys)start.Environment[key]="false";
        using var process=Process.Start(start)!;var stdout=process.StandardOutput.ReadToEndAsync();var stderr=process.StandardError.ReadToEndAsync();
        try {await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));}catch{if(!process.HasExited)process.Kill(true);throw;}
        var output=await stdout;Assert.Equal(1,process.ExitCode);Assert.DoesNotContain(secret,output);Assert.Empty(await stderr);
        var line=Assert.Single(output.Split('\n',StringSplitOptions.RemoveEmptyEntries));Assert.StartsWith(HostedCloseoutStateVerificationCommand.Prefix,line);
        using var json=JsonDocument.Parse(line[HostedCloseoutStateVerificationCommand.Prefix.Length..]);Assert.False(json.RootElement.GetProperty("Complete").GetBoolean());
        Assert.Equal(0,json.RootElement.GetProperty("WorkerOpenAttempts").GetInt32());Assert.False(json.RootElement.GetProperty("QueriesStarted").GetBoolean());
        Assert.Equal("refused",json.RootElement.GetProperty("Status").GetString());Assert.True(Encoding.UTF8.GetByteCount(line)<16384);
        Assert.Equal("refused",json.RootElement.GetProperty("FailureKind").GetString());Assert.Equal(JsonValueKind.Null,json.RootElement.GetProperty("FailureSqlErrorNumber").ValueKind);
    }
    private static string Packet(HostedCloseoutVerificationConfiguration cfg)=>Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(cfg));
    private static SqlException SqlError(int number)
    {
        var errorConstructor=typeof(SqlError).GetConstructors(BindingFlags.NonPublic|BindingFlags.Instance).First(x=>x.GetParameters().Length==8);
        var error=errorConstructor.Invoke([number,(byte)1,(byte)20,"synthetic-server","synthetic-private-message","synthetic-procedure",0,null]);
        var collection=(SqlErrorCollection)Activator.CreateInstance(typeof(SqlErrorCollection),true)!;
        typeof(SqlErrorCollection).GetMethod("Add",BindingFlags.NonPublic|BindingFlags.Instance)!.Invoke(collection,[error]);
        return (SqlException)typeof(SqlException).GetMethods(BindingFlags.NonPublic|BindingFlags.Static).Single(x=>x.Name=="CreateException"&&x.GetParameters().Length==2)
            .Invoke(null,[collection,"synthetic-version"])!;
    }
}
