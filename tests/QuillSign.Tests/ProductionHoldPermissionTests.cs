using System.Data.Common;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionHoldPermissionTests
{
    [Fact]
    public async Task Explicit_native_Sql_mode_grants_actual_context_select_insert_and_denies_mutation_only_after_opt_in()
    {
        await using var f=await NativeProductionHoldPrincipals.FreshAsync();
        var ids=await NativeProductionHoldPrincipals.ProvisionExplicitSqlPrincipalsAsync(f.Database,false);
        foreach(var name in new[]{"app_runtime","app_worker"})
        {
            await using var db=NativeProductionHoldPrincipals.OpenAs(f.Database,name);
            foreach(var table in new[]{"ProductionHoldRequests","ProductionHoldControls"})
            {
                var sql=table=="ProductionHoldRequests"?"SELECT TOP(0) * FROM dbo.ProductionHoldRequests":"SELECT TOP(0) * FROM dbo.ProductionHoldControls";
                var e=await Assert.ThrowsAsync<SqlException>(()=>db.Database.ExecuteSqlRawAsync(sql));Assert.Equal(229,e.Number);
            }
        }
        await using(var owner=f.Database.Open())
        {
            await owner.Database.OpenConnectionAsync();var c=(SqlConnection)owner.Database.GetDbConnection();
            await DatabasePermissions.GrantProductionHoldsAsync(c,"Sql",ids.RuntimeSid,ids.WorkerSid);
            await DatabasePermissions.GrantProductionHoldsAsync(c,"Sql",ids.RuntimeSid,ids.WorkerSid);
            await using var command=c.CreateCommand();
            command.CommandText="SELECT COUNT(*) FROM sys.database_permissions WHERE grantee_principal_id=DATABASE_PRINCIPAL_ID(N'app_production_hold_role')";
            Assert.Equal(8,Convert.ToInt32(await command.ExecuteScalarAsync()));
            command.CommandText="SELECT COUNT(*) FROM sys.database_role_members WHERE role_principal_id=DATABASE_PRINCIPAL_ID(N'app_production_hold_role')";
            Assert.Equal(2,Convert.ToInt32(await command.ExecuteScalarAsync()));
        }
        foreach(var name in new[]{"app_runtime","app_worker"})
        {
            Guid record;string policy;
            await using(var owner=f.Database.Open())
            {
                var e=new Envelope{SenderEmail="hold-role-"+Guid.NewGuid().ToString("N")+"@example.invalid",CreatedAt=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds())};
                await using var tx=await owner.Database.BeginTransactionAsync();owner.Add(e);
                await new ProductionRetentionLedger(owner,new(owner,TimeProvider.System),TimeProvider.System).PrepareNewLockedAsync(e,new(){Version="synthetic-role-v1",
                    ArchiveResponsibility="Synthetic role module evidence only",AbandonedDraftDays=1,ExpiredDays=1,DeclinedDays=1,VoidedDays=1,CompletedDays=1});
                await tx.CommitAsync();record=e.Id;policy=(await owner.ProductionRetentionPolicies.SingleAsync(x=>x.EnvelopeId==record)).PolicySha256;
            }
            await using var db=NativeProductionHoldPrincipals.OpenAs(f.Database,name);
            await db.Database.OpenConnectionAsync();await using(var who=db.Database.GetDbConnection().CreateCommand())
            {who.CommandText="SELECT USER_NAME()";Assert.Equal(name,Convert.ToString(await who.ExecuteScalarAsync()));}
            var hold=Guid.NewGuid();var plan=Guid.NewGuid();
            db.ProductionHoldRequests.Add(new(){CommandId=Guid.NewGuid(),EnvelopeId=record,HoldId=hold,Revision=1,Operation=0,At=DateTimeOffset.UtcNow,
                PolicySha256=policy,CommandSha256=new string('a',64),ProtectedEvidence=new string('x',64),Hash=SHA256.HashData(Guid.NewGuid().ToByteArray())});
            db.ProductionHoldControls.Add(new(){EventId=plan,PlanId=plan,EnvelopeId=record,HoldId=hold,Sequence=1,Kind=0,At=DateTimeOffset.UtcNow,
                PolicySha256=policy,PlanSha256=new string('b',64),PayloadSha256=new string('c',64),PlanPayload=[1],ProtectedEvidence=new string('x',64),Hash=new byte[32]});
            await db.SaveChangesAsync();db.ChangeTracker.Clear();
            Assert.Equal(1,await db.ProductionHoldRequests.CountAsync(x=>x.EnvelopeId==record));Assert.Equal(1,await db.ProductionHoldControls.CountAsync(x=>x.EnvelopeId==record));
            foreach(var table in new[]{"ProductionHoldRequests","ProductionHoldControls"})foreach(var verb in new[]{"UPDATE","DELETE"})
            {
                var sql=verb=="UPDATE"?"UPDATE dbo."+table+" SET ProtectedEvidence=N'forbidden' WHERE 1=0":"DELETE FROM dbo."+table+" WHERE 1=0";
                var denied=await Assert.ThrowsAsync<SqlException>(()=>db.Database.ExecuteSqlRawAsync(sql));Assert.Equal(229,denied.Number);
            }
            await using var matrix=db.Database.GetDbConnection().CreateCommand();
            foreach(var table in new[]{"ProductionHoldRequests","ProductionHoldControls"})foreach(var permission in new[]{"SELECT","INSERT","UPDATE","DELETE","ALTER"})
            {
                matrix.CommandText="SELECT HAS_PERMS_BY_NAME(@Object,'OBJECT',@Permission)";matrix.Parameters.Clear();
                matrix.Parameters.Add(new SqlParameter("@Object","dbo."+table));matrix.Parameters.Add(new SqlParameter("@Permission",permission));
                Assert.Equal(permission is "SELECT" or "INSERT"?1:0,Convert.ToInt32(await matrix.ExecuteScalarAsync()));
            }
        }
    }
    [Theory]
    [InlineData("runtime-sid")][InlineData("worker-sid")][InlineData("External")][InlineData("missing-worker")]
    [InlineData("role-user")][InlineData("role-owner")][InlineData("role-member")][InlineData("wide-permission")][InlineData("inherited-role")]
    public async Task Existing_identity_type_SID_or_role_corruption_refuses_without_granting_access(string fault)
    {
        await using var f=await NativeProductionHoldPrincipals.FreshAsync();var ids=await NativeProductionHoldPrincipals.ProvisionExplicitSqlPrincipalsAsync(f.Database,false);
        await using var db=f.Database.Open();await db.Database.OpenConnectionAsync();
        if(fault=="missing-worker")await db.Database.ExecuteSqlRawAsync("DROP USER app_worker");
        if(fault=="role-user")await db.Database.ExecuteSqlRawAsync("CREATE USER app_production_hold_role WITHOUT LOGIN");
        if(fault is "role-owner" or "role-member" or "wide-permission" or "inherited-role")
        {
            await db.Database.ExecuteSqlRawAsync("CREATE ROLE app_production_hold_role AUTHORIZATION dbo");
            if(fault=="role-owner")await db.Database.ExecuteSqlRawAsync("ALTER AUTHORIZATION ON ROLE::app_production_hold_role TO app_runtime");
            if(fault=="role-member")await db.Database.ExecuteSqlRawAsync("CREATE USER unexpected_member WITHOUT LOGIN;ALTER ROLE app_production_hold_role ADD MEMBER unexpected_member");
            if(fault=="wide-permission")await db.Database.ExecuteSqlRawAsync("GRANT SELECT ON dbo.Envelopes TO app_production_hold_role");
            if(fault=="inherited-role")await db.Database.ExecuteSqlRawAsync("ALTER ROLE db_datareader ADD MEMBER app_production_hold_role");
        }
        var runtime=fault is "runtime-sid" or "External"?Guid.NewGuid().ToByteArray():ids.RuntimeSid;
        var worker=fault is "worker-sid" or "External"?Guid.NewGuid().ToByteArray():ids.WorkerSid;
        var error=await Assert.ThrowsAsync<SqlException>(()=>DatabasePermissions.GrantProductionHoldsAsync((SqlConnection)db.Database.GetDbConnection(),fault=="External"?"External":"Sql",runtime,worker));Assert.Equal(50001,error.Number);
        await using var check=NativeProductionHoldPrincipals.OpenAs(f.Database,"app_runtime");
        var refused=await Assert.ThrowsAsync<SqlException>(()=>check.Database.ExecuteSqlRawAsync("SELECT TOP(0) * FROM dbo.ProductionHoldRequests"));Assert.Equal(229,refused.Number);
    }
    [Theory]
    [InlineData(null)][InlineData("")][InlineData("0x")][InlineData("0x1")][InlineData("ab")][InlineData("0X00")][InlineData("0xgg")]
    public void Missing_or_malformed_private_sid_selector_refuses(string? value)=>Assert.Throws<ArgumentException>(()=>DatabasePermissions.ReadProductionPrincipalSid(value));
    [Theory]
    [InlineData("external")][InlineData("Sql ")][InlineData("")][InlineData("Automatic")]
    public void Principal_mode_never_downgrades_or_normalizes(string mode)=>Assert.Throws<ArgumentException>(()=>DatabasePermissions.ValidateProductionHoldPrincipals(mode,Guid.NewGuid().ToByteArray(),Guid.NewGuid().ToByteArray()));
    [Fact]
    public void Sid_contract_requires_exact_distinct_owned_nonempty_values()
    {
        var sid=Guid.NewGuid().ToByteArray();var another=Guid.NewGuid().ToByteArray();
        Assert.Equal("E",DatabasePermissions.ValidateProductionHoldPrincipals("External",sid,another));
        Assert.Equal("S",DatabasePermissions.ValidateProductionHoldPrincipals("Sql",sid,another));
        Assert.Throws<ArgumentException>(()=>DatabasePermissions.ValidateProductionHoldPrincipals("External",sid.AsSpan(1),another));
        Assert.Throws<ArgumentException>(()=>DatabasePermissions.ValidateProductionHoldPrincipals("Sql",sid,sid));
        Assert.Throws<ArgumentException>(()=>DatabasePermissions.ValidateProductionHoldPrincipals("Sql",[],another));
        Assert.Equal(sid,DatabasePermissions.ReadProductionPrincipalSid("0x"+Convert.ToHexString(sid)));
    }
}

// Real native database-context proof, not Entra/SQL-login authentication proof.
internal static class NativeProductionHoldPrincipals
{
    internal sealed record Expected(byte[] RuntimeSid,byte[] WorkerSid);
    internal static async Task<Expected> ProvisionExplicitSqlPrincipalsAsync(SqlDatabaseFixture fixture,bool grantHolds=true)
    {
        await using var db=fixture.Open();await db.Database.OpenConnectionAsync();
        await db.Database.ExecuteSqlRawAsync("IF USER_ID('app_runtime') IS NULL CREATE USER app_runtime WITHOUT LOGIN;IF USER_ID('app_worker') IS NULL CREATE USER app_worker WITHOUT LOGIN;");
        var c=(SqlConnection)db.Database.GetDbConnection();await DatabasePermissions.GrantRuntimeAsync(c);
        await db.Database.ExecuteSqlRawAsync("ALTER ROLE app_runtime_role ADD MEMBER app_worker");
        await using var command=c.CreateCommand();command.CommandText="SELECT sid FROM sys.database_principals WHERE name=N'app_runtime' AND type='S'";
        var runtime=(byte[])(await command.ExecuteScalarAsync()??throw new InvalidDataException());
        command.CommandText="SELECT sid FROM sys.database_principals WHERE name=N'app_worker' AND type='S'";
        var worker=(byte[])(await command.ExecuteScalarAsync()??throw new InvalidDataException());
        if(grantHolds)await DatabasePermissions.GrantProductionHoldsAsync(c,"Sql",runtime,worker);
        return new(runtime.ToArray(),worker.ToArray());
    }
    internal static QuillSignDbContext OpenAs(SqlDatabaseFixture fixture,string principal)
    {
        if(principal is not("app_runtime" or "app_worker"))throw new ArgumentException("A fixed native application principal is required.");
        using var source=fixture.Open();var cs=new SqlConnectionStringBuilder(source.Database.GetConnectionString()){Pooling=false};
        return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(cs.ConnectionString).AddInterceptors(new Principal(principal)).Options);
    }
    private sealed class Principal(string name):DbConnectionInterceptor
    {
        private string Command=>name=="app_runtime"?"EXECUTE AS USER='app_runtime'":"EXECUTE AS USER='app_worker'";
        public override void ConnectionOpened(DbConnection connection,ConnectionEndEventData eventData)
        {using var c=connection.CreateCommand();c.CommandText=Command;c.ExecuteNonQuery();}
        public override async Task ConnectionOpenedAsync(DbConnection connection,ConnectionEndEventData eventData,CancellationToken cancellationToken=default)
        {await using var c=connection.CreateCommand();c.CommandText=Command;await c.ExecuteNonQueryAsync(cancellationToken);}
    }
    internal static async Task<Fresh> FreshAsync(){var db=new SqlDatabaseFixture();await db.InitializeAsync();return new(db);}
    internal sealed class Fresh(SqlDatabaseFixture database):IAsyncDisposable
    {internal SqlDatabaseFixture Database=>database;public async ValueTask DisposeAsync()=>await database.DisposeAsync();}
}
