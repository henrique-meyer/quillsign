using System.Data;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class HostedCloseoutStateVerificationTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Actual_fixed_SQL_reader_matches_all17_typed_sets_and_refuses_changed_protected_state()
    {
        await using var db=fixture.Open();var cfg=await Seed(db);await db.Database.OpenConnectionAsync();var connection=(SqlConnection)db.Database.GetDbConnection();
        cfg=cfg with{ExpectedSets=await Expected(connection,cfg)};
        var before=await db.EmailOutbox.AsNoTracking().Where(x=>cfg.OriginalWorkIds.Contains(x.Id)).Select(x=>x.RowVersion).ToArrayAsync();
        await using(var tx=(SqlTransaction)await connection.BeginTransactionAsync(IsolationLevel.Serializable)) {
            await using var timeout=HostedCloseoutStateVerification.Command(connection,"SET LOCK_TIMEOUT 5000",tx);Assert.Same(tx,timeout.Transaction);await timeout.ExecuteNonQueryAsync();
            var actual=await HostedCloseoutStateVerification.ReadSetsAsync(connection,cfg,default,tx);Assert.Equal(17,actual.Length);
            await HostedCloseoutStateVerification.ReadVisibleSchemaAsync(connection,default,tx);await tx.RollbackAsync();
        }
        var after=await db.EmailOutbox.AsNoTracking().Where(x=>cfg.OriginalWorkIds.Contains(x.Id)).Select(x=>x.RowVersion).ToArrayAsync();
        Assert.Equal(before.Select(Convert.ToBase64String),after.Select(Convert.ToBase64String));
        var mail=await db.EmailOutbox.SingleAsync(x=>x.Id==cfg.OriginalWorkIds[0]);mail.PayloadJson+=" ";await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>HostedCloseoutStateVerification.ReadSetsAsync(connection,cfg,default));
        // A freshly supplied digest of a forbidden state is still not authority.
        mail.Status=EmailStatus.Queued;await db.SaveChangesAsync();cfg=cfg with{ExpectedSets=await Expected(connection,cfg)};
        await Assert.ThrowsAsync<InvalidDataException>(()=>HostedCloseoutStateVerification.ReadSetsAsync(connection,cfg,default));
    }

    [Fact]
    public async Task Actual_visible_catalog_is_stable_and_both_own_native_permission_contexts_are_read_only()
    {
        await using var db=fixture.Open();await db.Database.OpenConnectionAsync();var connection=(SqlConnection)db.Database.GetDbConnection();
        var schema=await HostedCloseoutStateVerification.ReadVisibleSchemaAsync(connection,default);
        Assert.Equal(17,schema.Projection.Count(x=>x[0]=="column"));
        Assert.Equal(schema.Sha256,(await HostedCloseoutStateVerification.ReadVisibleSchemaAsync(connection,default)).Sha256);
        var data=Environment.GetEnvironmentVariable("QUILLSIGN_PRIVATE_DATA");
        if(!string.IsNullOrEmpty(data)&&Directory.Exists(data)) {
            var path=Path.Combine(data,"QUILS-139-isolated-visible-schema-"+Guid.NewGuid().ToString("N")+".private.json");
            await using var file=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None);
            await JsonSerializer.SerializeAsync(file,new{Version="closeout-visible-schema-v1",schema.Sha256,schema.Projection});Console.WriteLine("Visible schema proof: "+path);
        }
        await using var command=connection.CreateCommand();command.CommandText="IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN; IF DATABASE_PRINCIPAL_ID('app_worker') IS NULL CREATE USER [app_worker] WITHOUT LOGIN;";
        await command.ExecuteNonQueryAsync();await DatabasePermissions.GrantRuntimeAsync(connection);
        command.CommandText="ALTER ROLE [app_runtime_role] ADD MEMBER [app_worker]";await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantDemoPurgeAsync(connection);await DatabasePermissions.GrantLookupRetentionAsync(connection);await DatabasePermissions.GrantEmailPilotRetentionAsync(connection);
        foreach(var worker in new[]{false,true}) {
            command.CommandText=worker?"EXECUTE AS USER='app_worker'":"EXECUTE AS USER='app_runtime'";await command.ExecuteNonQueryAsync();
            try {
                await HostedCloseoutStateVerification.DemandPermissionsAsync(connection,worker,default);
                Assert.Equal(schema.Sha256,(await HostedCloseoutStateVerification.ReadVisibleSchemaAsync(connection,default)).Sha256);
                // Native WITHOUT LOGIN is S, and must NEVER masquerade as E/MI.
                await Assert.ThrowsAsync<InvalidDataException>(()=>HostedCloseoutStateVerification.DemandCallerAsync(connection,Configuration(),worker,default));
            } finally {command.CommandText="REVERT";await command.ExecuteNonQueryAsync();}
        }
    }

    internal static HostedCloseoutVerificationConfiguration Configuration()
    {
        var expected=HostedCloseoutStateVerification.SetIndices.Select(index=>new HostedCloseoutExpectedSet(index,new string('a',64),new string('b',64),index switch{1=>23,2 or 3=>5,4=>8,5=>20,7=>3,10 or 11=>6,_=>0})).ToArray();
        return new(HostedCloseoutStateVerificationCommand.Version,Guid.NewGuid(),new string('a',40),HostedCloseoutStateVerificationCommand.ApplicationHash(),"example.database.windows.net","synthetic",
            Guid.NewGuid(),Guid.NewGuid(),Convert.ToBase64String(Guid.NewGuid().ToByteArray()),Convert.ToBase64String(Guid.NewGuid().ToByteArray()),
            Enumerable.Range(0,5).Select(_=>Guid.NewGuid()).ToArray(),Enumerable.Range(0,3).Select(_=>Guid.NewGuid()).ToArray(),Enumerable.Range(0,6).Select(_=>Guid.NewGuid()).ToArray(),expected,new string('c',64));
    }
    private static async Task<HostedCloseoutVerificationConfiguration> Seed(QuillSignDbContext db)
    {
        var cfg=Configuration();var at=DateTimeOffset.UtcNow.AddDays(-1);
        for(var n=0;n<5;n++) {db.Add(new EmailPilotRunRecord{Id=cfg.ParentRunIds[n],CreatedAt=at,ExpiresAt=at.AddMinutes(60),ManifestSha256=new byte[32],CapabilitySha256=new byte[32]});
            db.Add(new EmailPilotSecretRecord{RunId=cfg.ParentRunIds[n],ProtectedManifest="synthetic opaque parent",DeleteAfter=at.AddDays(7)});}
        foreach(var id in cfg.EnvelopeIds)db.Add(new Envelope{Id=id,SenderEmail="sender@example.invalid"});
        for(var n=0;n<8;n++)db.Add(new EmailPilotEnrollmentRecord{RunId=cfg.ParentRunIds[n%5],SubjectEnvelopeId=n<3?cfg.EnvelopeIds[n]:Guid.NewGuid(),
            Scenario=n<5?EmailPilotScenario.Completion:EmailPilotScenario.Void,EnrolledAt=at,ProtectedBinding="synthetic opaque binding"});
        await db.SaveChangesAsync();
        for(var n=0;n<20;n++)db.Add(new EmailPilotReservationRecord{RunId=cfg.ParentRunIds[0],SubjectEnvelopeId=n>=12&&n<16?null:cfg.EnvelopeIds[0],OperationId=Guid.NewGuid(),
            Kind=n<12?EmailPilotAttemptKind.Application:n<16?EmailPilotAttemptKind.Simulator:EmailPilotAttemptKind.Timestamp,
            Role=n<12?EmailPilotRole.Sender:n<16?EmailPilotRole.Simulator:EmailPilotRole.None,EncodedBytes=n==0?27903:n<16?1:0,RequestSha256=new byte[32],ReservedAt=at,ProtectedReceipt="synthetic opaque receipt"});
        for(var n=0;n<6;n++) {
            var id=cfg.OriginalWorkIds[n];var mail=new EmailOutbox{Id=id,EnvelopeId=cfg.EnvelopeIds[n<4?0:1],To="sender@example.invalid",Template=n<4?CompletionNotificationJobs.Template:VoidNotificationJobs.Template,
                PayloadJson="{\"Protected\":\"synthetic opaque payload\"}",Status=EmailStatus.Failed,LastError="pilot-delivery-unavailable",AvailableAt=at};
            db.Add(mail);db.Add(new WorkItem{Id=id,EnvelopeId=mail.EnvelopeId,Kind=WorkKind.Email,Status=WorkStatus.Failed,Attempts=1,LastError=mail.LastError,AvailableAt=at,
                PayloadJson=n<4?CompletionNotificationJobs.WorkJson(id):VoidNotificationJobs.WorkJson(id)});
        }
        await db.SaveChangesAsync();db.ChangeTracker.Clear();return cfg;
    }
    private static async Task<HostedCloseoutExpectedSet[]> Expected(SqlConnection connection,HostedCloseoutVerificationConfiguration cfg)
    {
        var expected=new List<HostedCloseoutExpectedSet>();
        foreach(var index in HostedCloseoutStateVerification.SetIndices) {
            await using var command=new SqlCommand(HostedCloseoutStateVerification.Query(index),connection);
            foreach(var (prefix,values) in new[]{("p",cfg.ParentRunIds),("r",cfg.EnvelopeIds),("w",cfg.OriginalWorkIds)})for(var n=0;n<values.Length;n++)command.Parameters.Add("@"+prefix+n,SqlDbType.UniqueIdentifier).Value=values[n];
            await using var reader=await command.ExecuteReaderAsync();var rows=new List<IReadOnlyList<object?>>();while(await reader.ReadAsync()) {var values=new object[reader.FieldCount];reader.GetValues(values);rows.Add(values);}
            var hash=HostedCloseoutStoredStateFingerprint.Compute(index,rows);expected.Add(new(index,hash.SchemaSha256,hash.Sha256,hash.Rows.Length));
        }
        return expected.ToArray();
    }
}
