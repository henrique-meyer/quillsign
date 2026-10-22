using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

// Native SQL boundary tests, not external deletion/provider authority proof.
public sealed class ProductionPurgeSqlTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Fresh_migration_matches_model_and_new_cleanup_kind_is_distinct()
    {
        await using var db=fixture.Open();Assert.False(db.Database.HasPendingModelChanges());
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());Assert.NotEqual(WorkKind.Purge,WorkKind.ProductionPurge);
        Assert.Equal(23,ProductionPurgeSql.Tables.Count);
    }
    [Fact]
    public async Task Only_explicit_worker_execute_can_remove_owned_dependencies_and_preserve_globals_and_detached_work()
    {
        var f=await Seed();await Provision();var unrelated=await CloseoutAssociation(f.Neighbor,Guid.NewGuid());
        foreach(var user in new[]{"app_runtime","app_worker"})
        {
            await using var db=fixture.Open();await db.Database.OpenConnectionAsync();
            await db.Database.ExecuteSqlRawAsync(user=="app_worker"?"EXECUTE AS USER='app_worker'":"EXECUTE AS USER='app_runtime'");
            try{var e=await Assert.ThrowsAsync<SqlException>(()=>db.Database.ExecuteSqlRawAsync("DELETE FROM dbo.AuditEvents WHERE 1=0"));Assert.Equal(229,e.Number);}
            finally{await db.Database.ExecuteSqlRawAsync("REVERT");}
        }
        await using(var denied=fixture.Open())
        {
            await denied.Database.OpenConnectionAsync();await denied.Database.ExecuteSqlRawAsync("EXECUTE AS USER='app_runtime'");
            try{await using var tx=await denied.Database.BeginTransactionAsync();var e=await Assert.ThrowsAsync<SqlException>(()=>Call(denied,f));Assert.Equal(229,e.Number);}
            finally{await denied.Database.ExecuteSqlRawAsync("REVERT");}
        }
        await using(var db=fixture.Open())
        {
            await db.Database.OpenConnectionAsync();await db.Database.ExecuteSqlRawAsync("EXECUTE AS USER='app_worker'");
            try{await using var tx=await db.Database.BeginTransactionAsync();Assert.True(await Call(db,f));await tx.CommitAsync();}
            finally{await db.Database.ExecuteSqlRawAsync("REVERT");}
        }
        await using(var db=fixture.Open())
        {
            Assert.False(await db.Envelopes.AnyAsync(x=>x.Id==f.Id));Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==f.Id));
            Assert.False(await db.Signers.AnyAsync(x=>x.EnvelopeId==f.Id));Assert.False(await db.SignerContactRevisions.AnyAsync(x=>x.EnvelopeId==f.Id));
            Assert.False(await db.SignerContactSessions.AnyAsync(x=>x.EnvelopeId==f.Id));Assert.False(await db.LookupContactRetentionSnapshots.AnyAsync(x=>x.RequestId==f.Mail));
            var work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==f.Lease.Id);Assert.Null(work.EnvelopeId);
            Assert.Equal(WorkStatus.Leased,work.Status);Assert.Equal(f.Lease.Owner,work.LeaseOwner);Assert.Equal(f.Lease.Until,work.LeaseExpiresAt);
            Assert.Equal(f.Lease.Attempt,work.Attempts);Assert.Equal(Payload(f.Id,f.Deletion),work.PayloadJson);
            Assert.True(await db.Envelopes.AnyAsync(x=>x.Id==f.Neighbor));Assert.True(await db.EmailOutbox.AnyAsync(x=>x.Id==f.GlobalMail&&x.EnvelopeId==null));
            Assert.True(await db.ProductionOperatorAccessReceipts.AnyAsync(x=>x.Id==f.OperatorReceipt));
            Assert.True(await db.EmailPilotCloseouts.AnyAsync(x=>x.Id==unrelated.Header));
            Assert.True(await db.EmailPilotCloseoutOperations.AnyAsync(x=>x.Id==unrelated.Operation&&x.SubjectEnvelopeId==f.Neighbor));
            Assert.True(await db.Suppressions.AnyAsync(x=>x.Email==f.GlobalAddress));
            await using var tx=await db.Database.BeginTransactionAsync();Assert.False(await Call(db,f));await tx.RollbackAsync();
        }
    }
    [Theory]
    [InlineData("owner")][InlineData("attempt")][InlineData("deadline")][InlineData("rowversion")][InlineData("policy")]
    [InlineData("counts")][InlineData("unknown-count")][InlineData("request-prefix")][InlineData("control-prefix")]
    [InlineData("no-transaction")][InlineData("expired-lease")][InlineData("payload")][InlineData("demo")][InlineData("unreleased-hold")]
    public async Task Mixed_or_changed_scope_refuses_without_removing_private_rows(string fault)
    {
        var f=await Seed();
        await using var db=fixture.Open();
        if(fault=="payload")await db.WorkItems.Where(x=>x.Id==f.Lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
        if(fault=="demo")await db.Envelopes.Where(x=>x.Id==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.IsDemo,true));
        if(fault=="unreleased-hold")
        {
            var hash=SHA256.HashData(Guid.NewGuid().ToByteArray());
            db.ProductionHoldRequests.Add(new(){CommandId=Guid.NewGuid(),EnvelopeId=f.Id,HoldId=Guid.NewGuid(),Revision=1,Operation=0,
                At=DateTimeOffset.UtcNow,PolicySha256=f.Policy,CommandSha256=new string('0',64),ProtectedEvidence=new string('x',64),Hash=hash});
            await db.SaveChangesAsync();f=f with{Revision=1,Fence=Convert.ToHexStringLower(hash)};f.Counts["ProductionHoldRequests"]=1;
        }
        await db.Database.OpenConnectionAsync();await using var tx=fault=="no-transaction"?null:await db.Database.BeginTransactionAsync();
        var error=await Assert.ThrowsAsync<SqlException>(()=>Call(db,f,fault));Assert.Equal(50001,error.Number);
        if(tx is not null)await tx.RollbackAsync();
        await using var check=fixture.Open();Assert.True(await check.Envelopes.AnyAsync(x=>x.Id==f.Id));
        Assert.True(await check.ProductionRetentionPolicies.AnyAsync(x=>x.EnvelopeId==f.Id));
        Assert.True(await check.EmailOutbox.AnyAsync(x=>x.Id==f.Mail));Assert.True(await check.AuditEvents.AnyAsync(x=>x.EnvelopeId==f.Id));
    }
    [Theory]
    [InlineData("rollback")][InlineData("lost-ack")]
    public async Task Caller_transaction_controls_commit_and_detached_absence_is_only_factual_recovery(string outcome)
    {
        var f=await Seed();
        await using(var db=fixture.Open())
        {
            await using var tx=await db.Database.BeginTransactionAsync();Assert.True(await Call(db,f));
            if(outcome=="rollback")await tx.RollbackAsync();else await tx.CommitAsync();
        }
        await using(var check=fixture.Open())
        {
            Assert.Equal(outcome=="rollback",await check.Envelopes.AnyAsync(x=>x.Id==f.Id));
            if(outcome=="lost-ack")
            {
                await using var tx=await check.Database.BeginTransactionAsync();Assert.False(await Call(check,f));
                var e=await Assert.ThrowsAsync<SqlException>(()=>Call(check,f,"owner"));Assert.Equal(50001,e.Number);
            }
        }
    }
    [Fact]
    public async Task Closeout_direct_subject_association_refuses_without_deleting_global_receipts()
    {
        var f=await Seed();var linked=await CloseoutAssociation(f.Id,f.Lease.Id);await using var db=fixture.Open();
        await using var tx=await db.Database.BeginTransactionAsync();var e=await Assert.ThrowsAsync<SqlException>(()=>Call(db,f));
        Assert.Equal(50001,e.Number);Assert.Contains("A closeout association prevents production deletion.",e.Message);
        await tx.RollbackAsync();Assert.True(await db.Envelopes.AnyAsync(x=>x.Id==f.Id));
        Assert.True(await db.EmailPilotCloseouts.AnyAsync(x=>x.Id==linked.Header));
        Assert.True(await db.EmailPilotCloseoutOperations.AnyAsync(x=>x.Id==linked.Operation&&x.SubjectEnvelopeId==f.Id));
    }
    private async Task<(Guid Header,Guid Operation)> CloseoutAssociation(Guid record,Guid work)
    {
        await using var db=fixture.Open();var now=DateTimeOffset.UtcNow;
        var header=new EmailPilotCloseoutHeaderRecord{Id=Guid.NewGuid(),CreatedAt=now,Until=now.AddMinutes(30),DeleteAfter=now.AddDays(1),
            CapabilitySha256=new byte[32],ManifestSha256=new byte[32],ProtectedManifest="synthetic-global-closeout"};
        db.Add(header);await db.SaveChangesAsync();
        var operation=new EmailPilotCloseoutOperationRecord{Id=Guid.NewGuid(),CloseoutId=header.Id,Kind=0,Step=6,SubjectEnvelopeId=record,
            WorkId=work,At=now,RequestSha256=new byte[32],ProtectedReceipt="synthetic-global-closeout-receipt"};
        db.Add(operation);await db.SaveChangesAsync();return(header.Id,operation.Id);
    }
    private sealed record State(Guid Id,Guid Deletion,WorkLease Lease,byte[] Version,string Policy,DateTimeOffset Eligible,
        SortedDictionary<string,long> Counts,Guid Mail,Guid Neighbor,Guid GlobalMail,Guid OperatorReceipt,string GlobalAddress,long Revision=0,string? Fence=null);
    private async Task<State> Seed()
    {
        var created=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddDays(-3).ToUnixTimeSeconds());
        var e=new Envelope{SenderEmail="sql-"+Guid.NewGuid().ToString("N")+"@example.invalid",CreatedAt=created};
        await using var db=fixture.Open();await using(var tx=await db.Database.BeginTransactionAsync())
        {
            db.Add(e);await new ProductionRetentionLedger(db,new(db,TimeProvider.System),TimeProvider.System).PrepareNewLockedAsync(e,new(){
                Version="synthetic-sql-v1",ArchiveResponsibility="Synthetic module tests retain no actual agreement",AbandonedDraftDays=1,
                ExpiredDays=1,DeclinedDays=1,VoidedDays=1,CompletedDays=1});await tx.CommitAsync();
        }
        var signer=new Signer{EnvelopeId=e.Id,Order=1,FullName="Synthetic SQL signer",Email="signer@example.invalid"};
        var mail=new EmailOutbox{EnvelopeId=e.Id,To=e.SenderEmail,Template="synthetic",PayloadJson="{}"};
        var neighbor=new Envelope{SenderEmail="neighbor-"+Guid.NewGuid().ToString("N")+"@example.invalid"};
        var globalAddress="global-"+Guid.NewGuid().ToString("N")+"@example.invalid";
        var globalMail=new EmailOutbox{To=globalAddress,Template="synthetic",PayloadJson="{}"};
        var receipt=new ProductionOperatorAccessReceipt{Id=Guid.NewGuid(),At=DateTimeOffset.UtcNow,PayloadSha256=new byte[32],ProtectedReceipt="opaque-global-observability"};
        var deletion=Guid.NewGuid();var owner=Guid.NewGuid();var until=DateTimeOffset.UtcNow.AddMinutes(10);
        var work=new WorkItem{EnvelopeId=e.Id,Kind=WorkKind.ProductionPurge,PayloadJson=Payload(e.Id,deletion),Status=WorkStatus.Leased,
            Attempts=1,LeaseOwner=owner,LeaseExpiresAt=until,AvailableAt=DateTimeOffset.UtcNow.AddMinutes(-1)};
        db.AddRange(signer,mail,neighbor,globalMail,receipt,work,new Suppression{Email=globalAddress,Reason=SuppressionReason.Unsubscribe});await db.SaveChangesAsync();
        var contact=new SignerContactRevisionRecord{Id=Guid.NewGuid(),EnvelopeId=e.Id,SignerId=signer.Id,Number=1,
            ChangedAt=DateTimeOffset.UtcNow,EvidenceJson="{}",RetirementJson="{}"};db.Add(contact);await db.SaveChangesAsync();
        db.AddRange(new SignerContactSession{SessionId=Guid.NewGuid(),EnvelopeId=e.Id,SignerId=signer.Id,RevisionId=contact.Id,
            SessionSha256=new byte[32],CreatedAt=DateTimeOffset.UtcNow,ExpiresAt=DateTimeOffset.UtcNow.AddMinutes(5)},
            new AuthToken{EnvelopeId=e.Id,Purpose=TokenPurpose.SignerAccess,PartyType=PartyType.Signer,PartyId=signer.Id,SignerContactRevisionId=contact.Id,
                Email=signer.Email,TokenSha256=SHA256.HashData(Guid.NewGuid().ToByteArray()),ExpiresAt=DateTimeOffset.UtcNow.AddMinutes(5)},
            new DocumentField{EnvelopeId=e.Id,SignerId=signer.Id,Type=FieldType.Text,Page=1,X=.1m,Y=.1m,Width=.2m,Height=.1m},
            new LookupContactRetentionSnapshot{RequestId=mail.Id,PolicyVersion="synthetic-v1",Days=1,StartedAt=created,DeleteAfter=created.AddDays(1)});
        await db.SaveChangesAsync();db.ChangeTracker.Clear();
        var counts=new SortedDictionary<string,long>(StringComparer.Ordinal);
        foreach(var table in ProductionPurgeSql.Tables)
        {
            var where=table=="Envelopes"?"[Id]=@id":table=="LookupContactRetentionSnapshots"?"[RequestId] IN(SELECT [Id] FROM dbo.EmailOutbox WHERE [EnvelopeId]=@id)":"[EnvelopeId]=@id";
#pragma warning disable EF1003
            counts.Add(table,await db.Database.SqlQueryRaw<long>("SELECT COUNT_BIG(*) AS [Value] FROM [dbo].["+table+"] WHERE "+where,new SqlParameter("@id",e.Id)).SingleAsync());
#pragma warning restore EF1003
        }
        var parent=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==e.Id);var policy=await db.ProductionRetentionPolicies.AsNoTracking().SingleAsync(x=>x.EnvelopeId==e.Id);
        return new(e.Id,deletion,new(work.Id,owner,WorkKind.ProductionPurge,1,until),parent.RowVersion,policy.PolicySha256,created.AddDays(1),counts,mail.Id,neighbor.Id,globalMail.Id,receipt.Id,globalAddress);
    }
    private async Task Provision()
    {
        await using var db=fixture.Open();await db.Database.OpenConnectionAsync();
        await db.Database.ExecuteSqlRawAsync("IF USER_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN; IF USER_ID('app_worker') IS NULL CREATE USER [app_worker] WITHOUT LOGIN;");
        var c=(SqlConnection)db.Database.GetDbConnection();await DatabasePermissions.GrantRuntimeAsync(c);
        await db.Database.ExecuteSqlRawAsync("ALTER ROLE app_runtime_role ADD MEMBER app_worker");await DatabasePermissions.GrantProductionPurgeAsync(c);
    }
    private static string Payload(Guid id,Guid deletion)=>JsonSerializer.Serialize(new{Version="production-delete-work-v1",RecordId=id,DeletionId=deletion});
    private static async Task<bool> Call(QuillSignDbContext db,State f,string? fault=null)
    {
        await using var c=((SqlConnection)db.Database.GetDbConnection()).CreateCommand();c.Transaction=(SqlTransaction?)db.Database.CurrentTransaction?.GetDbTransaction();
        c.CommandType=CommandType.StoredProcedure;c.CommandText="dbo.RemoveExpiredProductionPrivateRecords";c.CommandTimeout=30;
        c.Parameters.AddWithValue("@EnvelopeId",f.Id);c.Parameters.AddWithValue("@DeletionId",f.Deletion);
        c.Parameters.AddWithValue("@WorkId",f.Lease.Id);c.Parameters.AddWithValue("@Owner",fault=="owner"?Guid.NewGuid():f.Lease.Owner);
        c.Parameters.AddWithValue("@Attempt",f.Lease.Attempt+(fault=="attempt"?1:0));c.Parameters.AddWithValue("@Until",fault=="expired-lease"?DateTimeOffset.UtcNow.AddSeconds(-1):f.Lease.Until);
        c.Parameters.AddWithValue("@ParentRowVersion",fault=="rowversion"?new byte[8]:f.Version);
        c.Parameters.AddWithValue("@PolicySha256",fault=="policy"?new string('0',64):f.Policy);
        c.Parameters.AddWithValue("@EligibleAt",f.Eligible.AddSeconds(fault=="deadline"?1:0));
        c.Parameters.AddWithValue("@RequestRevision",f.Revision+(fault=="request-prefix"?1:0));c.Parameters.AddWithValue("@FenceHash",(object?)f.Fence??DBNull.Value);
        c.Parameters.AddWithValue("@ControlSequence",fault=="control-prefix"?1:0);c.Parameters.AddWithValue("@ControlHash",DBNull.Value);
        var counts=new SortedDictionary<string,long>(f.Counts,StringComparer.Ordinal);if(fault=="counts")counts["EmailOutbox"]++;if(fault=="unknown-count")counts.Add("UnknownFutureTable",0);
        c.Parameters.AddWithValue("@CountsJson",JsonSerializer.Serialize(counts));c.Parameters.AddWithValue("@PlanSha256",new string('a',64));c.Parameters.AddWithValue("@StorageReceiptSha256",new string('b',64));
        return Convert.ToBoolean(await c.ExecuteScalarAsync());
    }
}