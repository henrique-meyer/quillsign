using System.Collections.Concurrent;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Azure.Storage.Blobs;
using Microsoft.Data.SqlClient;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Storage;
using Run=QuillSign.Tests.CompletionSealOutputTests.Run;

namespace QuillSign.Tests;

public sealed class CompletionUploadRetentionTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Actual_Azurite_fixed_deadline_publication_is_labeled_development_write_once_and_preserves_exact_files()
    {
        await using var run=await Run.Create(fixture,uploadRetentionDays:7);var pair=(await run.Prepare())!;var snapshot=await Policy(run);
        var blobs=run.Signing.H.App.Services.GetRequiredService<BlobServiceClient>();var store=new AzureCompletionFinalStore(blobs,run.Signing.H.Clock,run.Seal.App.Environment,true);
        await using var db=fixture.Open();await db.Database.OpenConnectionAsync();var connection=(SqlConnection)db.Database.GetDbConnection();await using var command=connection.CreateCommand();
        command.CommandText="IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN";await command.ExecuteNonQueryAsync();await DatabasePermissions.GrantRuntimeAsync(connection);
        command.CommandText="EXECUTE AS USER = 'app_runtime'";await command.ExecuteNonQueryAsync();PublishedCompletion? result=null;
        try {
            result=(await Service(run,db,store).PublishAsync(snapshot.EnvelopeId))!;
            Assert.Equal(snapshot.DeleteAfter,(await run.Signing.Refresh()).PurgeAfter);Assert.Equal(FinalProtection.DevelopmentWriteOnce,result.Executed.Protection);Assert.Null(result.Executed.ProtectedUntil);
            Assert.Equal(pair.Executed.Pdf.Bytes,result.ExecutedBytes);Assert.Equal(pair.Certificate.Pdf.Bytes,result.CertificateBytes);
            var read=(await Service(run,db,store).ReadAsync(snapshot.EnvelopeId))!;Assert.Equal(result.ExecutedBytes,read.ExecutedBytes);Assert.Equal(result.CertificateBytes,read.CertificateBytes);
        }
        finally {
            command.CommandText="REVERT";await command.ExecuteNonQueryAsync();
            if(result is not null)foreach(var value in new[]{result.Executed,result.Certificate})await blobs.GetBlobContainerClient("final").GetBlobClient($"{value.Document.EnvelopeId:N}/{value.Document.Kind.ToString().ToLowerInvariant()}/{value.Document.ObjectId:N}").DeleteIfExistsAsync();
        }
    }

    [Fact]
    public async Task Genuine_two_signer_publication_uses_the_upload_deadline_after_session_expiry_and_preserves_historical_reads()
    {
        await using var run=await Run.Create(fixture,uploadRetentionDays:7);var snapshot=await Policy(run);Advance(run,TimeSpan.FromHours(3));var pair=(await run.Prepare())!;
        var store=new Store(run.Signing.H.Clock);await using var db=fixture.Open();var service=Service(run,db,store);
        var original=run.Signing.Envelope.SentPdfSha256!.ToArray();var result=(await service.PublishAsync(snapshot.EnvelopeId))!;
        Assert.Equal(pair.Executed.Pdf.Bytes,result.ExecutedBytes);Assert.Equal(pair.Certificate.Pdf.Bytes,result.CertificateBytes);
        var envelope=await run.Signing.Refresh();Assert.Equal(snapshot.DeleteAfter,envelope.PurgeAfter);Assert.Equal(EnvelopeStatus.Completed,envelope.Status);
        Assert.NotEqual(result.CompletedAt.AddDays(7),envelope.PurgeAfter);Assert.Equal(original,envelope.SentPdfSha256);
        var intent=await db.CompletionPublicationIntents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==snapshot.EnvelopeId);Assert.Equal(7,intent.RetentionDays);
        using(var json=JsonDocument.Parse(intent.StageBindingsJson))Assert.Equal(snapshot.DeleteAfter,json.RootElement.GetProperty("UploadRetention").GetProperty("DeleteAfter").GetDateTimeOffset());
        Assert.All(store.Until,x=>Assert.Equal(snapshot.DeleteAfter,x));Assert.Equal(2,store.Objects.Count);Assert.Equal(2,run.Seal.Requests);
        var writes=store.Writes;Advance(run,TimeSpan.FromDays(8));run.Seal.Options.Pfx.Path="unavailable";
        var replay=(await Service(run,db,store).PublishAsync(snapshot.EnvelopeId))!;Assert.Equal(result.ExecutedBytes,replay.ExecutedBytes);Assert.Equal(result.CertificateBytes,replay.CertificateBytes);
        Assert.Equal(writes,store.Writes);Assert.Equal(2,run.Seal.Requests);Assert.Equal(snapshot.DeleteAfter,(await run.Signing.Refresh()).PurgeAfter);
    }

    [Theory]
    [InlineData(FinalDocumentKind.Executed)][InlineData(FinalDocumentKind.Certificate)]
    public async Task Lost_final_write_acknowledgements_reuse_exact_targets_and_the_original_deadline(FinalDocumentKind lost)
    {
        await using var run=await Run.Create(fixture,uploadRetentionDays:7);_=await run.Prepare();var snapshot=await Policy(run);var store=new Store(run.Signing.H.Clock) {Lose=lost};
        await using(var failed=fixture.Open())await Assert.ThrowsAsync<IOException>(()=>Service(run,failed,store).PublishAsync(snapshot.EnvelopeId));
        var old=store.Objects.Keys.ToArray();Advance(run,TimeSpan.FromHours(3));await using var db=fixture.Open();var result=await Service(run,db,store).PublishAsync(snapshot.EnvelopeId);Assert.NotNull(result);
        Assert.All(old,x=>Assert.Contains(x,store.Objects.Keys));Assert.Equal(2,store.Objects.Count);Assert.All(store.Until,x=>Assert.Equal(snapshot.DeleteAfter,x));
        Assert.Equal(snapshot.DeleteAfter,(await run.Signing.Refresh()).PurgeAfter);Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==snapshot.EnvelopeId && x.Event=="completed"));
    }

    [Theory]
    [InlineData("lost")][InlineData("rollback")][InlineData("cancel")]
    public async Task SQL_acknowledgement_rollback_and_postcommit_cancellation_preserve_one_fixed_publication(string mode)
    {
        await using var run=await Run.Create(fixture,uploadRetentionDays:7);_=await run.Prepare();var snapshot=await Policy(run);var store=new Store(run.Signing.H.Clock);using var stop=new CancellationTokenSource();
        var faults=new CompletionSealOutputTests.Faults {Event="completed",LoseCommit=mode=="lost",RejectCommit=mode=="rollback",CancelAfterCommit=mode=="cancel" ? stop : null};
        await using var baseline=fixture.Open();var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(faults);
        await using(var db=new QuillSignDbContext(options.Options)) {
            if(mode=="rollback")await Assert.ThrowsAsync<IOException>(()=>Service(run,db,store).PublishAsync(snapshot.EnvelopeId));
            else if(mode=="cancel")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Service(run,db,store).PublishAsync(snapshot.EnvelopeId,stop.Token));
            else Assert.NotNull(await Service(run,db,store).PublishAsync(snapshot.EnvelopeId));
        }
        Assert.Equal(mode=="rollback" ? EnvelopeStatus.Sent : EnvelopeStatus.Completed,(await run.Signing.Refresh()).Status);
        Advance(run,TimeSpan.FromHours(3));await using var recovered=fixture.Open();var result=(await Service(run,recovered,store).PublishAsync(snapshot.EnvelopeId))!;
        Assert.Equal(snapshot.DeleteAfter,(await run.Signing.Refresh()).PurgeAfter);Assert.All(store.Until,x=>Assert.Equal(snapshot.DeleteAfter,x));Assert.Equal(2,store.Objects.Count);
        Assert.Equal(1,await recovered.CompletionPublicationResults.CountAsync(x=>x.EnvelopeId==snapshot.EnvelopeId));Assert.Equal(2,run.Seal.Requests);Assert.Equal(result.Executed.Sha256,SHA256.HashData(result.ExecutedBytes));
    }

    [Theory]
    [InlineData("before")][InlineData("executed")][InlineData("certificate")][InlineData("intent-audit")][InlineData("completed-audit")]
    public async Task Crossing_the_exact_deadline_cannot_publish_or_extend_the_interval(string phase)
    {
        await using var run=await Run.Create(fixture,uploadRetentionDays:7);_=await run.Prepare();var snapshot=await Policy(run);var store=new Store(run.Signing.H.Clock);var advanced=false;
        void Expire() {if(advanced)return;advanced=true;Advance(run,snapshot.DeleteAfter-run.Signing.H.Clock.GetUtcNow());}
        if(phase=="before")Expire();
        if(phase is "executed" or "certificate")store.AfterWrite=target=> {if(target.Kind==(phase=="executed" ? FinalDocumentKind.Executed : FinalDocumentKind.Certificate))Expire();};
        await using var baseline=fixture.Open();var builder=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString());
        if(phase is "intent-audit" or "completed-audit")builder.AddInterceptors(new AuditAction(phase=="intent-audit" ? "completion_publication_prepared" : "completed",Expire));
        await using(var db=new QuillSignDbContext(builder.Options))await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>Service(run,db,store).PublishAsync(snapshot.EnvelopeId));
        Assert.True(advanced);Assert.Equal(EnvelopeStatus.Sent,(await run.Signing.Refresh()).Status);Assert.False(await baseline.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==snapshot.EnvelopeId));
        Assert.False(await baseline.AuditEvents.AnyAsync(x=>x.EnvelopeId==snapshot.EnvelopeId && x.Event=="completed"));
        Assert.All(store.Until,x=>Assert.Equal(snapshot.DeleteAfter,x));
        await using var retry=fixture.Open();await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>Service(run,retry,store).PublishAsync(snapshot.EnvelopeId));
    }

    [Theory]
    [InlineData(-1,false)][InlineData(1,false)][InlineData(0,true)]
    public async Task Short_overlong_or_indefinite_protection_cannot_confirm_a_fixed_deletion_promise(int skewSeconds,bool hold)
    {
        await using var run=await Run.Create(fixture,uploadRetentionDays:7);_=await run.Prepare();var store=new Store(run.Signing.H.Clock) {Skew=TimeSpan.FromSeconds(skewSeconds),Hold=hold};
        await using var db=fixture.Open();await Assert.ThrowsAsync<InvalidDataException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id));
        Assert.False(await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id));Assert.Equal(EnvelopeStatus.Sent,(await run.Signing.Refresh()).Status);
    }

    [Theory]
    [InlineData("snapshot")][InlineData("rebind")][InlineData("strip")]
    public async Task Rebound_immutable_policy_or_rehashed_intent_cannot_change_a_prepared_deadline(string mode)
    {
        await using var run=await Run.Create(fixture,uploadRetentionDays:7);_=await run.Prepare();var snapshot=await Policy(run);var store=new Store(run.Signing.H.Clock) {Lose=FinalDocumentKind.Executed};
        await using(var initial=fixture.Open())await Assert.ThrowsAsync<IOException>(()=>Service(run,initial,store).PublishAsync(snapshot.EnvelopeId));
        await using var db=fixture.Open();
        if(mode!="snapshot") {
            var saved=await db.CompletionPublicationIntents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==snapshot.EnvelopeId);var json=JsonNode.Parse(saved.StageBindingsJson)!;
            if(mode=="strip") {saved.StageBindingsJson=json["Stages"]!.ToJsonString();saved.RetentionDays=30;}
            else {json["UploadRetention"]!["Days"]=8;json["UploadRetention"]!["DeleteAfter"]=snapshot.DeleteAfter.AddDays(1);saved.StageBindingsJson=json.ToJsonString();saved.RetentionDays=8;}
            var method=typeof(CompletionPublication).GetMethods(BindingFlags.Static|BindingFlags.NonPublic).Single(x=>x.Name=="Recipe" && x.GetParameters()[0].ParameterType==typeof(CompletionPublicationIntent));
            saved.RecipeSha256=(byte[])method.Invoke(null,[saved])!;
            await db.CompletionPublicationIntents.Where(x=>x.Id==saved.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.StageBindingsJson,saved.StageBindingsJson).SetProperty(x=>x.RetentionDays,saved.RetentionDays).SetProperty(x=>x.RecipeSha256,saved.RecipeSha256));
        } else await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==snapshot.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Days,8).SetProperty(x=>x.DeleteAfter,snapshot.DeleteAfter.AddDays(1)));
        var error=await Record.ExceptionAsync(()=>Service(run,db,store).PublishAsync(snapshot.EnvelopeId));Assert.True(error is InvalidDataException or QuillSign.Documents.DocumentConflictException);
        Assert.Equal(1,store.Writes);Assert.False(await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==snapshot.EnvelopeId));
    }

    private async Task<DocumentRetentionSnapshot> Policy(Run run) {await using var db=fixture.Open();return await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id);}
    private static void Advance(Run run,TimeSpan amount) {run.Signing.H.Clock.Advance(amount);run.Seal.Time.Advance(amount);}
    private static CompletionPublication Service(Run run,QuillSignDbContext db,ICompletionFinalStore store)=>new(db,run.Candidates(db),run.Service(db),run.Collector(db),store,new(db,run.Signing.H.Clock),run.Signing.H.Clock,
        new() {DemoPurgeAfterDays=30,AllowDevelopmentWriteOnce=true},run.Seal.App.Environment);
    private sealed class AuditAction(string kind,Action action):SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> result,CancellationToken ct=default)
        {if(e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && x.Entity.Event==kind))action();return ValueTask.FromResult(result);}
    }
    private sealed class Store(TimeProvider time):ICompletionFinalStore
    {
        public ConcurrentDictionary<FinalDocument,(FinalStoredDocument Reference,byte[] Bytes)> Objects=new();public List<DateTimeOffset?> Until=[];
        public int Writes;public FinalDocumentKind? Lose;public Action<FinalDocument>? AfterWrite;public TimeSpan Skew;public bool Hold;
        public async Task<FinalStoredDocument> WriteAsync(ClaimsPrincipal authority,FinalDocument target,Stream source,long length,byte[] hash,DateTimeOffset? until,CancellationToken ct=default)
        {
            Demand("DemandWrite",authority,target,length,hash,until);Assert.True((bool)authority.GetType().GetProperty("ExactDeadline",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(authority)!);
            Until.Add(until);Writes++;using var bytes=new MemoryStream();await source.CopyToAsync(bytes,ct);Assert.Equal(hash,SHA256.HashData(bytes.ToArray()));
            var result=Objects.GetOrAdd(target,_=>(new(target,length,hash.ToArray(),"synthetic-version","synthetic-etag",Hold ? FinalProtection.LegalHold : FinalProtection.LockedTime,
                Hold ? null : until+Skew,time.GetUtcNow()),bytes.ToArray()));AfterWrite?.Invoke(target);
            if(Lose==target.Kind) {Lose=null;throw new IOException("Synthetic uncertain fixed final write");}return result.Reference;
        }
        public async Task ReadAsync(ClaimsPrincipal authority,FinalStoredDocument reference,Stream destination,CancellationToken ct=default)
        {Demand("DemandRead",authority,reference);Assert.True((bool)authority.GetType().GetProperty("ExactDeadline",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(authority)!);await destination.WriteAsync(Objects[reference.Document].Bytes,ct);}
        private static void Demand(string method,params object?[] args)
        {try {typeof(IBlobStore).Assembly.GetType("QuillSign.Storage.CompletionFinalCapability",true)!.GetMethod(method,BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,args);}catch(TargetInvocationException e) {System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException!).Throw();}}
    }
}
