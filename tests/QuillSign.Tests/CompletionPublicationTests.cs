using System.Collections.Concurrent;
using System.Data.Common;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Storage;
using Run=QuillSign.Tests.CompletionSealOutputTests.Run;

namespace QuillSign.Tests;

public sealed class CompletionPublicationTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Production_terminal_source_requires_actual_verified_publication_not_a_completed_status_alone()
    {
        await using var run=await Run.Create(fixture,demo:false);_=await run.Prepare();var store=new FinalStore(run.Signing.H.Clock);
        await using var db=fixture.Open();var published=(await Service(run,db,store).PublishAsync(run.Signing.Envelope.Id))!;
        await using var tx=await db.Database.BeginTransactionAsync();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==published.EnvelopeId);
        var chain=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==e.Id).OrderBy(x=>x.Sequence).ToArrayAsync();
        var source=await QuillSign.Lifecycle.ProductionRetentionTerminalSource.ReadAsync(db,e,chain,run.Signing.H.Clock,default);
        Assert.NotNull(source);Assert.Equal(published.CompletedAt,source.Value.At);Assert.Equal("completed",source.Value.Event.Event);
        await db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FinalSha256,new byte[32]));
        e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==e.Id);
        await Assert.ThrowsAsync<InvalidDataException>(()=>QuillSign.Lifecycle.ProductionRetentionTerminalSource.ReadAsync(db,e,chain,run.Signing.H.Clock,default));
        // Roll back the synthetic tamper; this fixture proves publication provenance only.
        // Enrollment-to-publication integration is the separately required QUILS-152 slice.
    }
    [Fact]
    public async Task Exact_production_seals_publish_once_and_remain_readable_after_owned_completion_and_a_large_audit_tail()
    {
        await using var run=await Run.Create(fixture); var pair=(await run.Prepare())!; var store=new FinalStore(run.Signing.H.Clock);
        var before=await run.Counts(); var oldEnvelope=await run.Signing.Refresh();
        await using var db=fixture.Open(); var result=(await Service(run,db,store).PublishAsync(oldEnvelope.Id))!;
        Assert.Equal(pair.Executed.Pdf.Bytes,result.ExecutedBytes); Assert.Equal(pair.Certificate.Pdf.Bytes,result.CertificateBytes);
        Assert.Equal(FinalProtection.DevelopmentWriteOnce,result.Executed.Protection); Assert.Equal(2,store.Objects.Count); Assert.Equal(2,run.Seal.Requests);
        var current=await run.Signing.Refresh(); Assert.Equal(EnvelopeStatus.Completed,current.Status); Assert.Equal(result.CompletedAt,current.CompletedAt);
        Assert.Equal(result.CompletedAt.AddDays(7),current.PurgeAfter); Assert.Equal(oldEnvelope.SentPdfSha256,current.SentPdfSha256);
        Assert.Equal(oldEnvelope.CurrentFinishId,current.CurrentFinishId); Assert.NotEqual(oldEnvelope.RowVersion,current.RowVersion);
        Assert.Equal(before with {Audit=before.Audit+2},await run.Counts());
        Assert.Null(await run.Read()); Assert.Null(await run.Signing.Collect());
        Assert.Null(await run.Signing.Use((SignerFields s)=>s.GetAsync(run.Signing.LastSigner,current.PublicId)));
        var again=(await Service(run,db,store).PublishAsync(current.Id))!; Assert.Equal(result.Executed.Document,again.Executed.Document); Assert.Equal(2,store.Writes);
        // Operational access events need not fit the original bounded certificate snapshot.
        await using(var tx=await db.Database.BeginTransactionAsync()) {
            var previous=await db.AuditEvents.AsNoTracking().Where(x=>x.EnvelopeId==current.Id).OrderByDescending(x=>x.Sequence).FirstAsync();
            for(var i=0;i<530;i++) {
                var entry=new AuditEvent {EnvelopeId=current.Id,Sequence=previous.Sequence+1,PrevHash=previous.Hash,At=run.Signing.H.Clock.GetUtcNow(),ActorType=PartyType.System,Event="synthetic_final_download",DataJson="{}"};
                entry.Hash=AuditHash.Compute(entry); db.Add(entry); previous=entry;
            }
            await db.SaveChangesAsync(); await tx.CommitAsync();
        }
        var acquired=run.Seal.Certificates.Calls; run.Seal.Options.Pfx.Path="unavailable"; run.Signing.H.Clock.Advance(TimeSpan.FromDays(31));
        var historical=(await Service(run,db,store).ReadAsync(current.Id))!; Assert.Equal(result.CertificateBytes,historical.CertificateBytes);
        Assert.Equal(acquired,run.Seal.Certificates.Calls); Assert.Equal(2,run.Seal.Requests); Assert.Equal(2,store.Writes);
        if(Environment.GetEnvironmentVariable("QUILLSIGN_FINAL_PUBLICATION_ARTIFACTS") is {Length:>0} path) {
            Directory.CreateDirectory(path); await File.WriteAllBytesAsync(Path.Combine(path,"executed.pdf"),result.ExecutedBytes);
            await File.WriteAllBytesAsync(Path.Combine(path,"certificate.pdf"),result.CertificateBytes);
            await File.WriteAllBytesAsync(Path.Combine(path,"staged-executed.pdf"),pair.Executed.Pdf.Bytes);
            await File.WriteAllBytesAsync(Path.Combine(path,"staged-certificate.pdf"),pair.Certificate.Pdf.Bytes);
        }
        using var scope=run.Signing.H.App.Services.CreateScope(); Assert.NotNull(scope.ServiceProvider.GetRequiredService<CompletionPublication>());
    }
    [Theory]
    [InlineData("rollback-intent")][InlineData("lost-intent")][InlineData("lost-completed")][InlineData("rollback-completed")][InlineData("uncertain-completed")]
    public async Task SQL_failure_recovery_preserves_one_stable_target_pair_and_atomic_completion(string mode)
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock);
        var faults=new Faults {Event=mode.EndsWith("intent") ? "completion_publication_prepared" : "completed",LoseCommit=mode.StartsWith("lost"),RejectAudit=mode.StartsWith("rollback"),RejectCommit=mode.StartsWith("uncertain")};
        await using var baseline=fixture.Open(); var builder=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(faults);
        await using var db=new QuillSignDbContext(builder.Options);
        if(mode.StartsWith("rollback"))await Assert.ThrowsAsync<DbUpdateException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id));
        else if(mode.StartsWith("uncertain"))await Assert.ThrowsAsync<IOException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id));
        else Assert.NotNull(await Service(run,db,store).PublishAsync(run.Signing.Envelope.Id));
        if(!mode.StartsWith("lost"))Assert.Equal(EnvelopeStatus.Sent,(await run.Signing.Refresh()).Status);
        var targets=store.Objects.Keys.ToArray(); var recovered=(await Service(run,baseline,store).PublishAsync(run.Signing.Envelope.Id))!;
        Assert.NotNull(recovered); Assert.Equal(2,store.Objects.Count); Assert.All(targets,x=>Assert.Contains(x,store.Objects.Keys)); Assert.Equal(2,run.Seal.Requests);
        Assert.Equal(1,await baseline.CompletionPublicationIntents.CountAsync(x=>x.EnvelopeId==recovered.EnvelopeId));
        Assert.Equal(1,await baseline.CompletionPublicationResults.CountAsync(x=>x.EnvelopeId==recovered.EnvelopeId));
        Assert.Equal(1,await baseline.AuditEvents.CountAsync(x=>x.EnvelopeId==recovered.EnvelopeId && x.Event=="completed"));
    }
    [Fact]
    public async Task Concurrent_workers_reuse_the_durable_targets_and_one_completion()
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock);
        var arrived=0; var gate=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        store.AfterWrite=async target=> {if(target.Kind!=FinalDocumentKind.Executed)return; if(Interlocked.Increment(ref arrived)==2)gate.TrySetResult(); await gate.Task.WaitAsync(TimeSpan.FromSeconds(60));};
        await using var first=fixture.Open(); await using var second=fixture.Open();
        var values=await Task.WhenAll(Service(run,first,store).PublishAsync(run.Signing.Envelope.Id),Service(run,second,store).PublishAsync(run.Signing.Envelope.Id));
        Assert.All(values,x=>Assert.NotNull(x)); Assert.Equal(values[0]!.Executed.Document,values[1]!.Executed.Document); Assert.Equal(2,store.Objects.Count);
        Assert.Equal(1,await first.CompletionPublicationResults.CountAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id)); Assert.Equal(2,run.Seal.Requests);
    }
    [Theory]
    [InlineData("source")][InlineData("stage")][InlineData("result")][InlineData("intent")][InlineData("audit")][InlineData("file")]
    public async Task Published_reads_reject_mutated_frozen_source_rows_proofs_and_final_bytes(string change)
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock); await using var db=fixture.Open();
        var published=(await Service(run,db,store).PublishAsync(run.Signing.Envelope.Id))!; var calls=store.Reads;
        if(change=="source")await db.Envelopes.Where(x=>x.Id==published.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Title,"changed"));
        if(change=="stage")await db.CompletionSealOutputs.Where(x=>x.EnvelopeId==published.EnvelopeId && x.Kind==CompletionSealKind.Executed).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PageCount,1));
        if(change=="result")await db.CompletionPublicationResults.Where(x=>x.EnvelopeId==published.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CompletedAt,published.CompletedAt.AddSeconds(-1)));
        if(change=="intent")await db.CompletionPublicationIntents.Where(x=>x.EnvelopeId==published.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.RetentionDays,1));
        if(change=="audit")await db.AuditEvents.Where(x=>x.EnvelopeId==published.EnvelopeId && x.Event=="completed").ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));
        if(change=="file")store.Objects[published.Executed.Document].Bytes[0]^=1;
        await Assert.ThrowsAsync<InvalidDataException>(()=>Service(run,db,store).ReadAsync(published.EnvelopeId)); Assert.Equal(2,run.Seal.Requests); Assert.Equal(2,store.Writes);
        if(change!="file")Assert.Equal(calls,store.Reads);
    }
    [Fact]
    public async Task Retention_protection_is_rechecked_at_actual_completion_and_unconfigured_policy_never_uploads()
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock); await using var db=fixture.Open();
        await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>Service(run,db,store,new()).PublishAsync(run.Signing.Envelope.Id)); Assert.Empty(store.Objects);
        store.Locked=true; store.AfterWrite=target=> {if(target.Kind==FinalDocumentKind.Certificate)run.Signing.H.Clock.Advance(TimeSpan.FromDays(2)); return Task.CompletedTask;};
        await Assert.ThrowsAsync<InvalidDataException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id)); Assert.Equal(EnvelopeStatus.Sent,(await run.Signing.Refresh()).Status);
        Assert.Equal(2,store.Objects.Count); Assert.False(await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id));
        store.AfterWrite=null; // Retained files cannot be extended/overwritten by publication.
        await Assert.ThrowsAsync<InvalidDataException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id)); Assert.Equal(2,store.Objects.Count);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Void_or_cancellation_during_final_IO_cannot_commit_completion(bool cancel)
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock); using var stop=new CancellationTokenSource();
        store.AfterWrite=async target=> {if(target.Kind!=FinalDocumentKind.Certificate)return; if(cancel)stop.Cancel(); else {await using var d=fixture.Open(); await d.Envelopes.Where(x=>x.Id==target.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));}};
        await using var db=fixture.Open();
        if(cancel)await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id,stop.Token));
        else await Assert.ThrowsAsync<DocumentConflictException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id));
        Assert.False(await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id)); Assert.Equal(2,store.Objects.Count); Assert.Equal(2,run.Seal.Requests);
    }
    [Fact]
    public async Task Runtime_can_publish_but_cannot_update_or_delete_publication_evidence()
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock); await using var db=fixture.Open();
        await db.Database.OpenConnectionAsync(); var connection=(SqlConnection)db.Database.GetDbConnection(); await using var command=connection.CreateCommand();
        command.CommandText="IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN"; await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection); command.CommandText="EXECUTE AS USER = 'app_runtime'"; await command.ExecuteNonQueryAsync();
        try {
            Assert.NotNull(await Service(run,db,store).PublishAsync(run.Signing.Envelope.Id));
            foreach(var table in new[]{"CompletionPublicationIntents","CompletionPublicationResults"}) {
                command.CommandText=$"DELETE FROM [{table}] WHERE 1=0"; Assert.Equal(229,(await Assert.ThrowsAsync<SqlException>(async ()=>await command.ExecuteNonQueryAsync())).Number);
            }
            await DatabaseCommands.VerifyRuntimeAsync(db);
        } finally {command.CommandText="REVERT"; await command.ExecuteNonQueryAsync();}
        var intent=await db.CompletionPublicationIntents.FirstAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id); intent.RetentionDays=1;
        await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync()); db.ChangeTracker.Clear();
        var result=await db.CompletionPublicationResults.FirstAsync(x=>x.EnvelopeId==run.Signing.Envelope.Id); db.Remove(result); await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());
    }
    private CompletionPublication Service(Run run,QuillSignDbContext db,FinalStore store,CompletionPublicationOptions? options=null)
        =>new(db,run.Candidates(db),run.Service(db),run.Collector(db),store,new(db,run.Signing.H.Clock),run.Signing.H.Clock,
            options ?? new() {DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},run.Seal.App.Environment);

    [Fact]
    public async Task Lost_final_write_acknowledgement_and_missing_saved_file_never_create_replacements()
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock) {LoseWrite=FinalDocumentKind.Certificate};
        await using var db=fixture.Open(); await Assert.ThrowsAsync<IOException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id));
        Assert.Equal(EnvelopeStatus.Sent,(await run.Signing.Refresh()).Status); var targets=store.Objects.Keys.ToArray(); Assert.Equal(2,targets.Length);
        var saved=(await Service(run,db,store).PublishAsync(run.Signing.Envelope.Id))!; Assert.All(targets,x=>Assert.Contains(x,store.Objects.Keys));
        Assert.True(store.Objects.TryRemove(saved.Certificate.Document,out var missing)); var writes=store.Writes;
        await Assert.ThrowsAsync<IOException>(()=>Service(run,db,store).PublishAsync(saved.EnvelopeId)); Assert.Equal(writes,store.Writes); Assert.Equal(2,run.Seal.Requests);
        Assert.True(store.Objects.TryAdd(saved.Certificate.Document,missing!)); Assert.Equal(saved.CertificateBytes,(await Service(run,db,store).ReadAsync(saved.EnvelopeId))!.CertificateBytes);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Candidate_and_seal_changes_during_final_read_are_rechecked_before_return(bool stage)
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock); await using var db=fixture.Open();
        var saved=(await Service(run,db,store).PublishAsync(run.Signing.Envelope.Id))!; var changed=false;
        store.AfterRead=async target=> {
            if(changed)return; changed=true; await using var other=fixture.Open();
            if(stage)await other.CompletionSealOutputs.Where(x=>x.EnvelopeId==target.EnvelopeId && x.Kind==CompletionSealKind.Executed).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PageCount,1));
            else await other.CompletionCandidates.Where(x=>x.EnvelopeId==target.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.RendererVersion,"changed"));
        };
        await Assert.ThrowsAsync<InvalidDataException>(()=>Service(run,db,store).ReadAsync(saved.EnvelopeId)); Assert.True(changed); Assert.Equal(2,run.Seal.Requests);
    }
    [Fact]
    public async Task Cancellation_after_actual_completion_commit_preserves_the_exact_authoritative_result()
    {
        await using var run=await Run.Create(fixture); _=await run.Prepare(); var store=new FinalStore(run.Signing.H.Clock); using var stop=new CancellationTokenSource();
        var faults=new Faults {Event="completed",CancelAfterCommit=stop}; await using var baseline=fixture.Open();
        var builder=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(faults); await using var db=new QuillSignDbContext(builder.Options);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Service(run,db,store).PublishAsync(run.Signing.Envelope.Id,stop.Token));
        Assert.Equal(EnvelopeStatus.Completed,(await run.Signing.Refresh()).Status);
        var result=(await Service(run,baseline,store).PublishAsync(run.Signing.Envelope.Id))!; Assert.NotNull(result); Assert.Equal(2,store.Writes); Assert.Equal(2,store.Objects.Count);
    }

    private sealed class Faults : DbTransactionInterceptor,ISaveChangesInterceptor
    {
        public string Event=""; public bool LoseCommit,RejectAudit,RejectCommit; public CancellationTokenSource? CancelAfterCommit; private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> result,CancellationToken ct=default)
        {if(e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && x.Entity.Event==Event)) {if(RejectAudit)throw new DbUpdateException("Synthetic publication rollback"); armed=true;} return ValueTask.FromResult(result);}
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default)
        {if(armed && CancelAfterCommit is not null) {CancelAfterCommit.Cancel(); CancelAfterCommit=null; ct.ThrowIfCancellationRequested();} if(armed && LoseCommit) {LoseCommit=false; throw new IOException("Synthetic publication lost commit");} return Task.CompletedTask;}
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,TransactionEventData e,InterceptionResult result,CancellationToken ct=default)
        {if(armed && RejectCommit) {RejectCommit=false; throw new IOException("Synthetic publication uncertain commit");} return ValueTask.FromResult(result);}
    }
    private sealed class FinalStore(TimeProvider time) : ICompletionFinalStore
    {
        public sealed record Object(FinalStoredDocument Reference,byte[] Bytes);
        public ConcurrentDictionary<FinalDocument,Object> Objects=new(); public int Writes,Reads; public bool Locked; public FinalDocumentKind? LoseWrite; public Func<FinalDocument,Task>? AfterWrite,AfterRead;
        public async Task<FinalStoredDocument> WriteAsync(ClaimsPrincipal p,FinalDocument target,Stream source,long length,byte[] hash,DateTimeOffset? until,CancellationToken ct=default)
        {
            Demand("DemandWrite",p,target,length,hash,until); ct.ThrowIfCancellationRequested(); Interlocked.Increment(ref Writes);
            using var bytes=new MemoryStream(); await source.CopyToAsync(bytes,ct); Assert.Equal(length,bytes.Length); Assert.Equal(hash,SHA256.HashData(bytes.ToArray()));
            var saved=Objects.GetOrAdd(target,_=>new(new(target,length,hash.ToArray(),"synthetic-version","synthetic-etag",Locked ? FinalProtection.LockedTime : FinalProtection.DevelopmentWriteOnce,
                Locked ? until?.AddHours(1) : null,time.GetUtcNow()),bytes.ToArray()));
            if(AfterWrite is not null)await AfterWrite(target); if(LoseWrite==target.Kind) {LoseWrite=null; throw new IOException("Synthetic lost final write acknowledgement");} ct.ThrowIfCancellationRequested(); return saved.Reference;
        }
        public async Task ReadAsync(ClaimsPrincipal p,FinalStoredDocument stored,Stream output,CancellationToken ct=default)
        {Demand("DemandRead",p,stored); ct.ThrowIfCancellationRequested(); Interlocked.Increment(ref Reads); if(!Objects.TryGetValue(stored.Document,out var value))throw new IOException("Synthetic missing final file"); await output.WriteAsync(value.Bytes,ct); if(AfterRead is not null)await AfterRead(stored.Document);}
        private static void Demand(string method,params object?[] args)
        {try {typeof(IBlobStore).Assembly.GetType("QuillSign.Storage.CompletionFinalCapability",true)!.GetMethod(method,BindingFlags.NonPublic|BindingFlags.Static)!.Invoke(null,args);} catch(TargetInvocationException e) {System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException!).Throw();}}
    }
}
