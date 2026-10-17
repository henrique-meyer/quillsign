using System.Reflection;
using System.Data.Common;
using System.Text.Json;
using Azure.Storage.Blobs;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Work;
using Run=QuillSign.Tests.CompletionSealOutputTests.Run;

namespace QuillSign.Tests;

public sealed class CompletionWorkTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Last_checkpoint_atomically_queues_one_job_and_real_processor_publishes_exact_pair()
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false); await using var db=fixture.Open(); var id=run.Signing.Envelope.Id;
        var job=Assert.Single(await db.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing).ToArrayAsync());
        Assert.Equal(WorkStatus.Queued,job.Status); Assert.False(await db.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==id));
        var payload=JsonSerializer.Deserialize<CompletionWorkPayload>(job.PayloadJson)!; Assert.Equal(run.Signing.Envelope.CurrentFinishId,payload.FinishId); Assert.Equal(2,payload.CopyVersion);
        var signals=run.Signing.H.Signals; var before=await run.Counts(); var service=Build(run,db,out var final);
        var processor=new WorkProcessor(new(db,run.Signing.H.App.Services.GetRequiredService<WorkOptions>(),run.Signing.H.Clock),signals,[service],run.Signing.H.Clock);
        Assert.True(await processor.RunOnceAsync(default)); var envelope=await run.Signing.Refresh(); Assert.Equal(EnvelopeStatus.Completed,envelope.Status);
        var result=(await Publication(run,db,final).ReadAsync(id))!; Assert.Equal(envelope.FinalSha256,result.Executed.Sha256); Assert.Equal(envelope.CertificateSha256,result.Certificate.Sha256);
        Assert.Equal(2,run.Seal.Requests); Assert.Equal(FinalProtection.DevelopmentWriteOnce,result.Executed.Protection);
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==job.Id)).Status);
        Assert.Equal(before with {Audit=before.Audit+5},await run.Counts()); Assert.False(await processor.RunOnceAsync(default));
        await signals.PublishAsync(job.Id,TimeSpan.Zero,default); Assert.True(await processor.RunOnceAsync(default)); Assert.Equal(2,run.Seal.Requests);
        Assert.Equal(1,await db.CompletionPublicationResults.CountAsync(x=>x.EnvelopeId==id));
        if(Environment.GetEnvironmentVariable("QUILLSIGN_COMPLETION_WORK_ARTIFACTS") is {Length:>0} path) {
            Directory.CreateDirectory(path); await File.WriteAllBytesAsync(Path.Combine(path,"executed.pdf"),result.ExecutedBytes); await File.WriteAllBytesAsync(Path.Combine(path,"certificate.pdf"),result.CertificateBytes);
        }
        await DeleteFinal(run,result);
    }
    [Fact]
    public async Task Empty_queue_and_unrelated_work_do_not_resolve_completion_dependencies()
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false); await using var db=fixture.Open(); var options=run.Signing.H.App.Services.GetRequiredService<WorkOptions>();
        var scope=new CompletionCommitScope(db,run.Signing.H.Clock); var resolved=false;
        var handler=new CompletionWorkHandler(db,new(db,run.Signing.H.Clock),scope,()=> {resolved=true; throw new InvalidOperationException("Unexpected completion resolution");},run.Signing.H.Clock);
        Assert.Equal(WorkOutcome.Failed,(await handler.ExecuteAsync(new(Guid.NewGuid(),Guid.NewGuid(),WorkKind.Rendering,1,run.Signing.H.Clock.GetUtcNow().AddMinutes(5)),default)).Outcome); Assert.False(resolved);
        var delivery=await run.Signing.H.Signals.ReceiveAsync(default); Assert.NotNull(delivery); await run.Signing.H.Signals.AcknowledgeAsync(delivery!,default);
        var processor=new WorkProcessor(new(db,options,run.Signing.H.Clock),run.Signing.H.Signals,[handler],run.Signing.H.Clock);
        Assert.False(await processor.RunOnceAsync(default)); Assert.False(resolved); Assert.Equal(0,run.Seal.Requests);
    }
    [Fact]
    public async Task Explicit_resume_repairs_missing_notification_with_the_same_verified_job_and_hint()
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false); await using var db=fixture.Open(); var id=run.Signing.Envelope.Id;
        var job=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing);
        var pending=await run.Signing.H.Signals.ReceiveAsync(default); Assert.NotNull(pending); await run.Signing.H.Signals.AcknowledgeAsync(pending!,default);
        var jobs=new CompletionJobs(db,new(db,run.Signing.H.Clock),()=>run.Signing.H.Signals,run.Signing.H.App.Services.GetRequiredService<WorkOptions>(),run.Signing.H.Clock);
        Assert.Equal(job.Id,await jobs.ResumeAsync(id)); Assert.Equal(1,await db.WorkItems.CountAsync(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing));
        var recovered=await run.Signing.H.Signals.ReceiveAsync(default); Assert.Equal(job.Id,recovered!.WorkId); await run.Signing.H.Signals.AcknowledgeAsync(recovered,default);
        await db.WorkItems.Where(x=>x.Id==job.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,WorkStatus.Failed));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>jobs.ResumeAsync(id)); Assert.Equal(WorkStatus.Failed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==job.Id)).Status);
    }
    [Theory]
    [InlineData("source")][InlineData("payload")][InlineData("void")]
    public async Task Stale_or_untrusted_scope_never_resolves_or_calls_the_pipeline(string change)
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false); await using var db=fixture.Open(); var id=run.Signing.Envelope.Id;
        var job=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing);
        if(change=="source") {var payload=JsonSerializer.Deserialize<CompletionWorkPayload>(job.PayloadJson)!; var altered=JsonSerializer.Serialize(payload with {FinishId=Guid.NewGuid()}); await db.WorkItems.Where(x=>x.Id==job.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,altered));}
        if(change=="payload")await db.WorkItems.Where(x=>x.Id==job.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"[]"));
        if(change=="void")await db.Envelopes.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
        var resolved=false; var scope=new CompletionCommitScope(db,run.Signing.H.Clock);
        var handler=new CompletionWorkHandler(db,new(db,run.Signing.H.Clock),scope,()=> {resolved=true; throw new InvalidOperationException();},run.Signing.H.Clock);
        var processor=new WorkProcessor(new(db,run.Signing.H.App.Services.GetRequiredService<WorkOptions>(),run.Signing.H.Clock),run.Signing.H.Signals,[handler],run.Signing.H.Clock);
        Assert.True(await processor.RunOnceAsync(default)); Assert.False(resolved); Assert.Equal(0,run.Seal.Requests); Assert.False(await db.CompletionPublicationIntents.AnyAsync(x=>x.EnvelopeId==id));
        Assert.Equal(WorkStatus.Failed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==job.Id)).Status);
    }

    private CompletionWorkHandler Build(Run run,QuillSignDbContext db,out ICompletionFinalStore final)
    {
        var clock=run.Signing.H.Clock; var delta=DateTimeOffset.UtcNow-clock.GetUtcNow(); if(delta>TimeSpan.Zero) {clock.Advance(delta); run.Seal.Time.Advance(delta);}
        var store=new AzureCompletionFinalStore(run.Signing.H.App.Services.GetRequiredService<BlobServiceClient>(),clock,run.Seal.App.Environment,true); final=store;
        var scope=new CompletionCommitScope(db,clock);
        return new(db,new(db,clock),scope,()=>new(run.Candidates(db,scope),run.Service(db,scope),Publication(run,db,store,scope)),clock);
    }

    [Fact]
    public async Task Final_checkpoint_and_completion_job_roll_back_together_when_the_durable_hint_fails()
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false,publishLast:false); var id=run.Signing.Envelope.Id;
        run.Signing.H.Signals.FailHint=true; await Assert.ThrowsAsync<IOException>(()=>run.Signing.H.Once());
        await using var db=fixture.Open(); Assert.False(await db.WorkItems.AnyAsync(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing));
        Assert.Equal(1,await db.Signers.CountAsync(x=>x.EnvelopeId==id && x.Status==SignerStatus.Signed));
        Assert.Equal(1,await db.SignerFinishAcceptances.CountAsync(x=>x.EnvelopeId==id && x.ProcessedAt==null));
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==id && x.Event=="signer_completed"));
        run.Signing.H.Signals.FailHint=false; run.Signing.H.Clock.Advance(TimeSpan.FromSeconds(20));
        Assert.True(await run.Signing.H.Signals.RecoverAsync(run.Signing.H.Clock.GetUtcNow(),default)>0); Assert.True(await run.Signing.H.Once());
        Assert.Equal(2,await db.Signers.CountAsync(x=>x.EnvelopeId==id && x.Status==SignerStatus.Signed));
        Assert.Equal(1,await db.WorkItems.CountAsync(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing)); Assert.Equal(0,run.Seal.Requests);
    }
    [Fact]
    public async Task A_lost_completion_notification_is_recovered_from_the_committed_storage_hint()
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false,publishLast:false); var id=run.Signing.Envelope.Id;
        run.Signing.H.Signals.FailPublish=true; Assert.True(await run.Signing.H.Once()); Assert.False(await run.Signing.H.Once());
        await using var db=fixture.Open(); Assert.Equal(2,await db.Signers.CountAsync(x=>x.EnvelopeId==id && x.Status==SignerStatus.Signed));
        var job=Assert.Single(await db.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing).ToArrayAsync());
        run.Signing.H.Signals.FailPublish=false; Assert.True(await run.Signing.H.Signals.RecoverAsync(run.Signing.H.Clock.GetUtcNow(),default)>0);
        var handler=Build(run,db,out var final); var processor=new WorkProcessor(new(db,run.Signing.H.App.Services.GetRequiredService<WorkOptions>(),run.Signing.H.Clock),run.Signing.H.Signals,[handler],run.Signing.H.Clock);
        Assert.True(await processor.RunOnceAsync(default)); var result=(await Publication(run,db,final).ReadAsync(id))!; Assert.NotNull(result);
        Assert.Equal(job.Id,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==job.Id)).Id); Assert.Equal(2,run.Seal.Requests); await DeleteFinal(run,result);
    }
    [Theory]
    [InlineData("candidate")][InlineData("executed")][InlineData("intent")][InlineData("completed")]
    public async Task An_expired_worker_cannot_commit_and_reconstruction_resumes_only_committed_stages(string phase)
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false); var id=run.Signing.Envelope.Id;
        var changed=false;DateTimeOffset? leaseUntil=null;
        void Expire() {
            if(changed)return;changed=true;
            var delta=(leaseUntil??throw new InvalidOperationException("Claim the target lease before injecting expiry."))-run.Signing.H.Clock.GetUtcNow()+TimeSpan.FromSeconds(1);
            if(delta<TimeSpan.Zero)delta=TimeSpan.Zero;run.Signing.H.Clock.Advance(delta);run.Seal.Time.Advance(delta);
        }
        if(phase is "candidate" or "executed")run.Storage.AfterWrite=b=> {if(b.Kind==(phase=="candidate" ? DocumentBlobKind.CompletionCandidate : DocumentBlobKind.CompletionExecutedSeal))Expire(); return Task.CompletedTask;};
        await using var baseline=fixture.Open();
        var target=await baseline.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing);
        var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString());
        if(phase is "intent" or "completed")options.AddInterceptors(new Expiry(phase=="intent" ? "completion_publication_prepared" : "completed",Expire));
        await using(var db=new QuillSignDbContext(options.Options)) {
            // This case targets a lease boundary, independently of queue ordering.
            // The separate processor tests cover transport/wakeup integration.
            var handler=Build(run,db,out _);var workStore=new WorkStore(db,run.Signing.H.App.Services.GetRequiredService<WorkOptions>(),run.Signing.H.Clock);
            var lease=Assert.IsType<WorkLease>((await workStore.ClaimAsync(target.Id,default)).Lease);WorkResult? outcome=null;
            leaseUntil=lease.Until;
            var error=await Record.ExceptionAsync(async()=>{outcome=await handler.ExecuteAsync(lease,default);await workStore.FinishAsync(lease,outcome,default);});
            Assert.True(changed,$"The injected {phase} phase was not reached; handler outcome: {outcome}.");
            Assert.True(run.Signing.H.Clock.GetUtcNow()>lease.Until);
            Assert.IsType<InvalidOperationException>(error);
        }
        Assert.Equal(EnvelopeStatus.Sent,(await run.Signing.Refresh()).Status); Assert.False(await baseline.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==id));
        if(phase=="candidate")Assert.False(await baseline.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==id));
        if(phase=="executed")Assert.False(await baseline.CompletionSealOutputs.AnyAsync(x=>x.EnvelopeId==id));
        if(phase=="intent")Assert.False(await baseline.CompletionPublicationIntents.AnyAsync(x=>x.EnvelopeId==id));
        run.Storage.AfterWrite=null; Assert.True(await run.Signing.H.Signals.RecoverAsync(run.Signing.H.Clock.GetUtcNow(),default)>0);
        await using var retry=fixture.Open(); var recovered=Build(run,retry,out var store);
        var retryWork=new WorkStore(retry,run.Signing.H.App.Services.GetRequiredService<WorkOptions>(),run.Signing.H.Clock);
        var nextLease=Assert.IsType<WorkLease>((await retryWork.ClaimAsync(target.Id,default)).Lease);var completed=await recovered.ExecuteAsync(nextLease,default);
        Assert.Equal(WorkOutcome.Completed,completed.Outcome);Assert.Null(await retryWork.FinishAsync(nextLease,completed,default));
        Assert.Equal(WorkStatus.Completed,(await retry.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==target.Id)).Status);
        var result=(await Publication(run,retry,store).ReadAsync(id))!; Assert.NotNull(result);
        Assert.Equal(phase=="executed" ? 3 : 2,run.Seal.Requests); Assert.Equal(1,await retry.CompletionPublicationResults.CountAsync(x=>x.EnvelopeId==id)); await DeleteFinal(run,result);
    }
    private sealed class Expiry(string kind,Action expire) : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> result,CancellationToken ct=default)
        {if(e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && x.Entity.Event==kind))expire(); return ValueTask.FromResult(result);}
    }
    [Fact]
    public async Task A_lost_work_finish_after_committed_publication_reuses_final_files_after_session_expiry_and_private_provider_loss()
    {
        await using var run=await Run.Create(fixture,prepareCandidate:false); var id=run.Signing.Envelope.Id; await using var baseline=fixture.Open();
        var failure=new LoseWorkFinish(); var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(failure);
        await using(var db=new QuillSignDbContext(options.Options)) {
            var handler=Build(run,db,out _); var processor=new WorkProcessor(new(db,run.Signing.H.App.Services.GetRequiredService<WorkOptions>(),run.Signing.H.Clock),run.Signing.H.Signals,[handler],run.Signing.H.Clock);
            await Assert.ThrowsAsync<IOException>(()=>processor.RunOnceAsync(default)); Assert.True(failure.Fired);
        }
        Assert.Equal(EnvelopeStatus.Completed,(await run.Signing.Refresh()).Status); Assert.Equal(1,await baseline.CompletionPublicationResults.CountAsync(x=>x.EnvelopeId==id));
        var old=await baseline.CompletionPublicationResults.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id); var calls=run.Seal.Certificates.Calls;
        run.Seal.Options.Pfx.Path="unavailable"; run.Signing.H.Clock.Advance(TimeSpan.FromHours(3)); run.Seal.Time.Advance(TimeSpan.FromHours(3));
        Assert.True(await run.Signing.H.Signals.RecoverAsync(run.Signing.H.Clock.GetUtcNow(),default)>0);
        await using var retry=fixture.Open(); var recovered=Build(run,retry,out var store);
        var clock=run.Signing.H.Clock;var expiry=new SigningExpiryHandler(retry,new(retry,new(retry,clock),new(retry,clock),clock));
        var processor2=new WorkProcessor(new(retry,run.Signing.H.App.Services.GetRequiredService<WorkOptions>(),clock),run.Signing.H.Signals,[recovered,expiry],clock);
        // The now-due expiry wake can precede the recovered completion lease.
        // Exercise both supported handlers instead of assuming a single queue message.
        for(var attempt=0;attempt<8 && await retry.WorkItems.AsNoTracking().AnyAsync(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing && x.Status!=WorkStatus.Completed);attempt++)
            Assert.True(await processor2.RunOnceAsync(default));
        var result=(await Publication(run,retry,store).ReadAsync(id))!;
        Assert.Equal(old.Id,(await retry.CompletionPublicationResults.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id)).Id);
        Assert.Equal(WorkStatus.Completed,(await retry.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==id && x.Kind==WorkKind.Sealing)).Status);
        Assert.Equal(2,run.Seal.Requests); Assert.Equal(calls,run.Seal.Certificates.Calls); await DeleteFinal(run,result);
    }
    private sealed class LoseWorkFinish : DbCommandInterceptor
    {
        public bool Fired;
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,CommandEventData e,InterceptionResult<int> result,CancellationToken ct=default)
        {
            if(!Fired && command.CommandText.StartsWith("UPDATE",StringComparison.Ordinal) && command.CommandText.Contains("[WorkItems]",StringComparison.Ordinal) &&
                command.Parameters.Cast<DbParameter>().Any(x=>Equals(x.Value,"Completed"))) {Fired=true; throw new IOException("Synthetic lost final work acknowledgement");}
            return ValueTask.FromResult(result);
        }
    }
    private static CompletionPublication Publication(Run run,QuillSignDbContext db,ICompletionFinalStore final,CompletionCommitScope? scope=null)
        =>new(db,run.Candidates(db,scope),run.Service(db,scope),run.Collector(db),final,new(db,run.Signing.H.Clock),run.Signing.H.Clock,
            new() {DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},run.Seal.App.Environment,scope);
    private static async Task DeleteFinal(Run run,PublishedCompletion pair)
    {
        var container=run.Signing.H.App.Services.GetRequiredService<BlobServiceClient>().GetBlobContainerClient("final");
        foreach(var reference in new[]{pair.Executed,pair.Certificate})await container.GetBlobClient($"{pair.EnvelopeId:N}/{reference.Document.Kind.ToString().ToLowerInvariant()}/{reference.Document.ObjectId:N}").DeleteIfExistsAsync();
    }
}
