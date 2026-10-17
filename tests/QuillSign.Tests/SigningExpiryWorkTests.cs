using System.Data.Common;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SigningExpiryWorkTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Explicit_preparation_binds_one_job_to_frozen_sent_source_and_preserves_files_and_authority()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var db=fixture.Open();
        var files=h.Blobs.Created.Count;var tokens=await db.AuthTokens.CountAsync();var mail=await db.EmailOutbox.CountAsync();
        var jobs=Jobs(db,h);var id=Assert.IsType<Guid>(await jobs.ResumeAsync(h.Envelope.Id));Assert.Equal(id,await jobs.ResumeAsync(h.Envelope.Id));
        var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id);Assert.Equal(WorkKind.Expiry,row.Kind);Assert.Equal(0,row.Attempts);
        var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);
        var payload=System.Text.Json.JsonSerializer.Deserialize<SigningExpiryPayload>(row.PayloadJson)!;
        Assert.Equal(e.Id,payload.EnvelopeId);Assert.Equal(e.SentAt,payload.SentAt);Assert.Equal(e.ExpiresAt,payload.Deadline);
        Assert.Equal(e.SentPdfBlob,payload.SentObjectId);Assert.Equal(Convert.ToHexStringLower(e.SentPdfSha256!),payload.SentSha256);
        Assert.Equal(Convert.ToHexStringLower(e.PdfSha256!),payload.SourceSha256);Assert.Equal(Convert.ToHexStringLower(e.ErsdSha256!),payload.DisclosureSha256);Assert.Equal(e.ExpiresAt,row.AvailableAt);
        Assert.Equal(e.ExpiresAt,await h.Signals.ReadDueAsync(id,default));Assert.Equal(files,h.Blobs.Created.Count);Assert.Empty(h.Blobs.Deleted);
        Assert.Equal(tokens,await db.AuthTokens.CountAsync());Assert.Equal(mail,await db.EmailOutbox.CountAsync());
        Assert.DoesNotContain(e.SenderEmail,row.PayloadJson);
    }

    [Fact]
    public async Task Future_wakes_longer_than_seven_days_empty_queue_and_storage_outage_never_open_SQL()
    {
        await using var signals=await SignalRun.Create();var counter=new Opens();await using var db=Database(counter);var clock=new SendDraftWorkflowTests.Clock();
        var id=Guid.NewGuid();var due=clock.GetUtcNow().AddDays(30);await signals.PutHintAsync(id,due,default);
        var processor=new WorkProcessor(new(db,new(),clock),signals,[],clock);
        Assert.False(await processor.RunOnceAsync(default));
        foreach(var days in new[]{0,7,14,21})
        {
            if(days>0)clock.Advance(TimeSpan.FromDays(7));
            await signals.PublishAsync(id,TimeSpan.Zero,default);Assert.True(await processor.RunOnceAsync(default));
            Assert.Equal(due,await signals.ReadDueAsync(id,default));
        }
        signals.FailRead=true;await signals.PublishAsync(id,TimeSpan.Zero,default);Assert.True(await processor.RunOnceAsync(default));
        signals.FailRead=false;Assert.Equal(due,await signals.ReadDueAsync(id,default));Assert.Equal(0,counter.Count);
        Assert.Equal(TimeSpan.FromMinutes(15),signals.LastDelay);Assert.Empty(db.ChangeTracker.Entries());
    }

    [Theory]
    [InlineData(null)][InlineData("invalid")][InlineData("3155378976000000000")][InlineData("0001")][InlineData("-1")]
    public async Task Missing_or_malformed_hint_cannot_authorize_a_future_job(string? metadata)
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var db=fixture.Open();
        await using var signals=await SignalRun.Create();var jobs=Jobs(db,h,signals);var id=(await jobs.ResumeAsync(h.Envelope.Id))!.Value;
        if(metadata is null)await signals.RemoveHintAsync(id,default);else await signals.Hints.GetBlobClient(id.ToString("N")).SetMetadataAsync(new Dictionary<string,string>{{"due",metadata}});
        await signals.PublishAsync(id,TimeSpan.Zero,default);
        var processor=Processor(db,h,signals);Assert.True(await processor.RunOnceAsync(default));
        var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id);Assert.Equal(WorkStatus.Queued,row.Status);Assert.Equal(0,row.Attempts);
        Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired"));
    }

    [Fact]
    public async Task Due_handler_records_one_expiration_and_duplicate_wakes_recover_without_new_mail_or_files()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var signals=await SignalRun.Create();await using var db=fixture.Open();
        var id=(await Jobs(db,h,signals).ResumeAsync(h.Envelope.Id))!.Value;var mail=await db.EmailOutbox.CountAsync();var files=h.Blobs.Created.Count;
        h.Clock.Advance(TimeSpan.FromDays(31));await signals.PublishAsync(id,TimeSpan.Zero,default);Assert.True(await Processor(db,h,signals).RunOnceAsync(default));
        Assert.Equal(EnvelopeStatus.Expired,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)).Status);Assert.Null(await signals.ReadDueAsync(id,default));
        await signals.PublishAsync(id,TimeSpan.Zero,default);Assert.True(await Processor(db,h,signals).RunOnceAsync(default));
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ToArrayAsync());
        Assert.Equal(mail,await db.EmailOutbox.CountAsync());Assert.Equal(files,h.Blobs.Created.Count);Assert.Empty(h.Blobs.Deleted);Assert.Equal(0,h.Sender.Calls);
    }

    [Theory]
    [InlineData("payload")][InlineData("source")][InlineData("deadline")][InlineData("owner")][InlineData("attempt")][InlineData("until")][InlineData("kind")]
    public async Task Tampered_payload_source_or_lease_cannot_expire_an_envelope(string part)
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var signals=await SignalRun.Create();await using var db=fixture.Open();
        var id=(await Jobs(db,h,signals).ResumeAsync(h.Envelope.Id))!.Value;h.Clock.Advance(TimeSpan.FromDays(31));
        var lease=(await new WorkStore(db,new(),h.Clock).ClaimAsync(id,default)).Lease!;
        if(part=="payload")await db.WorkItems.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
        if(part=="source")await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,new byte[32]));
        if(part=="deadline")await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,h.Envelope.ExpiresAt!.Value.AddMinutes(1)));
        lease=part switch {"owner"=>lease with {Owner=Guid.NewGuid()},"attempt"=>lease with {Attempt=lease.Attempt+1},"until"=>lease with {Until=lease.Until.AddTicks(1)},"kind"=>lease with {Kind=WorkKind.Purge},_=>lease};
        var result=await new SigningExpiryHandler(db,new(db,new(db,h.Clock),new(db,h.Clock),h.Clock)).ExecuteAsync(lease,default);
        Assert.Equal(WorkOutcome.Failed,result.Outcome);Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired"));
        Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Preparation_hint_failure_rolls_back_and_lost_commit_is_recovered_by_explicit_resume(bool lostCommit)
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var signals=await SignalRun.Create();
        await LegacyAsync(h,fixture);
        signals.FailAfterHint=!lostCommit;await using var db=Database(new PreparationFault(lostCommit));var jobs=Jobs(db,h,signals);
        await Assert.ThrowsAsync<IOException>(()=>jobs.ResumeAsync(h.Envelope.Id));Assert.Empty(db.ChangeTracker.Entries());
        var names=new List<string>();await foreach(var hint in signals.Hints.GetBlobsAsync())names.Add(hint.Name);
        var id=Guid.ParseExact(Assert.Single(names),"N");await using var check=fixture.Open();Assert.Equal(lostCommit,await check.WorkItems.AnyAsync(x=>x.Id==id));
        signals.FailAfterHint=false;Assert.Equal(id,await Jobs(check,h,signals).ResumeAsync(h.Envelope.Id));
        Assert.Single(await check.WorkItems.Where(x=>x.Id==id).ToArrayAsync());
    }

    [Fact]
    public async Task Lost_publication_recovers_from_storage_hint_and_expiry_commit_acknowledgement_replays_saved_evidence()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var signals=await SignalRun.Create();await using var db=fixture.Open();
        signals.FailPublish=true;var id=(await Jobs(db,h,signals).ResumeAsync(h.Envelope.Id))!.Value;Assert.False(await Processor(db,h,signals).RunOnceAsync(default));
        signals.FailPublish=false;h.Clock.Advance(TimeSpan.FromDays(31));Assert.Equal(1,await signals.RecoverAsync(h.Clock.GetUtcNow(),default));
        await using(var faulted=Database(new ExpiryFault(h.Clock,false)))Assert.True(await Processor(faulted,h,signals).RunOnceAsync(default));
        Assert.Equal(EnvelopeStatus.Expired,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
        h.Clock.Advance(TimeSpan.FromMinutes(2));await signals.PublishAsync(id,TimeSpan.Zero,default);Assert.True(await Processor(db,h,signals).RunOnceAsync(default));
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)).Status);
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ToArrayAsync());
    }

    [Fact]
    public async Task Lease_expiry_during_audit_rolls_back_the_expiration_and_stale_finish_is_rejected()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var signals=await SignalRun.Create();await using var db=fixture.Open();
        var id=(await Jobs(db,h,signals).ResumeAsync(h.Envelope.Id))!.Value;h.Clock.Advance(TimeSpan.FromDays(31));
        var lease=(await new WorkStore(db,new(),h.Clock).ClaimAsync(id,default)).Lease!;
        await using var faulted=Database(new ExpiryFault(h.Clock,true));var result=await new SigningExpiryHandler(faulted,new(faulted,new(faulted,h.Clock),new(faulted,h.Clock),h.Clock)).ExecuteAsync(lease,default);
        Assert.Equal(WorkOutcome.Failed,result.Outcome);Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired"));
        await Assert.ThrowsAsync<InvalidOperationException>(()=>new WorkStore(db,new(),h.Clock).FinishAsync(lease,new(WorkOutcome.Completed),default));
    }

    [Fact]
    public async Task Explicit_resume_preserves_live_lease_and_refuses_failed_or_foreign_jobs()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var signals=await SignalRun.Create();await using var db=fixture.Open();
        var jobs=Jobs(db,h,signals);var id=(await jobs.ResumeAsync(h.Envelope.Id))!.Value;h.Clock.Advance(TimeSpan.FromDays(31));
        var lease=(await new WorkStore(db,new(),h.Clock).ClaimAsync(id,default)).Lease!;Assert.Equal(id,await jobs.ResumeAsync(h.Envelope.Id));
        var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id);Assert.Equal(lease.Owner,row.LeaseOwner);Assert.Equal(lease.Attempt,row.Attempts);
        await new WorkStore(db,new(),h.Clock).FinishAsync(lease,new(WorkOutcome.Failed),default);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>jobs.ResumeAsync(h.Envelope.Id));
        await db.WorkItems.Where(x=>x.Id==id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Kind,WorkKind.Purge));
        await Assert.ThrowsAsync<InvalidDataException>(()=>jobs.ResumeAsync(h.Envelope.Id));
    }

    [Fact]
    public async Task Accepted_finish_waits_for_late_checkpoint_then_expires_only_the_remaining_signer()
    {
        await using var h=await CompletionEvidenceCollectorTests.Run.Create(fixture,firstOnly:true,publishLast:false);
        var clock=h.H.Clock;await using var db=fixture.Open();await using var signals=await SignalRun.Create();var envelope=h.Envelope.Id;
        var finish=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.EnvelopeId==envelope);var mail=await db.EmailOutbox.CountAsync();
        var id=(await new SigningExpiryJobs(db,new(db,clock),()=>signals,new(){Enabled=true},clock).ResumeAsync(envelope))!.Value;
        var deadline=h.Envelope.ExpiresAt!.Value;clock.Advance(deadline-clock.GetUtcNow()+TimeSpan.FromTicks(1));
        await signals.PublishAsync(id,TimeSpan.Zero,default);Assert.True(await Processor(db,clock,signals).RunOnceAsync(default));
        Assert.Equal(WorkStatus.Queued,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)).Status);
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==envelope && x.Event=="expired"));
        Assert.True(await h.H.Once());Assert.NotNull((await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==finish.Id)).ProcessedAt);
        clock.Advance(TimeSpan.FromMinutes(2));await signals.PublishAsync(id,TimeSpan.Zero,default);Assert.True(await Processor(db,clock,signals).RunOnceAsync(default));
        Assert.Equal(EnvelopeStatus.Expired,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelope)).Status);
        var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==finish.SignerId);Assert.Equal(SignerStatus.Signed,signer.Status);Assert.Equal(finish.FinishedAt,signer.SignedAt);
        Assert.Equal(mail,await db.EmailOutbox.CountAsync());
    }

    [Fact]
    public async Task All_signed_completion_is_preserved_after_deadline_without_expiration_or_sealing_by_expiry_worker()
    {
        await using var h=await CompletionSealOutputTests.Run.Create(fixture,prepareCandidate:false);var clock=h.Signing.H.Clock;
        await using var db=fixture.Open();await using var signals=await SignalRun.Create();var envelope=h.Signing.Envelope;
        var id=(await new SigningExpiryJobs(db,new(db,clock),()=>signals,new(){Enabled=true},clock).ResumeAsync(envelope.Id))!.Value;
        clock.Advance(envelope.ExpiresAt!.Value-clock.GetUtcNow()+TimeSpan.FromTicks(1));
        await signals.PublishAsync(id,TimeSpan.Zero,default);Assert.True(await Processor(db,clock,signals).RunOnceAsync(default));
        Assert.Equal(EnvelopeStatus.Sent,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==envelope.Id)).Status);
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)).Status);
        Assert.All(await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==envelope.Id).ToArrayAsync(),s=>Assert.Equal(SignerStatus.Signed,s.Status));
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==envelope.Id && x.Event=="expired"));
        Assert.Equal(WorkStatus.Queued,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==envelope.Id && x.Kind==WorkKind.Sealing)).Status);
    }

    private SigningExpiryJobs Jobs(QuillSignDbContext db,Shared h,IWorkSignals? signals=null)=>new(db,new(db,h.Clock),()=>signals??h.Signals,new(){Enabled=true},h.Clock);
    // Model a retained pre-QUILS-60 request: its last Send audit had no expiry
    // binding and no deadline job. This is fixture construction, never app repair.
    internal static async Task LegacyAsync(Shared h,SqlDatabaseFixture fixture)
    {
        await using var db=fixture.Open();var sent=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="sent");
        var data=System.Text.Json.Nodes.JsonNode.Parse(sent.DataJson)!.AsObject();var id=data["expiryWorkId"]!.GetValue<Guid>();
        data.Remove("expiryWorkId");data.Remove("signingDeadline");sent.DataJson=data.ToJsonString();sent.Hash=AuditHash.Compute(sent);
        await db.AuditEvents.Where(x=>x.Id==sent.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,sent.DataJson).SetProperty(x=>x.Hash,sent.Hash));
        await db.WorkItems.Where(x=>x.Id==id && x.EnvelopeId==h.Envelope.Id && x.Kind==WorkKind.Expiry).ExecuteDeleteAsync();
        await h.Signals.RemoveHintAsync(id,default);
    }
    private static WorkProcessor Processor(QuillSignDbContext db,Shared h,IWorkSignals signals)=>Processor(db,h.Clock,signals);
    private static WorkProcessor Processor(QuillSignDbContext db,TimeProvider clock,IWorkSignals signals)=>new(new(db,new(),clock),signals,
        [new SigningExpiryHandler(db,new(db,new(db,clock),new(db,clock),clock))],clock);
    private QuillSignDbContext Database(IInterceptor interceptor) {
        using var source=fixture.Open();return new(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(interceptor).Options);
    }
    private sealed class Opens:DbConnectionInterceptor {
        public int Count;
        public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection c,ConnectionEventData e,InterceptionResult r,CancellationToken ct=default) {Count++;return ValueTask.FromResult(r);}
    }
    private sealed class PreparationFault(bool lost):DbTransactionInterceptor,ISaveChangesInterceptor {
        private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> r,CancellationToken ct=default) {armed|=e.Context!.ChangeTracker.Entries<WorkItem>().Any(x=>x.State==EntityState.Added && x.Entity.Kind==WorkKind.Expiry);return ValueTask.FromResult(r);}
        public override Task TransactionCommittedAsync(DbTransaction t,TransactionEndEventData e,CancellationToken ct=default) {if(armed && lost)throw new IOException("Synthetic preparation response loss");return Task.CompletedTask;}
    }
    private sealed class ExpiryFault(SendDraftWorkflowTests.Clock clock,bool expireLease):DbTransactionInterceptor,ISaveChangesInterceptor {
        private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> r,CancellationToken ct=default) {
            if(e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && x.Entity.Event=="expired")) {armed=true;if(expireLease)clock.Advance(TimeSpan.FromMinutes(6));}return ValueTask.FromResult(r);
        }
        public override Task TransactionCommittedAsync(DbTransaction t,TransactionEndEventData e,CancellationToken ct=default) {if(armed && !expireLease) {armed=false;throw new IOException("Synthetic expiry response loss");}return Task.CompletedTask;}
    }
    private sealed class SignalRun(AzureWorkSignals inner,QueueClient queue,BlobContainerClient hints):IWorkSignals,IAsyncDisposable {
        public BlobContainerClient Hints=>hints;public bool FailRead,FailAfterHint,FailPublish;public TimeSpan? LastDelay;
        public static async Task<SignalRun> Create() {
            var connection=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE")!;var name="expirytest-"+Guid.NewGuid().ToString("N");
            var q=new QueueClient(connection,name,new QueueClientOptions(QueueClientOptions.ServiceVersion.V2023_11_03));
            var h=new BlobServiceClient(connection,new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)).GetBlobContainerClient(name);
            await q.CreateIfNotExistsAsync();await h.CreateIfNotExistsAsync();return new(new(q,h,new(),true),q,h);
        }
        public async Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct) {await inner.PutHintAsync(id,due,ct);if(FailAfterHint)throw new IOException("Synthetic hint loss");}
        public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>FailRead ? throw new IOException("Synthetic metadata outage") : inner.ReadDueAsync(id,ct);
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>inner.RemoveHintAsync(id,ct);
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct)=>FailPublish ? throw new IOException("Synthetic queue outage") : inner.PublishAsync(id,delay,ct);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>inner.ReceiveAsync(ct);
        public Task DeferAsync(WorkDelivery d,TimeSpan delay,CancellationToken ct) {LastDelay=delay;return inner.DeferAsync(d,delay,ct);}
        public Task AcknowledgeAsync(WorkDelivery d,CancellationToken ct)=>inner.AcknowledgeAsync(d,ct);
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>inner.RecoverAsync(now,ct);
        public Task VerifyAsync(CancellationToken ct)=>inner.VerifyAsync(ct);
        public async ValueTask DisposeAsync() {await queue.DeleteIfExistsAsync();await hints.DeleteIfExistsAsync();}
    }
}
