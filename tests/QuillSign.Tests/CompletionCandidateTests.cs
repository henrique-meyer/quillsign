using System.Data.Common;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using PdfSharp.Pdf.IO;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;
using Run=QuillSign.Tests.CompletionEvidenceCollectorTests.Run;

namespace QuillSign.Tests;

public sealed class CompletionCandidateTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Restricted_runtime_role_can_prepare_and_read_but_cannot_update_or_delete_saved_candidates()
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); await using var db=fixture.Open();
        await db.Database.OpenConnectionAsync(); var connection=(SqlConnection)db.Database.GetDbConnection(); await using var command=connection.CreateCommand();
        command.CommandText="IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER [app_runtime] WITHOUT LOGIN"; await command.ExecuteNonQueryAsync();
        await DatabasePermissions.GrantRuntimeAsync(connection); command.CommandText="EXECUTE AS USER = 'app_runtime'"; await command.ExecuteNonQueryAsync();
        try {
            var service=Service(db,run,probe); var candidate=(await service.PrepareAsync(run.Envelope.Id))!; Assert.NotNull(candidate);
            Assert.Equal(candidate.Packet.Bytes,(await service.ReadAsync(run.Envelope.Id))!.Packet.Bytes);
            command.CommandText="UPDATE [CompletionCandidates] SET [SnapshotVersion]='forbidden'";
            Assert.Equal(229,(await Assert.ThrowsAsync<SqlException>(async ()=>await command.ExecuteNonQueryAsync())).Number);
            command.CommandText="DELETE FROM [CompletionCandidates]";
            Assert.Equal(229,(await Assert.ThrowsAsync<SqlException>(async ()=>await command.ExecuteNonQueryAsync())).Number);
            await DatabaseCommands.VerifyRuntimeAsync(db);
        } finally {command.CommandText="REVERT"; await command.ExecuteNonQueryAsync();}
        Assert.NotNull(await Read(run,probe)); Assert.Single(probe.Writes); Assert.Empty(probe.Deletes);
    }

    [Fact]
    public async Task Genuine_chain_freezes_one_exact_packet_and_snapshot_across_retries_reconstruction_and_verified_audit_tails()
    {
        await using var run=await Run.Create(fixture,demo:true); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock);
        var source=(await run.Collect())!; var before=await Counts(run);
        var first=(await Prepare(run,probe))!; Assert.NotNull(first); Assert.Single(probe.Writes);
        Assert.Equal(source.SourceObjectId,first.SourceObjectId); Assert.Equal(source.FinishId,first.FinishId);
        Assert.Equal(source.Evidence.Document.CurrentSha256,first.Packet.SourceSha256); Assert.Equal(SHA256.HashData(first.Packet.Bytes),first.Packet.Sha256);
        Assert.Equal(2,first.Packet.DocumentPages); Assert.True(first.Packet.CertificatePages>0);
        using(var pdf=PdfReader.Open(new MemoryStream(first.Packet.Bytes),PdfDocumentOpenMode.Import))Assert.Equal(first.Packet.DocumentPages+first.Packet.CertificatePages,pdf.PageCount);
        var after=await Counts(run); Assert.Equal(before with {Audit=before.Audit+1},after);
        var repeated=(await Prepare(run,probe))!; Assert.Equal(first.Id,repeated.Id); Assert.Equal(first.Packet.Bytes,repeated.Packet.Bytes);
        run.H.Clock.Advance(TimeSpan.FromDays(31)); await Append(run,"synthetic_operational_tail");
        var recovered=(await Read(run,probe))!; Assert.Equal(first.Evidence.PreparedAt,recovered.Evidence.PreparedAt); Assert.Equal(first.Packet.Bytes,recovered.Packet.Bytes);
        Assert.Equal(first.Evidence.Events.Select(x=>x.Hash),recovered.Evidence.Events.Select(x=>x.Hash));
        Assert.DoesNotContain(recovered.Evidence.Events,x=>x.Event is "completion_prepared" or "synthetic_operational_tail");
        Assert.Single(probe.Writes); Assert.Empty(probe.Deletes);
        Assert.Equal(source.Source,((await run.Collect())!).Source); Assert.Equal(EnvelopeStatus.Sent,(await run.Refresh()).Status);
        Assert.Null(run.Envelope.FinalBlob); Assert.Null(run.Envelope.CompletedAt);
        await using(var db=fixture.Open()) {
            var row=await db.CompletionCandidates.SingleAsync(x=>x.EnvelopeId==run.Envelope.Id);
            row.PreparedAt=row.PreparedAt.AddSeconds(1); await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync()); db.ChangeTracker.Clear();
            row=await db.CompletionCandidates.SingleAsync(x=>x.EnvelopeId==run.Envelope.Id); db.Remove(row); await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());
        }
        using var scope=run.H.App.Services.CreateScope(); Assert.NotNull(scope.ServiceProvider.GetRequiredService<CompletionCandidates>());
        if(Environment.GetEnvironmentVariable("QUILLSIGN_COMPLETION_CANDIDATE_ARTIFACTS") is {Length:>0} path) {
            Directory.CreateDirectory(path); await File.WriteAllBytesAsync(Path.Combine(path,"source.pdf"),source.Source);
            await File.WriteAllBytesAsync(Path.Combine(path,"candidate.pdf"),first.Packet.Bytes);
        }
    }

    [Fact]
    public async Task Concurrent_preparations_reuse_one_winner_and_delete_only_the_proven_losing_object()
    {
        await using var run=await Run.Create(fixture); await using var a=new Probe(run.H.Blobs.Inner,run.H.Clock); await using var b=new Probe(run.H.Blobs.Inner,run.H.Clock);
        var arrived=0; var gate=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        async Task Rendezvous() {if(Interlocked.Increment(ref arrived)==2)gate.TrySetResult(); await gate.Task.WaitAsync(TimeSpan.FromSeconds(40));}
        a.AfterWrite=Rendezvous; b.AfterWrite=Rendezvous;
        var results=await Task.WhenAll(Prepare(run,a),Prepare(run,b)); Assert.All(results,x=>Assert.NotNull(x));
        Assert.Equal(results[0]!.Id,results[1]!.Id); Assert.Equal(results[0]!.Packet.Bytes,results[1]!.Packet.Bytes);
        Assert.Equal(2,a.Writes.Count+b.Writes.Count); Assert.Single(a.Deletes.Concat(b.Deletes));
        Assert.DoesNotContain(a.Deletes.Concat(b.Deletes),x=>x.ObjectId==results[0]!.PdfObjectId);
        await using var db=fixture.Open(); Assert.Single(await db.CompletionCandidates.Where(x=>x.EnvelopeId==run.Envelope.Id).ToArrayAsync());
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="completion_prepared").ToArrayAsync());
    }

    [Theory]
    [InlineData("lost-write")][InlineData("lost-commit")]
    public async Task Lost_storage_or_SQL_commit_acknowledgement_recovers_the_exact_committed_candidate(string fault)
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); var faults=new Faults();
        if(fault=="lost-write")probe.LoseWrite=true; else faults.LoseCommit=true;
        var prepared=(await Prepare(run,probe,faults))!; Assert.NotNull(prepared); Assert.Single(probe.Writes); Assert.Empty(probe.Deletes);
        var replay=(await Prepare(run,probe))!; Assert.Equal(prepared.Id,replay.Id); Assert.Equal(prepared.Packet.Bytes,replay.Packet.Bytes);
        Assert.Single(probe.Writes);
    }

    [Fact]
    public async Task Audit_failure_rolls_back_candidate_and_cleans_only_its_proven_object_then_retry_succeeds()
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); var before=await Counts(run);
        await Assert.ThrowsAsync<DbUpdateException>(()=>Prepare(run,probe,new() {RejectAudit=true}));
        Assert.Equal(before,await Counts(run)); Assert.Single(probe.Writes); Assert.Single(probe.Deletes);
        await using(var db=fixture.Open())Assert.False(await db.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id));
        var recovered=(await Prepare(run,probe))!; Assert.NotNull(recovered); Assert.Equal(2,probe.Writes.Count);
        Assert.NotEqual(probe.Deletes[0].ObjectId,recovered.PdfObjectId);
    }

    [Theory]
    [InlineData("void")][InlineData("audit")][InlineData("party")][InlineData("cancel")]
    public async Task Changes_or_cancellation_after_render_and_upload_cannot_publish_a_mixed_snapshot(string kind)
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); using var cancel=new CancellationTokenSource();
        probe.AfterWrite=async ()=> {
            await using var db=fixture.Open();
            if(kind=="void")await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
            else if(kind=="party")await db.Recipients.Where(x=>x.EnvelopeId==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Name,"Changed recipient"));
            else if(kind=="audit")await Append(run,"synthetic_concurrent_tail"); else cancel.Cancel();
        };
        if(kind=="cancel")await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Prepare(run,probe,ct:cancel.Token));
        else if(kind=="party")await Assert.ThrowsAsync<InvalidDataException>(()=>Prepare(run,probe));
        else await Assert.ThrowsAsync<DocumentConflictException>(()=>Prepare(run,probe));
        await using(var db=fixture.Open()) {
            Assert.False(await db.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id));
            Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="completion_prepared"));
        }
        Assert.Single(probe.Deletes);
        if(kind=="audit") {probe.AfterWrite=null; Assert.NotNull(await Prepare(run,probe));}
    }

    [Theory]
    [InlineData("missing-write")][InlineData("conflicting-write")][InlineData("corrupt-write")]
    public async Task Unknown_or_conflicting_uploads_fail_without_guessing_object_ownership(string kind)
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); var before=await Counts(run); probe.WriteFault=kind;
        if(kind=="missing-write")await Assert.ThrowsAsync<IOException>(()=>Prepare(run,probe));
        else await Assert.ThrowsAsync<InvalidDataException>(()=>Prepare(run,probe));
        Assert.Equal(before,await Counts(run));
        if(kind=="corrupt-write")Assert.Single(probe.Deletes); else Assert.Empty(probe.Deletes);
        await using var db=fixture.Open(); Assert.False(await db.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id));
    }

    [Theory]
    [InlineData("missing")][InlineData("corrupt")][InlineData("length")][InlineData("oversize")][InlineData("scope-expiry")]
    public async Task Saved_packet_storage_failure_never_regenerates_or_replaces_the_candidate(string kind)
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); var prepared=(await Prepare(run,probe))!; var before=await Counts(run);
        probe.ReadFault=kind;
        if(kind is "missing" or "scope-expiry")await Assert.ThrowsAsync<IOException>(()=>Prepare(run,probe));
        else await Assert.ThrowsAsync<InvalidDataException>(()=>Prepare(run,probe));
        Assert.Single(probe.Writes); Assert.Empty(probe.Deletes); Assert.Equal(before,await Counts(run));
        probe.ReadFault=null; Assert.Equal(prepared.Packet.Bytes,(await Read(run,probe))!.Packet.Bytes);
    }

    [Theory]
    [InlineData("source")][InlineData("packet")][InlineData("evidence")][InlineData("state")][InlineData("recipe")][InlineData("geometry")][InlineData("version")][InlineData("pages")][InlineData("anchor")]
    public async Task Saved_candidate_metadata_tampering_is_rejected_without_new_bytes_or_completion(string kind)
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); _=await Prepare(run,probe);
        await using var db=fixture.Open(); var query=db.CompletionCandidates.Where(x=>x.EnvelopeId==run.Envelope.Id); var random=RandomNumberGenerator.GetBytes(32);
        switch(kind) {
            case "source":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SourceSha256,random));break;
            case "packet":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PdfSha256,random));break;
            case "evidence":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.EvidenceJson,"{}"));break;
            case "state":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.FrozenStateSha256,random));break;
            case "recipe":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.RecipeSha256,random));break;
            case "geometry":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.GeometryJson,"[]"));break;
            case "version":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SnapshotVersion,"future"));break;
            case "pages":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CertificatePages,1));break;
            case "anchor":await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.AuditAnchor,random));break;
        }
        await Assert.ThrowsAsync<InvalidDataException>(()=>Read(run,probe)); Assert.Single(probe.Writes); Assert.Empty(probe.Deletes);
        Assert.Equal(EnvelopeStatus.Sent,(await run.Refresh()).Status);
    }

    [Fact]
    public async Task Concurrent_saved_state_changes_fail_closed_even_when_values_are_later_restored()
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); _=await Prepare(run,probe);
        var changed=false; probe.AfterCandidateRead=async ()=> {
            if(changed)return; changed=true; await using var db=fixture.Open();
            await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Voided));
        };
        await Assert.ThrowsAsync<DocumentConflictException>(()=>Read(run,probe)); Assert.Empty(probe.Deletes);
        probe.AfterCandidateRead=null;
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,EnvelopeStatus.Sent));
        // Restoring values does not restore the frozen row version.
        await Assert.ThrowsAsync<InvalidDataException>(()=>Read(run,probe));
    }

    [Fact]
    public async Task A_verified_audit_append_during_candidate_read_preserves_the_same_historical_snapshot()
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); var original=(await Prepare(run,probe))!;
        var appended=false; probe.AfterCandidateRead=async ()=> {if(appended)return; appended=true; await Append(run,"synthetic_tail_during_candidate_read");};
        var read=(await Read(run,probe))!; Assert.True(appended); Assert.Equal(original.Packet.Bytes,read.Packet.Bytes);
        Assert.Equal(original.Evidence.PreparedAt,read.Evidence.PreparedAt); Assert.Single(probe.Writes); Assert.Empty(probe.Deletes);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Missing_or_validly_rehashed_changed_preparation_event_cannot_authorize_the_saved_candidate(bool rehash)
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); _=await Prepare(run,probe);
        await using(var db=fixture.Open()) {
            var entry=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Envelope.Id && x.Event=="completion_prepared");
            if(rehash) {
                entry.DataJson="{\"serverEvidence\":\"changed\"}"; var hash=AuditHash.Compute(entry);
                await db.AuditEvents.Where(x=>x.Id==entry.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,entry.DataJson).SetProperty(x=>x.Hash,hash));
            } else await db.AuditEvents.Where(x=>x.Id==entry.Id).ExecuteDeleteAsync();
        }
        await Assert.ThrowsAsync<InvalidDataException>(()=>Read(run,probe)); Assert.Single(probe.Writes); Assert.Empty(probe.Deletes);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Unresolved_commit_or_post_commit_cancellation_retains_possible_owned_bytes_for_authoritative_retry(bool cancel)
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); using var cancellation=new CancellationTokenSource();
        var faults=new Faults {RejectCommit=!cancel,CancelAfterCommit=cancel ? cancellation : null};
        if(cancel)await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Prepare(run,probe,faults,cancellation.Token));
        else await Assert.ThrowsAsync<IOException>(()=>Prepare(run,probe,faults));
        Assert.Single(probe.Writes); Assert.Empty(probe.Deletes);
        await using(var db=fixture.Open())Assert.Equal(cancel,await db.CompletionCandidates.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id));
        var replay=(await Prepare(run,probe))!; Assert.NotNull(replay);
        Assert.Equal(cancel ? 1 : 2,probe.Writes.Count); Assert.Empty(probe.Deletes);
        Assert.Equal(cancel,probe.Writes[0].ObjectId==replay.PdfObjectId);
    }

    [Theory]
    [InlineData(EnvelopeStatus.Voided)][InlineData(EnvelopeStatus.Declined)][InlineData(EnvelopeStatus.Expired)]
    public async Task Ineligible_envelopes_do_not_create_candidates(EnvelopeStatus state)
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock);
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==run.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,state));
        Assert.Null(await Prepare(run,probe)); Assert.Empty(probe.Writes); Assert.Null(await Read(run,probe));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Prepare(run,probe,ct:new(true)));
    }

    [Fact]
    public async Task Candidate_capabilities_reject_public_identities_other_operations_targets_aliases_and_identity_changes()
    {
        await using var run=await Run.Create(fixture); await using var probe=new Probe(run.H.Blobs.Inner,run.H.Clock); var prepared=(await Prepare(run,probe))!;
        var blob=new DocumentBlob(run.Envelope.Id,DocumentBlobKind.CompletionCandidate,prepared.PdfObjectId);
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(run.Sender,blob));
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.Demand(run.Sender,blob));
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandDelete(run.Sender,blob));
        Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(run.LastSigner,blob));
        // The normalized kind cannot alias the separate candidate storage path.
        using var output=new MemoryStream(); await Assert.ThrowsAsync<Azure.RequestFailedException>(()=>run.H.Blobs.Inner.CopyToAsync(run.Sender,blob with {Kind=DocumentBlobKind.Normalized},output));
        foreach(var op in Enum.GetValues<Operation>()) {
            var principal=Capability(blob,op,run.H.Clock);
            void Demand(DocumentBlob target,Operation requested) {if(requested==Operation.Read)EnvelopeStorageAuthorization.DemandRead(principal,target);else if(requested==Operation.Write)EnvelopeStorageAuthorization.Demand(principal,target);else EnvelopeStorageAuthorization.DemandDelete(principal,target);}
            Demand(blob,op);
            foreach(var other in Enum.GetValues<Operation>().Where(x=>x!=op))Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob,other));
            Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob with {EnvelopeId=Guid.NewGuid()},op));
            Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob with {ObjectId=Guid.NewGuid()},op));
            Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob with {Kind=DocumentBlobKind.Normalized},op));
            principal.AddIdentity(new ClaimsIdentity([new Claim(EnvelopeStorageAuthorization.EnvelopeClaim,run.Envelope.Id.ToString())],EnvelopeStorageAuthorization.SenderScheme));
            Assert.Throws<UnauthorizedAccessException>(()=>Demand(blob,op));
        }
    }

    private enum Operation { Read,Write,Delete }
    private static ClaimsPrincipal Capability(DocumentBlob blob,Operation operation,TimeProvider time)
    {
        var assembly=typeof(IBlobStore).Assembly;
        var type=assembly.GetType("QuillSign.Storage.CompletionCandidateCapability",true)!;
        var op=Enum.Parse(assembly.GetType("QuillSign.Storage.AssetOperation",true)!,operation.ToString());
        return (ClaimsPrincipal)type.GetMethod("Create",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[blob,op,time])!;
    }

    private CompletionCandidates Service(QuillSignDbContext db,Run run,Probe probe)=>new(db,
        new(db,new(db,run.H.Clock),new(probe,run.H.Clock),probe,run.H.Clock),new(),probe,new(db,run.H.Clock),run.H.Clock);
    private async Task<CompletionCandidateData?> Prepare(Run run,Probe probe,Faults? faults=null,CancellationToken ct=default)
    {
        await using var baseline=fixture.Open(); var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString());
        if(faults is not null)options.AddInterceptors(faults); await using var db=new QuillSignDbContext(options.Options);
        return await Service(db,run,probe).PrepareAsync(run.Envelope.Id,ct);
    }
    private async Task<CompletionCandidateData?> Read(Run run,Probe probe) {await using var db=fixture.Open(); return await Service(db,run,probe).ReadAsync(run.Envelope.Id);}
    private async Task Append(Run run,string name) {await using var db=fixture.Open(); await using var transaction=await db.Database.BeginTransactionAsync(); await new AuditWriter(db,run.H.Clock).AppendAsync(run.Envelope.Id,name,null,null,null,default,"{}",PartyType.System); await transaction.CommitAsync();}
    private sealed record CountsData(int Audit,int Work,int Email,int Mail);
    private async Task<CountsData> Counts(Run run) {await using var db=fixture.Open(); return new(await db.AuditEvents.CountAsync(x=>x.EnvelopeId==run.Envelope.Id),await db.WorkItems.CountAsync(x=>x.EnvelopeId==run.Envelope.Id),await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Envelope.Id),run.H.Sender.Calls);}

    private sealed class Faults : DbTransactionInterceptor,ISaveChangesInterceptor
    {
        public bool RejectAudit,LoseCommit,RejectCommit; public CancellationTokenSource? CancelAfterCommit; private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e,InterceptionResult<int> result,CancellationToken ct=default)
        {
            if(e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && x.Entity.Event=="completion_prepared")) {
                if(RejectAudit)throw new DbUpdateException("Synthetic completion audit failure"); armed=true;
            }
            return ValueTask.FromResult(result);
        }
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData e,CancellationToken ct=default)
        {
            if(armed && CancelAfterCommit is not null) {CancelAfterCommit.Cancel(); CancelAfterCommit=null; ct.ThrowIfCancellationRequested();}
            if(armed && LoseCommit) {LoseCommit=false; throw new IOException("Synthetic lost completion commit acknowledgement");} return Task.CompletedTask;
        }
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,TransactionEventData e,InterceptionResult result,CancellationToken ct=default)
        {if(armed && RejectCommit) {RejectCommit=false; throw new IOException("Synthetic unknown completion commit outcome");} return ValueTask.FromResult(result);}
    }
    private sealed class Probe(IBlobStore inner,TimeProvider time) : IBlobStore,IAsyncDisposable
    {
        public List<DocumentBlob> Writes=[],Deletes=[]; public bool LoseWrite; public string? WriteFault,ReadFault;
        public Func<Task>? AfterWrite,AfterCandidateRead;
        public async Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream s,long length,CancellationToken ct)
        {
            EnvelopeStorageAuthorization.Demand(p,b); Assert.Equal(DocumentBlobKind.CompletionCandidate,b.Kind); Writes.Add(b);
            if(WriteFault=="missing-write")throw new IOException("Synthetic missing upload");
            if(WriteFault is "corrupt-write" or "conflicting-write") {
                var bytes=PdfFixtures.Create(text:"Different synthetic object"); await inner.WriteAsync(p,b,new MemoryStream(bytes),bytes.Length,ct);
                if(WriteFault=="conflicting-write")throw new Azure.RequestFailedException(412,"Synthetic conditional conflict");
            } else await inner.WriteAsync(p,b,s,length,ct);
            if(AfterWrite is not null)await AfterWrite(); if(LoseWrite)throw new IOException("Synthetic lost upload acknowledgement");
        }
        public async Task<long> CopyToAsync(ClaimsPrincipal p,DocumentBlob b,Stream destination,CancellationToken ct)
        {
            if(b.Kind!=DocumentBlobKind.CompletionCandidate)return await inner.CopyToAsync(p,b,destination,ct);
            if(ReadFault=="scope-expiry")((SendDraftWorkflowTests.Clock)time).Advance(TimeSpan.FromMinutes(3));
            EnvelopeStorageAuthorization.DemandRead(p,b);
            if(ReadFault=="missing")throw new Azure.RequestFailedException(404,"Synthetic missing candidate");
            if(ReadFault=="oversize") {var block=new byte[1024*1024]; for(var i=0;i<65;i++)await destination.WriteAsync(block,ct); return 65L*block.Length;}
            if(ReadFault=="corrupt") {var bytes=PdfFixtures.Create(text:"Changed synthetic packet"); await destination.WriteAsync(bytes,ct); return bytes.Length;}
            var n=await inner.CopyToAsync(p,b,destination,ct); if(AfterCandidateRead is not null)await AfterCandidateRead(); return ReadFault=="length" ? n-1 : n;
        }
        public async Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct) {EnvelopeStorageAuthorization.DemandDelete(p,b); Deletes.Add(b); await inner.DeleteAsync(p,b,ct);}
        public async ValueTask DisposeAsync() {foreach(var b in Writes.Distinct())await inner.DeleteAsync(Capability(b,Operation.Delete,time),b);}
    }
}
