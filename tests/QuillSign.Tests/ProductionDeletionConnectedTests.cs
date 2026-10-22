using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionDeletionConnectedTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_original_Draft_reaches_typed_worker_full_census_SQL_adapter_and_recorded_cleanup_without_erasing_inactive_provider_facts()
    {
        await using var run=await Eligible();var files=new Files(run.Id);var signals=new Signals();var gate=Gate(run,files,signals);
        var id=await gate.PrepareAsync(run.Id);Assert.Equal(1,signals.Published);
        await using var worker=fixture.Open();signals.Next=id;
        var processor=new WorkProcessor(new WorkStore(worker,new(){Enabled=true,LeaseSeconds=600},run.Time){DeletionAdmission=gate},signals,[new ProductionDeletionWork(()=>gate)],run.Time);
        Assert.True(await processor.RunOnceAsync(default));
        var state=await run.Journal.ReadAsync(run.Id);Assert.True(state.Deletion!.Terminal);Assert.True(state.Deletion.WorkFinished);Assert.True(state.Frozen);
        Assert.Equal(4,files.RootDeletes);Assert.Equal(8,files.VersionDeletes);Assert.Equal(2,state.Deletion.InactiveItems!.Length);
        Assert.All(state.Deletion.Effects!.Values,e=>Assert.NotNull(e.Result));
        await using var db=fixture.Open();Assert.False(await db.Envelopes.AnyAsync(x=>x.Id==run.Id));
        Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==run.Id));Assert.False(await db.ProductionRetentionPolicies.AnyAsync(x=>x.EnvelopeId==run.Id));
        var work=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id);Assert.Null(work.EnvelopeId);Assert.Equal(WorkStatus.Completed,work.Status);Assert.Equal(1,work.Attempts);
        var status=await gate.ReadRecordedStatusAsync(run.Id);Assert.True(status.SqlRemoved);Assert.True(status.ActiveDataCleaned);Assert.Contains("Recorded",status.State);
        Assert.Equal(1,signals.Acknowledged);Assert.Equal(1,signals.Removed);
        var head=state.HeadHash;await Assert.ThrowsAsync<InvalidDataException>(()=>run.Admission.BeginAsync(run.Id,Guid.NewGuid(),"test/after-deletion","closed"));
        Assert.Equal(head,(await run.Journal.ReadAsync(run.Id)).HeadHash);
    }

    [Fact]
    public async Task Lost_exact_delete_ack_uses_readonly_reconciliation_and_expired_epoch_is_replaced_without_second_DELETE()
    {
        await using var run=await Eligible();var files=new Files(run.Id){LoseNextDelete=true};var gate=Gate(run,files,new());
        var id=await gate.PrepareAsync(run.Id);WorkLease lease;
        await using(var db=fixture.Open())lease=(await gate.ClaimAsync(db,id,default)).Lease!;
        await Assert.ThrowsAsync<IOException>(()=>gate.ExecuteAsync(lease,default));Assert.Equal(1,files.RootDeletes+files.VersionDeletes);
        var pending=await run.Journal.ReadAsync(run.Id);Assert.Single(pending.Deletion!.Effects!);Assert.Null(pending.Deletion.Effects!.Values.Single().Result);
        run.Time.Now=lease.Until.AddSeconds(1);
        await gate.RecoverAsync(run.Id);
        var state=await run.Journal.ReadAsync(run.Id);Assert.True(state.Deletion!.Terminal);Assert.True(state.Deletion.WorkFinished);
        Assert.Equal(2,state.Deletion.Lease!.Attempt);Assert.NotEqual(lease.Owner,state.Deletion.Lease.Owner);Assert.Equal(4,files.RootDeletes);Assert.Equal(8,files.VersionDeletes);Assert.Equal(1,files.OutcomeReads);
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Admission.BeginAsync(run.Id,Guid.NewGuid(),"test/expired-deletion","closed"));
    }

    [Fact]
    public async Task Fresh_provider_hold_refuses_before_destructive_request_and_permanent_fence_survives_original_cleanup_lease_expiry()
    {
        await using var run=await Eligible();var files=new Files(run.Id){Held=true};var gate=Gate(run,files,new());var id=await gate.PrepareAsync(run.Id);
        WorkLease lease;await using(var db=fixture.Open())lease=(await gate.ClaimAsync(db,id,default)).Lease!;
        await Assert.ThrowsAsync<InvalidDataException>(()=>gate.ExecuteAsync(lease,default));Assert.Equal(0,files.RootDeletes+files.VersionDeletes);
        run.Time.Now=lease.Until.AddDays(1);await Assert.ThrowsAsync<InvalidDataException>(()=>run.Admission.BeginAsync(run.Id,Guid.NewGuid(),"test/expired-held-delete","closed"));
        await using var read=fixture.Open();Assert.True(await read.Envelopes.AnyAsync(x=>x.Id==run.Id));Assert.True((await run.Journal.ReadAsync(run.Id)).Frozen);
    }

    internal async Task<(ProductionRuntimeAdmissionTests.Run Run,Files Files,Signals Signals,ProductionDeletionCoordinator Coordinator)> CreateReady()
    {var run=await Eligible();var files=new Files(run.Id);var signals=new Signals();return(run,files,signals,Gate(run,files,signals));}
    private async Task<ProductionRuntimeAdmissionTests.Run> Eligible()
    {
        var run=await ProductionRuntimeAdmissionTests.Run.Create(fixture,initialTime:DateTimeOffset.UtcNow.AddDays(-5));
        await run.DeliverAndFinish(await run.Claim());await using(var db=fixture.Open())Assert.NotNull(await run.Sender(db).VerifyAsync(run.Token.Token,null,null));
        run.Time.Now=DateTimeOffset.UtcNow;return run;
    }
    private ProductionDeletionCoordinator Gate(ProductionRuntimeAdmissionTests.Run run,Files files,Signals signals)=>new(fixture.Open,run.Keys,run.Time,run.Journal,run.Coordinator,run.Admission,files,new Index(),
        new(){Enabled=true,CompletedCommitmentStatement="Synthetic explicit per-record copy/archive commitment."},new(){Enabled=true,LeaseSeconds=600},()=>signals);
    private sealed class Index:IProductionDeletionRecoveryIndex
    {
        private ProductionDeletionRecoveryHint? value;
        public async Task RememberAsync(ProductionDeletionObjectScope scope,ProductionDeletionRecoveryHint hint,CancellationToken ct=default){await scope.DemandAsync(ct);value=hint;}
        public Task<ProductionDeletionRecoveryHint> ReadAsync(Guid record,Guid deletion,CancellationToken ct=default)=>Task.FromResult(value??throw new InvalidOperationException());
        public Task<ProductionDeletionRecoveryPage> ListAsync(string? continuation,int maximum,CancellationToken ct=default)=>Task.FromResult(new ProductionDeletionRecoveryPage(value is null?[]:[value],null));
    }
    internal sealed class Signals:IWorkSignals
    {
        internal Guid Next;internal int Published,Removed,Acknowledged;internal bool LoseNextHint;
        public Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct){if(LoseNextHint){LoseNextHint=false;throw new IOException("Synthetic lost hint acknowledgement.");}return Task.CompletedTask;}
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct){Published++;return Task.CompletedTask;}
        public Task RemoveHintAsync(Guid id,CancellationToken ct){Removed++;return Task.CompletedTask;}
        public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>Task.FromResult<DateTimeOffset?>(null);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>Task.FromResult<WorkDelivery?>(new("synthetic","synthetic",Next));
        public Task DeferAsync(WorkDelivery delivery,TimeSpan delay,CancellationToken ct)=>throw new InvalidOperationException();
        public Task AcknowledgeAsync(WorkDelivery delivery,CancellationToken ct){Acknowledged++;return Task.CompletedTask;}
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>Task.FromResult(0);
        public Task VerifyAsync(CancellationToken ct)=>Task.CompletedTask;
    }
    internal sealed class Files:IProductionDeletionStore
    {
        private readonly Dictionary<string,(ProductionDeletionObject Item,byte[] Bytes)> objects=[];
        private readonly HashSet<string> absent=[];private readonly HashSet<string> roots=[];
        internal bool Held,LoseNextDelete;internal int RootDeletes,VersionDeletes,OutcomeReads;
        internal Files(Guid record){
            foreach(var area in ProductionDeletionObjectScope.Areas){
                var name=record.ToString("N")+"/"+Guid.NewGuid().ToString("N");Add(new(area,name,"v1","","\"one\"",3,true,false,false));Add(new(area,name,"v0","","\"old\"",3,false,false,false));
            }
            Add(new("originals",record.ToString("N")+"/"+Guid.NewGuid().ToString("N"),"deleted-v","","\"deleted\"",3,false,true,false));
            Add(new("final",record.ToString("N")+"/"+Guid.NewGuid().ToString("N"),"","","",0,false,false,true));
        }
        private void Add(ProductionDeletionObject item)=>objects.Add(ProductionDeletionProtocol.Identity(item),(item,[1,2,3]));
        public async Task<ProductionDeletionPage> ListAsync(ProductionDeletionObjectScope scope,string area,string prefix,string? continuation,int maximum,CancellationToken ct=default){
            await scope.DemandAsync(ct);var list=objects.Values.Where(x=>x.Item.Area==area&&x.Item.Name.StartsWith(prefix,StringComparison.Ordinal)).Select(x=>absent.Contains(ProductionDeletionProtocol.Identity(x.Item))?x.Item with{Deleted=true,IsCurrent=false}:x.Item).ToArray();return new(list,null);
        }
        public async Task<ProductionDeletionInspection> InspectAsync(ProductionDeletionObjectScope scope,ProductionDeletionObject item,CancellationToken ct=default){
            await scope.DemandAsync(ct);if(item.Deleted||item.HasVersionsOnly||absent.Contains(ProductionDeletionProtocol.Identity(item)))throw new InvalidDataException();
            return new(item,Convert.ToHexStringLower(SHA256.HashData(objects[ProductionDeletionProtocol.Identity(item)].Bytes)),Held,null,null);
        }
        public async Task<ProductionDeletionResult> DeleteAsync(ProductionDeletionObjectScope scope,ProductionDeletionInspection expected,ProductionDeletionPhase phase,CancellationToken ct=default){
            await scope.DemandAsync(ct);if(Held)throw new InvalidDataException();var key=ProductionDeletionProtocol.Identity(expected.Item);
            ProductionDeletionResult result;
            if(phase==ProductionDeletionPhase.RootDemotion){Assert.True(roots.Add(key));RootDeletes++;result=new(expected.Item,phase,false,true,expected);}
            else{Assert.True(absent.Add(key));VersionDeletes++;result=new(expected.Item,phase,true,true,null);}
            if(LoseNextDelete){LoseNextDelete=false;throw new IOException("Synthetic lost delete acknowledgement.");}return result;
        }
        public async Task<ProductionDeletionResult> ReadDeleteOutcomeAsync(ProductionDeletionObjectScope scope,ProductionDeletionInspection expected,ProductionDeletionPhase phase,CancellationToken ct=default){
            await scope.DemandAsync(ct);OutcomeReads++;var key=ProductionDeletionProtocol.Identity(expected.Item);
            return phase==ProductionDeletionPhase.RootDemotion?new(expected.Item,phase,false,roots.Contains(key),expected):new(expected.Item,phase,absent.Contains(key),roots.Contains(key),null);
        }
    }
}
