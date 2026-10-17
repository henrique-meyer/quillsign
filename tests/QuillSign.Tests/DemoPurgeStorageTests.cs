using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Storage;
using QuillSign.Work;
using Shared=QuillSign.Tests.DocumentWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class DemoPurgeStorageTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(-1,false)][InlineData(0,true)][InlineData(1,true)]
    public async Task Only_verified_first_upload_cutoff_can_issue_storage_authority(int seconds,bool allowed)
    {
        await using var run=await Run.Create(fixture);run.Time.Now=run.Policy.DeleteAfter.AddSeconds(seconds);
        // Later environment policy is irrelevant to the saved decision.
        run.H.Retention.PurgeAfterDays=30;
        if(allowed) {var cap=await run.Authorize();Assert.Equal(run.Policy.DeleteAfter,cap.DeleteAfter);Assert.Equal(UploadRetention.Digest(run.Policy),cap.PolicySha256);}
        else await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>run.Authorize());
    }
    [Theory]
    [InlineData("owner")][InlineData("attempt")][InlineData("expired")][InlineData("kind")][InlineData("payload")]
    [InlineData("missing-policy")][InlineData("changed-policy")][InlineData("ordinary")][InlineData("unenrolled")]
    public async Task Mixed_lease_or_unverifiable_enrollment_never_issues_authority(string fault)
    {
        await using var r=await Run.Create(fixture);
        r.Lease=fault switch {"owner"=>r.Lease with{Owner=Guid.NewGuid()},"attempt"=>r.Lease with{Attempt=r.Lease.Attempt+1},
            "expired"=>r.Lease with{Until=r.Time.Now},"kind"=>r.Lease with{Kind=WorkKind.Email},_=>r.Lease};
        await using(var db=fixture.Open()) {
            if(fault=="payload")await db.WorkItems.Where(x=>x.Id==r.Lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
            if(fault is "missing-policy" or "unenrolled")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==r.H.Id).ExecuteDeleteAsync();
            if(fault=="changed-policy")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==r.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.OriginalSha256,new byte[32]));
            if(fault=="ordinary")await db.Envelopes.Where(x=>x.Id==r.H.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.IsDemo,false));
        }
        var error=await Record.ExceptionAsync(()=>r.Authorize());Assert.True(error is UnauthorizedAccessException or InvalidDataException,error?.ToString());
    }
    [Fact]
    public async Task Bounded_real_storage_pass_removes_all_owned_layouts_and_snapshots_without_touching_neighbor_data()
    {
        await using var r=await Run.Create(fixture);var cap=await r.Authorize();var service=Service();var store=new AzureEnvelopePurgeStore(service);
        var own=new List<BlobClient>();var neighbor=new List<BlobClient>();
        try {
            foreach(var area in new[]{"originals","normalized","previews","final"}) {
                var container=service.GetBlobContainerClient(area);await container.CreateIfNotExistsAsync(PublicAccessType.None);
                foreach(var path in new[]{"replaced/",area=="normalized" ? "completion-seals/certificate/" : ""}) {
                    var blob=container.GetBlobClient($"{r.H.Id:N}/{path}{Guid.NewGuid():N}");own.Add(blob);await blob.UploadAsync(BinaryData.FromString("SYNTHETIC PURGE NO AGREEMENT"));
                }
                var other=container.GetBlobClient($"{Guid.NewGuid():N}/{Guid.NewGuid():N}");neighbor.Add(other);await other.UploadAsync(BinaryData.FromString("UNRELATED SYNTHETIC RECORD"));
            }
            await own[0].CreateSnapshotAsync();
            PurgeStorageCursor? cursor=null;var examined=0;var passes=0;
            do {var batch=await store.SweepAsync(cap,2,cursor);Assert.InRange(batch.Examined,0,2);examined+=batch.Examined;cursor=batch.Next;passes++;Assert.True(passes<20);}
            while(cursor is not null);
            // A snapshot can initially block base deletion; a new pass resolves the dependency.
            var last=await store.SweepAsync(cap,128);Assert.True(last.ReachedEnd);Assert.Equal(0,last.Protected);
            var empty=await store.SweepAsync(cap,128);Assert.True(empty.ReachedEnd);Assert.Equal(0,empty.Examined);Assert.True(examined>=10);
            foreach(var blob in own)Assert.False((await blob.ExistsAsync()).Value);
            foreach(var blob in neighbor)Assert.True((await blob.ExistsAsync()).Value);
            // End-of-pass is deliberately not a permanent fence against an old producer.
            var late=service.GetBlobContainerClient("normalized").GetBlobClient($"{r.H.Id:N}/completion-candidates/{Guid.NewGuid():N}");own.Add(late);
            await late.UploadAsync(BinaryData.FromString("LATE SYNTHETIC WRITE"));Assert.Equal(1,(await store.SweepAsync(cap,128)).Deleted);
            Assert.False((await late.ExistsAsync()).Value);
            // This dependency never removes SQL evidence or schedules more work.
            await using var db=fixture.Open();Assert.True(await db.Envelopes.AnyAsync(x=>x.Id==r.H.Id));Assert.True(await db.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==r.H.Id));
            Assert.Equal(WorkStatus.Leased,(await db.WorkItems.SingleAsync(x=>x.Id==r.Lease.Id)).Status);
        }
        finally {foreach(var blob in own.Concat(neighbor))await blob.DeleteIfExistsAsync(DeleteSnapshotsOption.IncludeSnapshots);}
    }
    [Fact]
    public async Task Invalid_continuation_cancellation_and_expired_scope_do_not_open_storage()
    {
        await using var r=await Run.Create(fixture);var cap=await r.Authorize();var store=new AzureEnvelopePurgeStore(new(new Uri("http://127.0.0.1:1")));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>store.SweepAsync(cap,2,new(Guid.NewGuid(),cap.PolicySha256,0,null)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>store.SweepAsync(cap,2,new(cap.EnvelopeId,"changed",0,null)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>store.SweepAsync(cap,2,new(cap.EnvelopeId,cap.PolicySha256,4,null)));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(()=>store.SweepAsync(cap,129));
        using var cancel=new CancellationTokenSource();cancel.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>store.SweepAsync(cap,2,ct:cancel.Token));
        r.Time.Now=r.Time.Now.AddMinutes(2);await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>store.SweepAsync(cap,2));
        await using var db=fixture.Open();await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>DemoPurgeAuthority.AuthorizeLockedAsync(db,r.Lease,r.Time));
    }
    internal static BlobServiceClient Service()=>new(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
    internal sealed class Clock:TimeProvider
    {public DateTimeOffset Now=new(2028,3,1,12,0,0,TimeSpan.Zero);public override DateTimeOffset GetUtcNow()=>Now;}
    internal sealed class Run(SqlDatabaseFixture fixture,Shared harness):IAsyncDisposable
    {
        internal Shared H=harness;internal Clock Time=new();internal DocumentRetentionSnapshot Policy=null!;internal WorkLease Lease=null!;
        internal static async Task<Run> Create(SqlDatabaseFixture fixture) {
            var h=await Shared.CreateAsync(fixture,demo:true);var r=new Run(fixture,h);h.Time=r.Time;h.Retention.PurgeAfterDays=1;
            try {
                Assert.True(await h.UploadAsync(PdfFixtures.Create(text:"SYNTHETIC PURGE NO AGREEMENT")));
                await using var db=fixture.Open();r.Policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Id);r.Time.Now=r.Policy.DeleteAfter;
                var work=new WorkItem {EnvelopeId=h.Id,Kind=WorkKind.Purge,PayloadJson=DemoPurgeAuthority.Payload(r.Policy),AvailableAt=r.Time.Now};db.WorkItems.Add(work);await db.SaveChangesAsync();
                r.Lease=(await new WorkStore(db,new(),r.Time).ClaimAsync(work.Id,default)).Lease!;Assert.NotNull(r.Lease);return r;
            } catch {await h.DisposeAsync();throw;}
        }
        internal async Task<DemoPurgeAuthority> Authorize() {
            await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();
            var cap=await DemoPurgeAuthority.AuthorizeLockedAsync(db,Lease,Time);await tx.CommitAsync();return cap;
        }
        public ValueTask DisposeAsync()=>H.DisposeAsync();
    }
}
