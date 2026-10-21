using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using QuillSign.Signing;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRecordUploadAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_production_upload_and_replacement_settle_exact_pairs_and_retain_prior_history_without_cleanup()
    {
        await using var test=await Prepared.Create(fixture);await using var db=fixture.Open();
        var before=await test.Record(db);Assert.True(await test.Upload(db,before));
        var first=await test.Record(db);Assert.NotNull(first.PdfBlob);Assert.NotEqual(before.RowVersion,first.RowVersion);
        Assert.True(await test.Upload(db,first));var second=await test.Record(db);
        Assert.NotEqual(first.PdfBlob,second.PdfBlob);Assert.NotEqual(first.OriginalBlob,second.OriginalBlob);
        Assert.Equal(4,test.Blobs.Objects.Count);Assert.Equal(0,test.Blobs.Deletes);Assert.Equal(0,test.Blobs.UnwitnessedWrites);
        Assert.Contains(test.Blobs.Objects.Keys,x=>x.ObjectId.ToString("N")==first.PdfBlob);
        Assert.Contains(test.Blobs.Objects.Keys,x=>x.ObjectId.ToString("N")==first.OriginalBlob);
        Assert.Equal(2,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==test.Run.Id&& (x.Event=="document_uploaded"||x.Event=="document_replaced")));
        Assert.Null((await test.Run.Journal.ReadAsync(test.Run.Id)).OutstandingOperation);
        Assert.False((await test.Run.Coordinator.ReadVerifiedAsync(test.Run.Id)).Frozen);
    }
    [Fact]
    public async Task Real_upload_replacement_history_forms_a_complete_protected_bundle_and_independent_releases_across_recreated_coordinators()
    {
        await using var test=await Prepared.Create(fixture);await using(var db=fixture.Open())
        {Assert.True(await test.Upload(db,await test.Record(db)));Assert.True(await test.Upload(db,await test.Record(db)));}
        using var provider=new ProductionHoldArchiveReleaseTests.Provider();
        foreach(var pair in test.Blobs.Objects)provider.SourceFiles.Add(test.Blobs.Address(pair.Key),pair.Value.ToArray());
        var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03){Transport=new HttpClientTransport(new HttpClient(provider,false))};options.Retry.MaxRetries=0;
        var service=new BlobServiceClient(new Uri("https://storage.example.invalid"),new ProductionHoldArchiveReleaseTests.Credential(),options);
        ProductionHoldCoordinator Coordinator()=>new(fixture.Open,test.Run.Keys,test.Run.Time,test.Run.Journal,test.Blobs,new(service),new(service));
        var a=Place(test.Run.Id);await Coordinator().SubmitAsync(Authority(test.Run.Time,a.Permission),Operators,a);
        var first=await Coordinator().PreserveAsync(test.Run.Id,a.HoldId,Guid.NewGuid());Assert.True(first.Holds[a.HoldId].Effective);Assert.Equal(6,provider.Files.Count);
        var b=Place(test.Run.Id,1);await Coordinator().SubmitAsync(Authority(test.Run.Time,b.Permission),Operators,b);
        Assert.True((await Coordinator().PreserveAsync(test.Run.Id,b.HoldId,Guid.NewGuid())).Holds[b.HoldId].Effective);Assert.Equal(12,provider.Files.Count);
        var releaseA=a with{CommandId=Guid.NewGuid(),Operation=ProductionHoldOperation.Release,ExpectedRevision=2};
        await Coordinator().SubmitAsync(Authority(test.Run.Time,releaseA.Permission),Operators,releaseA);Assert.True((await Coordinator().ReleaseAsync(test.Run.Id,a.HoldId)).Frozen);
        var releaseB=b with{CommandId=Guid.NewGuid(),Operation=ProductionHoldOperation.Release,ExpectedRevision=3};
        await Coordinator().SubmitAsync(Authority(test.Run.Time,releaseB.Permission),Operators,releaseB);Assert.False((await Coordinator().ReleaseAsync(test.Run.Id,b.HoldId)).Frozen);
        Assert.Equal(4,test.Blobs.Objects.Count);Assert.Equal(0,test.Blobs.Deletes);Assert.All(provider.Files.Values,x=>Assert.False(x.Held));
    }
    [Fact]
    public async Task Pending_hold_refuses_upload_before_provider_writes_and_exact_release_allows_original_valid_request()
    {
        await using var test=await Prepared.Create(fixture);var hold=await test.Run.Hold();await using var db=fixture.Open();
        var before=await test.Record(db);Assert.False(await test.Upload(db,before));
        Assert.Empty(test.Blobs.Objects);Assert.Equal(before.RowVersion,(await test.Record(db)).RowVersion);
        await test.Run.Release(hold);Assert.True(await test.Upload(db,before));Assert.Equal(2,test.Blobs.Objects.Count);
        Assert.Equal(0,test.Blobs.Deletes);
    }
    [Fact]
    public async Task Hold_arriving_between_pair_writes_freezes_new_operations_while_only_the_original_upload_drains()
    {
        await using var test=await Prepared.Create(fixture);var command=Place(test.Run.Id);
        test.Blobs.AfterWrite=async count=>
        {
            if(count!=1)return;
            var state=await test.Run.Coordinator.SubmitAsync(Authority(test.Run.Time,command.Permission),Operators,command);
            Assert.Equal(command,state.Unacknowledged);Assert.NotNull(state.OutstandingOperation);
            await using var check=fixture.Open();Assert.False(await check.ProductionHoldRequests.AnyAsync(x=>x.EnvelopeId==test.Run.Id));
        };
        await using var db=fixture.Open();Assert.True(await test.Upload(db,await test.Record(db)));
        var pending=await test.Run.Journal.ReadAsync(test.Run.Id);Assert.Null(pending.OutstandingOperation);Assert.Equal(command,pending.Unacknowledged);
        Assert.False(await test.Upload(db,await test.Record(db)));Assert.Equal(2,test.Blobs.Objects.Count);
        var accepted=await test.Run.Coordinator.SubmitAsync(Authority(test.Run.Time,command.Permission),Operators,command);
        Assert.Equal(1,accepted.RequestRevision);Assert.True(accepted.Frozen);Assert.Equal(0,test.Blobs.Deletes);
    }
    [Fact]
    public async Task Unknown_first_write_retains_its_exact_intent_and_bytes_without_SQL_adoption_cleanup_or_automatic_replay()
    {
        await using var test=await Prepared.Create(fixture);test.Blobs.LoseFirstAcknowledgement=true;await using var db=fixture.Open();
        var before=await test.Record(db);await Assert.ThrowsAsync<IOException>(()=>test.Upload(db,before));
        Assert.Null((await test.Record(db)).PdfBlob);Assert.Single(test.Blobs.Objects);Assert.Equal(0,test.Blobs.Deletes);
        var state=await test.Run.Journal.ReadAsync(test.Run.Id);Assert.NotNull(state.OutstandingOperation);
        Assert.False(await test.Upload(db,before));Assert.Single(test.Blobs.Objects);
        Assert.Equal(state.HeadHash,(await test.Run.Journal.ReadAsync(test.Run.Id)).HeadHash);
    }
    [Fact]
    public async Task Unknown_SQL_commit_keeps_verified_objects_and_sealed_outcome_without_a_new_upload_attempt()
    {
        await using var test=await Prepared.Create(fixture);string connection;Envelope before;
        await using(var initial=fixture.Open()){connection=initial.Database.GetConnectionString()!;before=await test.Record(initial);}
        await using(var lost=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
            await Assert.ThrowsAsync<IOException>(()=>test.Upload(lost,before));
        await using var db=fixture.Open();var after=await test.Record(db);Assert.NotNull(after.PdfBlob);
        var state=await test.Run.Journal.ReadAsync(test.Run.Id);Assert.NotNull(state.OutstandingOperation);Assert.True(state.Outcomes!.ContainsKey(state.OutstandingOperation!.Value));
        Assert.False(await test.Upload(db,after));Assert.Equal(2,test.Blobs.Objects.Count);Assert.Equal(0,test.Blobs.Deletes);
    }
    [Fact]
    public async Task SQL_conflict_after_both_verified_writes_leaves_unpublished_pair_pending_without_deleting_any_version()
    {
        await using var test=await Prepared.Create(fixture);test.Blobs.AfterWrite=async count=>
        {
            if(count!=2)return;
            await using var change=fixture.Open();await change.Envelopes.Where(x=>x.Id==test.Run.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Title,"Concurrent synthetic change"));
        };
        await using var db=fixture.Open();var before=await test.Record(db);
        await Assert.ThrowsAsync<InvalidDataException>(()=>test.Upload(db,before));
        Assert.Null((await test.Record(db)).PdfBlob);Assert.Equal(2,test.Blobs.Objects.Count);Assert.Equal(0,test.Blobs.Deletes);
        Assert.NotNull((await test.Run.Journal.ReadAsync(test.Run.Id)).OutstandingOperation);
    }
    [Fact]
    public async Task Invalid_row_version_cannot_start_provider_authority()
    {
        await using var test=await Prepared.Create(fixture);await using var db=fixture.Open();var before=await test.Record(db);
        before.RowVersion=new byte[8];
        await Assert.ThrowsAsync<DocumentConflictException>(()=>test.Upload(db,before));
        Assert.Empty(test.Blobs.Objects);
    }
    [Fact]
    public async Task A_draft_edit_during_preprocessing_is_settled_as_known_no_effect_before_any_provider_plan_or_write()
    {
        await using var test=await Prepared.Create(fixture);await using var db=fixture.Open();var before=await test.Record(db);
        using var input=new ChangedDuringRead(PdfFixtures.Create(),async()=>
        {
            var scope=await test.Run.Admission.BeginAsync(test.Run.Id,Guid.NewGuid(),"test/preprocess-edit","synthetic-independent-completed-edit");
            await using(var edit=fixture.Open())
            {
                await using var tx=await edit.Database.BeginTransactionAsync();
                await edit.Envelopes.Where(x=>x.Id==test.Run.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Title,"Synthetic newer draft details"));
                await test.Run.Admission.PrepareOutcomeLockedAsync(edit,scope);await tx.CommitAsync();
            }
            await test.Run.Admission.CompleteAsync(scope,Hash);
        });
        Assert.False(await test.Workflow(db).UploadAsync(test.Sender,before.PublicId,before.RowVersion,"synthetic.pdf",input,input.Length,null,null,default));
        Assert.True(input.Changed);Assert.Empty(test.Blobs.Objects);Assert.Equal(0,test.Blobs.Deletes);
        var state=await test.Run.Journal.ReadAsync(test.Run.Id);Assert.Null(state.OutstandingOperation);
        Assert.Equal("Synthetic newer draft details",(await test.Record(db)).Title);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Crossing_the_original_frozen_draft_deadline_stops_further_provider_effects_without_clock_renewal(bool firstObjectAlreadyWritten)
    {
        await using var test=await Prepared.Create(fixture);await using var db=fixture.Open();var before=await test.Record(db);
        DateTimeOffset deadline;
        await using(var tx=await db.Database.BeginTransactionAsync())
        {deadline=(await ProductionRecordRetentionAccess.ReadLockedAsync(db,before,test.Run.Time)).Deadline!.Value;await tx.RollbackAsync();}
        var originalPolicy=(await db.ProductionRetentionPolicies.AsNoTracking().SingleAsync(x=>x.EnvelopeId==test.Run.Id)).PolicyJson;
        var originalTokenDeadline=(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==test.Run.Token.TokenId)).ExpiresAt;
        if(firstObjectAlreadyWritten)test.Blobs.AfterWrite=count=>{if(count==1)test.Run.Time.Now=deadline;return Task.CompletedTask;};
        else test.Blobs.BeforeWrite=()=>{test.Run.Time.Now=deadline;return Task.CompletedTask;};
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>test.Upload(db,before));
        Assert.Equal(firstObjectAlreadyWritten?1:0,test.Blobs.Objects.Count);Assert.Equal(0,test.Blobs.Deletes);
        Assert.Null((await test.Record(db)).PdfBlob);Assert.NotNull((await test.Run.Journal.ReadAsync(test.Run.Id)).OutstandingOperation);
        Assert.Equal(originalPolicy,(await db.ProductionRetentionPolicies.AsNoTracking().SingleAsync(x=>x.EnvelopeId==test.Run.Id)).PolicyJson);
        Assert.Equal(originalTokenDeadline,(await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==test.Run.Token.TokenId)).ExpiresAt);
    }

    private sealed class ChangedDuringRead(byte[] bytes,Func<Task> change):MemoryStream(bytes,false)
    {
        internal bool Changed;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken cancellationToken=default)
        {if(!Changed){Changed=true;await change();}return await base.ReadAsync(buffer,cancellationToken);}
        public override async Task CopyToAsync(Stream destination,int bufferSize,CancellationToken cancellationToken)
        {if(!Changed){Changed=true;await change();}await base.CopyToAsync(destination,bufferSize,cancellationToken);}
    }

    private sealed class LostCommit:DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken cancellationToken=default)
            =>throw new IOException("Synthetic lost production upload SQL acknowledgement.");
    }
    internal sealed class Blobs:IProductionRecordUploadStore,IProductionRecordSendStore,IProductionSignaturePreviewStore,IBlobStore,IProductionHoldObjectSource
    {
        internal readonly Dictionary<DocumentBlob,byte[]> Objects=[];internal int Deletes,UnwitnessedWrites,Copies;
        internal bool LoseFirstAcknowledgement;internal Func<int,Task>? AfterWrite;internal Func<Task>? BeforeWrite;internal Func<Task>? AfterCopy;
        internal int MarkWrites,LoseMarkAcknowledgementAt;internal Func<int,Task>? AfterMarkWrite;internal Func<Task>? BeforeMarkWrite;
        internal string MarkVersionSuffix="";
        public async Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope,VerifiedSigner identity,ProductionRecordWriteDescriptor item,Stream source,
            bool mayWrite,ProductionRecordWriteReceipt? saved,Func<CancellationToken,Task> demand,CancellationToken ct=default)
        {
            Assert.Equal(scope.RecordId,identity.EnvelopeId);Assert.True(ProductionRecordPreviewWriteContract.Item(scope.RecordId,item));
            if(BeforeMarkWrite is not null)await BeforeMarkWrite();await demand(ct);
            if(mayWrite)
            {
                using var bytes=new MemoryStream();await source.CopyToAsync(bytes,ct);await demand(ct);
                Assert.Equal(item.Length,bytes.Length);Assert.Equal(item.Sha256,Convert.ToHexStringLower(SHA256.HashData(bytes.ToArray())));
                Objects.Add(item.Blob,bytes.ToArray());MarkWrites++;
                if(AfterMarkWrite is not null)await AfterMarkWrite(MarkWrites);
                if(LoseMarkAcknowledgementAt==MarkWrites)throw new IOException("Synthetic unknown signature mark write acknowledgement.");
            }
            await demand(ct);var actual=Objects[item.Blob];Assert.Equal(item.Length,actual.LongLength);
            Assert.Equal(item.Sha256,Convert.ToHexStringLower(SHA256.HashData(actual)));
            var receipt=new ProductionRecordWriteReceipt(item,"synthetic-version-"+item.Blob.ObjectId.ToString("N"),"\"synthetic-etag\"");
            if(saved is not null)Assert.Equal(saved,receipt);return receipt;
        }
        public async Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope,ClaimsPrincipal sender,ProductionRecordWriteDescriptor item,Stream source,
            bool mayWrite,ProductionRecordWriteReceipt? saved,Func<CancellationToken,Task> demand,CancellationToken ct=default)
        {
            EnvelopeStorageAuthorization.Demand(sender,item.Blob);if(BeforeWrite is not null)await BeforeWrite();await demand(ct);
            if(mayWrite)
            {
                using var bytes=new MemoryStream();await source.CopyToAsync(bytes,ct);await demand(ct);
                Assert.Equal(item.Length,bytes.Length);Assert.Equal(item.Sha256,Convert.ToHexStringLower(SHA256.HashData(bytes.ToArray())));
                Objects.Add(item.Blob,bytes.ToArray());
                if(AfterWrite is not null)await AfterWrite(Objects.Count);
                if(LoseFirstAcknowledgement&&Objects.Count==1)throw new IOException("Synthetic unknown provider write acknowledgement.");
            }
            await demand(ct);var stored=Objects[item.Blob];Assert.Equal(item.Length,stored.LongLength);
            var receipt=new ProductionRecordWriteReceipt(item,"synthetic-version-"+item.Blob.ObjectId.ToString("N"),"\"synthetic-etag\"");
            if(saved is not null)Assert.Equal(saved,receipt);return receipt;
        }
        public async Task WriteAsync(ClaimsPrincipal sender,DocumentBlob blob,Stream source,long length,CancellationToken cancellationToken=default)
        {UnwitnessedWrites++;EnvelopeStorageAuthorization.Demand(sender,blob);using var copy=new MemoryStream();await source.CopyToAsync(copy,cancellationToken);Assert.Equal(length,copy.Length);Objects.Add(blob,copy.ToArray());}
        public async Task<long> CopyToAsync(ClaimsPrincipal sender,DocumentBlob blob,Stream destination,CancellationToken cancellationToken=default)
        {EnvelopeStorageAuthorization.DemandRead(sender,blob);Copies++;await destination.WriteAsync(Objects[blob],cancellationToken);if(AfterCopy is not null)await AfterCopy();return Objects[blob].Length;}
        public Task DeleteAsync(ClaimsPrincipal sender,DocumentBlob blob,CancellationToken cancellationToken=default)
        {Deletes++;throw new InvalidOperationException("Production upload must retain historical and uncertain bytes.");}
        internal HoldObjectAddress Address(DocumentBlob blob)=>new(blob.Kind==DocumentBlobKind.Original?"originals":"normalized",
            $"{blob.EnvelopeId:N}/{blob.ObjectId:N}","synthetic-version-"+blob.ObjectId.ToString("N")+
            (blob.Kind is DocumentBlobKind.Signature or DocumentBlobKind.Initials?MarkVersionSuffix:""),"","\"synthetic-etag\"",Objects[blob].LongLength);
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope,string area,string? continuation,int maximum,CancellationToken ct)
        {scope.Demand(ct);Assert.Null(continuation);return Task.FromResult(new HoldObjectPage(Objects.Keys.Select(Address).Where(x=>x.Area==area).ToArray(),null));}
        public Task<string> HashAsync(ProductionHoldObjectScope scope,HoldObjectAddress address,CancellationToken ct)
        {scope.Demand(ct);var blob=Objects.Keys.Single(x=>Address(x)==address);return Task.FromResult(Convert.ToHexStringLower(SHA256.HashData(Objects[blob])));}
    }
    internal sealed class Prepared(ProductionRuntimeAdmissionTests.Run run):IAsyncDisposable
    {
        internal readonly ProductionRuntimeAdmissionTests.Run Run=run;internal readonly Blobs Blobs=new();internal ClaimsPrincipal Sender=null!;
        internal Task<Envelope> Record(QuillSignDbContext db)=>db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==Run.Id);
        internal DocumentWorkflow Workflow(QuillSignDbContext db)=>new(db,Blobs,new(new()),new(),new(db,Run.Time),Run.Time,NullLogger<DocumentWorkflow>.Instance)
            {HoldUploads=new(Run.Admission,Blobs),HoldAdmission=new(Run.Admission)};
        internal async Task<bool> Upload(QuillSignDbContext db,Envelope before)
        {var bytes=PdfFixtures.Create();using var input=new MemoryStream(bytes,false);return await Workflow(db).UploadAsync(Sender,before.PublicId,before.RowVersion,"synthetic.pdf",input,bytes.Length,null,null,default);}
        internal static async Task<Prepared> Create(SqlDatabaseFixture fixture,bool demo=false)
        {
            var run=await ProductionRuntimeAdmissionTests.Run.Create(fixture,demo);var test=new Prepared(run);await run.DeliverAndFinish(await run.Claim());
            await using var db=fixture.Open();var verified=await run.Sender(db).VerifyAsync(run.Token.Token,null,null);Assert.NotNull(verified);
            test.Sender=QuillSign.Sender.SenderConfiguration.Principal(verified);return test;
        }
        public ValueTask DisposeAsync()=>Run.DisposeAsync();
    }
}
