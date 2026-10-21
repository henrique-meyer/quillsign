using System.Data.Common;
using System.Security.Cryptography;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Legal;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

public sealed class ProductionRecordSendAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Genuine_Send_freezes_one_exact_PDF_then_complete_bundle_preservation_and_independent_releases_survive_recreation(bool requestedDeadline)
    {
        await using var test=await Ready.Create(fixture,requestedDeadline);var sent=await test.Send();Assert.NotNull(sent);
        await using(var db=fixture.Open())
        {
            var e=await test.Prepared.Record(db);Assert.Equal(EnvelopeStatus.Sent,e.Status);
            Assert.Equal(test.Original.PdfBlob,e.PdfBlob);Assert.NotEqual(e.PdfBlob,e.SentPdfBlob);
            var bytes=test.Prepared.Blobs.Objects.Single(x=>x.Key.ObjectId.ToString("N")==e.SentPdfBlob).Value;
            Assert.Equal(e.SentPdfSha256,SHA256.HashData(bytes));
            Assert.Equal(1,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==e.Id&&x.Template=="signer-invitation"));
            Assert.Equal(0,(await db.WorkItems.SingleAsync(x=>x.Id==sent.InvitationWorkId)).Attempts);
            Assert.Equal(requestedDeadline?2:1,test.Signals.Hints.Count);Assert.Equal(requestedDeadline?2:1,test.Signals.Published);
            Assert.Equal(1,test.Prepared.Run.Captured.Calls); // Only original fake verification, no invitation send.
        }
        Assert.Null((await test.Prepared.Run.Journal.ReadAsync(test.Prepared.Run.Id)).OutstandingOperation);
        var writes=test.Prepared.Blobs.Objects.Count;var replay=await test.Send();Assert.Equal(sent,replay);Assert.Equal(writes,test.Prepared.Blobs.Objects.Count);
        using var provider=new ProductionHoldArchiveReleaseTests.Provider();
        foreach(var pair in test.Prepared.Blobs.Objects)provider.SourceFiles.Add(test.Prepared.Blobs.Address(pair.Key),pair.Value.ToArray());
        var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03){Transport=new HttpClientTransport(new HttpClient(provider,false))};options.Retry.MaxRetries=0;
        var service=new BlobServiceClient(new Uri("https://storage.example.invalid"),new ProductionHoldArchiveReleaseTests.Credential(),options);
        ProductionHoldCoordinator Coordinator()=>new(fixture.Open,test.Prepared.Run.Keys,test.Prepared.Run.Time,test.Prepared.Run.Journal,test.Prepared.Blobs,new(service),new(service));
        var a=Place(test.Prepared.Run.Id);await Coordinator().SubmitAsync(Authority(test.Prepared.Run.Time,a.Permission),Operators,a);
        Assert.True((await Coordinator().PreserveAsync(a.RecordId,a.HoldId,Guid.NewGuid())).Holds[a.HoldId].Effective);Assert.Equal(5,provider.Files.Count);
        var b=Place(a.RecordId,1);await Coordinator().SubmitAsync(Authority(test.Prepared.Run.Time,b.Permission),Operators,b);
        Assert.True((await Coordinator().PreserveAsync(b.RecordId,b.HoldId,Guid.NewGuid())).Holds[b.HoldId].Effective);Assert.Equal(10,provider.Files.Count);
        var releaseA=a with{CommandId=Guid.NewGuid(),ExpectedRevision=2,Operation=ProductionHoldOperation.Release};
        await Coordinator().SubmitAsync(Authority(test.Prepared.Run.Time,releaseA.Permission),Operators,releaseA);Assert.True((await Coordinator().ReleaseAsync(a.RecordId,a.HoldId)).Frozen);
        var releaseB=b with{CommandId=Guid.NewGuid(),ExpectedRevision=3,Operation=ProductionHoldOperation.Release};
        await Coordinator().SubmitAsync(Authority(test.Prepared.Run.Time,releaseB.Permission),Operators,releaseB);Assert.False((await Coordinator().ReleaseAsync(a.RecordId,b.HoldId)).Frozen);
        Assert.Equal(3,test.Prepared.Blobs.Objects.Count);Assert.Equal(0,test.Prepared.Blobs.Deletes);
    }

    [Fact]
    public async Task Pending_hold_refuses_Send_before_frozen_write_or_SQL_but_normal_invalid_input_does_not_strand_a_reservation()
    {
        await using var test=await Ready.Create(fixture);
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>test.Send(acknowledge:false));
        Assert.Null((await test.Prepared.Run.Journal.ReadAsync(test.Prepared.Run.Id)).OutstandingOperation);
        var hold=Place(test.Prepared.Run.Id);await test.Prepared.Run.Coordinator.SubmitAsync(Authority(test.Prepared.Run.Time,hold.Permission),Operators,hold);
        Assert.Null(await test.Send());Assert.Equal(2,test.Prepared.Blobs.Objects.Count);Assert.Empty(test.Signals.Hints);
        await using var db=fixture.Open();var e=await test.Prepared.Record(db);Assert.Equal(EnvelopeStatus.Draft,e.Status);Assert.Equal(test.Original.RowVersion,e.RowVersion);
    }

    [Fact]
    public async Task Hold_arriving_after_frozen_write_waits_for_that_exact_Send_to_finish_without_admitting_new_operations()
    {
        await using var test=await Ready.Create(fixture);var hold=Place(test.Prepared.Run.Id);
        test.Prepared.Blobs.AfterWrite=async count=>
        {
            if(count!=3)return;
            var pending=await test.Prepared.Run.Coordinator.SubmitAsync(Authority(test.Prepared.Run.Time,hold.Permission),Operators,hold);
            Assert.Equal(hold,pending.Unacknowledged);Assert.NotNull(pending.OutstandingOperation);
        };
        Assert.NotNull(await test.Send());var state=await test.Prepared.Run.Journal.ReadAsync(test.Prepared.Run.Id);
        Assert.Null(state.OutstandingOperation);Assert.Equal(hold,state.Unacknowledged);
        var accepted=await test.Prepared.Run.Coordinator.SubmitAsync(Authority(test.Prepared.Run.Time,hold.Permission),Operators,hold);
        Assert.True(accepted.Frozen);Assert.Equal(1,accepted.RequestRevision);Assert.Equal(0,test.Prepared.Blobs.Deletes);
    }

    [Theory]
    [InlineData("provider")][InlineData("hint")]
    public async Task Crossing_original_Draft_deadline_stops_at_provider_or_hint_boundary_and_preserves_uncertain_bytes(string boundary)
    {
        await using var test=await Ready.Create(fixture);DateTimeOffset deadline;
        await using(var db=fixture.Open())await using(var tx=await db.Database.BeginTransactionAsync())
        {deadline=(await ProductionRecordRetentionAccess.ReadLockedAsync(db,test.Original,test.Prepared.Run.Time)).Deadline!.Value;await tx.RollbackAsync();}
        if(boundary=="provider")test.Prepared.Blobs.AfterWrite=count=>{if(count==3)test.Prepared.Run.Time.Now=deadline;return Task.CompletedTask;};
        else test.Signals.OnHint=()=>{test.Prepared.Run.Time.Now=deadline;return Task.CompletedTask;};
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>test.Send());
        await using var check=fixture.Open();Assert.Equal(EnvelopeStatus.Draft,(await test.Prepared.Record(check)).Status);
        Assert.Equal(3,test.Prepared.Blobs.Objects.Count);Assert.Equal(0,test.Prepared.Blobs.Deletes);Assert.Equal(0,test.Signals.Published);
        Assert.NotNull((await test.Prepared.Run.Journal.ReadAsync(test.Prepared.Run.Id)).OutstandingOperation);
        Assert.Equal(boundary=="provider"?0:1,test.Signals.Hints.Count);
    }

    [Fact]
    public async Task Expiry_during_readonly_copy_is_rejected_before_reservation_or_frozen_provider_effects()
    {
        await using var test=await Ready.Create(fixture);var before=await test.Prepared.Run.Journal.ReadAsync(test.Prepared.Run.Id);
        test.Prepared.Blobs.AfterCopy=()=>{test.Prepared.Run.Time.Now=test.Prepared.Run.Time.Now.AddYears(1);return Task.CompletedTask;};
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>test.Send());
        Assert.Equal(before.HeadHash,(await test.Prepared.Run.Journal.ReadAsync(test.Prepared.Run.Id)).HeadHash);
        Assert.Equal(2,test.Prepared.Blobs.Objects.Count);Assert.Empty(test.Signals.Hints);
    }
    [Fact]
    public async Task Lost_SQL_commit_is_reconciled_by_exact_Sent_readback_without_render_write_or_new_token()
    {
        await using var test=await Ready.Create(fixture);string connection;
        await using(var source=fixture.Open())connection=source.Database.GetConnectionString()!;
        await using(var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(connection).AddInterceptors(new LostCommit()).Options))
            await Assert.ThrowsAsync<IOException>(()=>test.Send(db));
        var state=await test.Prepared.Run.Journal.ReadAsync(test.Prepared.Run.Id);Assert.NotNull(state.OutstandingOperation);
        Assert.True(state.Outcomes!.ContainsKey(state.OutstandingOperation!.Value));Assert.Equal(3,test.Prepared.Blobs.Objects.Count);
        Assert.NotNull(await test.Send());Assert.Equal(3,test.Prepared.Blobs.Objects.Count);Assert.Equal(0,test.Prepared.Blobs.Deletes);
        Assert.Null((await test.Prepared.Run.Journal.ReadAsync(test.Prepared.Run.Id)).OutstandingOperation);
        await using var check=fixture.Open();Assert.Equal(1,await check.AuthTokens.CountAsync(x=>x.EnvelopeId==test.Prepared.Run.Id));
    }

    private sealed class LostCommit:DbTransactionInterceptor
    {
        public override Task TransactionCommittedAsync(DbTransaction transaction,TransactionEndEventData eventData,CancellationToken ct=default)
            =>throw new IOException("Synthetic unknown Send SQL acknowledgement.");
    }
    internal sealed class Signals:IWorkSignals
    {
        internal readonly Dictionary<Guid,DateTimeOffset> Hints=[];internal int Published;internal Func<Task>? OnHint;
        public async Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct){Hints.Add(id,due);if(OnHint is not null)await OnHint();}
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct){Published++;return Task.CompletedTask;}
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>throw new InvalidOperationException();
        public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>Task.FromResult<DateTimeOffset?>(Hints.GetValueOrDefault(id));
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>throw new InvalidOperationException();
        public Task DeferAsync(WorkDelivery delivery,TimeSpan delay,CancellationToken ct)=>throw new InvalidOperationException();
        public Task AcknowledgeAsync(WorkDelivery delivery,CancellationToken ct)=>throw new InvalidOperationException();
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>throw new InvalidOperationException();
        public Task VerifyAsync(CancellationToken ct)=>Task.CompletedTask;
    }
    private sealed class Ready(SqlDatabaseFixture fixture,ProductionRecordUploadAdmissionTests.Prepared prepared):IAsyncDisposable
    {
        internal readonly ProductionRecordUploadAdmissionTests.Prepared Prepared=prepared;internal readonly Signals Signals=new();
        internal Envelope Original=null!;private DraftReviewSnapshot Review=null!;private DisclosureSnapshot Disclosure=null!;
        private readonly ElectronicRecordDisclosure disclosures=new(ProductionRetentionAdmissionContractTests.Policies());
        internal static async Task<Ready> Create(SqlDatabaseFixture fixture,bool requestedDeadline=false)
        {
            var test=new Ready(fixture,await ProductionRecordUploadAdmissionTests.Prepared.Create(fixture));await using var db=fixture.Open();
            var p=test.Prepared;
            if(requestedDeadline)
            {
                // Explicit synthetic fixture input, sealed through the same
                // admission kernel; no runtime policy or clock is inferred.
                var setup=await p.Run.Admission.BeginAsync(p.Run.Id,Guid.NewGuid(),"test/deadline","synthetic-requested-signing-deadline");
                await using(var tx=await db.Database.BeginTransactionAsync())
                {
                    await db.Envelopes.Where(x=>x.Id==p.Run.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,p.Run.Time.Now.AddDays(1)));
                    await p.Run.Admission.PrepareOutcomeLockedAsync(db,setup);await tx.CommitAsync();
                }
                await p.Run.Admission.CompleteAsync(setup,Hash);
            }
            Assert.True(await p.Upload(db,await p.Record(db)));db.ChangeTracker.Clear();var e=await p.Record(db);
            Assert.True(await p.Workflow(db).ConfirmAsync(p.Sender,e.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default));db.ChangeTracker.Clear();e=await p.Record(db);
            var signers=new SignerSetup(db,new(db,p.Run.Time),new(),p.Run.Time){HoldAdmission=new(p.Run.Admission)};
            Assert.Equal(SignerSetupError.None,(await signers.ChangeAsync(p.Sender,e.PublicId,new(SignerChangeKind.Save,Convert.ToBase64String(e.RowVersion),FullName:"Synthetic First",Email:"first@example.invalid"),null,null)).Error);
            db.ChangeTracker.Clear();e=await p.Record(db);
            var details=new DraftDetails(db,new(db,p.Run.Time),new(),p.Run.Time){HoldAdmission=new(p.Run.Admission)};
            Assert.Equal(DetailsError.None,(await details.ChangeAsync(p.Sender,e.PublicId,new(DetailsChangeKind.SaveDetails,Convert.ToBase64String(e.RowVersion),Title:"Synthetic NO AGREEMENT"),null,null)).Error);
            db.ChangeTracker.Clear();test.Original=await p.Record(db);
            test.Review=(await new DraftReview(db,p.Run.Time).GetAsync(p.Sender,e.PublicId))!;Assert.True(test.Review.ChecksPassed);
            test.Disclosure=test.Review.ProductionDisclosure!.Build(test.disclosures,test.Review.Title!);return test;
        }
        internal async Task<SentDraft?> Send(QuillSignDbContext? supplied=null,bool acknowledge=true)
        {
            await using var owned=supplied is null?fixture.Open():null;var db=supplied??owned!;var run=Prepared.Run;
            var work=new WorkOptions{Enabled=true};var email=new EmailOptions{Enabled=true};
            var outbox=new SignerInvitationOutbox(db,()=>Signals,work,email,new(run.Keys),run.Time);
            var expiry=new SigningExpiryJobs(db,new(db,run.Time),()=>Signals,work,run.Time);
            var workflow=new SendDraftWorkflow(db,Prepared.Blobs,new(),new(),new(),new(),new(32*1024*1024,200,200),disclosures,outbox,work,email,
                new(db,run.Time),run.Time,NullLogger<SendDraftWorkflow>.Instance,expiry){HoldAdmission=new(run.Admission,Prepared.Blobs)};
            var reminder=SignerReminderPolicy.FromDays([]);
            return await workflow.SendAsync(Prepared.Sender,Original.PublicId,Original.RowVersion,true,acknowledge,SenderSendStatement.Version,null,null,
                reviewedRetentionSha256:Review.RetentionSha256,reviewedReminderSha256:reminder.Sha256,
                reviewedReminderSchedulingVersion:SignerReminderEvidence.Version,reviewedDisclosureSha256:Convert.ToHexStringLower(Disclosure.Sha256));
        }
        public ValueTask DisposeAsync()=>Prepared.DisposeAsync();
    }
}
