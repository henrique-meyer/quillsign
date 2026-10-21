using System.Security.Cryptography;
using System.Security.Claims;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionSignerReviewRuntimeContractTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public void Shared_original_snapshot_preserves_the_exact_existing_producer_formula_and_large_values()
    {
        var now=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero);var id=Guid.NewGuid();var signerId=Guid.NewGuid();var document=Guid.NewGuid();
        var identity=new VerifiedSigner(id,"synthetic-review",signerId,"synthetic@example.invalid",document,new('a',64),new('b',64),now.AddHours(1));
        var envelope=new Envelope{Id=id,RowVersion=[1,2,3,4,5,6,7,8],PageCount=1,PageSizesJson="[]"};
        var signer=new Signer{Id=signerId,EnvelopeId=id,FullName="Synthetic signer",ConsentAt=now,RowVersion=[8,7,6,5,4,3,2,1]};
        var preview=new SignaturePreview{Id=Guid.NewGuid(),SignatureSha256=new byte[32],InitialsSha256=Enumerable.Repeat((byte)1,32).ToArray(),NormalizationVersion=SignaturePng.Version};
        var fields=Enumerable.Range(0,200).Select(i=>new DocumentField{EnvelopeId=id,SignerId=signerId,Type=FieldType.Text,Value=new('界',4000),
            FilledAt=now,FilledBy=PartyType.Signer,Page=1,X=.1m,Y=.1m,Width=.2m,Height=.1m,RowVersion=[1,2,3,4,5,6,7,8]}).ToArray();
        var original=JsonSerializer.Serialize(new {version=SignerReviewCandidates.SnapshotVersion,identity.EnvelopeId,identity.SignerId,identity.DocumentId,
            identity.DocumentHash,identity.DisclosureHash,envelope.RowVersion,envelope.PageCount,envelope.PageSizesJson,
            signer.FullName,signer.ConsentAt,signerVersion=signer.RowVersion,adoptionId=preview.Id,preview.SignatureSha256,preview.InitialsSha256,preview.NormalizationVersion,fields});
        var shared=SignerReviewCandidates.OriginalSnapshotJson(identity,envelope,signer,preview,fields);
        Assert.Equal(original,shared);Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(original)),SHA256.HashData(Encoding.UTF8.GetBytes(shared)));
        Assert.True(Encoding.UTF8.GetByteCount(shared)>4_000_000);using var saved=JsonDocument.Parse(shared);
        Assert.Equal(200,saved.RootElement.GetProperty("fields").GetArrayLength());Assert.Equal(4000,saved.RootElement.GetProperty("fields")[199].GetProperty("Value").GetString()!.Length);
    }

    [Fact]
    public void Shared_prepared_audit_is_byte_identical_to_the_current_producer()
    {
        var p=new SignerReviewCandidate{EnvelopeId=Guid.NewGuid(),SignerId=Guid.NewGuid(),AdoptionId=Guid.NewGuid(),SourceObjectId=Guid.NewGuid(),PdfObjectId=Guid.NewGuid(),PdfLength=32,
            SourceSha256=new byte[32],DisclosureSha256=new byte[32],SessionSha256=new byte[32],SnapshotSha256=new byte[32],PdfSha256=new byte[32],RecipeSha256=new byte[32],
            RendererVersion="signer-pdf-v1",SnapshotVersion=SignerReviewCandidates.SnapshotVersion,PreparedAt=new(2030,1,1,12,0,0,TimeSpan.Zero),ExpiresAt=new(2030,1,1,12,10,0,TimeSpan.Zero),ProspectiveDate=new(2030,1,1)};
        string Hex(byte[] value)=>Convert.ToHexStringLower(value);
        var expected=JsonSerializer.Serialize(new {candidateId=p.Id,p.PdfObjectId,p.SourceObjectId,p.PdfLength,p.AdoptionId,
            sourceSha256=Hex(p.SourceSha256),disclosureSha256=Hex(p.DisclosureSha256),sessionSha256=Hex(p.SessionSha256),snapshotSha256=Hex(p.SnapshotSha256),pdfSha256=Hex(p.PdfSha256),recipeSha256=Hex(p.RecipeSha256),
            p.RendererVersion,p.SnapshotVersion,p.ProspectiveDate,p.PreparedAt,p.ExpiresAt,serverEvidence="exact_review_pdf_prepared_not_user_review_or_finish"});
        Assert.Equal(expected,SignerReviewCandidates.PreparedEvidenceJson(p));
    }

    [Fact]
    public async Task Checkpoint_hint_is_bracketed_by_same_transaction_exact_work_demands_and_replay_has_no_effect()
    {
        await using var db=fixture.Open();var envelope=new Envelope{IsDemo=true,SenderEmail="synthetic@example.invalid"};db.Add(envelope);await db.SaveChangesAsync();
        var time=new ProductionHoldWitnessJournalTests.Clock();var finish=new SignerFinishAcceptance{EnvelopeId=envelope.Id};var signals=new Hints();var calls=0;
        var jobs=new SignerCheckpointJobs(db,()=>signals,new(){Enabled=true},time);
        await using(var tx=await db.Database.BeginTransactionAsync())
        {
            var original=tx.TransactionId;
            Assert.True(await jobs.PrepareAsync(finish,default,async(id,due,ct)=>{
                calls++;Assert.Equal(original,db.Database.CurrentTransaction!.TransactionId);Assert.Equal(finish.Id,id);
                var row=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id,ct);Assert.Equal(due,row.AvailableAt);
                Assert.Equal(WorkKind.Rendering,row.Kind);Assert.Equal(JsonSerializer.Serialize(new SignerCheckpointPayload(SignerCheckpointJobs.Version,finish.Id)),row.PayloadJson);
            }));
            Assert.Equal(2,calls);Assert.Equal(1,signals.Put);Assert.False(await jobs.PrepareAsync(finish,default,(_,_,_)=>throw new InvalidDataException()));await tx.CommitAsync();
        }
        Assert.Equal(2,calls);Assert.Equal(1,signals.Put);
    }

    [Fact]
    public async Task Hint_guard_failure_before_effect_rolls_back_new_work_and_never_publishes()
    {
        await using var db=fixture.Open();var envelope=new Envelope{IsDemo=true,SenderEmail="synthetic@example.invalid"};db.Add(envelope);await db.SaveChangesAsync();
        var finish=new SignerFinishAcceptance{EnvelopeId=envelope.Id};var signals=new Hints();
        var jobs=new SignerCheckpointJobs(db,()=>signals,new(){Enabled=true},new ProductionHoldWitnessJournalTests.Clock());
        await using(var tx=await db.Database.BeginTransactionAsync())
        {
            await Assert.ThrowsAsync<InvalidDataException>(()=>jobs.PrepareAsync(finish,default,(_,_,_)=>throw new InvalidDataException("Synthetic blocked hint")));
            await tx.RollbackAsync();
        }
        await using var check=fixture.Open();Assert.False(await check.WorkItems.AnyAsync(x=>x.Id==finish.Id));Assert.Equal(0,signals.Put);Assert.Equal(0,signals.Published);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Actual_first_review_Finish_and_checkpoint_reuse_accepted_PDF_and_stop_before_second_invitation_submission(bool demo)
    {
        await using var flow=await Flow.Create(fixture,demo:demo);
        var candidate=(await flow.Prepare())!;Assert.NotNull(candidate);var read=await flow.Read(candidate.Receipt);Assert.NotNull(read);
        Assert.Equal(candidate.PdfSha256,Convert.ToHexStringLower(SHA256.HashData(read.Pdf)));
        var accepted=await flow.Finish(candidate.Receipt);Assert.Equal(SignerFinishOutcome.Accepted,accepted.Outcome);
        Assert.Equal(SignerFinishOutcome.AlreadyAccepted,(await flow.Finish(candidate.Receipt)).Outcome);
        var lease=await flow.Claim(accepted.Acceptance!.Id);Assert.Equal(WorkOutcome.Completed,(await flow.Handle(lease)).Outcome);await flow.FinishWork(lease);
        await using var readback=fixture.Open();var e=await readback.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==flow.Id);
        var f=await readback.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==accepted.Acceptance!.Id);
        Assert.Equal(1,e.CurrentCopyVersion);Assert.Equal(f.Id,e.CurrentFinishId);Assert.Equal(candidate.PdfSha256,Convert.ToHexStringLower(f.PdfSha256));
        var second=await readback.Signers.AsNoTracking().SingleAsync(x=>x.EnvelopeId==flow.Id&&x.Order==2);Assert.Equal(SignerStatus.Pending,second.Status);
        Assert.False(await readback.AuthTokens.AnyAsync(x=>x.EnvelopeId==flow.Id&&x.PartyId==second.Id));
        var mail=await readback.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==f.NextInvitationId);Assert.Equal(EmailStatus.Queued,mail.Status);Assert.Equal(0,mail.Attempts);Assert.Null(mail.ProviderMessageId);
        Assert.Equal(demo?0:2,((ReviewStore)flow.Store).Writes);Assert.Equal(0,flow.Blobs.Deletes);Assert.Equal(1,flow.Delivered.Sender.Calls);
        Assert.Null((await flow.Record.Journal.ReadAsync(flow.Id)).OutstandingOperation);
        Assert.Equal(WorkStatus.Completed,(await readback.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id)).Status);
        Assert.False(await readback.WorkItems.AnyAsync(x=>x.EnvelopeId==flow.Id&&x.Kind==WorkKind.Sealing));
    }
    internal sealed class Flow(SqlDatabaseFixture fixture,ProductionSignaturePreviewAdmissionTests.Flow marks,IProductionSignerReviewStore store):IAsyncDisposable
    {
        internal readonly ProductionSignaturePreviewAdmissionTests.Flow Marks=marks;
        internal readonly IProductionSignerReviewStore Store=store;
        internal ProductionInvitationWorkerAdmissionTests.Delivered Delivered=>Marks.Delivered;
        internal ProductionRuntimeAdmissionTests.Run Record=>Marks.Record;
        internal Guid Id=>Marks.Id;
        internal ProductionRecordUploadAdmissionTests.Blobs Blobs=>Marks.Blobs;
        internal VerifiedSigner Identity=>Marks.Identity;
        internal ClaimsPrincipal Principal=>Marks.Principal;
        internal string PublicId=>Delivered.Ready.Original.PublicId;
        private ProductionSignerReviewAdmission Hook=>new(Record.Admission,Record.Keys,Store,Record.Time);
        internal static async Task<Flow> Create(SqlDatabaseFixture fixture,bool demo=false,
            Func<ProductionRecordUploadAdmissionTests.Blobs,IProductionSignerReviewStore>? store=null)
        {
            var marks=await ProductionSignaturePreviewAdmissionTests.Flow.Create(fixture,demo:demo,twoSigners:true);
            var preview=(await marks.Prepare())!;Assert.Equal(SignatureAdoptionResult.Adopted,await marks.Adopt(preview));
            var field=(await marks.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
            Assert.Equal(SignerFieldOutcome.Applied,(await marks.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:preview.Id))).Outcome);
            return new(fixture,marks,store?.Invoke(marks.Blobs)??new ReviewStore(marks.Blobs));
        }
        internal SignerReviewCandidates Reviews(QuillSignDbContext db)=>new(db,ProductionSignerMutationAdmissionTests.Access(Delivered,db),Marks.Adoption(db),
            new(Blobs,new()){HoldAdmission=new(Record.Admission)},new(64*1024*1024,200,200),Blobs,new(Record.Keys,Record.Time),new(db,Record.Time),Record.Time){HoldAdmission=Hook};
        internal SignerFinish FinishService(QuillSignDbContext db)=>new(db,ProductionSignerMutationAdmissionTests.Access(Delivered,db),Reviews(db),new(Record.Keys,Record.Time),
            new(db,Record.Time),Record.Time,new(db,()=>Delivered.Ready.Signals,new(){Enabled=true},Record.Time)){HoldAdmission=Hook};
        internal async Task<SignerReviewPrepared?> Prepare(QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;return await Reviews(supplied??owned!).PrepareAsync(Principal,PublicId);}
        internal async Task<SignerReviewData?> Read(string receipt,QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;return await Reviews(supplied??owned!).ReadAsync(Principal,PublicId,receipt);}
        internal async Task<SignerFinishResult> Finish(string receipt,QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;return await FinishService(supplied??owned!).AcceptAsync(Principal,PublicId,receipt,true,SignerFinishStatement.Version);}
        internal WorkStore Work(QuillSignDbContext db)=>new(db,new(){Enabled=true},Record.Time,new ProductionWorkAdmission(fixture.Open,Record.Admission));
        internal async Task<WorkLease> Claim(Guid finishId)
        {
            await using var db=fixture.Open();
            if(!(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==Id)).IsDemo)
            {
                var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==Id);Assert.Equal("[3,7]",e.ReminderDaysJson);
                Assert.True((await QuillSign.Sender.SenderSentStatus.ReadSentAsync(db,e,null,default)).Reminders!.Days.IsEmpty);
                var f=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==finishId);var p=await db.SignerReviewCandidates.AsNoTracking().SingleAsync(x=>x.Id==f.ReviewCandidateId);
                Assert.True(SignerFinish.MatchesCandidate(f,p));Assert.Null((await Record.Journal.ReadAsync(Id)).OutstandingOperation);
                await ProductionWorkAdmission.DemandInitialCheckpointAsync(db,finishId,Id,default);
            }
            var lease=(await Work(db).ClaimAsync(finishId,default)).Lease;Assert.NotNull(lease);return lease;
        }
        internal SignerCheckpointHandler Checkpoint(QuillSignDbContext db)=>new(db,new(db,Record.Time),new(Blobs,Record.Time),
            new(db,()=>Delivered.Ready.Signals,new(){Enabled=true},new(){Enabled=true},new(Record.Keys),Record.Time),new(db,Record.Time),Record.Time)
            {HoldAdmission=new ProductionWorkAdmission(fixture.Open,Record.Admission)};
        internal async Task<WorkResult> Handle(WorkLease lease,QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;return await Checkpoint(supplied??owned!).ExecuteAsync(lease,default);}
        internal async Task FinishWork(WorkLease lease,QuillSignDbContext? supplied=null)
        {await using var owned=supplied is null?fixture.Open():null;await Work(supplied??owned!).FinishAsync(lease,new(WorkOutcome.Completed),default);}
        internal async Task Process(Guid finishId,Action<WorkLease>? captureLease=null)
        {var lease=await Claim(finishId);captureLease?.Invoke(lease);Assert.Equal(WorkOutcome.Completed,(await Handle(lease)).Outcome);await FinishWork(lease);}
        public ValueTask DisposeAsync()=>Marks.DisposeAsync();
    }
    private sealed class ReviewStore(ProductionRecordUploadAdmissionTests.Blobs blobs):IProductionSignerReviewStore
    {
        internal int Writes;
        public async Task<ProductionRecordWriteReceipt> WriteAsync(ProductionRecordOperation scope,VerifiedSigner identity,ProductionRecordWriteDescriptor item,
            Stream source,bool mayWrite,ProductionRecordWriteReceipt? saved,Func<CancellationToken,Task> demand,CancellationToken ct=default)
        {
            await demand(ct);
            if(mayWrite){Assert.False(blobs.Objects.ContainsKey(item.Blob));using var copy=new MemoryStream();await source.CopyToAsync(copy,ct);await demand(ct);
                Assert.Equal(item.Length,copy.Length);Assert.Equal(item.Sha256,Convert.ToHexStringLower(SHA256.HashData(copy.ToArray())));blobs.Objects.Add(item.Blob,copy.ToArray());Writes++;}
            var bytes=blobs.Objects[item.Blob];Assert.Equal(item.Length,bytes.LongLength);Assert.Equal(item.Sha256,Convert.ToHexStringLower(SHA256.HashData(bytes)));
            var receipt=new ProductionRecordWriteReceipt(item,"synthetic-review-version-"+item.Blob.ObjectId.ToString("N"),"\"synthetic-review-etag\"");
            if(saved is not null)Assert.Equal(saved,receipt);await demand(ct);return receipt;
        }
    }
    private sealed class Hints:IWorkSignals
    {
        internal int Put,Published;
        public Task PutHintAsync(Guid id,DateTimeOffset at,CancellationToken ct){Put++;return Task.CompletedTask;}
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct){Published++;return Task.CompletedTask;}
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>Task.CompletedTask;
        public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>Task.FromResult<DateTimeOffset?>(null);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>Task.FromResult<WorkDelivery?>(null);
        public Task DeferAsync(WorkDelivery delivery,TimeSpan delay,CancellationToken ct)=>Task.CompletedTask;
        public Task AcknowledgeAsync(WorkDelivery delivery,CancellationToken ct)=>Task.CompletedTask;
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>Task.FromResult(0);
        public Task VerifyAsync(CancellationToken ct)=>Task.CompletedTask;
    }
}
