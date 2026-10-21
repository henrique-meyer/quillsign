using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Email;
using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Sealing;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionCompletionConnectedTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Configured_fixture_clock_binds_CMS_signing_time_to_the_same_validated_RFC3161_and_certificate_time()
    {
        var at=new DateTimeOffset(2030,1,1,12,0,0,TimeSpan.Zero);await using var seal=await SealFixtures.Create(initialTime:at);
        var source=PdfFixtures.Create();var pdf=await seal.Engine.SealAsync(source,SHA256.HashData(source));
        var inspected=await new SealCms(seal.Options,seal.Timestamps).VerifyAsync(pdf.Bytes,seal.Seal,at,default);
        Assert.Equal(at,pdf.SealedAt);Assert.Equal(at,inspected.Timestamp.At);
        var cms=new System.Security.Cryptography.Pkcs.SignedCms();cms.Decode(inspected.Timestamp.Encoded);
        var attribute=Assert.Single(cms.SignerInfos[0].SignedAttributes.Cast<System.Security.Cryptography.CryptographicAttributeObject>(),x=>x.Oid.Value=="1.2.840.113549.1.9.5");
        Assert.Equal(at.UtcDateTime,new System.Security.Cryptography.Pkcs.Pkcs9SigningTime(attribute.Values[0].RawData).SigningTime);
        Assert.Equal(1,seal.Requests);
    }
    [Fact]
    public async Task Genuine_two_signers_complete_all_seven_slots_then_submit_four_exact_pairs_and_preserve_independent_holds()
    {
        await using var run=await LastCheckpoint();var originalClock=run.Record.Time.Now;
        await using var seal=await SealFixtures.Create(initialTime:originalClock);
        using var provider=new Provider(run.Record.Time);
        using var store=new AzureProductionCompletionStore(new("https://storage.example.invalid"),new Credential(),provider.Transport);
        var effects=new ObservedEffects(new ProductionCompletionEffects(run.Record.Admission,run.Record.Keys,store,seal.Engine));
        var completion=new ProductionCompletionAdmission(run.Record.Admission,effects);
        var admission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission){Completion=completion};
        WorkLease lease;string tokens;
        await using(var db=fixture.Open())
        {
            tokens=JsonSerializer.Serialize(await db.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==run.Id).OrderBy(x=>x.Id).ToArrayAsync());
            lease=(await new WorkStore(db,new(){Enabled=true,LeaseSeconds=600},run.Record.Time,admission).ClaimAsync(CompletionJobs.WorkId(run.Id),default)).Lease!;
        }
        Assert.NotNull(lease);
        var blobs=new ReadOnlyBlobs(run.Blobs,new AzureBlobStore(provider.Client,64*1024*1024));
        await using var work=fixture.Open();var scope=new CompletionCommitScope(work,run.Record.Time);
        var collector=new CompletionEvidenceCollector(work,new(work,run.Record.Time),new(blobs,run.Record.Time),blobs,run.Record.Time);
        var candidate=new CompletionCandidates(work,collector,new(),blobs,new(work,run.Record.Time),run.Record.Time,scope);
        var seals=new CompletionSealOutputs(work,candidate,collector,new(),seal.Engine,new(seal.Options,seal.Timestamps),blobs,new(work,run.Record.Time),run.Record.Time,scope);
        CompletionPublication? publication=null;
        var state=new CompletionAccessState(work,collector,()=>publication!,run.Record.Time);
        var notifications=new CompletionNotificationJobs(work,state,new(run.Record.Keys),()=>run.Delivered.Ready.Signals,new(){Enabled=true},new(work,run.Record.Time),run.Record.Time);
        var final=new AzureCompletionFinalStore(provider.Client,run.Record.Time,seal.App.Environment);
        publication=new(work,candidate,seals,collector,final,new(work,run.Record.Time),run.Record.Time,new(),seal.App.Environment,scope,()=>notifications);
        var handler=new CompletionWorkHandler(work,new(work,run.Record.Time),scope,()=>new(candidate,seals,publication),run.Record.Time){HoldAdmission=completion};
        var result=await handler.ExecuteAsync(lease,default);
        Assert.True(result.Outcome==WorkOutcome.Completed,result.Code+Environment.NewLine+effects.Error+
            $"\nSDK commits={provider.Commits}; TSA requests={seal.Requests}");
        var handlerState=await run.Record.Journal.ReadAsync(run.Id);
        Assert.Equal(lease.Owner,handlerState.OutstandingOperation);Assert.NotNull(handlerState.HandlerOutcomes![lease.Owner]);
        Assert.Equal(6,handlerState.Completions![lease.Owner].Slots!.Count);
        await using(var finish=fixture.Open())await new WorkStore(finish,new(){Enabled=true,LeaseSeconds=600},run.Record.Time,admission).FinishAsync(lease,new(WorkOutcome.Completed),default);

        var saved=await run.Record.Journal.ReadAsync(run.Id);Assert.Null(saved.OutstandingOperation);
        var completed=saved.Completions![lease.Owner];Assert.NotNull(completed.ClaimExpected);Assert.NotNull(completed.ClaimAcknowledged);
        Assert.Equal(Enum.GetValues<CompletionSlot>(),completed.Slots!.Keys.Order());
        Assert.All(completed.Slots.Values,slot=>{Assert.NotNull(slot.Expected);Assert.NotNull(slot.Acknowledged);Assert.Equal(slot.Started.Count,slot.Receipts.Count);});
        var receipts=completed.Slots.Values.SelectMany(x=>x.Receipts.Values).ToArray();
        Assert.Equal(11,receipts.Count(x=>x.Stored?.Item.Blob.Kind==DocumentBlobKind.CompletionInput));
        Assert.Equal(19,receipts.Length);Assert.Equal(17,provider.Objects.Count);Assert.Equal(2,seal.Requests);
        foreach(var receipt in receipts)
        {
            if(receipt.Stored is {} item)
            {
                var blob=provider.Objects.Values.Single(x=>x.Version==item.VersionId&&x.Tag==item.ETag);
                Assert.Equal(item.Item.Length,blob.Bytes.LongLength);Assert.Equal(item.Item.Sha256,Hex(SHA256.HashData(blob.Bytes)));
            }
            if(receipt.Final is {} file)
            {
                var blob=provider.Objects.Values.Single(x=>x.Version==file.VersionId&&x.Tag==file.ETag);
                Assert.Equal(file.Length,blob.Bytes.LongLength);Assert.Equal(file.Sha256,SHA256.HashData(blob.Bytes));
                Assert.Equal(FinalProtection.LockedTime,file.Protection);Assert.Equal(file.ProtectedUntil,blob.Until);
                Assert.Equal(0,file.ProtectedUntil!.Value.Ticks%TimeSpan.TicksPerSecond);
            }
        }
        await using var read=fixture.Open();var envelope=await read.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id);
        Assert.Equal(EnvelopeStatus.Completed,envelope.Status);Assert.Equal(originalClock,envelope.CompletedAt);Assert.Equal(originalClock,run.Record.Time.Now);
        Assert.Equal(WorkStatus.Completed,(await read.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lease.Id)).Status);
        Assert.Equal(1,await read.CompletionCandidates.CountAsync(x=>x.EnvelopeId==run.Id));Assert.Equal(2,await read.CompletionSealOutputs.CountAsync(x=>x.EnvelopeId==run.Id));
        Assert.Equal(1,await read.CompletionPublicationIntents.CountAsync(x=>x.EnvelopeId==run.Id));Assert.Equal(1,await read.CompletionPublicationResults.CountAsync(x=>x.EnvelopeId==run.Id));
        var mail=await read.EmailOutbox.AsNoTracking().Where(x=>x.EnvelopeId==run.Id&&x.Template==CompletionNotificationJobs.Template).ToArrayAsync();
        Assert.Equal(4,mail.Length);Assert.All(mail,x=>{Assert.Equal(EmailStatus.Queued,x.Status);Assert.Equal(0,x.Attempts);Assert.Null(x.SubmissionStartedAt);Assert.Null(x.ProviderMessageId);});
        Assert.Equal(4,await read.WorkItems.CountAsync(x=>x.EnvelopeId==run.Id&&x.Kind==WorkKind.Email&&x.Status==WorkStatus.Queued&&x.Attempts==0));
        Assert.Equal(tokens,JsonSerializer.Serialize(await read.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==run.Id).OrderBy(x=>x.Id).ToArrayAsync()));
        var published=(await publication.ReadAsync(run.Id))!;Assert.NotNull(published);Assert.Equal(envelope.FinalSha256,SHA256.HashData(published.ExecutedBytes));
        Assert.Equal(envelope.CertificateSha256,SHA256.HashData(published.CertificateBytes));
        Assert.Equal(2,run.Delivered.Sender.Calls);Assert.Equal(0,blobs.Writes);Assert.Equal(0,blobs.Deletes);Assert.Equal(0,run.Blobs.UnwitnessedWrites);Assert.Equal(0,run.Blobs.Deletes);
        Assert.Equal(17,provider.Commits);Assert.Equal(0,provider.OtherMutations);
        Assert.All(provider.Objects.Keys,name=>Assert.Contains(run.Id.ToString("N"),name));

        // The completed worker's old lease never becomes historical read authority.
        // Fresh hold scopes reopen the exact original inputs/plan after that lease expires.
        var census=new CompletedObjects(run.Blobs,provider);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered,census,store);
        foreach(var item in census.Completed)holds.Provider.SourceFiles.Add(item.Key,item.Value.ToArray());
        var first=await holds.Place(0);
        ProductionHoldProtectedPlan originalPlan;
        await using(var inspect=fixture.Open())
        {
            await using var tx=await inspect.Database.BeginTransactionAsync();
            var controls=await new ProductionHoldControls(inspect,run.Record.Keys,run.Record.Time).ReadLockedAsync(run.Id);
            originalPlan=Assert.Single(controls.Plans.Values,x=>x.HoldId==first.HoldId);
            await tx.RollbackAsync();
        }
        var frozen=ProductionHoldBundlePlan.OpenVerified(originalPlan,run.Record.Keys,run.Record.Time);
        Assert.Equal(run.Blobs.Objects.Count+provider.Objects.Count+2,frozen.Items.Length);
        run.Record.Time.Now=run.Record.Time.Now.AddMinutes(11);
        Assert.True(run.Record.Time.Now>lease.Until);
        var reopened=ProductionHoldBundlePlan.OpenVerified(originalPlan,run.Record.Keys,run.Record.Time);
        Assert.Equal(frozen.Snapshot.ManifestSha256,reopened.Snapshot.ManifestSha256);
        Assert.Equal(frozen.Snapshot.SqlStateSha256,reopened.Snapshot.SqlStateSha256);
        var inventory=ProductionHoldObjectInventory.OpenVerified(reopened.Snapshot,run.Record.Keys,run.Record.Time);
        await using(var inspect=fixture.Open())
        {
            await using var tx=await inspect.Database.BeginTransactionAsync();
            var held=await run.Record.Journal.ReadAsync(run.Id);
            var current=await new ProductionHoldSqlInventory(inspect,run.Record.Keys,run.Record.Time)
                .CaptureLockedAsync(run.Id,held.RequestRevision,held.RequestFenceHash!);
            var currentScope=ProductionHoldObjectScope.FromVerified(current,run.Record.Keys,run.Record.Time);
            var references=ProductionHoldCompletionInputReferences.References(run.Id,held);Assert.Equal(11,references.Length);
            foreach(var reference in references)
            {
                var evidence=Assert.Single(inventory,x=>x.Address.Area=="normalized"&&x.Address.Name==$"{run.Id:N}/completion-inputs/{reference.Item.Blob.ObjectId:N}");
                var inputScope=ProductionCompletionInputReadScope.FromHold(currentScope,reference.Context,reference.Kind,reference.Item,reference.Receipt,evidence);
                try
                {
                    var cipher=await store.ReadAsync(inputScope);
                    _=ProductionCompletionInputCodec.OpenVerified(run.Record.Keys,run.Id,reference.Context,reference.Kind,reference.Item,cipher);
                }
                finally{inputScope.Close();}
                Assert.Throws<InvalidDataException>(()=>inputScope.Demand());
            }
            await tx.RollbackAsync();
        }
        var mailAdmission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission){Completion=completion,CompletionMail=new(run.Record.Keys,run.Record.Time)};
        await using(var blocked=fixture.Open())
        {
            var before=await blocked.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==mail[0].Id);
            Assert.Null((await new WorkStore(blocked,new(){Enabled=true,LeaseSeconds=600},run.Record.Time,mailAdmission).ClaimAsync(mail[0].Id,default)).Lease);
            Assert.Equal(JsonSerializer.Serialize(before),JsonSerializer.Serialize(await blocked.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==before.Id)));
        }
        var second=await holds.Place(1);
        var independent=await holds.Coordinator().ReadVerifiedAsync(run.Id);
        Assert.True(independent.Holds[first.HoldId].Effective);Assert.True(independent.Holds[second.HoldId].Effective);
        Assert.True(await holds.Release(first,2));
        await using(var blocked=fixture.Open())Assert.Null((await new WorkStore(blocked,new(){Enabled=true,LeaseSeconds=600},run.Record.Time,mailAdmission).ClaimAsync(mail[0].Id,default)).Lease);
        Assert.False(await holds.Release(second,3));
        Assert.All(holds.Provider.Files.Values,x=>Assert.False(x.Held));
        await using(var inspect=fixture.Open())
        {
            Assert.Equal(tokens,JsonSerializer.Serialize(await inspect.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==run.Id).OrderBy(x=>x.Id).ToArrayAsync()));
            var after=await inspect.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id);
            Assert.Equal(envelope.CompletedAt,after.CompletedAt);Assert.Equal(envelope.PurgeAfter,after.PurgeAfter);
            Assert.Equal(envelope.FinalSha256,after.FinalSha256);Assert.Equal(envelope.CertificateSha256,after.CertificateSha256);
        }
        Assert.All(provider.Objects.Values.Where(x=>x.Until is not null),x=>Assert.Equal(envelope.PurgeAfter,x.Until));
        Assert.Equal(17,provider.Commits);Assert.Equal(0,provider.OtherMutations);Assert.Equal(2,seal.Requests);

        var capture=new CompletionCapture(published.ExecutedBytes,published.CertificateBytes);
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SignerAccess).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddScoped<RazorEmailViews>();
        await using var app=builder.Build();using var services=app.Services.CreateScope();var views=services.ServiceProvider.GetRequiredService<RazorEmailViews>();
        var dispatchedAt=run.Record.Time.Now;var leases=new List<WorkLease>();
        foreach(var queued in mail)
        {
            await using var dispatch=fixture.Open();
            var storeWork=new WorkStore(dispatch,new(){Enabled=true,LeaseSeconds=600},run.Record.Time,mailAdmission);
            var emailLease=(await storeWork.ClaimAsync(queued.Id,default)).Lease!;Assert.NotNull(emailLease);leases.Add(emailLease);
            var delivery=CompletionHandler(dispatch,run,seal,blobs,final,views,capture,mailAdmission);
            var outcome=await delivery.ExecuteAsync(emailLease,default);Assert.Equal(WorkOutcome.Completed,outcome.Outcome);
            await storeWork.FinishAsync(emailLease,outcome,default);
            Assert.Null((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
        }
        Assert.Equal(4,capture.Messages.Count);Assert.Equal(4,capture.Messages.Select(x=>x.To).Distinct().Count());
        var delivered=await run.Record.Journal.ReadAsync(run.Id);Assert.Equal(4,delivered.CompletionMailBaselines!.Count);
        await using(var inspect=fixture.Open())
        {
            Assert.Equal(4,await inspect.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Id&&x.Template==CompletionNotificationJobs.Template&&x.Status==EmailStatus.Sent&&x.Attempts==1));
            var issued=await inspect.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==run.Id&&x.Purpose==TokenPurpose.CompletionAccess).ToArrayAsync();
            Assert.Equal(4,issued.Length);Assert.All(issued,t=>{Assert.Null(t.UsedAt);Assert.Equal(dispatchedAt.AddHours(24),t.ExpiresAt);});
            Assert.Equal(tokens,JsonSerializer.Serialize(await inspect.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==run.Id&&x.Purpose!=TokenPurpose.CompletionAccess).OrderBy(x=>x.Id).ToArrayAsync()));
        }
        var transportFirst=await holds.Place(4);
        ProductionHoldProtectedPlan transportPlan;
        await using(var inspect=fixture.Open())
        {
            await using var tx=await inspect.Database.BeginTransactionAsync();var controls=await new ProductionHoldControls(inspect,run.Record.Keys,run.Record.Time).ReadLockedAsync(run.Id);
            transportPlan=Assert.Single(controls.Plans.Values,x=>x.HoldId==transportFirst.HoldId);await tx.RollbackAsync();
        }
        var transportFrozen=ProductionHoldBundlePlan.OpenVerified(transportPlan,run.Record.Keys,run.Record.Time);
        Assert.Equal(frozen.Items.Length,transportFrozen.Items.Length);        using(var projection=ProductionHoldSqlInventory.OpenVerified(transportFrozen.Snapshot.Sql,run.Record.Keys))
            DemandHistoricalMailFaults(projection.RootElement,await run.Record.Journal.ReadAsync(run.Id),run.Record.Keys,
                ProductionHoldObjectInventory.OpenVerified(transportFrozen.Snapshot,run.Record.Keys,run.Record.Time));
        run.Record.Time.Now=run.Record.Time.Now.AddMinutes(11);Assert.All(leases,l=>Assert.True(run.Record.Time.Now>l.Until));
        Assert.Equal(transportFrozen.Snapshot.ManifestSha256,ProductionHoldBundlePlan.OpenVerified(transportPlan,run.Record.Keys,run.Record.Time).Snapshot.ManifestSha256);
        var transportSecond=await holds.Place(5);
        Assert.True(await holds.Release(transportFirst,6));Assert.False(await holds.Release(transportSecond,7));
        Assert.All(holds.Provider.Files.Values,x=>Assert.False(x.Held));
        Assert.Equal(17,provider.Commits);Assert.Equal(0,provider.OtherMutations);Assert.Equal(2,seal.Requests);Assert.Equal(4,capture.Messages.Count);
        Assert.Equal(0,blobs.Writes);Assert.Equal(0,blobs.Deletes);Assert.Equal(0,run.Blobs.UnwitnessedWrites);Assert.Equal(0,run.Blobs.Deletes);
    }

    private static void DemandHistoricalMailFaults(JsonElement sql,HoldWitnessState state,Microsoft.AspNetCore.DataProtection.IDataProtectionProvider keys,IReadOnlyList<HoldObjectEvidence> objects)
    {
        var history=ProductionHoldCompletionMailReferences.ReadVerified(sql,state,keys,objects);Assert.Equal(4,history.TokenIds.Count);Assert.Equal(12,history.AuditSequences.Count);
        var first=state.CompletionMailBaselines!.First();
        foreach(var fault in new[]{"missing-baseline","foreign-publication","expired-claim","missing-dispatch","missing-handler","wrong-settlement"})
        {
            var baselines=state.CompletionMailBaselines!.ToDictionary(x=>x.Key,x=>x.Value);var changed=state;
            switch(fault)
            {
                case "missing-baseline":baselines.Remove(first.Key);changed=state with{CompletionMailBaselines=baselines};break;
                case "foreign-publication":baselines[first.Key]=first.Value with{PublicationId=Guid.NewGuid()};changed=state with{CompletionMailBaselines=baselines};break;
                case "expired-claim":baselines[first.Key]=first.Value with{ClaimUntil=first.Value.ClaimUntil.AddDays(-1)};changed=state with{CompletionMailBaselines=baselines};break;
                case "missing-dispatch":var starts=state.DispatchStarts!.ToDictionary(x=>x.Key,x=>x.Value);starts.Remove(first.Key);changed=state with{DispatchStarts=starts};break;
                case "missing-handler":var handlers=state.HandlerOutcomes!.ToDictionary(x=>x.Key,x=>x.Value);handlers.Remove(first.Key);changed=state with{HandlerOutcomes=handlers};break;
                case "wrong-settlement":var receipts=state.SettledOperations.ToDictionary(x=>x.Key,x=>x.Value);receipts[first.Key]=new string('a',64);changed=state with{SettledOperations=receipts};break;
            }
            Assert.Throws<InvalidDataException>(()=>ProductionHoldCompletionMailReferences.ReadVerified(sql,changed,keys,objects));
        }
        foreach(var fault in new[]{"token-deadline","provider-receipt","future-wrapper","extra-attempt"})
        {
            var copy=JsonNode.Parse(sql.GetRawText())!.AsObject();
            JsonArray Table(string name)=>copy["Tables"]!.AsArray().Single(x=>x!["Table"]!.GetValue<string>()==name)!["Rows"]!.AsArray();
            if(fault=="token-deadline")
            {
                var token=Table("AuthTokens").Single(x=>x!["Id"]!.GetValue<Guid>()==history.TokenIds.First())!;
                token["ExpiresAt"]=token["ExpiresAt"]!.GetValue<DateTimeOffset>().AddMinutes(1);
            }
            else if(fault is "provider-receipt" or "future-wrapper")
            {
                var mail=Table("EmailOutbox").Single(x=>x!["Id"]!.GetValue<Guid>()==first.Value.WorkId)!;
                if(fault=="provider-receipt")mail["ProviderMessageId"]="synthetic-substituted-receipt";
                else{var wrapper=JsonNode.Parse(mail["PayloadJson"]!.GetValue<string>())!.AsObject();wrapper["Future"]=true;mail["PayloadJson"]=wrapper.ToJsonString();}
            }
            else
            {
                var tail=Table("AuditEvents").Select(x=>x!.Deserialize<AuditEvent>(new JsonSerializerOptions{Converters={new System.Text.Json.Serialization.JsonStringEnumConverter()}})!).OrderBy(x=>x.Sequence).Last();
                var extra=new AuditEvent{Id=tail.Id+1,EnvelopeId=tail.EnvelopeId,Sequence=tail.Sequence+1,At=tail.At,ActorType=PartyType.System,
                    Event="completion_notification_attempt",DataJson="{}",PrevHash=tail.Hash};extra.Hash=AuditHash.Compute(extra);
                Table("AuditEvents").Add(JsonSerializer.SerializeToNode(extra,new JsonSerializerOptions{Converters={new System.Text.Json.Serialization.JsonStringEnumConverter()}}));
            }
            using var malformed=JsonDocument.Parse(copy.ToJsonString());
            Assert.Throws<InvalidDataException>(()=>ProductionHoldCompletionMailReferences.ReadVerified(malformed.RootElement,state,keys,objects));
        }
        var changedSource=objects.Select(x=>x.Address.Area=="final"?x with{Address=x.Address with{VersionId=x.Address.VersionId+"-foreign"}}:x).ToArray();
        Assert.Throws<InvalidDataException>(()=>ProductionHoldCompletionMailReferences.ReadVerified(sql,state,keys,changedSource));
    }
    private EmailWorkHandler CompletionHandler(QuillSignDbContext db,ProductionSignerReviewRuntimeContractTests.Flow run,SealFixtures seal,IBlobStore blobs,
        ICompletionFinalStore final,RazorEmailViews views,IEmailSender capture,IProductionWorkAdmission admission)
    {
        var options=new EmailOptions{Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};
        var scope=new CompletionCommitScope(db,run.Record.Time);var audit=new AuditWriter(db,run.Record.Time);
        var collector=new CompletionEvidenceCollector(db,new(db,run.Record.Time),new(blobs,run.Record.Time),blobs,run.Record.Time);
        var candidates=new CompletionCandidates(db,collector,new(),blobs,audit,run.Record.Time,scope);
        var seals=new CompletionSealOutputs(db,candidates,collector,new(),seal.Engine,new(seal.Options,seal.Timestamps),blobs,audit,run.Record.Time,scope);
        CompletionPublication? publication=null;var accessState=new CompletionAccessState(db,collector,()=>publication!,run.Record.Time);
        var jobs=new CompletionNotificationJobs(db,accessState,new(run.Record.Keys),()=>run.Delivered.Ready.Signals,new(){Enabled=true},audit,run.Record.Time);
        publication=new(db,candidates,seals,collector,final,audit,run.Record.Time,new(),seal.App.Environment,scope,()=>jobs);
        var access=new CompletionAccess(db,accessState,new(run.Record.Keys,run.Record.Time),new(),audit,run.Record.Time,()=>publication);
        var delivery=new CompletionNotificationDelivery(db,accessState,access,jobs,new(run.Record.Keys),()=>new(options,views),capture,options,audit,run.Record.Time);
        return new EmailWorkHandler(db,options,new(run.Record.Keys),new(options,views),capture,run.Record.Time,completions:()=>delivery){HoldAdmission=admission};
    }
    private sealed class CompletionCapture(byte[] executed,byte[] certificate):IEmailSender
    {
        internal readonly List<OutgoingEmail> Messages=[];
        public Task<EmailDelivery> SendAsync(OutgoingEmail message,CancellationToken ct=default)
        {
            ct.ThrowIfCancellationRequested();Assert.EndsWith("@example.invalid",message.To);
            Assert.Equal(2,message.Attachments!.Count);Assert.Equal(executed,message.Attachments[0].CopyBytes());Assert.Equal(certificate,message.Attachments[1].CopyBytes());
            Assert.Contains("complete/access#token=",message.Text);Messages.Add(message);return Task.FromResult(new EmailDelivery("SyntheticCompletionCapture","synthetic-completion-"+Messages.Count));
        }
    }
    private async Task<ProductionSignerReviewRuntimeContractTests.Flow> LastCheckpoint()
    {
        var ready=await ProductionRecordSendAdmissionTests.Ready.Create(fixture,withFields:true,twoSigners:true,withRecipient:true);
        var delivery=new ProductionInvitationWorkerAdmissionTests.Delivered(fixture,ready){WorkId=(await ready.Send())!.InvitationWorkId};
        await delivery.ClaimAsync();Assert.Equal(WorkOutcome.Completed,(await delivery.ExecuteAsync()).Outcome);await delivery.FinishAsync();
        ProductionSignerReviewRuntimeContractTests.Flow? last=null;
        for(var party=0;party<2;party++)
        {
            var steps=new ProductionSignerMutationAdmissionTests(fixture);var identity=(await steps.Redeem(delivery))!;Assert.NotNull(identity);
            var principal=SignerAccessConfiguration.Principal(identity);var pdf=await steps.Preview(delivery,principal);
            Assert.Equal(ConsentResult.Accepted,await steps.Accept(delivery,principal,pdf.Receipt));
            var marks=new ProductionSignaturePreviewAdmissionTests.Flow(fixture,delivery,identity);var preview=(await marks.Prepare())!;
            Assert.Equal(SignatureAdoptionResult.Adopted,await marks.Adopt(preview));var signature=(await marks.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
            Assert.Equal(SignerFieldOutcome.Applied,(await marks.Change(new(signature.Id,signature.Version,SignerFieldAction.Apply,AdoptionId:preview.Id))).Outcome);
            last=new(fixture,marks,marks.Blobs);var review=(await last.Prepare())!;var accepted=await last.Finish(review.Receipt);
            Assert.Equal(SignerFinishOutcome.Accepted,accepted.Outcome);await last.Process(accepted.Acceptance!.Id);
            if(party==0)
            {
                await using var db=fixture.Open();delivery.WorkId=(await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==accepted.Acceptance.Id)).NextInvitationId!.Value;
                await delivery.ClaimAsync();Assert.Equal(WorkOutcome.Completed,(await delivery.ExecuteAsync()).Outcome);await delivery.FinishAsync();
            }
        }
        return last!;
    }

    private sealed class ReadOnlyBlobs(IBlobStore original,IBlobStore completed):IBlobStore
    {
        internal int Writes,Deletes;
        public Task WriteAsync(ClaimsPrincipal p,DocumentBlob b,Stream source,long length,CancellationToken ct=default){Writes++;throw new InvalidOperationException("No generic completion write is admitted.");}
        public Task DeleteAsync(ClaimsPrincipal p,DocumentBlob b,CancellationToken ct=default){Deletes++;throw new InvalidOperationException("No completion cleanup is admitted.");}
        public Task<long> CopyToAsync(ClaimsPrincipal p,DocumentBlob b,Stream target,CancellationToken ct=default)
            =>(b.Kind is DocumentBlobKind.CompletionCandidate or DocumentBlobKind.CompletionExecutedSeal or DocumentBlobKind.CompletionCertificateSource or DocumentBlobKind.CompletionCertificateSeal?completed:original).CopyToAsync(p,b,target,ct);
    }
    private sealed class ObservedEffects(IProductionCompletionEffects actual):IProductionCompletionEffects
    {
        internal Exception? Error;
        private async Task<T> Observe<T>(Func<Task<T>> run){try{return await run();}catch(Exception e){Error=e;throw;}}
        public Task<CompletionOwnedRowPlan> CandidateLockedAsync(QuillSignDbContext db,ProductionRecordOperation s,CompletionCandidate row,PreparedCompletionPacket p,CancellationToken ct)=>Observe(()=>actual.CandidateLockedAsync(db,s,row,p,ct));
        public Task<CompletionOwnedSeal> SealLockedAsync(QuillSignDbContext db,ProductionRecordOperation s,CompletionCandidateData c,CompletionSealKind k,CompletionSealTargets t,byte[] b,CompletionSealData? e,CancellationToken ct)=>Observe(()=>actual.SealLockedAsync(db,s,c,k,t,b,e,ct));
        public Task<CompletionOwnedRowPlan> IntentLockedAsync(QuillSignDbContext db,ProductionRecordOperation s,CompletionPublicationIntent row,CancellationToken ct)=>Observe(()=>actual.IntentLockedAsync(db,s,row,ct));
        public Task<CompletionPublicationFiles> PublicationLockedAsync(QuillSignDbContext db,ProductionRecordOperation s,CompletionPublicationIntent i,CompletionSealPair p,DateTimeOffset at,DateTimeOffset? until,CancellationToken ct)=>Observe(()=>actual.PublicationLockedAsync(db,s,i,p,at,until,ct));
        public Task<CompletionOwnedRowPlan> ResultLockedAsync(QuillSignDbContext db,ProductionRecordOperation s,CompletionPublicationTransition t,CancellationToken ct)=>Observe(()=>actual.ResultLockedAsync(db,s,t,ct));
    }
    private sealed class CompletedObjects(IProductionHoldObjectSource original,Provider provider):IProductionHoldObjectSource
    {
        internal IReadOnlyDictionary<HoldObjectAddress,byte[]> Completed=>provider.Objects.ToDictionary(x=>Address(x.Key,x.Value),x=>x.Value.Bytes);
        private static HoldObjectAddress Address(string path,Stored item)
        {
            var pieces=path.TrimStart('/').Split('/',2);
            return new(pieces[0],pieces[1],item.Version,"",item.Tag,item.Bytes.LongLength);
        }
        public async Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope scope,string area,string? continuation,int maximum,CancellationToken ct)
        {
            scope.Demand(ct);Assert.Null(continuation);var prior=await original.ListAsync(scope,area,null,maximum,ct);
            Assert.Null(prior.Continuation);var all=prior.Objects.Concat(Completed.Keys.Where(x=>x.Area==area)).ToArray();
            Assert.InRange(all.Length,0,maximum);Assert.Equal(all.Length,all.Distinct().Count());
            foreach(var item in all)scope.Demand(item,ct);
            return new(all,null);
        }
        public Task<string> HashAsync(ProductionHoldObjectScope scope,HoldObjectAddress address,CancellationToken ct)
        {
            scope.Demand(address,ct);
            return Completed.TryGetValue(address,out var bytes)?Task.FromResult(Hex(SHA256.HashData(bytes))):original.HashAsync(scope,address,ct);
        }
    }
    private sealed record Stored(byte[] Bytes,string Version,string Tag,string Owner,DateTimeOffset Created,DateTimeOffset? Until,bool Hold);
    private sealed class Provider:HttpMessageHandler
    {
        private readonly TimeProvider time;private readonly Dictionary<string,byte[]> blocks=[];
        internal readonly Dictionary<string,Stored> Objects=[];internal int Commits,OtherMutations;
        internal readonly HttpClientTransport Transport;internal readonly BlobServiceClient Client;
        internal Provider(TimeProvider time)
        {
            this.time=time;Transport=new(new HttpClient(this,false));var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03){Transport=Transport};
            options.Retry.MaxRetries=0;Client=new(new Uri("https://storage.example.invalid"),new Credential(),options);
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            Assert.Equal("storage.example.invalid",request.RequestUri!.Host);var query=QueryHelpers.ParseQuery(request.RequestUri.Query);
            string Q(string key)=>query.TryGetValue(key,out var values)?values.ToString():"";var path=Uri.UnescapeDataString(request.RequestUri.AbsolutePath);
            if(Q("restype")=="container")
            {
                Assert.Equal(HttpMethod.Get,request.Method);Assert.True(path is "/normalized" or "/final");var config=Reply([]);
                config.Headers.TryAddWithoutValidation("x-ms-has-immutability-policy","true");config.Headers.TryAddWithoutValidation("x-ms-immutable-storage-with-versioning-enabled","true");return config;
            }
            if(request.Method==HttpMethod.Put)
            {
                if(Q("comp")=="block")
                {
                    var key=path+"?"+Q("blockid");Assert.False(blocks.ContainsKey(key));blocks.Add(key,await request.Content!.ReadAsByteArrayAsync(ct));return Reply([],HttpStatusCode.Created);
                }
                if(Q("comp")!="blocklist"){OtherMutations++;throw new InvalidOperationException("Unexpected provider mutation.");}
                Assert.Equal("*",request.Headers.GetValues("If-None-Match").Single());Assert.False(Objects.ContainsKey(path));
                var xml=XDocument.Parse(await request.Content!.ReadAsStringAsync(ct));var ids=xml.Root!.Elements().Select(x=>x.Value).ToArray();Assert.NotEmpty(ids);
                var bytes=ids.SelectMany(id=>blocks[path+"?"+id]).ToArray();var owner=request.Headers.GetValues("x-ms-meta-quillsign_completion").Single();Assert.Equal(64,owner.Length);
                var until=request.Headers.TryGetValues("x-ms-immutability-policy-until-date",out var policy)?DateTimeOffset.ParseExact(policy.Single(),"R",CultureInfo.InvariantCulture): (DateTimeOffset?)null;
                var hold=request.Headers.TryGetValues("x-ms-legal-hold",out var holds)&&bool.Parse(holds.Single());
                if(path.StartsWith("/final/",StringComparison.Ordinal)){Assert.True(until is not null||hold);if(until is not null)Assert.Equal("Locked",request.Headers.GetValues("x-ms-immutability-policy-mode").Single(),ignoreCase:true);}
                else{Assert.Null(until);Assert.False(hold);}
                var number=++Commits;Objects.Add(path,new(bytes,"version-"+number,"\"completion-"+number+"\"",owner,time.GetUtcNow(),until,hold));return Reply([],HttpStatusCode.Created);
            }
            Assert.True(request.Method==HttpMethod.Get||request.Method==HttpMethod.Head);
            if(!Objects.TryGetValue(path,out var item))return Error(HttpStatusCode.NotFound,"BlobNotFound");
            if(Q("versionid").Length!=0){Assert.Equal(item.Version,Q("versionid"));Assert.Equal(item.Tag,request.Headers.GetValues("If-Match").Single());}
            var response=Reply(request.Method==HttpMethod.Get?item.Bytes:[]);response.Content.Headers.ContentLength=item.Bytes.Length;response.Content.Headers.LastModified=item.Created;
            response.Headers.TryAddWithoutValidation("x-ms-creation-time",item.Created.ToString("R"));response.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");
            response.Headers.TryAddWithoutValidation("ETag",item.Tag);response.Headers.TryAddWithoutValidation("x-ms-version-id",item.Version);response.Headers.TryAddWithoutValidation("x-ms-meta-quillsign_completion",item.Owner);
            response.Headers.TryAddWithoutValidation("x-ms-legal-hold",item.Hold?"true":"false");
            if(item.Until is {} expiry){response.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date",expiry.ToString("R"));response.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode","Locked");}
            return response;
        }
        private static HttpResponseMessage Reply(byte[] bytes,HttpStatusCode status=HttpStatusCode.OK)
        {var result=new HttpResponseMessage(status){Content=new ByteArrayContent(bytes)};result.Headers.TryAddWithoutValidation("x-ms-version","2023-11-03");return result;}
        private static HttpResponseMessage Error(HttpStatusCode status,string code)
        {var result=Reply(Encoding.UTF8.GetBytes($"<Error><Code>{code}</Code><Message>Synthetic failure.</Message></Error>"),status);result.Headers.TryAddWithoutValidation("x-ms-error-code",code);return result;}
    }
    private sealed class Credential:TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context,CancellationToken ct)=>new("synthetic",DateTimeOffset.MaxValue);
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context,CancellationToken ct)=>ValueTask.FromResult(GetToken(context,ct));
    }
    private static string Hex(byte[] value)=>Convert.ToHexStringLower(value);
}
