using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionHoldInvitationHistoryTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("resend")][InlineData("correction")][InlineData("reminder")]
    public async Task Actual_followup_producer_and_finished_dispatch_preserve_every_original_epoch_token_and_schedule(string action)
    {
        var ready=await ProductionRecordSendAdmissionTests.Ready.Create(fixture,withFields:true,reminderDays:action=="reminder"?[1]:null);
        await using var run=new ProductionInvitationWorkerAdmissionTests.Delivered(fixture,ready){WorkId=(await ready.Send())!.InvitationWorkId};
        await run.ClaimAsync();Assert.Equal(WorkOutcome.Completed,(await run.ExecuteAsync()).Outcome);await run.FinishAsync();
        if(action=="correction")
        {
            // The same case preserves an actually used old mailbox preview and
            // applied mark before correction retires its consent/adoption/field.
            var steps=new ProductionSignerMutationAdmissionTests(fixture);var identity=(await steps.Redeem(run))!;
            var principal=SignerAccessConfiguration.Principal(identity);var receipt=(await steps.Preview(run,principal)).Receipt;
            Assert.Equal(ConsentResult.Accepted,await steps.Accept(run,principal,receipt));
            var marks=new ProductionSignaturePreviewAdmissionTests.Flow(fixture,run,identity);var prepared=(await marks.Prepare())!;
            Assert.Equal(SignatureAdoptionResult.Adopted,await marks.Adopt(prepared));var field=(await marks.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
            Assert.Equal(SignerFieldOutcome.Applied,(await marks.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:prepared.Id))).Outcome);
        }
        await using var db=fixture.Open();var time=run.Record.Time;var keys=run.Record.Keys;
        var work=new WorkOptions{Enabled=true};var email=new EmailOptions{Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};
        var access=new SignerAccess(db,new(db,time),new(),time);var originals=new SignerInvitationProtection(keys);
        var resends=new InvitationResendProtection(keys);var successors=new InvitationSuccessorProtection(keys);
        var lineage=new InvitationLineage(db,originals,resends,successors,time);var audit=new AuditWriter(db,time);
        var options=new SignerContactCorrectionOptions{Enabled=true,DailyAddressRequests=10,DailyIpRequests=10,DailySenderRequests=10,DailyRequests=10};
        var correctionPolicy=new SignerContactCorrectionPolicy(db,options,email,work,time);
        var reminderOptions=new SignerReminderOptions{Enabled=action=="reminder",Days=[1],DailyRequests=10,DailySenderRequests=10,DailyAddressRequests=10};
        var admission=new ProductionWorkAdmission(fixture.Open,run.Record.Admission);
        var reminders=new SignerReminderJobs(db,access,lineage,successors,reminderOptions,work,email,()=>ready.Signals,audit,time){HoldAdmission=admission};
        var jobs=new InvitationSuccessorJobs(db,access,lineage,successors,[correctionPolicy,reminders],work,email,()=>ready.Signals,audit,time);
        var resendOptions=new InvitationResendOptions{Enabled=true,DailyAddressRequests=10,DailyIpRequests=10,DailySenderRequests=10,DailyRequests=10};
        var request=Guid.NewGuid();Guid mailId;
        var store=new WorkStore(db,work,time,admission);
        if(action=="correction")
        {
            var correction=new SignerContactCorrections(db,options,email,work,access,lineage,jobs,audit,time){HoldAdmission=new(run.Record.Admission)};
            var review=await correction.PreviewAsync(ready.Prepared.Sender,ready.Original.PublicId,time.Now.AddHours(1),"corrected@example.invalid");Assert.NotNull(review);
            Assert.Equal(SignerContactCorrectionOutcome.Queued,await correction.RequestAsync(ready.Prepared.Sender,ready.Original.PublicId,time.Now.AddHours(1),request,review.Review,true,
                SignerContactCorrectionStatement.Version,"127.0.0.1",null,reviewExpiresAt:time.Now.AddMinutes(5)));
            mailId=InvitationSuccessorJobs.CorrectionWorkId(request);
        }
        else if(action=="resend")
        {
            var resend=new InvitationResends(db,resendOptions,email,work,resends,originals,access,audit,()=>ready.Signals,time,lineage,successors){HoldAdmission=new(run.Record.Admission)};
            var review=await resend.ReviewAsync(ready.Prepared.Sender,ready.Original.PublicId,time.Now.AddHours(1));Assert.NotNull(review);
            Assert.Equal(InvitationResendOutcome.Queued,await resend.RequestAsync(ready.Prepared.Sender,ready.Original.PublicId,time.Now.AddHours(1),request,review,true,
                InvitationResendStatement.Version,"127.0.0.1",null,reviewExpiresAt:time.Now.AddMinutes(5)));mailId=request;
        }
        else
        {
            var originalJob=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.Record.Id&&x.Kind==WorkKind.Reminder);
            time.Now=originalJob.AvailableAt.AddSeconds(1);
            var lease=(await store.ClaimAsync(originalJob.Id,default)).Lease;Assert.NotNull(lease);
            var result=await new SignerReminderHandler(reminders).ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,result.Outcome);
            await store.FinishAsync(lease,result,default);mailId=SignerReminderEvidence.EmailId(originalJob.Id);
            Assert.Equal(originalJob.PayloadJson,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==originalJob.Id)).PayloadJson);
        }
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SignerAccess).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.Logging.ClearProviders();builder.Services.AddRazorPages();builder.Services.AddScoped<RazorEmailViews>();
        await using var app=builder.Build();using var viewScope=app.Services.CreateScope();var views=viewScope.ServiceProvider.GetRequiredService<RazorEmailViews>();
        var handler=new EmailWorkHandler(db,email,new(keys),new(email,views),run.Sender,time,
            resends:()=>new(db,resendOptions,resends,access,new(new(),time),new(email,views),run.Sender,email,work,audit,time,lineage,successors),
            successors:()=>new(db,successors,jobs,lineage,access,new(new(),time),new(email,views),run.Sender,email,work,audit,time)){HoldAdmission=admission};
        var next=(await store.ClaimAsync(mailId,default)).Lease;Assert.NotNull(next);
        var sent=await handler.ExecuteAsync(next,default);Assert.Equal(WorkOutcome.Completed,sent.Outcome);await store.FinishAsync(next,sent,default);
        Assert.Equal(2,run.Sender.Calls);Assert.Null((await run.Record.Journal.ReadAsync(run.Record.Id)).OutstandingOperation);
        var currentTokens=await db.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==run.Record.Id).ToDictionaryAsync(x=>x.Id,x=>x.ExpiresAt);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run);
        var command=ProductionHoldWitnessJournalTests.Place(run.Record.Id);
        var state=await holds.Coordinator().SubmitAsync(ProductionHoldWitnessJournalTests.Authority(time,command.Permission),ProductionHoldWitnessJournalTests.Operators,command);
        await using var capture=fixture.Open();await using var tx=await capture.Database.BeginTransactionAsync();
        var snapshot=await new ProductionHoldObjectInventory(capture,keys,time,ready.Prepared.Blobs).CaptureLockedAsync(run.Record.Id,state.RequestRevision,state.RequestFenceHash!);
        using var sql=ProductionHoldSqlInventory.OpenVerified(snapshot.Sql,keys);var objects=ProductionHoldObjectInventory.OpenVerified(snapshot,keys,time);
        var history=await ProductionHoldInvitationHistoryReferences.ReadVerifiedLockedAsync(capture,sql.RootElement,objects,keys,state,time);
        var complete=ProductionHoldReviewCheckpointReferences.ReadVerified(sql.RootElement,objects,keys,[],history);
        Assert.Equal(action=="correction"?1:0,complete.Previews.Count);Assert.Empty(complete.Reviews);Assert.Equal(2,history.MailIds.Count);Assert.Equal(2,history.TokenIds.Count);
        Assert.Equal(action=="reminder"?3:2,history.WorkIds.Count);
        // A correctly retained SQL row can never be replaced by an older mailbox
        // or an unrecorded token, and new event fields cannot hide in the suffix.
        var node=JsonNode.Parse(sql.RootElement.GetRawText())!;
        var tables=node["Tables"]!.AsArray();
        var mail=tables.Single(x=>x!["Table"]!.GetValue<string>()=="EmailOutbox")!["Rows"]!.AsArray().Single(x=>x!["Id"]!.GetValue<Guid>()==mailId)!;
        mail["ProviderMessageId"]="changed-fact";
        using var altered=JsonDocument.Parse(node.ToJsonString());
        await Assert.ThrowsAsync<InvalidDataException>(()=>ProductionHoldInvitationHistoryReferences.ReadVerifiedLockedAsync(capture,altered.RootElement,objects,keys,state,time));
        Assert.Equal(currentTokens,await capture.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==run.Record.Id).ToDictionaryAsync(x=>x.Id,x=>x.ExpiresAt));
        if(action is "reminder" or "correction")
        {
            // Reuse the exact original schedule and finished successor for full
            // coordinator publication, without another signing/TSA pipeline.
            await tx.RollbackAsync();await tx.DisposeAsync();
            var preserved=await holds.Coordinator().PreserveAsync(run.Record.Id,command.HoldId,Guid.NewGuid());
            Assert.True(preserved.Holds[command.HoldId].Effective);
            Assert.False(await holds.Release(command,1));
            Assert.Equal(currentTokens,await capture.AuthTokens.AsNoTracking().Where(x=>x.EnvelopeId==run.Record.Id).ToDictionaryAsync(x=>x.Id,x=>x.ExpiresAt));
        }
    }
}
