using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionSequentialSigningAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task A_timely_accepted_Finish_processed_after_the_original_signing_deadline_keeps_exact_evidence_without_a_new_invitation()
    {
        await using var run=await WithOriginalDeadline();
        var review=(await run.Prepare())!;var accepted=await run.Finish(review.Receipt);
        Assert.Equal(SignerFinishOutcome.Accepted,accepted.Outcome);DateTimeOffset deadline;
        await using(var db=fixture.Open())deadline=(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id)).ExpiresAt!.Value;
        run.Record.Time.Now=deadline.AddSeconds(1);await run.Process(accepted.Acceptance!.Id);
        await using(var db=fixture.Open())
        {
            var finish=await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==accepted.Acceptance.Id);
            Assert.True(finish.FinishedAt<deadline);Assert.True(finish.ProcessedAt>=deadline);Assert.Null(finish.NextInvitationId);
            Assert.Equal(1,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id)).CurrentCopyVersion);
            Assert.Equal(1,await db.AuthTokens.CountAsync(x=>x.EnvelopeId==run.Id&&x.Purpose==TokenPurpose.SignerAccess));
            Assert.False(await db.WorkItems.AnyAsync(x=>x.EnvelopeId==run.Id&&x.Kind==WorkKind.Sealing));
        }
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        var first=await holds.Place(0);var second=await holds.Place(1);Assert.Equal(18,holds.Provider.Files.Count);
        Assert.True(await holds.Release(first,2));Assert.False(await holds.Release(second,3));
        Assert.Null(await run.Prepare());Assert.Equal(2,run.Blobs.ReviewWrites);Assert.Equal(0,run.Blobs.Deletes);
        Assert.Equal(1,run.Delivered.Sender.Calls);Assert.Null((await run.Record.Journal.ReadAsync(run.Id)).OutstandingOperation);
    }

    private async Task<ProductionSignerReviewRuntimeContractTests.Flow> WithOriginalDeadline()
    {
        var ready=await ProductionRecordSendAdmissionTests.Ready.Create(fixture,requestedDeadline:true,withFields:true,twoSigners:true);
        var delivered=new ProductionInvitationWorkerAdmissionTests.Delivered(fixture,ready){WorkId=(await ready.Send())!.InvitationWorkId};
        await delivered.ClaimAsync();Assert.Equal(WorkOutcome.Completed,(await delivered.ExecuteAsync()).Outcome);await delivered.FinishAsync();
        var steps=new ProductionSignerMutationAdmissionTests(fixture);var identity=(await steps.Redeem(delivered))!;Assert.NotNull(identity);
        var principal=SignerAccessConfiguration.Principal(identity);var pdf=await steps.Preview(delivered,principal);
        Assert.Equal(ConsentResult.Accepted,await steps.Accept(delivered,principal,pdf.Receipt));
        var marks=new ProductionSignaturePreviewAdmissionTests.Flow(fixture,delivered,identity);var preview=(await marks.Prepare())!;
        Assert.NotNull(preview);Assert.Equal(SignatureAdoptionResult.Adopted,await marks.Adopt(preview));
        var field=(await marks.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
        Assert.Equal(SignerFieldOutcome.Applied,(await marks.Change(new(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:preview.Id))).Outcome);
        return new(fixture,marks,marks.Blobs);
    }

    [Fact]
    public async Task Genuine_two_signers_preserve_exact_sequential_bundles_and_stop_at_one_unattempted_Sealing_item()
    {
        await using var first=await ProductionSignerReviewRuntimeContractTests.Flow.Create(fixture,store:b=>b);
        var firstReview=(await first.Prepare())!;Assert.NotNull(await first.Read(firstReview.Receipt));
        var firstFinish=await first.Finish(firstReview.Receipt);Assert.Equal(SignerFinishOutcome.Accepted,firstFinish.Outcome);
        await first.Process(firstFinish.Acceptance!.Id);
        var delivery=first.Delivered;Guid secondMail;AuthToken originalToken;
        await using(var db=fixture.Open())
        {
            secondMail=(await db.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==firstFinish.Acceptance.Id)).NextInvitationId!.Value;
            originalToken=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==delivery.TokenRecord.Id);
        }
        delivery.WorkId=secondMail;await delivery.ClaimAsync();Assert.Equal(WorkOutcome.Completed,(await delivery.ExecuteAsync()).Outcome);await delivery.FinishAsync();
        Assert.NotEqual(originalToken.Id,delivery.TokenRecord.Id);Assert.Equal(2,delivery.Sender.Calls);
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,delivery);
        async Task PreservePair(long revision,int items)
        {
            foreach(var pair in first.Blobs.Objects)
            {
                var address=first.Blobs.Address(pair.Key);
                if(!holds.Provider.SourceFiles.TryAdd(address,pair.Value.ToArray()))Assert.Equal(pair.Value,holds.Provider.SourceFiles[address]);
            }
            var before=holds.Provider.Files.Count;var a=await holds.Place(revision);var b=await holds.Place(revision+1);
            Assert.Equal(before+items*2,holds.Provider.Files.Count);
            Assert.True(await holds.Release(a,revision+2));Assert.False(await holds.Release(b,revision+3));
        }
        await PreservePair(0,9);
        var steps=new ProductionSignerMutationAdmissionTests(fixture);var identity=(await steps.Redeem(delivery))!;Assert.NotNull(identity);
        var principal=SignerAccessConfiguration.Principal(identity);var originalPdf=await steps.Preview(delivery,principal);
        Assert.Equal(firstReview.PdfSha256,Convert.ToHexStringLower(originalPdf.Context.DocumentSha256));
        Assert.Equal(ConsentResult.Accepted,await steps.Accept(delivery,principal,originalPdf.Receipt));
        var marks=new ProductionSignaturePreviewAdmissionTests.Flow(fixture,delivery,identity);
        var preview=(await marks.Prepare())!;Assert.NotNull(preview);Assert.Equal(SignatureAdoptionResult.Adopted,await marks.Adopt(preview));
        var signature=(await marks.Fields())!.Fields.Single(x=>x.Type==FieldType.Signature);
        Assert.Equal(SignerFieldOutcome.Applied,(await marks.Change(new(signature.Id,signature.Version,SignerFieldAction.Apply,AdoptionId:preview.Id))).Outcome);
        var second=new ProductionSignerReviewRuntimeContractTests.Flow(fixture,marks,first.Blobs);
        var secondReview=(await second.Prepare())!;Assert.NotNull(secondReview);Assert.NotEqual(firstReview.Id,secondReview.Id);
        var exact=(await second.Read(secondReview.Receipt))!;Assert.Equal(secondReview.PdfSha256,Convert.ToHexStringLower(SHA256.HashData(exact.Pdf)));
        await PreservePair(4,13);
        var accepted=await second.Finish(secondReview.Receipt);Assert.Equal(SignerFinishOutcome.Accepted,accepted.Outcome);
        Assert.Equal(SignerFinishOutcome.AlreadyAccepted,(await second.Finish(secondReview.Receipt)).Outcome);
        await second.Process(accepted.Acceptance!.Id);await PreservePair(8,13);
        await using var readback=fixture.Open();var record=await readback.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==first.Id);
        Assert.Equal(2,record.CurrentCopyVersion);Assert.Equal(accepted.Acceptance.Id,record.CurrentFinishId);
        var signers=await readback.Signers.AsNoTracking().Where(x=>x.EnvelopeId==first.Id).ToArrayAsync();Assert.Equal(2,signers.Length);Assert.All(signers,x=>Assert.Equal(SignerStatus.Signed,x.Status));
        var finish=await readback.SignerFinishAcceptances.AsNoTracking().SingleAsync(x=>x.Id==accepted.Acceptance.Id);
        Assert.NotNull(finish.ProcessedAt);Assert.Null(finish.NextInvitationId);Assert.Equal(secondReview.PdfSha256,Convert.ToHexStringLower(finish.PdfSha256));
        var queued=await readback.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==first.Id&&x.Kind==WorkKind.Sealing);
        Assert.Equal(WorkStatus.Queued,queued.Status);Assert.Equal(0,queued.Attempts);
        var beforeClaim=await first.Record.Journal.ReadAsync(first.Id);
        Assert.Null((await second.Work(readback).ClaimAsync(queued.Id,default)).Lease);
        Assert.Equal(beforeClaim.HeadHash,(await first.Record.Journal.ReadAsync(first.Id)).HeadHash);
        var retained=await readback.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==originalToken.Id);
        Assert.Equal(originalToken.ExpiresAt,retained.ExpiresAt);Assert.Equal(originalToken.UsedAt,retained.UsedAt);
        Assert.Equal(4,first.Blobs.ReviewWrites);Assert.Equal(0,first.Blobs.Deletes);Assert.Equal(0,first.Blobs.UnwitnessedWrites);
        Assert.Null((await first.Record.Journal.ReadAsync(first.Id)).OutstandingOperation);
    }
}
