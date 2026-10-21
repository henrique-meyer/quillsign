using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionSignerReviewAdmissionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_two_signer_preparation_delivers_only_first_invitation_and_preserves_first_owned_fields()
    {
        await using var run=await ProductionSignaturePreviewAdmissionTests.Flow.Create(fixture,twoSigners:true);
        var preview=(await run.Prepare())!;Assert.NotNull(preview);
        Assert.Equal(SignatureAdoptionResult.Adopted,await run.Adopt(preview));
        foreach(var field in (await run.Fields())!.Fields)
        {
            var change=field.Type switch {
                FieldType.Signature or FieldType.Initials=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply,AdoptionId:preview.Id),
                FieldType.FullName=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply),
                _=>new SignerFieldChange(field.Id,field.Version,SignerFieldAction.Apply,"Synthetic first signer value")};
            Assert.Equal(field.Type==FieldType.DateSigned?SignerFieldOutcome.ReadOnly:SignerFieldOutcome.Applied,(await run.Change(change)).Outcome);
        }
        await using var db=fixture.Open();
        var signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==run.Id).OrderBy(x=>x.Order).ToArrayAsync();
        Assert.Equal(2,signers.Length);Assert.Equal(run.Identity.SignerId,signers[0].Id);
        Assert.Equal(SignerStatus.Viewed,signers[0].Status);Assert.Equal(SignerStatus.Pending,signers[1].Status);
        Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==run.Id&&x.PartyId==signers[1].Id));
        Assert.Null(signers[1].ConsentAt);Assert.Null(signers[1].SignatureAdoptionId);
        Assert.Equal(0,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==run.Id)).CurrentCopyVersion);
        Assert.Equal(1,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==run.Id&&x.Template=="signer-invitation"));
        Assert.False(await db.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==run.Id));
        using var holds=new ProductionSignerMutationAdmissionTests.Holds(fixture,run.Delivered);
        var hold=await holds.Place(0);Assert.Equal(7,holds.Provider.Files.Count);Assert.False(await holds.Release(hold,1));
        Assert.Equal(0,run.Blobs.Deletes);Assert.Equal(2,run.Blobs.MarkWrites);
    }
}
