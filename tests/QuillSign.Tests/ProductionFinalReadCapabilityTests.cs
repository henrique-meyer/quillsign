using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionFinalReadCapabilityTests
{
    [Fact]
    public void A_frozen_access_deadline_bounds_an_in_flight_read_without_changing_preservation()
    {
        var time=new SealFixtures.Clock();var deadline=time.GetUtcNow().AddTicks(1234567);
        var stored=new FinalStoredDocument(new(Guid.NewGuid(),FinalDocumentKind.Executed,Guid.NewGuid()),32,new byte[32],
            "synthetic-version","synthetic-etag",FinalProtection.LockedTime,time.GetUtcNow().AddDays(30),time.GetUtcNow());
        var scope=CompletionFinalCapability.ReadBounded(stored,time,deadline);
        _=CompletionFinalCapability.DemandRead(scope,stored);
        Assert.Throws<UnauthorizedAccessException>(()=>CompletionFinalCapability.DemandWrite(scope,stored.Document,stored.Length,stored.Sha256,null));
        Assert.Throws<UnauthorizedAccessException>(()=>CompletionFinalCapability.DemandRead(scope,stored with {Document=stored.Document with {ObjectId=Guid.NewGuid()}}));
        time.Advance(deadline-time.GetUtcNow()-TimeSpan.FromTicks(1));_=CompletionFinalCapability.DemandRead(scope,stored);
        time.Advance(TimeSpan.FromTicks(1));Assert.Throws<IOException>(()=>CompletionFinalCapability.DemandRead(scope,stored));
        Assert.True(stored.ProtectedUntil>deadline);
    }

    [Fact]
    public void Indefinite_preservation_does_not_extend_the_two_minute_internal_capability()
    {
        var time=new SealFixtures.Clock();
        var stored=new FinalStoredDocument(new(Guid.NewGuid(),FinalDocumentKind.Executed,Guid.NewGuid()),32,new byte[32],
            "synthetic-version","synthetic-etag",FinalProtection.LegalHold,null,time.GetUtcNow());
        var scope=CompletionFinalCapability.ReadBounded(stored,time,null);
        time.Advance(TimeSpan.FromMinutes(2));Assert.Throws<IOException>(()=>CompletionFinalCapability.DemandRead(scope,stored));
    }
}
