using System.Security.Cryptography;
using Azure.Core;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionCompletionDeletionTransportTests
{
    [Fact]
    public async Task Actual_sdk_census_exact_delete_readback_and_idempotent_encrypted_hint_use_same_connected_transport()
    {
        var time=TimeProvider.System;var now=time.GetUtcNow();var record=Guid.NewGuid();var deletion=Guid.NewGuid();
        var archive=$"production-holds/{record:N}/{Guid.NewGuid():N}/{Guid.NewGuid():N}/";
        var secondArchive=$"production-holds/{record:N}/{Guid.NewGuid():N}/{Guid.NewGuid():N}/";
        var scope=ProductionDeletionObjectScope.Create(record,deletion,[archive,secondArchive],time,now.AddMinutes(1),_=>Task.CompletedTask);
        using var transport=new ProductionCompletionDeletionTransport(time){PageLength=1};
        using var store=new AzureProductionDeletionStore(new("https://storage.example.invalid/"),new Credential(),transport.Transport());
        var sources=ProductionDeletionObjectScope.Areas.Select(area=>new HoldObjectAddress(area,$"{record:N}/{Guid.NewGuid():N}","synthetic-version","","\"synthetic-etag\"",3))
            .Append(new("originals",$"{record:N}/{Guid.NewGuid():N}","second-original","","\"second-original\"",3))
            .Concat(new[]{archive,secondArchive}.Select(x=>new HoldObjectAddress("final",x+"sql/"+new string('a',64),"archive-version","","\"archive-etag\"",3))).ToArray();
        foreach(var address in sources)transport.Seed(address,[1,2,3],now.AddMinutes(-1));
        var all=await ProductionDeletionCoordinator.ReadStorageAddressesAsync(store,scope);
        Assert.Equal(sources.Length,all.Length);Assert.Contains(transport.Cursors,x=>x.Area=="originals"&&x.Marker=="1");
        foreach(var item in all)
        {
            var address=Assert.Single(sources,x=>x.Area==item.Area&&x.Name==item.Name);
            var prefix=scope.ArchivePrefixes.FirstOrDefault(x=>address.Name.StartsWith(x,StringComparison.Ordinal))??$"{record:N}/";
            var terminal=await store.ListAsync(scope,address.Area,prefix,address.Area=="originals"?"1":null,128);Assert.Null(terminal.Continuation);
            Assert.Equal(address.VersionId,item.VersionId);Assert.Equal(address.ETag,item.ETag);Assert.True(item.IsCurrent);Assert.False(item.Deleted);
            var inspected=await store.InspectAsync(scope,item);Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(new byte[]{1,2,3})),inspected.Sha256);
            Assert.False(inspected.LegalHold);Assert.Equal("Locked",inspected.ImmutableMode);Assert.True(inspected.ImmutableUntil<now);
            var demoted=await store.DeleteAsync(scope,inspected,ProductionDeletionPhase.RootDemotion);Assert.True(demoted.RootAbsent);Assert.False(demoted.Absent);
            Assert.Equal(inspected,demoted.Remaining);Assert.True((await store.ReadDeleteOutcomeAsync(scope,inspected,ProductionDeletionPhase.RootDemotion)).RootAbsent);
            var deleted=await store.DeleteAsync(scope,inspected,ProductionDeletionPhase.HistoricalDelete);Assert.True(deleted.Absent);
            Assert.True((await store.ReadDeleteOutcomeAsync(scope,inspected,ProductionDeletionPhase.HistoricalDelete)).Absent);
        }
        var retained=await ProductionDeletionCoordinator.ReadStorageAddressesAsync(store,scope);Assert.Equal(all.Length,retained.Length);
        Assert.All(retained,x=>{Assert.True(x.Deleted);Assert.False(x.IsCurrent);});
        Assert.Equal(sources.Length*2,transport.Deletes.Count);Assert.All(transport.Objects.Values,x=>Assert.Equal(new byte[]{1,2,3},x.Bytes));
        Assert.Equal(ProductionDeletionObjectScope.Areas.Order(),transport.ListedAreas.Order());Assert.Contains("final/"+archive,transport.ListedPrefixes);
        using var index=new AzureProductionDeletionRecoveryIndex(new("https://storage.example.invalid/recovery-index"),new Credential(),new EphemeralDataProtectionProvider(),new('b',64),transport.Transport());
        var hint=new ProductionDeletionRecoveryHint(record,deletion,new('c',64));
        await index.RememberAsync(scope,hint);Assert.Equal(hint,await index.ReadAsync(record,deletion));
        await index.RememberAsync(scope,hint);Assert.Equal(hint,await index.ReadAsync(record,deletion));
        var secondHint=new ProductionDeletionRecoveryHint(Guid.NewGuid(),Guid.NewGuid(),new('d',64));
        var secondScope=ProductionDeletionObjectScope.Create(secondHint.RecordId,secondHint.DeletionId,[],time,now.AddMinutes(1),_=>Task.CompletedTask);
        await index.RememberAsync(secondScope,secondHint);
        var firstPage=await index.ListAsync(null,32);Assert.Single(firstPage.Hints);Assert.Equal("1",firstPage.Continuation);
        var lastPage=await index.ListAsync(firstPage.Continuation,32);Assert.Single(lastPage.Hints);Assert.Null(lastPage.Continuation);
        Assert.Equal(new[]{hint,secondHint}.OrderBy(x=>x.RecordId),firstPage.Hints.Concat(lastPage.Hints).OrderBy(x=>x.RecordId));
        Assert.Equal(3,transport.HintPuts);Assert.Equal(2,transport.HintCreates);Assert.Equal(sources.Length*2,transport.Deletes.Count);
        Assert.Contains(transport.Cursors,x=>x.Area=="recovery-index"&&x.Marker=="1");secondScope.Close();
        scope.Close();
    }
    [Theory]
    [InlineData(true,false)][InlineData(false,true)]
    public async Task Full_consumer_rejects_duplicate_selectors_and_repeated_nonempty_markers(bool duplicate,bool repeated)
    {
        var time=TimeProvider.System;var record=Guid.NewGuid();var scope=ProductionDeletionObjectScope.Create(record,Guid.NewGuid(),[],time,time.GetUtcNow().AddMinutes(1),_=>Task.CompletedTask);
        using var transport=new ProductionCompletionDeletionTransport(time){PageLength=1,DuplicateSecondPage=duplicate,RepeatMarker=repeated};
        using var store=new AzureProductionDeletionStore(new("https://storage.example.invalid/"),new Credential(),transport.Transport());
        foreach(var id in new[]{Guid.NewGuid(),Guid.NewGuid()})transport.Seed(new("originals",$"{record:N}/{id:N}","synthetic-version","","\"synthetic-etag\"",3),[1,2,3]);
        await Assert.ThrowsAsync<InvalidDataException>(()=>ProductionDeletionCoordinator.ReadStorageAddressesAsync(store,scope));
        Assert.Equal(2,transport.Cursors.Count);Assert.Equal("1",transport.Cursors[1].Marker);Assert.Empty(transport.Deletes);scope.Close();
    }
    private sealed class Credential:TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext,CancellationToken cancellationToken)=>new("synthetic-connected-delete",DateTimeOffset.MaxValue);
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,CancellationToken cancellationToken)=>ValueTask.FromResult(GetToken(requestContext,cancellationToken));
    }
}
