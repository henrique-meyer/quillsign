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
        var scope=ProductionDeletionObjectScope.Create(record,deletion,[archive],time,now.AddMinutes(1),_=>Task.CompletedTask);
        using var transport=new ProductionCompletionDeletionTransport(time);
        using var store=new AzureProductionDeletionStore(new("https://storage.example.invalid/"),new Credential(),transport.Transport());
        var sources=ProductionDeletionObjectScope.Areas.Select(area=>new HoldObjectAddress(area,$"{record:N}/{Guid.NewGuid():N}","synthetic-version","","\"synthetic-etag\"",3))
            .Append(new("final",archive+"sql/"+new string('a',64),"archive-version","","\"archive-etag\"",3)).ToArray();
        foreach(var address in sources)transport.Seed(address,[1,2,3],now.AddMinutes(-1));
        foreach(var address in sources)
        {
            var prefix=address.Name.StartsWith(archive,StringComparison.Ordinal)?archive:$"{record:N}/";
            var page=await store.ListAsync(scope,address.Area,prefix,null,128);var item=Assert.Single(page.Objects);Assert.True(string.IsNullOrEmpty(page.Continuation));
            Assert.Equal(address.VersionId,item.VersionId);Assert.Equal(address.ETag,item.ETag);Assert.True(item.IsCurrent);Assert.False(item.Deleted);
            var inspected=await store.InspectAsync(scope,item);Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(new byte[]{1,2,3})),inspected.Sha256);
            Assert.False(inspected.LegalHold);Assert.Equal("Locked",inspected.ImmutableMode);Assert.True(inspected.ImmutableUntil<now);
            var demoted=await store.DeleteAsync(scope,inspected,ProductionDeletionPhase.RootDemotion);Assert.True(demoted.RootAbsent);Assert.False(demoted.Absent);
            Assert.Equal(inspected,demoted.Remaining);Assert.True((await store.ReadDeleteOutcomeAsync(scope,inspected,ProductionDeletionPhase.RootDemotion)).RootAbsent);
            var deleted=await store.DeleteAsync(scope,inspected,ProductionDeletionPhase.HistoricalDelete);Assert.True(deleted.Absent);
            Assert.True((await store.ReadDeleteOutcomeAsync(scope,inspected,ProductionDeletionPhase.HistoricalDelete)).Absent);
            var retained=Assert.Single((await store.ListAsync(scope,address.Area,prefix,null,128)).Objects);Assert.True(retained.Deleted);Assert.False(retained.IsCurrent);
        }
        Assert.Equal(sources.Length*2,transport.Deletes.Count);Assert.All(transport.Objects.Values,x=>Assert.Equal(new byte[]{1,2,3},x.Bytes));
        Assert.Equal(ProductionDeletionObjectScope.Areas.Order(),transport.ListedAreas.Order());Assert.Contains("final/"+archive,transport.ListedPrefixes);
        using var index=new AzureProductionDeletionRecoveryIndex(new("https://storage.example.invalid/recovery-index"),new Credential(),new EphemeralDataProtectionProvider(),new('b',64),transport.Transport());
        var hint=new ProductionDeletionRecoveryHint(record,deletion,new('c',64));
        await index.RememberAsync(scope,hint);Assert.Equal(hint,await index.ReadAsync(record,deletion));
        await index.RememberAsync(scope,hint);Assert.Equal(hint,await index.ReadAsync(record,deletion));
        Assert.Equal(2,transport.HintPuts);Assert.Equal(1,transport.HintCreates);Assert.Equal(sources.Length*2,transport.Deletes.Count);
        scope.Close();
    }
    private sealed class Credential:TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext,CancellationToken cancellationToken)=>new("synthetic-connected-delete",DateTimeOffset.MaxValue);
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,CancellationToken cancellationToken)=>ValueTask.FromResult(GetToken(requestContext,cancellationToken));
    }
}
