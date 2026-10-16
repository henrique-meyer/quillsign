using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Sealing;

namespace QuillSign.Tests;

public sealed class ProtectedSealStoreTests
{
    [Fact]
    public async Task Azurite_conditional_first_use_preserves_one_protected_identity_and_never_overwrites_corruption()
    {
        var service=new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE") ?? throw new InvalidOperationException("Run local stack tests."),new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
        Assert.True(service.Uri.IsLoopback); var name="demo-seal-test-"+Guid.NewGuid().ToString("N")+".dp"; var raw=service.GetBlobContainerClient("keys").GetBlobClient(name);
        var keyBlob=service.GetBlobContainerClient("keys").GetBlobClient(name+".keyring.xml");
        ServiceProvider Protection() {var services=new ServiceCollection(); services.AddDataProtection().SetApplicationName(name).PersistKeysToAzureBlobStorage(keyBlob); return services.BuildServiceProvider();}
        using var firstServices=Protection(); var protection=firstServices.GetRequiredService<IDataProtectionProvider>(); var options=new SealOptions(); options.SelfSigned.BlobName=name;
        SelfSignedSealCertificateProvider Provider()=>new(()=>new BlobProtectedSealStore(service,true,name),protection,options,TimeProvider.System);
        try {
            var leases=await Task.WhenAll(Provider().AcquireAsync(default),Provider().AcquireAsync(default));
            byte[] certificate; try {Assert.Equal(leases[0].Certificate.RawData,leases[1].Certificate.RawData); certificate=leases[0].Certificate.RawData;} finally {foreach(var lease in leases)lease.Dispose();}
            var saved=(await raw.DownloadContentAsync()).Value.Content.ToArray(); var etag=(await raw.GetPropertiesAsync()).Value.ETag;
            Assert.False(await new BlobProtectedSealStore(service,true,name).TryCreateAsync([1,2,3],default));
            using var restartedServices=Protection();
            using(var restarted=await new SelfSignedSealCertificateProvider(()=>new BlobProtectedSealStore(service,true,name),restartedServices.GetRequiredService<IDataProtectionProvider>(),options,TimeProvider.System).AcquireAsync(default))Assert.Equal(certificate,restarted.Certificate.RawData);
            Assert.Equal(etag,(await raw.GetPropertiesAsync()).Value.ETag);
            saved[^1]^=1; await raw.UploadAsync(BinaryData.FromBytes(saved),overwrite:true);
            var corruptedEtag=(await raw.GetPropertiesAsync()).Value.ETag;
            await Assert.ThrowsAsync<SealUnavailableException>(()=>Provider().AcquireAsync(default));
            Assert.Equal(corruptedEtag,(await raw.GetPropertiesAsync()).Value.ETag); Assert.Equal(saved,(await raw.DownloadContentAsync()).Value.Content.ToArray());
            Assert.Equal(Azure.Storage.Blobs.Models.PublicAccessType.None,(await service.GetBlobContainerClient("keys").GetAccessPolicyAsync()).Value.BlobPublicAccess);
        }
        finally {await raw.DeleteIfExistsAsync(); await keyBlob.DeleteIfExistsAsync();}
    }
}
