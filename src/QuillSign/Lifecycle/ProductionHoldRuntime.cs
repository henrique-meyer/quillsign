using System.Security.Cryptography;
using System.Text.Json;
using Azure.Core;
using Azure.Identity;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sealing;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

public sealed class ProductionHoldRuntimeOptions
{
    public bool Enabled {get;set;}
    public string InstallationId {get;set;}="";
    public string InstallationDigest {get;set;}="";
    public string ServiceUri {get;set;}="";
    public string WitnessContainerUri {get;set;}="";
    public bool AllowIndefiniteWitnessLegalHold {get;set;}
    internal void Validate(IConfiguration config)
    {
        if(InstallationId.Length!=0||InstallationDigest.Length!=0||WitnessContainerUri.Length!=0){
            var expected=IdentityDigest(InstallationId,WitnessContainerUri);if(InstallationDigest.Length!=0&&InstallationDigest!=expected)throw Invalid();InstallationDigest=expected;
        }
        if(!Enabled)return;
        static bool Https(string raw)=>Uri.TryCreate(raw,UriKind.Absolute,out var u)&&u.Scheme=="https"&&u.UserInfo.Length==0&&u.Query.Length==0&&u.Fragment.Length==0&&!u.Host.Contains("-secondary.",StringComparison.OrdinalIgnoreCase);
        if(!AllowIndefiniteWitnessLegalHold||InstallationDigest is not{Length:64}||!InstallationDigest.All(char.IsAsciiHexDigitLower)||!Https(ServiceUri)||!Https(WitnessContainerUri)||
            new Uri(ServiceUri).AbsolutePath!="/"||new Uri(ServiceUri).Host!=new Uri(WitnessContainerUri).Host||
            config["Storage:Provider"]!="Azure"||config["Storage:BlobServiceUri"]!=ServiceUri||!config.GetValue<bool>("Work:Enabled"))throw Invalid();
        var lifecycle=config.GetSection("Records").Get<RecordLifecycleOptions>()??new();if(lifecycle.Mode!="Production")throw Invalid();
        _=ProductionRetentionPolicyContract.Freeze(Guid.Parse("00000000000000000000000000000001"),DateTimeOffset.UnixEpoch,lifecycle.Production);
    }
    internal static string IdentityDigest(string installationId,string witnessUri)
    {
        if(!Guid.TryParseExact(installationId,"N",out var id)||id==Guid.Empty||id.ToString("N")!=installationId||
            !Uri.TryCreate(witnessUri,UriKind.Absolute,out var uri)||uri.Scheme!="https"||uri.AbsoluteUri!=witnessUri||
            uri.UserInfo.Length!=0||uri.Query.Length!=0||uri.Fragment.Length!=0||uri.AbsolutePath.EndsWith('/')||uri.AbsolutePath.Split('/',StringSplitOptions.RemoveEmptyEntries).Length!=1||
            uri.Host.Contains("-secondary.",StringComparison.OrdinalIgnoreCase))throw Invalid();
        return Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new{Version="production-hold-installation-v1",InstallationId=installationId,WitnessContainerUri=witnessUri})));
    }
    private static InvalidOperationException Invalid()=>new("Configure the complete default-disabled production hold runtime explicitly.");
}
internal static class ProductionHoldRuntime
{
    private sealed record Credential(TokenCredential Value);
    internal static IServiceCollection AddProductionHoldRuntime(this IServiceCollection services,IConfiguration config)
    {
        if(services.Any(d=>d.ServiceType==typeof(ProductionHoldRuntimeOptions)))return services;
        var settings=config.GetSection("ProductionHolds").Get<ProductionHoldRuntimeOptions>()??new();settings.Validate(config);services.AddSingleton(settings);
        if(!settings.Enabled){Closed(services,settings,config);Decorate(services);return services;}
        var credential=string.IsNullOrWhiteSpace(config["Storage:ManagedIdentityClientId"])?new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned):
            new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(config["Storage:ManagedIdentityClientId"]!));services.AddSingleton(new Credential(credential));
        services.AddScoped<IProductionHoldWitnessStore>(sp=>new AzureProductionHoldWitnessStore(new(settings.WitnessContainerUri),credential,settings.InstallationDigest,true));
        services.AddScoped<ProductionHoldWitnessJournal>(sp=>new(sp.GetRequiredService<IProductionHoldWitnessStore>(),sp.GetRequiredService<IDataProtectionProvider>(),sp.GetRequiredService<TimeProvider>(),settings.InstallationDigest));
        services.AddScoped<ProductionRecordOperationAdmission>(sp=>new(Open(sp),sp.GetRequiredService<IDataProtectionProvider>(),sp.GetRequiredService<TimeProvider>(),sp.GetRequiredService<ProductionHoldWitnessJournal>()));
        services.AddScoped<AzureProductionRecordUploadStore>(sp=>new(new(settings.ServiceUri),credential,sp.GetRequiredService<DocumentOptions>().MaximumBytes));
        services.AddScoped<IProductionRecordUploadStore>(sp=>sp.GetRequiredService<AzureProductionRecordUploadStore>());
        services.AddScoped<IProductionRecordSendStore>(sp=>sp.GetRequiredService<AzureProductionRecordUploadStore>());
        services.AddScoped<AzureProductionSignaturePreviewStore>(sp=>new(new(settings.ServiceUri),credential,sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<IProductionSignaturePreviewStore>(sp=>sp.GetRequiredService<AzureProductionSignaturePreviewStore>());
        services.AddScoped<AzureProductionSignerReviewStore>(sp=>new(new(settings.ServiceUri),credential,sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<IProductionSignerReviewStore>(sp=>sp.GetRequiredService<AzureProductionSignerReviewStore>());
        services.AddScoped<IProductionReviewInputSource>(sp=>sp.GetRequiredService<AzureProductionSignerReviewStore>());
        services.AddScoped<AzureProductionCompletionStore>(sp=>new(new(settings.ServiceUri),credential));
        services.AddScoped<IProductionCompletionObjectStore>(sp=>sp.GetRequiredService<AzureProductionCompletionStore>());
        services.AddScoped<IProductionCompletionInputSource>(sp=>sp.GetRequiredService<AzureProductionCompletionStore>());
        services.AddScoped<IProductionCompletionEffects,ProductionCompletionEffects>();
        services.AddScoped<ProductionCompletionAdmission>(sp=>new(sp.GetRequiredService<ProductionRecordOperationAdmission>(),sp.GetRequiredService<IProductionCompletionEffects>()));
        services.AddScoped<ProductionCompletionMailAdmission>();
        services.AddScoped<ProductionWorkAdmission>(sp=>new(Open(sp),sp.GetRequiredService<ProductionRecordOperationAdmission>()){
            Completion=sp.GetRequiredService<ProductionCompletionAdmission>(),CompletionMail=sp.GetRequiredService<ProductionCompletionMailAdmission>()});
        services.AddScoped<IProductionWorkAdmission>(sp=>sp.GetRequiredService<ProductionWorkAdmission>());
        services.AddScoped<ProductionSenderPreparationAdmission>();services.AddScoped<ProductionSignerMutationAdmission>();services.AddScoped<ProductionSignaturePreviewAdmission>();
        services.AddScoped<ProductionSignerReviewAdmission>();services.AddScoped<ProductionRecordUploadAdmission>();services.AddScoped<ProductionRecordSendAdmission>();
        services.AddScoped<ProductionTerminalMutationAdmission>();services.AddScoped<ProductionCompletionReadAdmission>();
        services.AddScoped<AzureProductionHoldArchiveWriter>(sp=>new(Client(settings.ServiceUri,credential)));
        services.AddScoped<AzureProductionHoldArchiveReleaseStore>(sp=>new(Client(settings.ServiceUri,credential)));
        services.AddScoped<IProductionHoldArchiveInspectionStore>(sp=>new AzureProductionHoldArchiveInspectionStore(new(settings.ServiceUri),credential,sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<IProductionHoldObjectSource>(sp=>new AzureProductionHoldObjectSource(Client(settings.ServiceUri,credential)));
        services.AddScoped<ProductionHoldCoordinator>(sp=>new(Open(sp),sp.GetRequiredService<IDataProtectionProvider>(),sp.GetRequiredService<TimeProvider>(),sp.GetRequiredService<ProductionHoldWitnessJournal>(),
            sp.GetRequiredService<IProductionHoldObjectSource>(),sp.GetRequiredService<AzureProductionHoldArchiveWriter>(),sp.GetRequiredService<AzureProductionHoldArchiveReleaseStore>(),
            sp.GetRequiredService<IProductionReviewInputSource>(),sp.GetRequiredService<IProductionCompletionInputSource>()));
        Decorate(services);return services;
    }
    private static void Closed(IServiceCollection services,ProductionHoldRuntimeOptions settings,IConfiguration config)
    {
        services.AddScoped<ClosedProductionStores>();
        if(settings.InstallationDigest.Length==64){
            // Disabling operator writes does not switch the established witness
            // namespace or turn retained production evidence into absence.
            var credential=string.IsNullOrWhiteSpace(config["Storage:ManagedIdentityClientId"])?new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned):
                new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(config["Storage:ManagedIdentityClientId"]!));
            services.AddScoped<IProductionHoldWitnessStore>(_=>new ReadOnlyProductionWitnessStore(
                new AzureProductionHoldWitnessStore(new(settings.WitnessContainerUri),credential,settings.InstallationDigest,true)));
        }else services.AddScoped<IProductionHoldWitnessStore>(sp=>sp.GetRequiredService<ClosedProductionStores>());
        services.AddScoped<IProductionRecordUploadStore>(sp=>sp.GetRequiredService<ClosedProductionStores>());
        services.AddScoped<IProductionRecordSendStore>(sp=>sp.GetRequiredService<ClosedProductionStores>());
        services.AddScoped<IProductionSignaturePreviewStore>(sp=>sp.GetRequiredService<ClosedProductionStores>());
        services.AddScoped<IProductionSignerReviewStore>(sp=>sp.GetRequiredService<ClosedProductionStores>());
        services.AddScoped<IProductionCompletionObjectStore>(sp=>sp.GetRequiredService<ClosedProductionStores>());
        services.AddScoped<ProductionHoldWitnessJournal>(sp=>new(sp.GetRequiredService<IProductionHoldWitnessStore>(),sp.GetRequiredService<IDataProtectionProvider>(),sp.GetRequiredService<TimeProvider>(),settings.InstallationDigest));
        services.AddScoped<ProductionRecordOperationAdmission>(sp=>new(Open(sp),sp.GetRequiredService<IDataProtectionProvider>(),sp.GetRequiredService<TimeProvider>(),sp.GetRequiredService<ProductionHoldWitnessJournal>()){
            AuthenticatedDemoOrigin=true,ProductionAdmissionEnabled=false});
        services.AddScoped<IProductionCompletionEffects,ClosedProductionCompletionEffects>();
        services.AddScoped<ProductionCompletionAdmission>(sp=>new(sp.GetRequiredService<ProductionRecordOperationAdmission>(),sp.GetRequiredService<IProductionCompletionEffects>()));
        services.AddScoped<ProductionCompletionMailAdmission>();services.AddScoped<ProductionWorkAdmission>(sp=>new(Open(sp),sp.GetRequiredService<ProductionRecordOperationAdmission>()){
            Completion=sp.GetRequiredService<ProductionCompletionAdmission>(),CompletionMail=sp.GetRequiredService<ProductionCompletionMailAdmission>()});
        services.AddScoped<IProductionWorkAdmission>(sp=>sp.GetRequiredService<ProductionWorkAdmission>());
        services.AddScoped<ProductionSenderPreparationAdmission>();services.AddScoped<ProductionSignerMutationAdmission>();services.AddScoped<ProductionSignaturePreviewAdmission>();
        services.AddScoped<ProductionSignerReviewAdmission>();services.AddScoped<ProductionRecordUploadAdmission>();services.AddScoped<ProductionRecordSendAdmission>();
        services.AddScoped<ProductionTerminalMutationAdmission>();services.AddScoped<ProductionCompletionReadAdmission>();
    }
    private static Func<QuillSignDbContext> Open(IServiceProvider sp){var options=sp.GetRequiredService<DbContextOptions<QuillSignDbContext>>();return()=>new(options);}
    private static BlobServiceClient Client(string uri,TokenCredential credential)
    {var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03);options.Retry.MaxRetries=0;options.Diagnostics.IsLoggingEnabled=false;options.Diagnostics.IsLoggingContentEnabled=false;options.Diagnostics.IsDistributedTracingEnabled=false;return new(new Uri(uri),credential,options);}

    // A closed compiled hook registry. No public names, callbacks or reflection
    // options can select a service/property. Existing factory-owned dependencies
    // retain their normal lifetimes and the SAME scoped admission kernel.
    internal static readonly (Type Target,string Property,Type Value)[] Hooks=[
        (typeof(SenderWorkflow),"HoldAdmission",typeof(ProductionRecordOperationAdmission)),(typeof(CompletionJobs),"HoldAdmission",typeof(ProductionRecordOperationAdmission)),
        (typeof(SendDraftWorkflow),"HoldAdmission",typeof(ProductionRecordSendAdmission)),(typeof(DocumentWorkflow),"HoldAdmission",typeof(ProductionSenderPreparationAdmission)),
        (typeof(DocumentWorkflow),"HoldUploads",typeof(ProductionRecordUploadAdmission)),(typeof(DraftDetails),"HoldAdmission",typeof(ProductionSenderPreparationAdmission)),
        (typeof(SignerSetup),"HoldAdmission",typeof(ProductionSenderPreparationAdmission)),(typeof(FieldEditor),"HoldAdmission",typeof(ProductionSenderPreparationAdmission)),
        (typeof(SignerAccess),"HoldAdmission",typeof(ProductionSignerMutationAdmission)),(typeof(SignerConsent),"HoldAdmission",typeof(ProductionSignerMutationAdmission)),
        (typeof(SignerPdfAccess),"HoldAdmission",typeof(ProductionSignerMutationAdmission)),(typeof(SignerFields),"HoldAdmission",typeof(ProductionSignerMutationAdmission)),
        (typeof(SignatureAdoption),"HoldAdmission",typeof(ProductionSignerMutationAdmission)),(typeof(SignatureAdoption),"HoldPreviews",typeof(ProductionSignaturePreviewAdmission)),
        (typeof(SignerReviewCandidates),"HoldAdmission",typeof(ProductionSignerReviewAdmission)),(typeof(SignerFinish),"HoldAdmission",typeof(ProductionSignerReviewAdmission)),
        (typeof(SignerCheckpointReads),"HoldAdmission",typeof(ProductionSignerMutationAdmission)),(typeof(SignerCheckpointHandler),"HoldAdmission",typeof(IProductionWorkAdmission)),
        (typeof(EmailWorkHandler),"HoldAdmission",typeof(IProductionWorkAdmission)),(typeof(SignerReminderJobs),"HoldAdmission",typeof(IProductionWorkAdmission)),
        (typeof(CompletionWorkHandler),"HoldAdmission",typeof(ProductionCompletionAdmission)),(typeof(SigningExpiry),"HoldAdmission",typeof(ProductionTerminalMutationAdmission)),
        (typeof(SigningExpiry),"WorkHoldAdmission",typeof(IProductionWorkAdmission)),(typeof(SenderVoid),"HoldAdmission",typeof(ProductionTerminalMutationAdmission)),
        (typeof(InvitationResends),"HoldAdmission",typeof(ProductionTerminalMutationAdmission)),(typeof(SignerContactCorrections),"HoldAdmission",typeof(ProductionTerminalMutationAdmission)),
        (typeof(CompletionAccess),"HoldAdmission",typeof(ProductionCompletionReadAdmission)),(typeof(CompletionDownloads),"HoldAdmission",typeof(ProductionCompletionReadAdmission)),
        (typeof(DocumentLookup),"HoldAdmission",typeof(ProductionCompletionReadAdmission)),(typeof(LookupPacketAccess),"HoldAdmission",typeof(ProductionCompletionReadAdmission))];
    private static void Decorate(IServiceCollection services)
    {
        foreach(var hook in Hooks){var property=hook.Target.GetProperty(hook.Property,System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Instance);
            if(property?.PropertyType!=hook.Value||property.SetMethod is null)throw new InvalidOperationException("Production admission hook registry changed.");}
        foreach(var descriptor in services.ToArray()) {
            if(descriptor.ServiceType==typeof(WorkStore)){services.Remove(descriptor);services.AddScoped(sp=>new WorkStore(sp.GetRequiredService<QuillSignDbContext>(),sp.GetRequiredService<WorkOptions>(),sp.GetRequiredService<TimeProvider>(),sp.GetRequiredService<IProductionWorkAdmission>()));continue;}
            var mapped=Hooks.Any(h=>h.Target==descriptor.ServiceType);
            if(!mapped&&descriptor.ServiceType!=typeof(IWorkHandler))continue;
            if(descriptor.Lifetime!=ServiceLifetime.Scoped||descriptor.ImplementationInstance is not null)throw new InvalidOperationException("Production admission boundaries require their original scoped lifetime.");
            services.Remove(descriptor);services.Add(ServiceDescriptor.Describe(descriptor.ServiceType,sp=>{
                var target=descriptor.ImplementationInstance??descriptor.ImplementationFactory?.Invoke(sp)??ActivatorUtilities.CreateInstance(sp,descriptor.ImplementationType??descriptor.ServiceType);
                foreach(var hook in Hooks.Where(h=>h.Target.IsInstanceOfType(target)))hook.Target.GetProperty(hook.Property,System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Instance)!.SetValue(target,sp.GetRequiredService(hook.Value));
                return target;},descriptor.Lifetime));
        }
    }
}
