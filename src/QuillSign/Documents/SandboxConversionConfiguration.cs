using Azure.Identity;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace QuillSign.Documents;

public static class SandboxConversionConfiguration
{
    public static IServiceCollection AddSandboxDocumentConversion(this IServiceCollection services, IConfiguration config, GotenbergOptions conversion, DocumentOptions limits)
    {
        if (!(conversion.Enabled && conversion.Transport == "Sandbox") && !conversion.Sandbox.MaintenanceEnabled) return services;
        var options = conversion.Sandbox;
        options.Validate();
        services.AddSingleton(options);
        services.TryAddSingleton(limits);
        services.TryAddSingleton<TimeProvider>(TimeProvider.System);
        services.AddHttpClient("QuillSignSandboxConversion", client => client.Timeout = Timeout.InfiniteTimeSpan)
            .RemoveAllLoggers().ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
            { AllowAutoRedirect = false, UseProxy = false, AutomaticDecompression = System.Net.DecompressionMethods.None, MaxResponseHeadersLength = 16 });
        services.AddScoped<ISandboxConversionApi>(sp =>
        {
            var clientId = options.ManagedIdentityClientId.Length != 0 ? options.ManagedIdentityClientId : config["Storage:ManagedIdentityClientId"];
            var credential = string.IsNullOrWhiteSpace(clientId) ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned) : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(clientId));
            return new SandboxConversionApi(sp.GetRequiredService<IHttpClientFactory>().CreateClient("QuillSignSandboxConversion"), credential, options);
        });
        services.AddScoped<ISandboxConversionLedger>(sp => new BlobSandboxConversionLedger(sp.GetRequiredService<BlobServiceClient>().GetBlobContainerClient("originals"),
            sp.GetRequiredService<IDataProtectionProvider>(), options, config["Storage:Provider"] == "Azurite"));
        services.AddScoped<SandboxDocxTransport>();
        services.AddScoped<ISandboxDocxTransport>(sp => sp.GetRequiredService<SandboxDocxTransport>());
        return services;
    }
}
