using Azure.Core;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.AspNetCore.DataProtection;

namespace QuillSign.Storage;

public static class StorageConfiguration
{
    public static IServiceCollection AddQuillSignStorage(this IServiceCollection services, IConfiguration config, IHostEnvironment environment)
    {
        var provider = config["Storage:Provider"];
        if (string.IsNullOrWhiteSpace(provider))
        {
            // Bootstrap only. Document/session workflows must require configured persistent storage.
            services.AddSingleton<IBlobStore>(_ => throw new InvalidOperationException("Configure Storage__Provider before using documents."));
            services.AddSingleton<ICompletionFinalStore>(_ => throw new InvalidOperationException("Configure Storage__Provider before final publication."));
            return services;
        }

        var local = provider == "Azurite";
        if ((!local && provider != "Azure") || (local && !environment.IsDevelopment()))
            throw new InvalidOperationException("Use Azure storage when hosted; Azurite is Development-only.");
        var limit = config.GetValue<long?>("Storage:MaximumBlobBytes") ?? 25 * 1024 * 1024;
        if (limit <= 0 || limit > 1024L * 1024 * 1024)
            throw new InvalidOperationException("Storage maximum must be between 1 byte and 1 GiB.");

        TokenCredential? credential = null;
        BlobServiceClient service;
        if (local)
        {
            var connection = config["Storage:ConnectionString"];
            if (string.IsNullOrWhiteSpace(connection)) throw new InvalidOperationException("Configure the local Azurite connection.");
            service = new BlobServiceClient(connection, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
            if (!service.Uri.IsLoopback && service.Uri.Host != "azurite")
                throw new InvalidOperationException("Azurite must use a local emulator endpoint.");
        }
        else
        {
            credential = string.IsNullOrWhiteSpace(config["Storage:ManagedIdentityClientId"])
                ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(config["Storage:ManagedIdentityClientId"]!));
            var uri = HttpsUri(config["Storage:BlobServiceUri"], "Storage:BlobServiceUri");
            if (uri.AbsolutePath != "/") throw new InvalidOperationException("Configure a Blob service endpoint, without a container path.");
            service = new BlobServiceClient(uri, credential);
        }

        services.AddSingleton(service);
        services.AddSingleton<ICompletionFinalStore>(sp=>new AzureCompletionFinalStore(service,sp.GetRequiredService<TimeProvider>(),environment,local));
        services.AddSingleton<IBlobStore>(new AzureBlobStore(service, limit, local));
        var keys = service.GetBlobContainerClient("keys");
        var keyBlob = config["DataProtection:KeyRingBlobName"] ?? "data-protection.xml";
        if (keyBlob.Length == 0 || keyBlob.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not '-' and not '_' and not '.'))
            throw new InvalidOperationException("Data Protection key-ring blob name must be a plain filename.");
        var applicationName = config["DataProtection:ApplicationName"];
        var protection = services.AddDataProtection()
            .SetApplicationName(string.IsNullOrWhiteSpace(applicationName) ? $"QuillSign:{environment.EnvironmentName}" : applicationName)
            .PersistKeysToAzureBlobStorage(_ =>
            {
                // Hosted containers are provisioned through approved infrastructure. Only the
                // local emulator creates containers lazily; key data is never in document purge.
                if (local) keys.CreateIfNotExists(PublicAccessType.None);
                return keys.GetBlobClient(keyBlob);
            });
        if (!local)
        {
            var key = HttpsUri(config["DataProtection:KeyVaultKeyIdentifier"], "DataProtection:KeyVaultKeyIdentifier");
            var parts = key.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 2 || parts[0] != "keys")
                throw new InvalidOperationException("Use a versionless Key Vault key identifier; retain old key versions.");
            protection.ProtectKeysWithAzureKeyVault(key, credential!);
        }
        return services;
    }

    private static Uri HttpsUri(string? value, string setting)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0)
            throw new InvalidOperationException($"Configure {setting} as an HTTPS endpoint without credentials or a query string.");
        return uri;
    }
}
