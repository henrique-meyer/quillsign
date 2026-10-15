using System.Text.RegularExpressions;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class StorageConfigurationTests
{
    private static string Connection => Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE") ??
        throw new InvalidOperationException("Run scripts/dev/Use-LocalDatabase.ps1 -Action Test with Azurite running.");

    private static ServiceProvider Provider(Dictionary<string, string?> settings, string environment = "Development")
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddQuillSignStorage(new ConfigurationBuilder().AddInMemoryCollection(settings).Build(), new TestEnvironment(environment));
        return services.BuildServiceProvider();
    }

    private static Dictionary<string, string?> Local(string name, string blob) => new()
    {
        ["Storage:Provider"] = "Azurite", ["Storage:ConnectionString"] = Connection,
        ["DataProtection:ApplicationName"] = name, ["DataProtection:KeyRingBlobName"] = blob
    };

    [Fact]
    public async Task Protected_sender_ticket_survives_provider_restart_and_key_rotation_across_replicas()
    {
        var name = "QuillSign-test-" + Guid.NewGuid().ToString("N");
        var blob = name + ".xml";
        var settings = Local(name, blob);
        var envelope = Guid.NewGuid();
        string protectedTicket;
        TicketDataFormat Format(ServiceProvider provider) => new(provider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("QuillSign.Tests.SenderTicket", "v1"));
        try
        {
            using (var first = Provider(settings))
            {
                var ticket = new AuthenticationTicket(BlobStorageTests.Sender(envelope), new AuthenticationProperties(), EnvelopeStorageAuthorization.SenderScheme);
                protectedTicket = Format(first).Protect(ticket);
            }
            using var restarted = Provider(settings);
            var restored = Format(restarted).Unprotect(protectedTicket);
            Assert.NotNull(restored);
            Assert.Equal(envelope.ToString(), restored.Principal.FindFirst(EnvelopeStorageAuthorization.EnvelopeClaim)?.Value);
            restarted.GetRequiredService<IKeyManager>().CreateNewKey(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));
            using var replica = Provider(settings);
            Assert.NotNull(Format(replica).Unprotect(protectedTicket));
            var newTicket = Format(replica).Protect(restored);
            Assert.NotNull(Format(restarted).Unprotect(newTicket));
            using var otherApp = Provider(Local(name + "-other", blob));
            Assert.Null(Format(otherApp).Unprotect(protectedTicket));
            var wrongPurpose = restarted.GetRequiredService<IDataProtectionProvider>().CreateProtector("OtherPurpose");
            Assert.Throws<System.Security.Cryptography.CryptographicException>(() => wrongPurpose.Unprotect(protectedTicket));
            var service = restarted.GetRequiredService<BlobServiceClient>();
            Assert.True((await service.GetBlobContainerClient("keys").GetBlobClient(blob).ExistsAsync()).Value);
            Assert.False((await service.GetBlobContainerClient("originals").GetBlobClient(blob).ExistsAsync()).Value);
        }
        finally
        {
            var service = new BlobServiceClient(Connection, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03));
            await service.GetBlobContainerClient("keys").GetBlobClient(blob).DeleteIfExistsAsync();
        }
    }

    [Fact]
    public void Key_store_failure_does_not_silently_fall_back_to_ephemeral_keys()
    {
        var settings = Local("QuillSign-failure-test", "failure-" + Guid.NewGuid().ToString("N") + ".xml");
        settings["Storage:ConnectionString"] = Regex.Replace(Connection, "AccountKey=[^;]+",
            "AccountKey=" + Convert.ToBase64String(new byte[64]));
        using var provider = Provider(settings);
        Assert.ThrowsAny<Exception>(() => provider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("failure-test").Protect("synthetic ticket"));
    }

    [Fact]
    public void Unconfigured_bootstrap_registers_without_accessing_storage()
    {
        using var provider = Provider([]);
        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IBlobStore>());
    }

    [Theory]
    [InlineData("Azurite", "Production", null)]
    [InlineData("Unknown", "Development", null)]
    [InlineData("Azure", "Production", null)]
    [InlineData("Azure", "Production", "https://placeholder.vault.azure.net/keys/key/version")]
    [InlineData("Azure", "Production", "https://placeholder.vault.azure.net/keys/key?secret=bad")]
    public void Hosted_configuration_cannot_use_emulator_or_unprotected_keys(string backend, string environment, string? key)
    {
        var settings = new Dictionary<string, string?>
        {
            ["Storage:Provider"] = backend,
            ["Storage:BlobServiceUri"] = "https://placeholder.blob.core.windows.net/",
            ["DataProtection:KeyVaultKeyIdentifier"] = key
        };
        Assert.Throws<InvalidOperationException>(() => Provider(settings, environment));
    }

    [Fact]
    public void Valid_hosted_configuration_requires_no_cloud_call_to_register()
    {
        using var provider = Provider(new()
        {
            ["Storage:Provider"] = "Azure",
            ["Storage:BlobServiceUri"] = "https://placeholder.blob.core.windows.net/",
            ["DataProtection:KeyVaultKeyIdentifier"] = "https://placeholder.vault.azure.net/keys/key"
        }, "Production");
        Assert.IsType<AzureBlobStore>(provider.GetRequiredService<IBlobStore>());
    }

    private sealed class TestEnvironment(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "QuillSign.Tests";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
