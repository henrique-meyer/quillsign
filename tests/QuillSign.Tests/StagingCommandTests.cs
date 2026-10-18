using Microsoft.Extensions.Configuration;
using QuillSign.Operations;
using System.Security.Cryptography;
using PdfSharp.Pdf;

namespace QuillSign.Tests;

public class StagingCommandTests
{
    [Theory]
    [InlineData("Storage:Provider", "Azurite")]
    [InlineData("Storage:Provider", "")]
    [InlineData("ElectronicRecords:Profile", "")]
    [InlineData("Email:Enabled", "true")]
    [InlineData("Email:Enabled", null)]
    [InlineData("Completion:AllowDevelopmentWriteOnce", "true")]
    public void Operator_probe_rejects_non_demo_or_enabled_email_before_services(string key, string? value)
    {
        var settings = new Dictionary<string, string?> {
            ["Storage:Provider"] = "Azure", ["ElectronicRecords:Profile"] = "synthetic-demo-v1", ["Email:Enabled"] = "false"
        };
        settings[key] = value;
        Assert.Throws<InvalidOperationException>(() => StagingCommands.DemandConfiguration(new ConfigurationBuilder().AddInMemoryCollection(settings).Build()));
    }

    [Fact]
    public void Operator_probe_configuration_does_not_need_a_database_or_email_credentials()
    {
        StagingCommands.DemandConfiguration(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["Storage:Provider"] = "Azure", ["ElectronicRecords:Profile"] = "synthetic-demo-v1", ["Email:Enabled"] = "false"
        }).Build());
    }

    [Fact]
    public async Task Unrecognized_arguments_never_start_a_probe()
    {
        Assert.Equal(2, await StagingCommands.RunAsync([]));
        Assert.Equal(2, await StagingCommands.RunAsync(["seal", "retry"]));
        Assert.Equal(2, await StagingCommands.RunAsync(["unknown"]));
        Assert.Equal(2, await StagingCommands.RunAsync(["cleanup", "wrong", "wrong", "wrong"]));
    }

    [Theory]
    [InlineData("title")][InlineData("hash")][InlineData("pages")]
    public void Explicit_probe_cleanup_requires_the_nominated_hash_and_synthetic_unsigned_document(string fault)
    {
        using var pdf = new PdfDocument();
        pdf.Info.Title = fault == "title" ? "An ordinary document" : "SYNTHETIC STORAGE AND SEAL CHECK - NO AGREEMENT";
        pdf.AddPage(); if (fault == "pages") pdf.AddPage();
        using var output = new MemoryStream(); pdf.Save(output, false); var bytes = output.ToArray();
        var hash = SHA256.HashData(bytes); if (fault == "hash") hash[0] ^= 1;
        Assert.Throws<InvalidDataException>(() => StagingCommands.DemandSyntheticDocument(bytes, hash));
    }

    [Fact]
    public void Exact_small_synthetic_probe_document_can_be_nominated_for_operator_cleanup()
    {
        using var pdf = new PdfDocument(); pdf.Info.Title = "SYNTHETIC STORAGE AND SEAL CHECK - NO AGREEMENT"; pdf.AddPage();
        using var output = new MemoryStream(); pdf.Save(output, false); var bytes = output.ToArray();
        StagingCommands.DemandSyntheticDocument(bytes, SHA256.HashData(bytes));
    }
}
