using Microsoft.Extensions.Configuration;
using QuillSign.Operations;

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
    }
}
