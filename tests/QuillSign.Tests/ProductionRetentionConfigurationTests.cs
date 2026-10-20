using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Documents;
using QuillSign.Legal;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionRetentionConfigurationTests
{
    [Fact]
    public void Missing_mode_preserves_demo_and_production_requires_complete_explicit_configuration()
    {
        var services=new ServiceCollection();services.AddQuillSignDocuments(new ConfigurationBuilder().Build());
        using var provider=services.BuildServiceProvider();
        Assert.Equal("Demo",provider.GetRequiredService<RecordLifecycleOptions>().Mode);
        Assert.Throws<InvalidOperationException>(()=>new ServiceCollection().AddQuillSignDocuments(Config(new {Mode="unknown"},new ElectronicRecordOptions())));
        Assert.Throws<InvalidOperationException>(()=>new ServiceCollection().AddQuillSignDocuments(Config(new {Mode="Production"},ProductionRetentionAdmissionContractTests.Policies())));
        Assert.Throws<DisclosureRejectedException>(()=>new ServiceCollection().AddQuillSignDocuments(Config(ProductionRetentionAdmissionContractTests.Settings(),new ElectronicRecordOptions())));
    }

    [Theory]
    [InlineData(365)][InlineData(0)]
    public void Complete_production_configuration_binds_without_resolving_private_backends(int days)
    {
        var settings=ProductionRetentionAdmissionContractTests.Settings();settings.Production.CompletedDays=days;
        var services=new ServiceCollection();services.AddQuillSignDocuments(Config(settings,ProductionRetentionAdmissionContractTests.Policies()));
        using var provider=services.BuildServiceProvider();var bound=provider.GetRequiredService<RecordLifecycleOptions>();
        Assert.Equal("Production",bound.Mode);Assert.Equal(days,bound.Production.CompletedDays);
        Assert.Equal("synthetic-v1",bound.Production.Version);
        Assert.Equal("",provider.GetRequiredService<ElectronicRecordOptions>().Profile);
    }

    private static IConfiguration Config(object records,ElectronicRecordOptions policies)
    {
        var bytes=JsonSerializer.SerializeToUtf8Bytes(new {Records=records,ElectronicRecords=policies});
        return new ConfigurationBuilder().AddJsonStream(new MemoryStream(bytes)).Build();
    }
}
