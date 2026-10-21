using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Operator;
using QuillSign.Sealing;

namespace QuillSign.Tests;

public sealed class ProductionOperatorBoundaryTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("/operator/retention")][InlineData("/operator/retention/Status")]
    public async Task Default_disabled_private_pages_disclose_no_record_or_backend(string path)
    {
        var b=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(ProductionOperatorBrowser).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        b.Logging.ClearProviders();b.WebHost.UseTestServer();b.Services.AddRazorPages();b.Services.AddAuthentication();b.Services.AddDataProtection();b.Services.AddSingleton(TimeProvider.System);
        b.Services.AddProductionOperator(new ConfigurationBuilder().Build());await using var app=b.Build();app.UseRouting();app.UseRateLimiter();app.UseAuthentication();app.UseAuthorization();app.MapRazorPages();await app.StartAsync();
        using var client=app.GetTestClient();client.BaseAddress=new("https://localhost");using var response=await client.GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);var text=await response.Content.ReadAsStringAsync();Assert.DoesNotContain("Private reason",text);Assert.DoesNotContain("Record identifier",text);
    }
    [Theory]
    [InlineData("issuer")][InlineData("client")][InlineData("secret")][InlineData("subject")][InlineData("duplicate")][InlineData("no-permissions")]
    public void Oidc_configuration_never_infers_identity_or_permissions(string fault)
    {
        var o=Options();Assert.True(o.Policy().Enabled);switch(fault){case "issuer":o.Issuer="http://operator.example.invalid";break;case "client":o.ClientId="";break;
            case "secret":o.ClientSecret="";break;case "subject":o.Grants[0].Subject=" ";break;case "duplicate":o.Grants=[o.Grants[0],o.Grants[0]];break;case "no-permissions":o.Grants[0].Status=false;break;}
        Assert.Throws<InvalidOperationException>(()=>o.Policy());
    }
    [Fact]
    public void Stable_installation_namespace_binds_exact_explicit_id_and_witness_location()
    {
        var id="00000000000000000000000000000001";var uri="https://storage.example.invalid/witness";
        var first=ProductionHoldRuntimeOptions.IdentityDigest(id,uri);Assert.Equal(64,first.Length);
        Assert.NotEqual(first,ProductionHoldRuntimeOptions.IdentityDigest("00000000000000000000000000000002",uri));
        Assert.NotEqual(first,ProductionHoldRuntimeOptions.IdentityDigest(id,"https://storage.example.invalid/other"));
        var changed=new ProductionHoldRuntimeOptions{InstallationId=id,WitnessContainerUri=uri,InstallationDigest=new string('a',64)};
        Assert.Throws<InvalidOperationException>(()=>changed.Validate(new ConfigurationBuilder().Build()));
        Assert.Throws<InvalidOperationException>(()=>ProductionHoldRuntimeOptions.IdentityDigest(id,uri+"?sig=untrusted"));
        Assert.Throws<InvalidOperationException>(()=>ProductionHoldRuntimeOptions.IdentityDigest(id,uri+"/"));
        Assert.Throws<InvalidOperationException>(()=>ProductionHoldRuntimeOptions.IdentityDigest("",uri));
        var disabled=new ProductionHoldRuntimeOptions{InstallationId=id,WitnessContainerUri=uri};disabled.Validate(new ConfigurationBuilder().Build());Assert.Equal(first,disabled.InstallationDigest);
    }
    [Fact]
    public async Task Every_closed_hook_is_installed_with_same_scoped_kernel_even_after_disable()
    {
        var services=new ServiceCollection();services.AddSingleton<TimeProvider>(TimeProvider.System);services.AddDataProtection();await using var db=fixture.Open();
        services.AddDbContext<QuillSignDbContext>(o=>o.UseSqlServer(db.Database.GetConnectionString()));
        services.AddScoped(_=>(PlatformPdfSeal)RuntimeHelpers.GetUninitializedObject(typeof(PlatformPdfSeal)));
        foreach(var type in ProductionHoldRuntime.Hooks.Select(h=>h.Target).Distinct())services.AddScoped(type,_=>RuntimeHelpers.GetUninitializedObject(type));
        services.AddProductionHoldRuntime(new ConfigurationBuilder().Build());using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        foreach(var hook in ProductionHoldRuntime.Hooks){var target=scope.ServiceProvider.GetRequiredService(hook.Target);var value=hook.Target.GetProperty(hook.Property,System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Instance)!.GetValue(target);
            Assert.NotNull(value);Assert.Same(scope.ServiceProvider.GetRequiredService(hook.Value),value);}
        var store=scope.ServiceProvider.GetRequiredService<IProductionHoldWitnessStore>();Assert.IsType<ClosedProductionStores>(store);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>store.ReadAsync(Guid.NewGuid()));
    }
    [Fact]
    public async Task Private_read_receipt_is_bounded_append_only_and_outside_business_inventory()
    {
        await using var db=fixture.Open();Assert.False(db.Database.HasPendingModelChanges());
        var row=new ProductionOperatorAccessReceipt{Id=Guid.NewGuid(),At=DateTimeOffset.UtcNow,PayloadSha256=new byte[32],ProtectedReceipt=new string('x',4096)};
        db.Add(row);await db.SaveChangesAsync();db.ChangeTracker.AutoDetectChangesEnabled=false;row.ProtectedReceipt="changed";await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync());db.ChangeTracker.Clear();
        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.ProductionOperatorAccessReceipts.Where(x=>x.Id==row.Id).ExecuteDeleteAsync());
        Assert.True(await db.ProductionOperatorAccessReceipts.AnyAsync(x=>x.Id==row.Id));
    }
    internal static ProductionOperatorOptions Options()=>new(){Enabled=true,Issuer="https://operator.example.invalid",ClientId="synthetic-client",ClientSecret="synthetic-client-secret",Grants=[new(){Subject="synthetic-operator",Status=true}]};
}
