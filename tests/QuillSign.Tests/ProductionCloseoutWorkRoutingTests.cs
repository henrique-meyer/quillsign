using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Lifecycle;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionCloseoutWorkRoutingTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("known-disabled-alias")][InlineData("ordinary-demo")][InlineData("production-purge")][InlineData("held-production")][InlineData("missing-alias-service")]
    public async Task Decorated_worker_preserves_closeout_refusal_demo_origin_and_typed_deletion_routing(string kind)
    {
        await using var run=await ProductionRuntimeAdmissionTests.Run.Create(fixture,demo:kind!="held-production");
        if(kind=="held-production")await run.Hold();
        await using(var seed=fixture.Open())
        {
            if(kind is "known-disabled-alias" or "missing-alias-service")
            {
                var header=new EmailPilotCloseoutHeaderRecord{Id=Guid.NewGuid(),CreatedAt=run.Time.Now,Until=run.Time.Now.AddMinutes(30),DeleteAfter=run.Time.Now.AddDays(1),
                    CapabilitySha256=new byte[32],ManifestSha256=new byte[32],ProtectedManifest="synthetic-disabled-closeout"};
                seed.Add(header);await seed.SaveChangesAsync();
                seed.Add(new EmailPilotCloseoutOperationRecord{Id=Guid.NewGuid(),CloseoutId=header.Id,Kind=0,Step=6,SubjectEnvelopeId=run.Id,WorkId=run.WorkId,
                    At=run.Time.Now,RequestSha256=new byte[32],ProtectedReceipt="synthetic-disabled-closeout-operation"});
            }
            if(kind=="production-purge") (await seed.WorkItems.SingleAsync(x=>x.Id==run.WorkId)).Kind=WorkKind.ProductionPurge;
            await seed.SaveChangesAsync();
        }
        var services=new ServiceCollection();services.AddSingleton<TimeProvider>(run.Time);services.AddSingleton(run.Keys);
        services.AddSingleton(new WorkOptions{Enabled=true});services.AddScoped(_=>fixture.Open());services.AddScoped<WorkStore>();
        if(kind!="missing-alias-service")services.AddScoped<EmailPilotCloseout>(sp=>new(new(),new EmailOptions(),sp.GetRequiredService<WorkOptions>(),()=>sp.GetRequiredService<QuillSignDbContext>(),
            ()=>throw new InvalidOperationException("No pilot ledger authority."),()=>throw new InvalidOperationException("No pilot proof authority."),run.Time));
        services.AddProductionHoldRuntime(new ConfigurationBuilder().Build());
        // Use the actual genuine-demo origin verifier with this fixture's original
        // keys/journal. The central factory must additionally retain closeout.
        services.AddScoped<IProductionWorkAdmission>(_=>new ProductionWorkAdmission(fixture.Open,run.Admission));
        await using var provider=services.BuildServiceProvider();await using var scope=provider.CreateAsyncScope();
        var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();
        var before=JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId));
        if(kind=="ordinary-demo")Assert.NotNull((await store.ClaimAsync(run.WorkId,default)).Lease);
        else if(kind=="held-production")
        {
            var blocked=await store.ClaimAsync(run.WorkId,default);Assert.Null(blocked.Lease);Assert.NotNull(blocked.RetryAt);
            Assert.True((await run.Journal.ReadAsync(run.Id)).Frozen);
            Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId)));
        }
        else
        {
            await Assert.ThrowsAsync<InvalidDataException>(()=>store.ClaimAsync(run.WorkId,default));
            Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==run.WorkId)));
        }
        Assert.Equal(0,run.Captured.Calls);
    }
}
