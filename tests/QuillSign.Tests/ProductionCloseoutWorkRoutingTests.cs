using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Lifecycle;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class ProductionCloseoutWorkRoutingTests
{
    [Theory]
    [InlineData("demo")][InlineData("production")][InlineData("downgraded")]
    public async Task Canonical_private_lookup_record_still_requires_existing_demo_origin_and_no_production_state(string kind)
    {
        await using var fixture=new SqlDatabaseFixture();await fixture.InitializeAsync();
        var demo=kind=="demo";await using var run=await ProductionRuntimeAdmissionTests.Run.Create(fixture,demo:demo);
        if(!demo)await run.Hold();
        if(kind=="downgraded"){await using var seed=fixture.Open();await seed.Envelopes.Where(x=>x.Id==run.Id).ExecuteUpdateAsync(x=>x.SetProperty(e=>e.IsDemo,true));}
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();
        var kernel=new ProductionWorkAdmission(fixture.Open,run.Admission);
        if(demo)await kernel.DemandCloseoutDemoLockedAsync(db,run.Id,default);
        else await Assert.ThrowsAsync<ProductionWorkBlockedException>(()=>kernel.DemandCloseoutDemoLockedAsync(db,run.Id,default));
        await tx.RollbackAsync();Assert.Equal(0,run.Captured.Calls);
    }
    [Fact]
    public void Direct_and_ordinary_handler_resolve_same_production_decorated_scoped_instance()
    {
        var services=new ServiceCollection();services.AddLogging();services.AddSingleton<TimeProvider>(TimeProvider.System);
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        services.AddSingleton(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer("Server=localhost;Database=unused;Integrated Security=true;Encrypt=false").Options);
        services.AddScoped<EmailWorkHandler>(_=>new(null!,new(),null!,null!,null!,TimeProvider.System));
        services.AddScoped<IWorkHandler>(sp=>sp.GetRequiredService<EmailWorkHandler>());
        services.AddProductionHoldRuntime(new ConfigurationBuilder().Build());
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        var concrete=scope.ServiceProvider.GetRequiredService<EmailWorkHandler>();
        Assert.Same(concrete,scope.ServiceProvider.GetRequiredService<IWorkHandler>());
        Assert.NotNull(concrete.HoldAdmission);Assert.Same(scope.ServiceProvider.GetRequiredService<IProductionWorkAdmission>(),concrete.HoldAdmission);
    }

    [Theory]
    [InlineData("known-disabled-alias")][InlineData("ordinary-demo")][InlineData("production-purge")][InlineData("held-production")][InlineData("missing-alias-service")]
    [InlineData("initial-missing-alias-service")][InlineData("initial-cleared-alias-config")]
    [InlineData("unbound-null")][InlineData("known-null")]
    public async Task Decorated_worker_preserves_closeout_refusal_demo_origin_and_typed_deletion_routing(string kind)
    {
        // A closeout authority is a one-header-ever installation. Independent
        // configuration cases must not share corrupt multiple-header state.
        await using var fixture=new SqlDatabaseFixture();await fixture.InitializeAsync();
        await using var run=await ProductionRuntimeAdmissionTests.Run.Create(fixture,demo:kind!="held-production");
        var workId=run.WorkId;
        if(kind=="held-production")await run.Hold();
        await using(var seed=fixture.Open())
        {
            if(kind.StartsWith("initial-",StringComparison.Ordinal)) {
                var auth=Guid.NewGuid();var pairs=new List<EmailPilotCloseoutQueue>();
                var originals=new List<(EmailOutbox Mail,WorkItem Work)>();
                for(var n=0;n<6;n++) {
                    var mail=new EmailOutbox{EnvelopeId=run.Id,To="sender@example.invalid",Template=n<4?CompletionNotificationJobs.Template:VoidNotificationJobs.Template,
                        PayloadJson="{\"Protected\":\"original-ciphertext\"}",Status=EmailStatus.Failed,LastError="pilot-delivery-unavailable",AvailableAt=run.Time.Now.AddHours(-1)};
                    var work=new WorkItem{Id=mail.Id,EnvelopeId=run.Id,Kind=WorkKind.Email,Status=WorkStatus.Failed,Attempts=1,LastError=mail.LastError,AvailableAt=mail.AvailableAt,
                        PayloadJson=n<4?CompletionNotificationJobs.WorkJson(mail.Id):VoidNotificationJobs.WorkJson(mail.Id)};
                    seed.AddRange(mail,work);originals.Add((mail,work));
                }
                await seed.SaveChangesAsync();await using var tx=await seed.Database.BeginTransactionAsync();
                for(var n=0;n<6;n++)pairs.Add(await EmailPilotCloseout.InsertAliasPairLockedAsync(seed,auth,(EmailPilotCloseoutStep)n,originals[n].Mail,originals[n].Work,run.Time.Now));
                seed.Add(new EmailPilotCloseoutHeaderRecord{Id=auth,CreatedAt=run.Time.Now,Until=run.Time.Now.AddMinutes(30),DeleteAfter=run.Time.Now.AddDays(1),
                    CapabilitySha256=new byte[32],ManifestSha256=new byte[32],ProtectedManifest=JsonSerializer.Serialize(pairs)});
                await seed.SaveChangesAsync();await tx.CommitAsync();workId=pairs[^1].WorkId;
                Assert.False(await seed.EmailPilotCloseoutOperations.AnyAsync());
            }
            if(kind is "known-disabled-alias" or "missing-alias-service")
            {
                var header=new EmailPilotCloseoutHeaderRecord{Id=Guid.NewGuid(),CreatedAt=run.Time.Now,Until=run.Time.Now.AddMinutes(30),DeleteAfter=run.Time.Now.AddDays(1),
                    CapabilitySha256=new byte[32],ManifestSha256=new byte[32],ProtectedManifest="synthetic-disabled-closeout"};
                seed.Add(header);await seed.SaveChangesAsync();
                seed.Add(new EmailPilotCloseoutOperationRecord{Id=Guid.NewGuid(),CloseoutId=header.Id,Kind=0,Step=6,SubjectEnvelopeId=run.Id,WorkId=run.WorkId,
                    At=run.Time.Now,RequestSha256=new byte[32],ProtectedReceipt="synthetic-disabled-closeout-operation"});
            }
            if(kind is "unbound-null" or "known-null") {
                (await seed.WorkItems.SingleAsync(x=>x.Id==workId)).EnvelopeId=null;
                (await seed.EmailOutbox.SingleAsync(x=>x.Id==workId)).EnvelopeId=null;
                if(kind=="known-null") {
                    var header=new EmailPilotCloseoutHeaderRecord{Id=Guid.NewGuid(),CreatedAt=run.Time.Now,Until=run.Time.Now.AddMinutes(30),DeleteAfter=run.Time.Now.AddDays(1),CapabilitySha256=new byte[32],ManifestSha256=new byte[32],ProtectedManifest="not-authenticated"};
                    seed.Add(header);await seed.SaveChangesAsync();seed.Add(new EmailPilotCloseoutOperationRecord{Id=Guid.NewGuid(),CloseoutId=header.Id,Kind=0,Step=9,SubjectEnvelopeId=run.Id,WorkId=workId,At=run.Time.Now,RequestSha256=new byte[32],ProtectedReceipt="not-a-private-fact"});
                }
            }
            if(kind=="production-purge") (await seed.WorkItems.SingleAsync(x=>x.Id==run.WorkId)).Kind=WorkKind.ProductionPurge;
            await seed.SaveChangesAsync();
        }
        var services=new ServiceCollection();services.AddSingleton<TimeProvider>(run.Time);services.AddSingleton(run.Keys);
        services.AddSingleton(new WorkOptions{Enabled=true});services.AddScoped(_=>fixture.Open());services.AddScoped<WorkStore>();
        if(!kind.Contains("missing-alias-service",StringComparison.Ordinal))services.AddScoped<EmailPilotCloseout>(sp=>new(new(),new EmailOptions(),sp.GetRequiredService<WorkOptions>(),()=>sp.GetRequiredService<QuillSignDbContext>(),
            ()=>throw new InvalidOperationException("No pilot ledger authority."),()=>throw new InvalidOperationException("No pilot proof authority."),run.Time));
        services.AddProductionHoldRuntime(new ConfigurationBuilder().Build());
        // Use the actual genuine-demo origin verifier with this fixture's original
        // keys/journal. The central factory must additionally retain closeout.
        services.AddScoped<IProductionWorkAdmission>(_=>new ProductionWorkAdmission(fixture.Open,run.Admission));
        await using var provider=services.BuildServiceProvider();await using var scope=provider.CreateAsyncScope();
        var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var store=scope.ServiceProvider.GetRequiredService<WorkStore>();
        var before=JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==workId));
        if(kind=="ordinary-demo")Assert.NotNull((await store.ClaimAsync(workId,default)).Lease);
        else if(kind is "held-production" or "unbound-null")
        {
            var blocked=await store.ClaimAsync(workId,default);Assert.Null(blocked.Lease);Assert.NotNull(blocked.RetryAt);
            if(kind=="held-production")Assert.True((await run.Journal.ReadAsync(run.Id)).Frozen);
            Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==workId)));
        }
        else
        {
            await Assert.ThrowsAsync<InvalidDataException>(()=>store.ClaimAsync(workId,default));
            Assert.Equal(before,JsonSerializer.Serialize(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==workId)));
        }
        Assert.Equal(0,run.Captured.Calls);
    }
}
