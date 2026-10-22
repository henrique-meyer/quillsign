using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Lifecycle;

internal static partial class ProductionHoldRuntime
{
    private static void AddProductionDeletionRuntime(IServiceCollection services,IConfiguration config,ProductionHoldRuntimeOptions holds)
    {
        var options=config.GetSection("ProductionDeletion").Get<ProductionDeletionOptions>()??new();services.AddSingleton(options);
        if(!options.Enabled){services.AddScoped<IProductionDeletionWorkAdmission,ClosedProductionDeletionWorkAdmission>();return;}
        options.Demand();if(!holds.Enabled||!config.GetValue<bool>("Work:Enabled"))throw new InvalidOperationException("Production deletion requires the complete enabled production protection runtime.");
        services.AddScoped<IProductionDeletionStore>(sp=>new AzureProductionDeletionStore(new(holds.ServiceUri),sp.GetRequiredService<Credential>().Value));
        services.AddScoped<IProductionDeletionRecoveryIndex>(sp=>new AzureProductionDeletionRecoveryIndex(new(holds.WitnessContainerUri),sp.GetRequiredService<Credential>().Value,
            sp.GetRequiredService<IDataProtectionProvider>(),holds.InstallationDigest));
        services.AddScoped<ProductionDeletionCoordinator>(sp=>new(Open(sp),sp.GetRequiredService<IDataProtectionProvider>(),sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ProductionHoldWitnessJournal>(),sp.GetRequiredService<ProductionHoldCoordinator>(),sp.GetRequiredService<ProductionRecordOperationAdmission>(),
            sp.GetRequiredService<IProductionDeletionStore>(),sp.GetRequiredService<IProductionDeletionRecoveryIndex>(),options,sp.GetRequiredService<WorkOptions>(),()=>sp.GetRequiredService<IWorkSignals>()));
        services.AddScoped<IProductionDeletionWorkAdmission>(sp=>sp.GetRequiredService<ProductionDeletionCoordinator>());
        services.AddScoped<IWorkHandler>(sp=>new ProductionDeletionWork(()=>sp.GetRequiredService<IProductionDeletionWorkAdmission>()));
    }
    private sealed class ClosedProductionDeletionWorkAdmission:IProductionDeletionWorkAdmission
    {
        public Task<WorkClaim> ClaimAsync(QuillSignDbContext db,Guid id,CancellationToken ct)=>throw ProductionDeletionProtocol.Invalid();
        public Task<WorkResult> ExecuteAsync(WorkLease lease,CancellationToken ct)=>throw ProductionDeletionProtocol.Invalid();
        public Task<DateTimeOffset?> FinishAsync(QuillSignDbContext db,WorkLease lease,WorkResult result,CancellationToken ct)=>throw ProductionDeletionProtocol.Invalid();
        public Task ReconcileCompletedAsync(WorkLease lease,Guid recordId,CancellationToken ct)=>throw ProductionDeletionProtocol.Invalid();
    }
}
