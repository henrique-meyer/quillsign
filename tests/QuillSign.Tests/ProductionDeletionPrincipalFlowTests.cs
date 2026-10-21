using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Lifecycle;
using QuillSign.Sender;
using QuillSign.Sealing;
using QuillSign.Storage;
using QuillSign.Work;
using static QuillSign.Tests.ProductionHoldWitnessJournalTests;

namespace QuillSign.Tests;

// Effective database users on native SQL Server, not Entra/login authentication.
public sealed class ProductionDeletionPrincipalFlowTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Explicit_SQL_principals_run_enabled_participant_worker_hold_and_registered_deletion_with_worker_only_procedure()
    {
        await NativeProductionHoldPrincipals.ProvisionExplicitSqlPrincipalsAsync(fixture);
        await using(var admin=fixture.Open()){
            await admin.Database.OpenConnectionAsync();
            await DatabasePermissions.GrantProductionPurgeAsync((Microsoft.Data.SqlClient.SqlConnection)admin.Database.GetDbConnection());
        }
        var keys=new EphemeralDataProtectionProvider();var clock=new Clock{Now=DateTimeOffset.UtcNow.AddDays(-5)};
        var witness=new ProductionOperatorOidcTests.MemoryWitness();var captured=new ProductionRuntimeAdmissionTests.CapturedSender();
        var signals=new ProductionDeletionConnectedTests.Signals();var files=new EmptyFiles();var index=new Index();
        await using var runtime=Build("app_runtime");await using var worker=Build("app_worker");
        var first=await Request();var second=await Request();
        using(var scope=worker.Services.CreateScope()){
            await Who(scope,"app_worker");var store=scope.ServiceProvider.GetRequiredService<WorkStore>();
            var claim=(await store.ClaimAsync(first.Work,default)).Lease!;Assert.NotNull(claim);
            var result=await scope.ServiceProvider.GetRequiredService<EmailWorkHandler>().ExecuteAsync(claim,default);
            Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(claim,result,default);
        }
        using(var scope=runtime.Services.CreateScope()){
            await Who(scope,"app_runtime");Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SenderWorkflow>().VerifyAsync(first.Token.Token,null,null));
            var command=Place(first.Record);var holds=scope.ServiceProvider.GetRequiredService<ProductionHoldCoordinator>();
            await holds.SubmitAsync(Authority(clock,command.Permission),Operators,command);
            await using var db=NativeProductionHoldPrincipals.OpenAs(fixture,"app_runtime");
            Assert.Single(await db.ProductionHoldRequests.Where(x=>x.EnvelopeId==first.Record).ToArrayAsync());
            await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(()=>db.Database.ExecuteSqlRawAsync("DELETE FROM dbo.AuditEvents WHERE 1=0"));
            await db.Database.OpenConnectionAsync();await using var check=db.Database.GetDbConnection().CreateCommand();
            check.CommandText="SELECT HAS_PERMS_BY_NAME('dbo.RemoveExpiredProductionPrivateRecords','OBJECT','EXECUTE')";Assert.Equal(0,Convert.ToInt32(await check.ExecuteScalarAsync()));
        }
        using(var scope=worker.Services.CreateScope()){
            await Who(scope,"app_worker");var store=scope.ServiceProvider.GetRequiredService<WorkStore>();
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
            var before=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==first.Work);
            var journal=scope.ServiceProvider.GetRequiredService<ProductionHoldWitnessJournal>();var head=await journal.ReadAsync(first.Record);
            Assert.True(head.Frozen);Assert.Equal(1,captured.Calls);
            await Assert.ThrowsAsync<InvalidDataException>(()=>scope.ServiceProvider.GetRequiredService<ProductionRecordOperationAdmission>()
                .BeginAsync(first.Record,Guid.NewGuid(),"test/held-worker","synthetic-held-operation"));
            Assert.Equal(head.HeadHash,(await journal.ReadAsync(first.Record)).HeadHash);
            var after=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==first.Work);
            Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.Attempts,after.Attempts);Assert.Equal(before.LeaseOwner,after.LeaseOwner);Assert.Equal(1,captured.Calls);
            var lease=(await store.ClaimAsync(second.Work,default)).Lease!;Assert.NotNull(lease);
            var result=await scope.ServiceProvider.GetRequiredService<EmailWorkHandler>().ExecuteAsync(lease,default);
            Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
        }
        using(var scope=runtime.Services.CreateScope())Assert.NotNull(await scope.ServiceProvider.GetRequiredService<SenderWorkflow>().VerifyAsync(second.Token.Token,null,null));
        clock.Now=DateTimeOffset.UtcNow;
        Guid deletionWork;
        using(var scope=worker.Services.CreateScope()){
            await Who(scope,"app_worker");deletionWork=await scope.ServiceProvider.GetRequiredService<ProductionDeletionCoordinator>().PrepareAsync(second.Record);
            signals.Next=deletionWork;var processor=new WorkProcessor(scope.ServiceProvider.GetRequiredService<WorkStore>(),signals,
                scope.ServiceProvider.GetServices<IWorkHandler>(),clock);Assert.True(await processor.RunOnceAsync(default));
            var status=await scope.ServiceProvider.GetRequiredService<ProductionDeletionCoordinator>().ReadRecordedStatusAsync(second.Record);
            Assert.True(status.SqlRemoved);Assert.True(status.ActiveDataCleaned);
        }
        await using(var read=NativeProductionHoldPrincipals.OpenAs(fixture,"app_worker")){
            Assert.False(await read.Envelopes.AnyAsync(x=>x.Id==second.Record));Assert.True(await read.Envelopes.AnyAsync(x=>x.Id==first.Record));
            var work=await read.WorkItems.SingleAsync(x=>x.Id==deletionWork);Assert.Equal(WorkStatus.Completed,work.Status);Assert.Null(work.EnvelopeId);Assert.Equal(1,work.Attempts);
        }
        Assert.Equal(2,captured.Calls);Assert.Equal(0,files.Deletes);

        async Task<(Guid Record,Guid Work,VerificationPayload Token)> Request(){
            using var scope=runtime.Services.CreateScope();await Who(scope,"app_runtime");var sender=scope.ServiceProvider.GetRequiredService<SenderWorkflow>();
            var address="role-"+Guid.NewGuid().ToString("N")+"@example.invalid";Assert.Equal(SenderRequestOutcome.Neutral,await sender.RequestAsync(address,null,null));
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.To==address);
            return(mail.EnvelopeId!.Value,mail.Id,scope.ServiceProvider.GetRequiredService<EmailPayloadProtection>().Unprotect(mail.PayloadJson));
        }
        WebApplication Build(string principal){
            var b=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(SenderWorkflow).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});b.Logging.ClearProviders();b.Services.AddRazorPages();
            using var source=NativeProductionHoldPrincipals.OpenAs(fixture,principal);var options=(DbContextOptions<QuillSignDbContext>)source.GetService<IDbContextOptions>();
            b.Services.AddSingleton(options);b.Services.AddScoped(_=>new QuillSignDbContext(options));b.Services.AddSingleton<IDataProtectionProvider>(keys);b.Services.AddSingleton<TimeProvider>(clock);
            var data=new Dictionary<string,string?>{
                ["ProductionHolds:Enabled"]="true",["ProductionHolds:InstallationId"]="00000000000000000000000000000001",["ProductionHolds:ServiceUri"]="https://storage.example.invalid/",
                ["ProductionHolds:WitnessContainerUri"]="https://storage.example.invalid/witness",["ProductionHolds:AllowIndefiniteWitnessLegalHold"]="true",
                ["Storage:Provider"]="Azure",["Storage:BlobServiceUri"]="https://storage.example.invalid/",["ConnectionStrings:Database"]="synthetic-configured",["Work:Enabled"]="true",
                ["ProductionDeletion:Enabled"]="true",["ProductionDeletion:CompletedCommitmentStatement"]="Synthetic explicit copy and archive responsibility.",
                ["Records:Mode"]="Production",["Records:Production:Version"]="synthetic-v1",["Records:Production:ArchiveResponsibility"]="Synthetic original responsibility.",
                ["Records:Production:AbandonedDraftDays"]="1",["Records:Production:ExpiredDays"]="1",["Records:Production:DeclinedDays"]="1",["Records:Production:VoidedDays"]="1",["Records:Production:CompletedDays"]="1"};
            var config=new ConfigurationBuilder().AddInMemoryCollection(data).Build();var email=new EmailOptions{Enabled=true,BaseUrl="https://example.invalid",FromEmail="noreply@example.invalid"};var work=new WorkOptions{Enabled=true,LeaseSeconds=600};
            b.Services.AddSingleton(email);b.Services.AddSingleton(work);b.Services.AddSingleton(new SenderOptions());b.Services.AddSingleton(new QuillSign.Documents.DocumentOptions());b.Services.AddSingleton(new QuillSign.Documents.PreparationOptions());
            b.Services.AddSingleton<IWorkSignals>(signals);b.Services.AddSingleton(new EmailPayloadProtection(keys));b.Services.AddSingleton<IEmailSender>(captured);
            b.Services.AddScoped<RazorEmailViews>();b.Services.AddScoped<VerificationEmailTemplate>();b.Services.AddScoped<EmailOutboxWriter>();b.Services.AddScoped<WorkStore>();b.Services.AddScoped<AuditWriter>(sp=>new(sp.GetRequiredService<QuillSignDbContext>(),clock));
            b.Services.AddScoped<SenderWorkflow>(sp=>new(sp.GetRequiredService<QuillSignDbContext>(),sp.GetRequiredService<SenderOptions>(),new(email,work,config),()=>sp.GetRequiredService<EmailOutboxWriter>(),sp.GetRequiredService<AuditWriter>(),clock,
                lifecycle:config.GetSection("Records").Get<RecordLifecycleOptions>(),electronicRecords:ProductionRetentionAdmissionContractTests.Policies()));
            b.Services.AddScoped<EmailWorkHandler>(sp=>new(sp.GetRequiredService<QuillSignDbContext>(),email,sp.GetRequiredService<EmailPayloadProtection>(),sp.GetRequiredService<VerificationEmailTemplate>(),captured,clock));
            b.Services.AddPlatformPdfSeals(config);b.Services.AddProductionHoldRuntime(config);
            b.Services.AddScoped<IProductionHoldWitnessStore>(_=>witness);b.Services.AddScoped<IProductionHoldObjectSource>(_=>new EmptyObjects());
            b.Services.AddScoped<IProductionDeletionStore>(_=>files);b.Services.AddScoped<IProductionDeletionRecoveryIndex>(_=>index);
            return b.Build();
        }
    }
    private static async Task Who(IServiceScope scope,string expected){
        var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();await db.Database.OpenConnectionAsync();await using var c=db.Database.GetDbConnection().CreateCommand();c.CommandText="SELECT USER_NAME()";Assert.Equal(expected,await c.ExecuteScalarAsync());await db.Database.CloseConnectionAsync();
    }
    private sealed class EmptyObjects:IProductionHoldObjectSource{
        public Task<HoldObjectPage> ListAsync(ProductionHoldObjectScope s,string area,string? c,int max,CancellationToken ct)=>Task.FromResult(new HoldObjectPage([],null));
        public Task<string> HashAsync(ProductionHoldObjectScope s,HoldObjectAddress a,CancellationToken ct)=>throw new InvalidOperationException();
    }
    private sealed class EmptyFiles:IProductionDeletionStore{
        internal int Deletes;
        public async Task<ProductionDeletionPage> ListAsync(ProductionDeletionObjectScope s,string area,string prefix,string? c,int max,CancellationToken ct){await s.DemandAsync(ct);return new([],null);}
        public Task<ProductionDeletionInspection> InspectAsync(ProductionDeletionObjectScope s,ProductionDeletionObject i,CancellationToken ct)=>throw new InvalidOperationException();
        public Task<ProductionDeletionResult> DeleteAsync(ProductionDeletionObjectScope s,ProductionDeletionInspection i,ProductionDeletionPhase p,CancellationToken ct){Deletes++;throw new InvalidOperationException();}
        public Task<ProductionDeletionResult> ReadDeleteOutcomeAsync(ProductionDeletionObjectScope s,ProductionDeletionInspection i,ProductionDeletionPhase p,CancellationToken ct)=>throw new InvalidOperationException();
    }
    private sealed class Index:IProductionDeletionRecoveryIndex{
        public async Task RememberAsync(ProductionDeletionObjectScope s,ProductionDeletionRecoveryHint hint,CancellationToken ct){await s.DemandAsync(ct);}
        public Task<ProductionDeletionRecoveryHint> ReadAsync(Guid r,Guid d,CancellationToken ct)=>throw new InvalidOperationException();
        public Task<ProductionDeletionRecoveryPage> ListAsync(string? c,int max,CancellationToken ct)=>Task.FromResult(new ProductionDeletionRecoveryPage([],null));
    }
}
