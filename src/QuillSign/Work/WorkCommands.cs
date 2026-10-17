using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Storage;
using QuillSign.Signing;

namespace QuillSign.Work;

public static class WorkCommands
{
    public static async Task<int> RunAsync(string[] args)
    {
        var republish = args.Length == 2 && args[0] == "publish-notification" && Guid.TryParseExact(args[1],"N",out _);
        var completion=args.Length==2 && args[0]=="resume-completion-notifications" && Guid.TryParseExact(args[1],"N",out _);
        var voids=args.Length==2 && args[0]=="resume-void-notifications" && Guid.TryParseExact(args[1],"N",out _);
        var expiry=args.Length is >=1 and <=3 && args[0]=="expire";
        var batch=32;
        if(expiry && args.Length>=2 && (!int.TryParse(args[1],System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out batch) || batch is <1 or >64))expiry=false;
        if (!republish && !completion && !voids && !expiry && (args.Length != 1 || args[0] is not ("once" or "recover" or "listen" or "verify")))
        { Console.Error.WriteLine("Usage: work once|recover|listen|verify OR work expire [1-64] [continuation] OR work publish-notification <32-character-item-id> OR work resume-completion-notifications|resume-void-notifications <32-character-envelope-id>"); return 2; }
        try
        {
            var builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders(); // CLI failures must not expose private payloads/endpoints.
            builder.Services.AddQuillSignWork(builder.Configuration, builder.Environment, registerHandlers: args[0] != "recover");
            if (args[0] != "recover")
            {
                builder.Services.AddRazorPages();
                builder.Services.AddQuillSignDatabase(builder.Configuration);
                builder.Services.AddQuillSignStorage(builder.Configuration, builder.Environment);
                builder.Services.AddQuillSignEmail(builder.Configuration, builder.Environment);
            }
            if (args[0] == "listen" && !builder.Environment.IsDevelopment()) throw new InvalidOperationException("Listen is Development-only.");
            using var app = builder.Build();
            if (!expiry && !app.Services.GetRequiredService<WorkOptions>().Enabled) throw new InvalidOperationException("Durable work is disabled.");
            using var timeout = new CancellationTokenSource(args[0] == "recover" ? TimeSpan.FromSeconds(50) : TimeSpan.FromSeconds(240));
            if (args[0] == "listen") timeout.CancelAfter(Timeout.InfiniteTimeSpan);
            Console.CancelKeyPress += (_, eventArgs) => { eventArgs.Cancel = true; timeout.Cancel(); };
            if(expiry) {
                await using var scope=app.Services.CreateAsyncScope();
                var result=await scope.ServiceProvider.GetRequiredService<SigningExpiry>().RunBatchAsync(batch,args.Length==3 ? args[2] : null,timeout.Token);
                Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new {operation="work-expire",status=result.Failed==0 ? "ok" : "partial",result.Examined,result.Expired,result.AlreadyExpired,result.Skipped,result.Failed,result.NextCursor}));
                return result.Failed==0 ? 0 : 1;
            }
            var signals = app.Services.GetRequiredService<IWorkSignals>();
            var count = 0;
            if(voids) {
                await using var scope=app.Services.CreateAsyncScope();
                count=await scope.ServiceProvider.GetRequiredService<VoidNotificationJobs>().ResumeAsync(Guid.ParseExact(args[1],"N"),timeout.Token);
            }
            else if(completion) {
                await using var scope=app.Services.CreateAsyncScope();
                count=await scope.ServiceProvider.GetRequiredService<CompletionNotificationJobs>().ResumeAsync(Guid.ParseExact(args[1],"N"),timeout.Token);
            }
            else if (republish)
            {
                await using var scope = app.Services.CreateAsyncScope();
                var writer = scope.ServiceProvider.GetRequiredService<DeclineNotificationWriter>();
                count = await writer.RepublishAsync(Guid.ParseExact(args[1],"N"),timeout.Token) ? 1 : 0;
            }
            else if (args[0] == "recover") count = await signals.RecoverAsync(DateTimeOffset.UtcNow, timeout.Token);
            else if (args[0] == "verify")
            {
                await using var scope = app.Services.CreateAsyncScope();
                var db = scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
                if ((await db.Database.GetPendingMigrationsAsync(timeout.Token)).Any()) throw new InvalidOperationException("Apply migrations before verifying work.");
                await using (var transaction = await db.Database.BeginTransactionAsync(timeout.Token))
                {
                    var item = new WorkItem { Kind = WorkKind.Purge };
                    db.WorkItems.Add(item);
                    await db.SaveChangesAsync(timeout.Token);
                    if (!await db.WorkItems.AnyAsync(x => x.Id == item.Id, timeout.Token)) throw new InvalidOperationException("Work storage verification failed.");
                    await db.WorkItems.Where(x => x.Id == item.Id).ExecuteUpdateAsync(set => set.SetProperty(x => x.LastError, "synthetic-probe"), timeout.Token);
                    await db.WorkItems.Where(x => x.Id == item.Id).ExecuteDeleteAsync(timeout.Token);
                    await transaction.RollbackAsync(timeout.Token);
                }
                var protection = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector("QuillSign.Work.RuntimeProbe");
                if (protection.Unprotect(protection.Protect("synthetic-probe")) != "synthetic-probe") throw new InvalidOperationException("Key-ring verification failed.");
                await signals.VerifyAsync(timeout.Token);
            }
            else
            {
                var nextRecovery = DateTimeOffset.MinValue;
                do
                {
                    await using var scope = app.Services.CreateAsyncScope();
                    if (await scope.ServiceProvider.GetRequiredService<WorkProcessor>().RunOnceAsync(timeout.Token)) count++;
                    if (args[0] == "once") break;
                    if (DateTimeOffset.UtcNow >= nextRecovery)
                    {
                        await signals.RecoverAsync(DateTimeOffset.UtcNow, timeout.Token);
                        nextRecovery = DateTimeOffset.UtcNow.AddMinutes(1);
                    }
                    await Task.Delay(TimeSpan.FromSeconds(1), timeout.Token);
                } while (!timeout.IsCancellationRequested);
            }
            Console.WriteLine($"{{\"operation\":\"work-{args[0]}\",\"status\":\"ok\",\"count\":{count}}}");
            return 0;
        }
        catch (Exception e)
        {
            var details = new List<string>();
            for (Exception? detail = e; detail is not null; detail = detail.InnerException)
                details.Add(detail is Azure.RequestFailedException request ? $"{detail.GetType().Name}:{request.Status}:{request.ErrorCode}" :
                    detail is Microsoft.Data.SqlClient.SqlException sql ? $"SqlException:{sql.Number}" : detail.GetType().Name);
            Console.Error.WriteLine($"Work command failed ({string.Join(" -> ", details)}).");
            return 1;
        }
    }
}
