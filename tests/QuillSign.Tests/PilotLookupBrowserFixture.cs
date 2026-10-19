using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

internal sealed class PilotLookupBrowserFixture:IAsyncDisposable
{
    internal WebApplication App=null!;private EmailPilotLookupTests.Harness h=null!;
    internal static async Task<PilotLookupBrowserFixture> Create(EmailPilotLookupTests.Harness h)
    {
        var f=new PilotLookupBrowserFixture{h=h};var port=int.TryParse(Environment.GetEnvironmentVariable("QUILLSIGN_PILOT_LOOKUP_BROWSER_PORT"),out var p)?p:(int?)null;
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(DocumentLookup).Assembly.FullName,EnvironmentName="Development",ContentRootPath=AppContext.BaseDirectory,
            WebRootPath=port is null?null:Path.Combine(Repository(),"src/QuillSign/wwwroot")});
        builder.Logging.ClearProviders();if(port is null)builder.WebHost.UseTestServer();else builder.WebHost.UseUrls("http://127.0.0.1:"+port);
        builder.Configuration["Demo:PurgeAfterDays"]="7";builder.Services.AddRazorPages();
        builder.Services.AddDbContext<QuillSignDbContext>(o=>o.UseSqlServer(h.Db.Database.GetConnectionString()));
        builder.Services.AddQuillSignEmail(builder.Configuration,builder.Environment);builder.Services.AddQuillSignWork(builder.Configuration,builder.Environment);
        builder.Services.AddSingleton(h.T.Email);builder.Services.AddSingleton(h.T.Work);builder.Services.AddSingleton<TimeProvider>(h.Time);builder.Services.AddSingleton(h.T.Keys);
        builder.Services.AddSingleton<IBlobStore>(h.T.Run.Storage);builder.Services.AddSingleton(new DocumentOptions());
        builder.Services.AddQuillSignSender(builder.Configuration,builder.Environment);builder.Services.AddQuillSignSignerAccess(builder.Configuration,builder.Environment);
        builder.Services.AddScoped<SignerCheckpointReads>();builder.Services.AddScoped<SignerReviewProtection>();builder.Services.AddSignerReviewBrowser();builder.Services.AddScoped<SenderSentStatus>();
        builder.Services.AddCompletionDownloads();builder.Services.AddCompletionAccess(builder.Configuration);builder.Services.AddCompletionReaderBrowser(builder.Environment);
        builder.Services.AddDocumentLookup(builder.Configuration);builder.Services.AddDocumentLookupBrowser(builder.Environment);
        builder.Services.AddScoped<CompletionEvidenceCollector>(sp=>h.T.Run.Collector(sp.GetRequiredService<QuillSignDbContext>()));
        builder.Services.AddScoped<CompletionPublication>(sp=>h.For(sp.GetRequiredService<QuillSignDbContext>()).Publication);
        builder.Services.AddScoped<EmailPilotLookupAccess>(sp=>h.For(sp.GetRequiredService<QuillSignDbContext>()).Access);
        f.App=builder.Build();f.App.UseStaticFiles();f.App.UseRouting();f.App.UseDocumentLookupBrowser();f.App.UseRateLimiter();f.App.UseAuthentication();f.App.UseAuthorization();f.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);
        await f.App.StartAsync();return f;
    }
    internal async Task PauseForBrowser()
    {
        var folder=Path.Combine(Repository(),"artifacts");Directory.CreateDirectory(folder);
        var path=Path.Combine(folder,"QUILS-135-browser.private.json");var done=Path.Combine(folder,"QUILS-135-browser.done");if(File.Exists(done))File.Delete(done);
        await File.WriteAllTextAsync(path,JsonSerializer.Serialize(new{url=App.Urls.Single()+"/find/access#token="+h.Transport.Code,publicId=h.PublicId,stopFile=done}));
        using var timeout=new CancellationTokenSource(TimeSpan.FromMinutes(30));
        while(!File.Exists(done))await Task.Delay(TimeSpan.FromSeconds(1),timeout.Token);
        Assert.True(await h.Db.AuthTokens.AnyAsync(x=>x.EmailPilotLookupRequestId!=null && x.UsedAt!=null));Assert.Equal(1,h.Transport.Calls);Assert.False(h.T.Email.Enabled);
    }
    private static string Repository()
    {
        for(var folder=new DirectoryInfo(AppContext.BaseDirectory);folder is not null;folder=folder.Parent)
            if(File.Exists(Path.Combine(folder.FullName,"src/QuillSign/QuillSign.csproj")))return folder.FullName;
        throw new InvalidOperationException("Local source checkout is required for interactive browser validation.");
    }
    public async ValueTask DisposeAsync()=>await App.DisposeAsync();
}
