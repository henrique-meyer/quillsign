using System.Data.Common;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Sender;
using Flow=QuillSign.Tests.CompletionDownloadTests.Flow;
using Reader=QuillSign.Tests.CompletionReaderPageTests;

namespace QuillSign.Tests;

public sealed class CompletedRecordRetentionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Genuine_completed_parties_get_bounded_exact_files_then_no_private_metadata_or_bytes_at_the_deadline()
    {
        await using var f=await Create();var cutoff=await Cutoff(f);Advance(f,cutoff.AddSeconds(-1));var samples=new List<Sample>();
        foreach(var role in new[]{"sender","signer","reader"}) {
            var sample=await Capture(f,role);f.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
            using(var prepared=await Prepare(f,sample)) {
                Assert.Equal(HttpStatusCode.OK,prepared.StatusCode);
                var grant=JsonSerializer.Deserialize<PreparedFinalDownload>(await prepared.Content.ReadAsStringAsync(),new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
                Assert.Equal(cutoff,grant.ExpiresAt);Assert.Equal(sample.File,grant.Url);
            }
            f.Client.DefaultRequestHeaders.Accept.Clear();sample=sample with{Cookies=f.Cookies.ToDictionary()};
            using(var pdf=await f.Client.GetAsync(sample.File)) {f.Take(pdf);Assert.Equal(HttpStatusCode.OK,pdf.StatusCode);Assert.Equal(f.Published.ExecutedBytes,await pdf.Content.ReadAsByteArrayAsync());}
            samples.Add(sample);
        }
        var state=await State(f);var reads=f.Store.Reads;Advance(f,cutoff);
        foreach(var sample in samples) {
            f.Restore(sample.Cookies);
            using(var page=await f.Client.GetAsync(sample.Page))await Denied(f,page);
            using(var file=await f.Client.GetAsync(sample.File))await Denied(f,file);
        }
        Assert.Equal(reads,f.Store.Reads);Assert.Equal(state,await State(f));Assert.Equal(3,await f.Count());
        // Trusted retained-file verification is separate from expired public sessions.
        await using var db=fixture.Open();var historical=await f.Publication(db).ReadAsync(f.Id);
        Assert.NotNull(historical);Assert.Equal(f.Published.ExecutedBytes,historical.ExecutedBytes);
    }

    [Theory]
    [InlineData("missing")][InlineData("changed")]
    public async Task Unverifiable_enrollment_hides_metadata_and_prevents_download_preparation_only_after_party_authorization(string fault)
    {
        await using var f=await Create();var samples=new List<Sample>();
        foreach(var role in new[]{"sender","signer","reader"})samples.Add(await Capture(f,role));
        await using(var db=fixture.Open()) {
            if(fault=="missing")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.Id).ExecuteDeleteAsync();
            else await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.OriginalSha256,new byte[32]));
        }
        var state=await State(f);var reads=f.Store.Reads;
        f.Restore([]);foreach(var sample in samples)using(var unknown=await f.Client.GetAsync(sample.Page)) {
            Assert.Contains(unknown.StatusCode,new[]{HttpStatusCode.Unauthorized,HttpStatusCode.NotFound,HttpStatusCode.Found});await Denied(f,unknown);
        }
        foreach(var sample in samples) {
            f.Restore(sample.Cookies);
            using(var page=await f.Client.GetAsync(sample.Page)){Assert.Equal(HttpStatusCode.ServiceUnavailable,page.StatusCode);await Denied(f,page);}
            using(var preparation=await Prepare(f,sample)){Assert.Equal(HttpStatusCode.ServiceUnavailable,preparation.StatusCode);await Denied(f,preparation);AssertNoGrant(preparation);}
        }
        Assert.Equal(reads,f.Store.Reads);Assert.Equal(state,await State(f));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Slow_final_storage_crossing_cannot_issue_a_grant_or_return_bytes(bool reading)
    {
        await using var f=await Create();var cutoff=await Cutoff(f);Advance(f,cutoff.AddSeconds(-1));var sample=await Capture(f,"sender");
        if(reading)using(var ready=await Prepare(f,sample))Assert.Equal(HttpStatusCode.Redirect,ready.StatusCode);
        var state=await State(f);var calls=0;f.Store.AfterRead=()=>{calls++;Advance(f,cutoff);return Task.CompletedTask;};
        using(var result=reading ? await f.Client.GetAsync(sample.File) : await Prepare(f,sample)){await Denied(f,result);AssertNoGrant(result);}
        Assert.True(calls>0);Assert.Equal(state,await State(f));
    }

    [Fact]
    public async Task Download_audit_crossing_the_cutoff_rolls_back_without_grant_or_private_response()
    {
        await using var f=await Create();var cutoff=await Cutoff(f);Advance(f,cutoff.AddSeconds(-1));var sample=await Capture(f,"sender");var state=await State(f);var calls=0;
        f.Faults.Event="final_download_prepared";f.Faults.BeforeAudit=()=>{calls++;Advance(f,cutoff);};
        using(var result=await Prepare(f,sample)){Assert.Equal(HttpStatusCode.Gone,result.StatusCode);await Denied(f,result);AssertNoGrant(result);}
        Assert.Equal(1,calls);Assert.Equal(state,await State(f));Assert.Equal(0,await f.Count());
    }

    [Theory]
    [InlineData("sender")][InlineData("signer")]
    public async Task Final_page_composition_cannot_render_metadata_loaded_before_a_later_availability_read_crosses(string role)
    {
        Flow? active=null;DateTimeOffset? deadline=null;var cross=new CrossRead(()=>Advance(active!,deadline!.Value));
        await using var f=await Create(cross);active=f;var sample=await Capture(f,role);var cutoff=await Cutoff(f);deadline=cutoff;Advance(f,cutoff.AddSeconds(-1));var state=await State(f);
        cross.Armed=true;
        using(var response=await f.Client.GetAsync(sample.Page))await Denied(f,response);
        Assert.Equal(1,cross.Calls);Assert.Equal(state,await State(f));
    }

    private async Task<Flow> Create(DbCommandInterceptor? readFault=null) {
        var f=await Flow.Create(fixture,completionReaders:true,uploadRetentionDays:1,afterUploadDelay:TimeSpan.FromHours(23.5),readFault:readFault);
        // This fixture exercises many party/negative flows; separate production-limit tests remain unchanged.
        f.App.Services.GetRequiredService<SenderOptions>().RequestsPerWindow=1000;return f;
    }
    private sealed record Sample(string Role,string Page,string File,string Html,Dictionary<string,string> Cookies);
    private async Task<Sample> Capture(Flow f,string role) {
        f.Restore([]);string page;
        if(role=="reader") {
            await using var db=fixture.Open();var recipient=await db.Recipients.Where(x=>x.EnvelopeId==f.Id).Select(x=>x.Id).SingleAsync();
            await Reader.Open(f,await Reader.Issue(f,PartyType.Recipient,recipient));page="/complete/"+f.PublicId;
        }else{await f.Session(role);page=f.PagePath;}
        using var response=await f.Client.GetAsync(page);f.Take(response);var html=await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode==HttpStatusCode.OK,$"{role}: {response.StatusCode}: {html[..Math.Min(html.Length,1600)]}");
        var file=role=="reader" ? Reader.Resource(f,"executed") : f.Resource("executed");
        return new(role,page,file,html,f.Cookies.ToDictionary());
    }
    private static Task<HttpResponseMessage> Prepare(Flow f,Sample sample)=>
        Reader.Post(f,sample.Page+"?handler=Download",sample.Html,new(){{"kind","executed"}});
    private async Task<DateTimeOffset> Cutoff(Flow f) {await using var db=fixture.Open();return await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==f.Id).Select(x=>x.DeleteAfter).SingleAsync();}
    private static void Advance(Flow f,DateTimeOffset until) {
        var delta=until-f.Clock.GetUtcNow();Assert.True(delta>=TimeSpan.Zero);f.Clock.Advance(delta);f.Run.Seal.Time.Advance(delta);
    }
    private static void AssertNoGrant(HttpResponseMessage response)=>Assert.False(response.Headers.TryGetValues("Set-Cookie",out var values) && values.Any(x=>x.StartsWith("QuillSign.Final.",StringComparison.Ordinal)));
    private static async Task Denied(Flow f,HttpResponseMessage response) {
        Assert.Contains(response.StatusCode,new[]{HttpStatusCode.Gone,HttpStatusCode.NotFound,HttpStatusCode.Unauthorized,HttpStatusCode.ServiceUnavailable,HttpStatusCode.Found});
        var body=await response.Content.ReadAsStringAsync();Assert.DoesNotContain("%PDF",body);Assert.DoesNotContain(f.Run.Signing.Envelope.Title!,body);Assert.DoesNotContain(f.Run.Signing.Envelope.SenderEmail,body);
        if(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Found) {
            Assert.True(string.IsNullOrWhiteSpace(body));
            if(response.StatusCode==HttpStatusCode.Found) {Assert.NotNull(response.Headers.Location);Assert.DoesNotContain("token=",response.Headers.Location.OriginalString,StringComparison.OrdinalIgnoreCase);Assert.DoesNotContain("receipt",response.Headers.Location.OriginalString,StringComparison.OrdinalIgnoreCase);}
        }
        else{Assert.True(response.Headers.CacheControl?.NoStore is true);Assert.Contains("no-referrer",response.Headers.GetValues("Referrer-Policy"));}
    }
    private async Task<string> State(Flow f) {
        await using var db=fixture.Open();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==f.Id);
        return JsonSerializer.Serialize(new{e.RowVersion,e.Status,e.PurgeAfter,Audit=await db.AuditEvents.CountAsync(x=>x.EnvelopeId==f.Id),
            Jobs=await db.WorkItems.CountAsync(x=>x.EnvelopeId==f.Id),Mail=await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==f.Id)});
    }
    private sealed class CrossRead(Action cross):DbCommandInterceptor {
        public bool Armed;public int Calls;
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command,CommandExecutedEventData data,DbDataReader result,CancellationToken ct=default) {
            if(Armed && command.CommandText.Contains("FROM [CompletionPublicationResults]",StringComparison.Ordinal)){Armed=false;Calls++;cross();}return ValueTask.FromResult(result);
        }
    }

    // Test-only actual loopback host, with synthetic documents and local captured services.
    public sealed class BrowserSession:IAsyncDisposable
    {
        private readonly Flow flow;
        private BrowserSession(Flow flow)=>this.flow=flow;
        public string PublicId=>flow.PublicId;
        public string ExecutedSha256=>Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(flow.Published.ExecutedBytes));
        public DateTimeOffset Deadline=>flow.Run.Signing.Envelope.PurgeAfter??throw new InvalidOperationException("No verified synthetic retention deadline.");
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port) {
            var flow=await Flow.Create(fixture,completionReaders:true,uploadRetentionDays:1,afterUploadDelay:TimeSpan.FromHours(23.5),browserPort:port);
            await flow.Run.Signing.Refresh();return new(flow);
        }
        public async Task<string> ReaderLink() {
            using var scope=flow.App.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
            var recipient=await db.Recipients.Where(x=>x.EnvelopeId==flow.Id).Select(x=>x.Id).SingleAsync();
            var link=await scope.ServiceProvider.GetRequiredService<CompletionAccess>().IssueAsync(flow.Id,PartyType.Recipient,recipient);
            return "/complete/access#token="+(link??throw new InvalidOperationException("No synthetic reader link.")).RawToken;
        }
        public void Expire()=>Advance(flow,Deadline);
        public ValueTask DisposeAsync()=>flow.DisposeAsync();
    }
}
