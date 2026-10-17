using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Verification;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class VerificationBoundaryTests
{
    private static readonly byte[] Pdf=Encoding.ASCII.GetBytes("%PDF-1.7 SYNTHETIC PRIVATE CONTENT NO AGREEMENT");
    [Fact]
    public async Task GET_and_clean_query_redirect_are_readonly_without_database_or_verifier_resolution()
    {
        await using var h=await Harness.Create();var page=await h.Page();Assert.Contains("processed in memory",page);Assert.Contains("legal validity",page);Assert.Contains("name=\"Upload\"",page);
        Assert.DoesNotContain("SYNTHETIC PRIVATE",page);Assert.Equal(0,h.Calls);
        using var query=await h.Client.GetAsync("/verify?sha256=synthetic");Assert.Equal(HttpStatusCode.Redirect,query.StatusCode);Assert.Equal("/verify",query.Headers.Location!.OriginalString);Assert.Equal(0,h.Calls);
        using var health=await h.Client.GetAsync("/health");Assert.Equal(HttpStatusCode.OK,health.StatusCode);Assert.Equal(0,h.Calls);
    }
    [Fact]
    public async Task Normal_antiforgery_remains_mandatory_and_valid_form_errors_never_echo_filename_content_or_private_exceptions()
    {
        await using var h=await Harness.Create();var page=await h.Page();
        using(var missing=await h.Post(page,Pdf,csrf:false)) {Assert.Equal(HttpStatusCode.BadRequest,missing.StatusCode);Assert.Contains("current form",await missing.Content.ReadAsStringAsync());}
        await using(var other=await Harness.Create()) {var foreign=await other.Page();using var rejected=await h.Post(foreign,Pdf);Assert.Equal(HttpStatusCode.BadRequest,rejected.StatusCode);}
        Assert.Equal(0,h.Calls);
        using var response=await h.Post(page,Pdf,filename:"../../SYNTHETIC_PRIVATE_FILENAME.pdf");Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.Equal(1,h.Calls);
        var body=await response.Content.ReadAsStringAsync();Assert.Contains("No integrity result is confirmed",body);Assert.DoesNotContain("SYNTHETIC_PRIVATE",body);Assert.DoesNotContain("SYNTHETIC PRIVATE CONTENT",body);
        Assert.True(response.Headers.CacheControl!.NoStore);Assert.Equal("no-referrer",Assert.Single(response.Headers.GetValues("Referrer-Policy")));Assert.Equal("nosniff",Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        Assert.DoesNotContain("QuillSign.Sender",string.Join(';',response.Headers.TryGetValues("Set-Cookie",out var cookies) ? cookies : []));
    }
    [Theory]
    [InlineData("extra-file")][InlineData("extra-field")][InlineData("duplicate-token")][InlineData("transfer-encoding")][InlineData("declared-part")][InlineData("query")]
    public async Task Ambiguous_or_unsupported_multipart_requests_never_reach_the_verifier(string kind)
    {
        await using var h=await Harness.Create();var page=await h.Page();using var form=h.Form(page,Pdf);
        if(kind=="extra-file")form.Add(new ByteArrayContent(Pdf),"Upload","second.pdf");
        if(kind=="extra-field")form.Add(new StringContent("synthetic"),"sha256");
        if(kind=="duplicate-token")form.Add(new StringContent(Token(page)),"__RequestVerificationToken");
        if(kind=="transfer-encoding")form.First().Headers.Add("Content-Transfer-Encoding","base64");
        if(kind=="declared-part")form.First().Headers.ContentLength=Pdf.Length+1;
        using var response=await h.Client.PostAsync(kind=="query" ? "/verify?handler=Other" : "/verify",form);
        Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);Assert.Equal(0,h.Calls);Assert.True(response.Headers.CacheControl!.NoStore);
    }
    [Fact]
    public async Task File_and_chunked_total_body_bounds_reject_before_verifier_and_do_not_spill_to_form_buffering()
    {
        await using var h=await Harness.Create(maximum:64);var page=await h.Page();
        using(var file=await h.Post(page,new byte[65]))Assert.Equal(HttpStatusCode.RequestEntityTooLarge,file.StatusCode);
        const string boundary="synthetic-boundary";
        var padding=new string('x',7900);
        var raw=Encoding.UTF8.GetBytes(padding+"\r\n--"+boundary+"\r\nContent-Disposition: form-data; name=\"Upload\"; filename=\"synthetic.pdf\"\r\nX-Padding: "+padding+"\r\n\r\n"+Encoding.ASCII.GetString(Pdf)+
            "\r\n--"+boundary+"\r\nContent-Disposition: form-data; name=\"__RequestVerificationToken\"\r\nX-Padding: "+padding+"\r\n\r\n"+new string('a',2000)+"\r\n--"+boundary+"--\r\n"+padding);
        using var content=new UnknownLengthContent(raw);content.Headers.ContentType=new("multipart/form-data");content.Headers.ContentType.Parameters.Add(new("boundary",boundary));
        using var response=await h.Client.PostAsync("/VERIFY/",content);Assert.Equal(HttpStatusCode.RequestEntityTooLarge,response.StatusCode);Assert.Equal(0,h.Calls);
    }
    [Fact]
    public async Task A_custom_host_without_the_boundary_rejects_before_form_reads_or_verifier_access()
    {
        await using var h=await Harness.Create(boundary:false);var page=await h.Page();using var message=new HttpRequestMessage(HttpMethod.Post,"/verify") {Content=h.Form(page,Pdf)};
        message.Headers.Add("X-Synthetic-Id","missing-boundary");using var response=await h.Client.SendAsync(message);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Equal(0,h.Reads["missing-boundary"].Count);Assert.Equal(0,h.Calls);
    }
    [Fact]
    public async Task Dedicated_rate_limit_rejects_before_body_read_and_does_not_block_metadata_or_health()
    {
        await using var h=await Harness.Create(rate:1);var page=await h.Page();using(var first=await h.Post(page,Pdf))Assert.Equal(HttpStatusCode.ServiceUnavailable,first.StatusCode);
        using var message=new HttpRequestMessage(HttpMethod.Post,"/verify") {Content=h.Form(page,Pdf)};message.Headers.Add("X-Synthetic-Id","rate-rejected");
        using var limited=await h.Client.SendAsync(message);Assert.Equal(HttpStatusCode.TooManyRequests,limited.StatusCode);Assert.Equal(0,h.Reads["rate-rejected"].Count);Assert.Equal(1,h.Calls);
        Assert.Contains("Choose a PDF",await h.Page());using var health=await h.Client.GetAsync("/health");Assert.Equal(HttpStatusCode.OK,health.StatusCode);
    }
    [Fact]
    public async Task Nonqueued_global_concurrency_guard_rejects_before_body_read_and_releases_after_the_first_request()
    {
        await using var h=await Harness.Create();var page=await h.Page();
        using var first=new HttpRequestMessage(HttpMethod.Post,"/verify") {Content=h.Form(page,Pdf)};first.Headers.Add("X-Synthetic-Hold","yes");first.Headers.Add("X-Synthetic-Id","held");
        var running=h.Client.SendAsync(first);await h.Held.Task.WaitAsync(TimeSpan.FromSeconds(5));
        using var second=new HttpRequestMessage(HttpMethod.Post,"/verify") {Content=h.Form(page,Pdf)};second.Headers.Add("X-Synthetic-Id","concurrency-rejected");
        using(var rejected=await h.Client.SendAsync(second)) {Assert.Equal(HttpStatusCode.TooManyRequests,rejected.StatusCode);Assert.Equal(0,h.Reads["concurrency-rejected"].Count);}
        Assert.Equal(0,h.Reads["held"].Count);Assert.Contains("Choose a PDF",await h.Page());
        h.Release.TrySetResult();using(var completed=await running)Assert.Equal(HttpStatusCode.ServiceUnavailable,completed.StatusCode);
        using(var next=await h.Post(page,Pdf))Assert.Equal(HttpStatusCode.ServiceUnavailable,next.StatusCode);Assert.Equal(2,h.Calls);
    }
    private static string Token(string page)=>System.Net.WebUtility.HtmlDecode(Regex.Match(page,"name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
    private sealed class Harness : IAsyncDisposable
    {
        public WebApplication App=null!;public HttpClient Client=null!;public int Calls;
        private readonly Dictionary<string,string> cookies=[];
        public readonly ConcurrentDictionary<string,Counted> Reads=[];
        public readonly TaskCompletionSource Held=new(TaskCreationOptions.RunContinuationsAsynchronously),Release=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public static async Task<Harness> Create(int maximum=65536,int rate=10,bool boundary=true)
        {
            var h=new Harness();var builder=WebApplication.CreateBuilder(new WebApplicationOptions {ApplicationName=typeof(QuillSign.Pages.VerifyModel).Assembly.FullName,EnvironmentName="Development",ContentRootPath=AppContext.BaseDirectory});
            builder.Logging.ClearProviders();builder.WebHost.UseTestServer();builder.Configuration.AddInMemoryCollection(new Dictionary<string,string?> {
                ["ConnectionStrings:Database"]="",["Storage:Provider"]="",["Email:Enabled"]="false",["Work:Enabled"]="false",["PdfVerification:MaximumBytes"]=maximum.ToString(),["PdfVerification:RequestsPerMinute"]=rate.ToString()});
            builder.Services.AddRazorPages();builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();builder.Services.AddQuillSignDatabase(builder.Configuration);
            builder.Services.AddQuillSignEmail(builder.Configuration,builder.Environment);builder.Services.AddQuillSignWork(builder.Configuration,builder.Environment,registerHandlers:false);builder.Services.AddQuillSignSender(builder.Configuration,builder.Environment);
            builder.Services.AddPdfVerificationBrowser(builder.Configuration);builder.Services.AddScoped<Func<UploadedPdfVerification>>(_=>()=> {Interlocked.Increment(ref h.Calls);throw new InvalidOperationException("SYNTHETIC_PRIVATE_EXCEPTION");});
            h.App=builder.Build();h.App.UseRouting();
            h.App.Use(async (http,next)=> {var id=http.Request.Headers["X-Synthetic-Id"].ToString();if(id.Length>0) {var counted=new Counted(http.Request.Body);h.Reads[id]=counted;http.Request.Body=counted;}await next();});
            h.App.UseRateLimiter();h.App.Use(async (http,next)=> {if(http.Request.Headers["X-Synthetic-Hold"]=="yes") {h.Held.TrySetResult();await h.Release.Task;}await next();});
            if(boundary)h.App.UseMiddleware<VerificationUploadBoundary>();h.App.UseAuthentication();h.App.UseAuthorization();h.App.MapRazorPages().RequireRateLimiting(SenderConfiguration.RatePolicy);h.App.MapGet("/health",()=>"ok");
            await h.App.StartAsync();h.Client=h.App.GetTestClient();return h;
        }
        public async Task<string> Page() {using var response=await Client.GetAsync("/verify");Take(response);Assert.Equal(HttpStatusCode.OK,response.StatusCode);Assert.True(response.Headers.CacheControl!.NoStore);return await response.Content.ReadAsStringAsync();}
        public MultipartFormDataContent Form(string page,byte[] bytes,bool csrf=true,string filename="synthetic.pdf") {var form=new MultipartFormDataContent();form.Add(new ByteArrayContent(bytes),"Upload",filename);if(csrf)form.Add(new StringContent(Token(page)),"__RequestVerificationToken");return form;}
        public async Task<HttpResponseMessage> Post(string page,byte[] bytes,bool csrf=true,string filename="synthetic.pdf") {using var form=Form(page,bytes,csrf,filename);var response=await Client.PostAsync("/verify",form);Take(response);return response;}
        private void Take(HttpResponseMessage response) {if(response.Headers.TryGetValues("Set-Cookie",out var values))foreach(var value in values) {var pair=value.Split(';')[0].Split('=',2);cookies[pair[0]]=pair[1];}Client.DefaultRequestHeaders.Remove("Cookie");if(cookies.Count>0)Client.DefaultRequestHeaders.Add("Cookie",string.Join("; ",cookies.Select(x=>x.Key+"="+x.Value)));}
        public async ValueTask DisposeAsync() {Release.TrySetResult();Client.Dispose();await App.DisposeAsync();}
    }
    private sealed class UnknownLengthContent(byte[] bytes) : HttpContent
    {
        protected override bool TryComputeLength(out long length) {length=0;return false;}
        protected override Task SerializeToStreamAsync(Stream stream,TransportContext? context)=>stream.WriteAsync(bytes).AsTask();
    }
    private sealed class Counted(Stream inner) : Stream
    {
        public int Count;public override bool CanRead=>true;public override bool CanSeek=>false;public override bool CanWrite=>false;
        public override long Length=>throw new NotSupportedException();public override long Position {get=>throw new NotSupportedException();set=>throw new NotSupportedException();}
        public override int Read(byte[] buffer,int offset,int count) {var read=inner.Read(buffer,offset,count);Count+=read;return read;}
        public override Task<int> ReadAsync(byte[] buffer,int offset,int count,CancellationToken ct)=>ReadAsync(buffer.AsMemory(offset,count),ct).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default) {var read=await inner.ReadAsync(buffer,ct);Count+=read;return read;}
        public override void Flush()=>throw new NotSupportedException();public override long Seek(long offset,SeekOrigin origin)=>throw new NotSupportedException();public override void SetLength(long value)=>throw new NotSupportedException();public override void Write(byte[] buffer,int offset,int count)=>throw new NotSupportedException();
    }
}
