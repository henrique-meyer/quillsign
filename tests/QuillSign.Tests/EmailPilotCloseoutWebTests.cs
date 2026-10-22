using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Email.Pilot;

namespace QuillSign.Tests;

public sealed class EmailPilotCloseoutWebTests
{
    private const string Id="11111111111111111111111111111111";
    private static DefaultHttpContext Request(string path,string method="GET",string query="")
    {
        var c=new DefaultHttpContext();c.Request.Path=path;c.Request.Method=method;c.Request.QueryString=new(query);
        c.Features.Get<IHttpRequestFeature>()!.RawTarget=path+query;return c;
    }
    [Theory]
    [InlineData("/","GET","")]
    [InlineData("/draft/new","POST","")]
    [InlineData("/sender/verify","HEAD","?token=a")]
    [InlineData("/sign/invitation","HEAD","")]
    [InlineData("/sign/11111111111111111111111111111111/finish","POST","")]
    [InlineData("/draft/11111111111111111111111111111111/details","POST","?handler=SaveDetails")]
    [InlineData("/draft/11111111111111111111111111111111/fields","GET","")]
    [InlineData("/api/envelopes/11111111111111111111111111111111/fields","PATCH","")]
    [InlineData("/operator/pilot","GET","")]
    [InlineData("/operator/pilot-closeout","POST","?handler=Start&handler=Lookup")]
    [InlineData("/operator/pilot-closeout","POST","?Handler=Start")]
    [InlineData("/operator/pilot-closeout","GET","?handler=Start")]
    [InlineData("/find/documents","POST","?handler=Next")]
    [InlineData("/find/access/Next","POST","")]
    [InlineData("/find/access/Redeem","POST","?handler=Redeem")]
    [InlineData("/find/documents/Open","POST","?handler=First")]
    [InlineData("/find/access/begin","POST","")]
    [InlineData("/find/access/Begin","GET","")]
    [InlineData("/complete/access","POST","")]
    [InlineData("/draft/11111111111111111111111111111111/final/executed","GET","")]
    public void Unlisted_method_path_or_ambiguous_handler_has_no_route(string path,string method,string query)
        =>Assert.Null(EmailPilotCloseoutWeb.Route(Request(path,method,query).Request));
    [Theory]
    [InlineData("/operator/pilot-closeout","POST","?handler=Receipt",CloseoutWebArea.Operator)]
    [InlineData("/sender/verify","GET","?token=a",CloseoutWebArea.Verify)]
    [InlineData("/draft/11111111111111111111111111111111","POST","?handler=Upload",CloseoutWebArea.Draft)]
    [InlineData("/draft/11111111111111111111111111111111/signers","POST","?handler=Save",CloseoutWebArea.Signers)]
    [InlineData("/draft/11111111111111111111111111111111/review","POST","?handler=Send",CloseoutWebArea.Review)]
    [InlineData("/sign/11111111111111111111111111111111","GET","?handler=Pdf&download=true",CloseoutWebArea.Sign)]
    [InlineData("/sign/11111111111111111111111111111111","POST","?handler=Decline",CloseoutWebArea.Sign)]
    [InlineData("/sign/11111111111111111111111111111111/decline","POST","",CloseoutWebArea.Decline)]
    [InlineData("/find/access","POST","?handler=Begin",CloseoutWebArea.LookupEntry)]
    [InlineData("/find/documents","POST","?handler=Open",CloseoutWebArea.LookupList)]
    [InlineData("/complete/11111111111111111111111111111111/final/certificate","GET","",CloseoutWebArea.Final)]
    [InlineData("/health","GET","",CloseoutWebArea.Static)]
    public void Only_closed_syntactic_routes_reach_readonly_authentication(string path,string method,string query,object area)
        =>Assert.Equal((CloseoutWebArea)area,Assert.IsType<CloseoutWebRoute>(EmailPilotCloseoutWeb.Route(Request(path,method,query).Request)).Area);
    [Theory]
    [InlineData("/draft%2f11111111111111111111111111111111")]
    [InlineData("/draft//11111111111111111111111111111111")]
    [InlineData("/draft/11111111111111111111111111111111/")]
    [InlineData("/DRAFT/11111111111111111111111111111111")]
    public void Noncanonical_paths_are_not_normalized_into_permission(string path)=>Assert.Null(EmailPilotCloseoutWeb.Route(Request(path).Request));
    [Fact]
    public void Encoded_raw_target_and_pathbase_refuse_even_when_decoded_path_is_allowed()
    {
        var c=Request("/sender/verify");c.Features.Get<IHttpRequestFeature>()!.RawTarget="/sender/%76erify";Assert.Null(EmailPilotCloseoutWeb.Route(c.Request));
        c=Request("/health");c.Request.PathBase="/prefix";Assert.Null(EmailPilotCloseoutWeb.Route(c.Request));
    }
    [Fact]
    public void Body_cannot_override_route_handler_or_add_parties_or_fields()
    {
        var route=new CloseoutWebRoute(CloseoutWebArea.Signers,"Save",Id);
        var form=new FormCollection(new Dictionary<string,StringValues>{{"Version","AAAAAAAAAAA="},{"Input.FullName","Synthetic first"},{"Input.Email","first@example.invalid"},{"Input.Role",""}});
        Assert.True(EmailPilotCloseoutWeb.FormShape(route,form));form=new(new Dictionary<string,StringValues>{{"handler","Remove"}});
        Assert.False(EmailPilotCloseoutWeb.FormShape(route,form));form=new(new Dictionary<string,StringValues>{{"Input.Email",new[]{"first@example.invalid","second@example.invalid"}}});
        Assert.False(EmailPilotCloseoutWeb.FormShape(route,form));
    }
    [Fact]
    public async Task Input_hash_length_filename_and_stream_are_all_required_before_upload()
    {
        var bytes=Enumerable.Range(0,32).Select(x=>(byte)x).ToArray();
        var expected=new EmailPilotCloseoutWebInput(Convert.ToHexStringLower(SHA256.HashData(bytes)),bytes.Length,"synthetic.pdf");
        IFormFile File(string name,byte[] content)=>new FormFile(new MemoryStream(content),0,content.Length,"Upload",name);
        Assert.True(await EmailPilotCloseoutWeb.InputAsync(File("synthetic.pdf",bytes),expected,default));
        Assert.False(await EmailPilotCloseoutWeb.InputAsync(File("other.pdf",bytes),expected,default));
        Assert.False(await EmailPilotCloseoutWeb.InputAsync(File("synthetic.pdf",bytes[..^1]),expected,default));
        var changed=bytes.ToArray();changed[0]^=1;Assert.False(await EmailPilotCloseoutWeb.InputAsync(File("synthetic.pdf",changed),expected,default));
    }
    [Fact]
    public void Empty_fields_and_single_selected_signer_are_the_only_preparation_shape()
    {
        var input=new EmailPilotCloseoutWebInput(new string('a',64),32,"synthetic.pdf");
        var e=new Envelope{IsDemo=true};var s=new Signer{FullName="Synthetic first",Email="first@example.invalid",Order=1};
        Assert.True(EmailPilotCloseoutWebAccess.Preparation(e,[],false,false,s.Email,input));
        Assert.True(EmailPilotCloseoutWebAccess.Preparation(e,[s],false,false,s.Email,input));
        Assert.False(EmailPilotCloseoutWebAccess.Preparation(e,[s],true,false,s.Email,input));
        Assert.False(EmailPilotCloseoutWebAccess.Preparation(e,[s],false,true,s.Email,input));
        Assert.False(EmailPilotCloseoutWebAccess.Preparation(e,[s,s],false,false,s.Email,input));
        s.Role="Other";Assert.False(EmailPilotCloseoutWebAccess.Preparation(e,[s],false,false,s.Email,input));s.Role=null;
        e.Message="new message";Assert.False(EmailPilotCloseoutWebAccess.Preparation(e,[s],false,false,s.Email,input));
    }
    [Fact]
    public void Existing_renderer_accepts_zero_fields_without_signing_or_timestamp_services()
    {
        var bytes=File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory,"Fixtures","synthetic-conversion.pdf"));
        using var source=new MemoryStream(bytes);using var normalized=new MemoryStream();
        var pages=new PdfValidation(new()).Rewrite(source,normalized);var pdf=normalized.ToArray();
        var rendered=new SenderPdfRenderer(1024*1024,20,100).Render(pdf,SHA256.HashData(pdf),pages,[]);
        Assert.Equal(SHA256.HashData(pdf),rendered.SourceSha256);Assert.Equal(SHA256.HashData(rendered.Bytes),rendered.Sha256);
        Assert.NotEmpty(rendered.Bytes);
        var envelope=new Envelope{PublicId=Id,IsDemo=true,Title="synthetic.pdf",PdfBlob=Guid.NewGuid().ToString("N"),PdfSha256=SHA256.HashData(pdf),
            PreviewConfirmedAt=DateTimeOffset.UtcNow,PageCount=pages.Count,PageSizesJson=JsonSerializer.Serialize(pages),RowVersion=new byte[8]};
        var review=DraftReview.CheckPreparation(envelope,[new QuillSign.Signing.SignerListItem(Guid.NewGuid(),1,"Synthetic first","first@example.invalid",null)],[],[]);
        Assert.True(review.ChecksPassed);Assert.Single(review.Warnings);Assert.Empty(review.Fields);
    }
    [Fact]
    public void Standard_effective_configuration_and_explicit_entry_must_agree_even_when_OFF()
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();h.Options.HostRole=EmailPilotCloseoutHostRole.Web;
        h.Options.PrivateConfigurationSet="private";h.Options.WebInput=new(){Sha256=new string('a',64),Bytes=32,Filename="synthetic.pdf"};
        h.Email.Enabled=true;h.Email.Ses.ConfigurationSet="normal";
        IConfiguration Config()=>new ConfigurationBuilder().AddJsonStream(new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(new{EmailPilot=new{Enabled=false,Closeout=h.Options},Email=h.Email,Work=h.Work}))).Build();
        Assert.True(EmailPilotCloseoutWebStartup.PrivateEntry(["closeout-web"]));Assert.Throws<InvalidOperationException>(()=>EmailPilotCloseoutWebStartup.PrivateEntry(["closeout-web","work"]));
        EmailPilotCloseoutWebStartup.Demand(Config(),true);
        h.Options.Enabled=false;EmailPilotCloseoutWebStartup.Demand(Config(),true);
        Assert.Throws<InvalidOperationException>(()=>EmailPilotCloseoutWebStartup.Demand(Config(),false));
        h.Options.HostRole=EmailPilotCloseoutHostRole.Handoff;Assert.Throws<InvalidOperationException>(()=>EmailPilotCloseoutWebStartup.Demand(Config(),true));
    }
    [Fact]
    public void Retained_input_changes_shared_purpose_for_every_role_but_legacy_bytes_stay_unchanged()
    {
        var h=new EmailPilotCloseoutBrowserTests.Harness();var legacy=JsonSerializer.Serialize(h.Options.Capture());Assert.DoesNotContain("WebInput",legacy);
        h.Options.HostRole=EmailPilotCloseoutHostRole.Web;h.Options.PrivateConfigurationSet="private";h.Options.WebInput=new(){Sha256=new string('a',64),Bytes=32,Filename="synthetic.pdf"};
        var web=JsonSerializer.Serialize(h.Options.Capture());h.Options.HostRole=EmailPilotCloseoutHostRole.Pass;Assert.Equal(web,JsonSerializer.Serialize(h.Options.Capture()));
        h.Options.HostRole=EmailPilotCloseoutHostRole.Handoff;h.Options.Enabled=false;Assert.Equal(web,JsonSerializer.Serialize(h.Options.CaptureReceiptConfiguration()));
        h.Options.WebInput.Sha256=new string('b',64);Assert.NotEqual(web,JsonSerializer.Serialize(h.Options.CaptureReceiptConfiguration()));
    }
    [Fact]
    public async Task Coarse_denial_runs_before_any_dependency_page_or_body_effect()
    {
        var reached=0;
        var builder=WebApplication.CreateBuilder();builder.WebHost.UseTestServer();
        await using var app=builder.Build();
        app.Use((c,next)=>{c.Features.Get<IHttpRequestFeature>()!.RawTarget=c.Request.Path+c.Request.QueryString;return next();});
        app.UseCloseoutWebRoutes();app.UseCloseoutWebAccess();app.Run(c=>{reached++;return c.Response.WriteAsync("effect");});
        await app.StartAsync();var client=app.GetTestClient();
        foreach(var path in new[]{"/","/draft/new","/operator/pilot","/sign/"+Id+"/finish"})
            Assert.Equal(System.Net.HttpStatusCode.NotFound,(await client.PostAsync(path,new StringContent("not even a form"))).StatusCode);
        Assert.Equal(0,reached);Assert.Equal(System.Net.HttpStatusCode.OK,(await client.GetAsync("/health")).StatusCode);Assert.Equal(1,reached);
    }
    [Fact]
    public async Task Operator_preheader_Start_and_OFF_original_receipt_do_not_require_or_mint_a_replacement_header()
    {
        const string capability="1234567890123456789012345678901234567890123";
        var h=new EmailPilotCloseoutBrowserTests.Harness();h.Options.HostRole=EmailPilotCloseoutHostRole.Web;h.Options.PrivateConfigurationSet="private";
        h.Options.WebInput=new(){Sha256=new string('a',64),Bytes=32,Filename="synthetic.pdf"};h.Email.Enabled=true;h.Email.Ses.ConfigurationSet="normal";
        var reads=0;var core=new EmailPilotCloseout(h.Options,h.Email,h.Work,()=>{reads++;throw new InvalidOperationException("No database in this proof.");},()=>throw new InvalidOperationException(),()=>new(h.Keys),h.Clock);
        var browser=new EmailPilotCloseoutOperatorBrowser(h.Options,h.Email,h.Work,h.Clock,new Environment(),()=>h.Keys,new(){Enabled=false});
        var access=new EmailPilotCloseoutWebAccess(core,null!,browser,h.Clock,new ServiceCollection().BuildServiceProvider());
        var http=Request("/operator/pilot-closeout","POST","?handler=Unlock");http.Request.Scheme="http";http.Request.Host=new("localhost");
        http.Request.Form=new FormCollection(new Dictionary<string,StringValues>{{"Capability","wrong"}});
        Assert.False(await access.AllowsAsync(http,new(CloseoutWebArea.Operator,"Unlock"),default));
        http.Request.Form=new FormCollection(new Dictionary<string,StringValues>{{"Capability",capability}});
        Assert.True(await access.AllowsAsync(http,new(CloseoutWebArea.Operator,"Unlock"),default));Assert.Equal(0,http.Response.Headers.SetCookie.Count);
        Assert.True(browser.Unlock(http,capability));var cookie=http.Response.Headers.SetCookie.Single()!.Split(';')[0];
        var start=Request("/operator/pilot-closeout","POST","?handler=Start");start.Request.Headers.Cookie=cookie;start.Request.Form=new FormCollection(new Dictionary<string,StringValues>());
        Assert.True(await access.AllowsAsync(start,new(CloseoutWebArea.Operator,"Start"),default));
        h.Clock.Now=h.Options.StartsAt.AddMinutes(25);Assert.False(await access.AllowsAsync(start,new(CloseoutWebArea.Operator,"Start"),default));
        h.Options.Enabled=false;Assert.True(await access.AllowsAsync(start,new(CloseoutWebArea.Operator,"Receipt"),default));
        Assert.False(await access.AllowsAsync(http,new(CloseoutWebArea.Operator,"Unlock"),default));
        h.Clock.Now=h.Options.Until;Assert.False(await access.AllowsAsync(start,new(CloseoutWebArea.Operator,"Receipt"),default));Assert.Equal(0,reads);
    }
    private sealed class Environment:Microsoft.Extensions.Hosting.IHostEnvironment
    {public string EnvironmentName{get;set;}="Development";public string ApplicationName{get;set;}="Synthetic";public string ContentRootPath{get;set;}=".";public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider{get;set;}=new Microsoft.Extensions.FileProviders.NullFileProvider();}
    [Fact]
    public async Task Declared_file_length_cannot_hide_trailing_stream_bytes()
    {
        var bytes=Enumerable.Range(0,32).Select(x=>(byte)x).ToArray();
        var expected=new EmailPilotCloseoutWebInput(Convert.ToHexStringLower(SHA256.HashData(bytes)),bytes.Length,"synthetic.pdf");
        Assert.False(await EmailPilotCloseoutWeb.InputAsync(new UnboundedFile([..bytes,99],bytes.Length),expected,default));
        Assert.False(await EmailPilotCloseoutWeb.InputAsync(new UnboundedFile(bytes[..^1],bytes.Length),expected,default));
    }
    private sealed class UnboundedFile(byte[] bytes,long declared):IFormFile
    {
        public string ContentType=>"application/pdf";public string ContentDisposition=>"";public IHeaderDictionary Headers{get;}=new HeaderDictionary();
        public long Length=>declared;public string Name=>"Upload";public string FileName=>"synthetic.pdf";
        public Stream OpenReadStream()=>new MemoryStream(bytes,false);
        public void CopyTo(Stream target)=>throw new NotSupportedException();
        public Task CopyToAsync(Stream target,CancellationToken ct=default)=>throw new NotSupportedException();
    }
    [Fact]
    public void Duplicate_cookie_names_and_encoded_query_handler_refuse_before_authentication()
    {
        var c=Request("/health");c.Request.Headers.Cookie="proof=a; proof=b";Assert.Null(EmailPilotCloseoutWeb.Route(c.Request));
        c=Request("/operator/pilot-closeout","POST","?handler=%53tart");Assert.Null(EmailPilotCloseoutWeb.Route(c.Request));
    }
    [Theory]
    [InlineData("database","migrate")][InlineData("database","grant-runtime")]
    [InlineData("database","remove-expired-closeout-secret")][InlineData("work","closeout-pass")]
    [InlineData("staging","seal")][InlineData("closeout-web","database")]
    public void Web_effective_configuration_refuses_before_generic_dispatch(string command,string operation)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"EmailPilot:Closeout:HostRole","Web"}}).Build();
        var dispatched=0;
        void Dispatch(){EmailPilotCloseoutWebStartup.DemandDispatch(config,[command,operation]);dispatched++;}
        Assert.Throws<InvalidOperationException>(Dispatch);Assert.Equal(0,dispatched);
    }
    [Theory]
    [InlineData("Legacy","database","migrate")][InlineData("Pass","work","closeout-pass")]
    [InlineData("Handoff","work","recover")]
    public void Dispatch_fence_does_not_reparse_or_replace_existing_nonWeb_command_authority(string role,string command,string operation)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"EmailPilot:Closeout:HostRole",role}}).Build();
        EmailPilotCloseoutWebStartup.DemandDispatch(config,[command,operation]);
    }
    [Fact]
    public async Task Actual_Razor_optional_handler_LinkGenerator_paths_are_accepted_without_query_override()
    {
        var builder=WebApplication.CreateBuilder(new WebApplicationOptions{ApplicationName=typeof(EmailPilotCloseoutOptions).Assembly.FullName,ContentRootPath=AppContext.BaseDirectory,EnvironmentName="Development"});
        builder.WebHost.UseTestServer();builder.Services.AddRazorPages();await using var app=builder.Build();app.MapRazorPages();await app.StartAsync();
        var links=app.Services.GetRequiredService<LinkGenerator>();
        foreach(var (page,handler,area) in new[]{("/Lookup/Access","Begin",CloseoutWebArea.LookupEntry),("/Lookup/Access","Redeem",CloseoutWebArea.LookupEntry),
            ("/Lookup/Documents","Open",CloseoutWebArea.LookupList),("/Lookup/Documents","First",CloseoutWebArea.LookupList)})
        {
            var path=links.GetPathByPage(page,handler);Assert.NotNull(path);Assert.EndsWith("/"+handler,path);
            var route=Assert.IsType<CloseoutWebRoute>(EmailPilotCloseoutWeb.Route(Request(path!,"POST").Request));Assert.Equal(handler,route.Handler);Assert.Equal(area,route.Area);
            Assert.Null(EmailPilotCloseoutWeb.Route(Request(path!,"POST","?handler="+handler).Request));
        }
    }
}
