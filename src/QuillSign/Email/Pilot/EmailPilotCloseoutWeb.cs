using System.Security.Cryptography;
using Microsoft.AspNetCore.Http.Features;

namespace QuillSign.Email.Pilot;

internal static class EmailPilotCloseoutWebStartup
{
    internal const string Entry="closeout-web";
    internal static (WebApplicationBuilder Builder,bool PrivateWeb) Prepare(string[] args)
    {
        var privateWeb=PrivateEntry(args);
        // Existing CLI commands build standard configuration WITHOUT forwarding
        // their operation arguments. Preserve that precedence, not an env-only
        // duplicate parser or an accidental command-line config override.
        var command=args.Length>0&&args[0] is "database" or "work" or "staging";
        var builder=WebApplication.CreateBuilder(privateWeb||command?[]:args);
        DemandDispatch(builder.Configuration,args);
        if(privateWeb)Demand(builder.Configuration,true);
        return(builder,privateWeb);
    }
    internal static void DemandDispatch(IConfiguration configuration,string[] args)
    {
        var privateWeb=PrivateEntry(args);
        var role=configuration.GetValue<EmailPilotCloseoutHostRole>("EmailPilot:Closeout:HostRole");
        if((role==EmailPilotCloseoutHostRole.Web)!=privateWeb)
            throw new InvalidOperationException("Private Web configuration requires its fixed entry before command dispatch.");
    }
    internal static bool PrivateEntry(string[] args)
    {
        if(args.Length==0||args[0]!=Entry)return false;
        if(args.Length!=1)throw new InvalidOperationException("The private Web host takes no command arguments.");
        return true;
    }
    internal static void Demand(IConfiguration configuration,bool privateWeb)
    {
        var options=configuration.GetSection("EmailPilot:Closeout").Get<EmailPilotCloseoutOptions>()??new();
        options.Validate();
        if((options.HostRole==EmailPilotCloseoutHostRole.Web)!=privateWeb)
            throw new InvalidOperationException("Private Web configuration and entry must agree.");
        if(!privateWeb)return;
        var email=configuration.GetSection("Email").Get<EmailOptions>()??new();
        var work=configuration.GetSection("Work").Get<Work.WorkOptions>()??new();
        var pilot=configuration.GetSection("EmailPilot").Get<EmailPilotOptions>()??new();
        // Enabled may be OFF for the already-issued receipt session; nothing
        // here admits a request or extends the original configured interval.
        _=options.CaptureReceiptConfiguration();
        if(options.WebInput is null||!options.Host(email,work,true)||pilot.Enabled)
            throw new InvalidOperationException("Configure one closed private Web purpose and retained input.");
    }
}

internal enum CloseoutWebArea { Static, Operator, Verify, Draft, Signers, Review, Sent, Document, Invitation, Sign, Decline, Declined, LookupEntry, LookupList, Complete, Final }
internal sealed record CloseoutWebRoute(CloseoutWebArea Area,string Handler="",string? PublicId=null,string? ObjectId=null);
internal static class EmailPilotCloseoutWeb
{
    internal const int MaximumBody=131072;
    private static readonly HashSet<string> Assets=new(StringComparer.Ordinal) {
        "/site.css","/logo.svg","/logo-mark.svg","/review.css","/signer.css","/field-editor.css",
        "/vendor/pdfjs/web/pdf_viewer.css","/vendor/pdfjs/build/pdf.mjs","/vendor/pdfjs/build/pdf.worker.mjs",
        "/vendor/interact/interact.min.js","/js/document-upload.mjs","/js/pdf-preview.mjs",
        "/js/field-editor.mjs","/js/signer-consent.mjs","/lookup-access.js"
    };
    private static bool Id(string s)=>s.Length==32&&s.All(c=>c is >= '0' and <= '9' or >= 'a' and <= 'f')&&Guid.ParseExact(s,"N")!=Guid.Empty;
    internal static CloseoutWebRoute? Route(HttpRequest request)
    {
        var path=request.Path.Value??"";
        var raw=request.HttpContext.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if(request.PathBase.HasValue||path.Length>256||path.Contains('%')||path.Contains('\\')||path.Contains("//",StringComparison.Ordinal)||
            raw is not null&&(raw.Contains('%')||raw.Split('?')[0]!=path))return null;
        if(request.Method is not ("GET" or "HEAD" or "POST"))return null;
        var cookieNames=request.Headers.Cookie.SelectMany(x=>(x??"").Split(';',StringSplitOptions.RemoveEmptyEntries))
            .Select(x=>x.Trim().Split('=',2)[0]).ToArray();
        if(request.Headers.Cookie.Sum(x=>x?.Length??0)>32768||cookieNames.Distinct(StringComparer.Ordinal).Count()!=cookieNames.Length)return null;
        if(request.Query.Any(x=>x.Value.Count!=1||x.Key.Length>32))return null;
        string? handler=request.Query.TryGetValue("handler",out var h)?h[0]:null;
        if(request.Query.Keys.Any(k=>k.Equals("handler",StringComparison.OrdinalIgnoreCase)&&k!="handler"))return null;
        bool Query(params string[] keys)=>request.Query.Keys.All(k=>keys.Contains(k,StringComparer.Ordinal));
        return Classify();
        CloseoutWebRoute? Classify()
        {
            if(Assets.Contains(path))return request.Method is "GET" or "HEAD"&&Query("v")?new(CloseoutWebArea.Static):null;
            if(path=="/health")return request.Method=="GET"&&Query()?new(CloseoutWebArea.Static):null;
            if(request.Method=="HEAD")return null;
            if(path==EmailPilotCloseoutOperatorBrowser.Path&&Query("handler"))
                return request.Method=="GET"&&handler is null||request.Method=="POST"&&handler is "Unlock" or "Lock" or "Receipt" or "Start" or "Verification" or "Lookup"
                    ?new(CloseoutWebArea.Operator,handler??""):null;
            if(path=="/sender/verify")return request.Method=="GET"&&Query("token")&&handler is null?new(CloseoutWebArea.Verify):null;
            if(path=="/sign/invitation")return Query("token")&&handler is null?new(CloseoutWebArea.Invitation):null;
            if(path=="/find/access"||path.StartsWith("/find/access/",StringComparison.Ordinal))return LookupRoute("/find/access",CloseoutWebArea.LookupEntry,["Begin","Redeem"]);
            if(path=="/find/documents"||path.StartsWith("/find/documents/",StringComparison.Ordinal))return LookupRoute("/find/documents",CloseoutWebArea.LookupList,["First","Open"]);
            var parts=path.Split('/');
            if(parts.Length<3||!Id(parts[2]))return null;
            var id=parts[2];
            if(parts[1]=="draft"&&Query("handler"))
            {
                if(parts.Length==3)return request.Method=="GET"&&handler is null||request.Method=="POST"&&handler is "Upload" or "Confirm"?new(CloseoutWebArea.Draft,handler??"",id):null;
                if(parts.Length==4&&parts[3]=="signers")return request.Method=="GET"&&handler is null||request.Method=="POST"&&handler=="Save"?new(CloseoutWebArea.Signers,handler??"",id):null;
                if(parts.Length==4&&parts[3]=="review")return request.Method=="GET"&&handler is null||request.Method=="POST"&&handler=="Send"?new(CloseoutWebArea.Review,handler??"",id):null;
                if(parts.Length==4&&parts[3]=="sent")return request.Method=="GET"&&handler is null?new(CloseoutWebArea.Sent,"",id):null;
                if(parts.Length==5&&parts[3]=="document"&&Id(parts[4]))return request.Method=="GET"&&handler is null?new(CloseoutWebArea.Document,"",id,parts[4]):null;
            }
            if(parts[1]=="sign")
            {
                if(parts.Length==3&&Query("handler","download"))return request.Method=="GET"&&handler is null or "Pdf" or "Disclosure"&&(!request.Query.ContainsKey("download")||handler=="Pdf"&&request.Query["download"] is var d&&d[0] is "true" or "false")||
                    request.Method=="POST"&&Query("handler")&&handler is null or "Decline"?new(CloseoutWebArea.Sign,handler??"",id):null;
                if(parts.Length==4&&parts[3]=="decline"&&Query()&&handler is null)return new(CloseoutWebArea.Decline,"",id);
                if(parts.Length==4&&parts[3]=="declined"&&request.Method=="GET"&&Query())return new(CloseoutWebArea.Declined,"",id);
            }
            if(parts[1]=="complete")
            {
                if(parts.Length==3&&Query("handler"))return request.Method=="GET"&&handler is null||request.Method=="POST"&&handler=="Download"?new(CloseoutWebArea.Complete,handler??"",id):null;
                if(parts.Length==5&&parts[3]=="final"&&parts[4] is "executed" or "certificate"&&request.Method=="GET"&&Query())return new(CloseoutWebArea.Final,parts[4],id);
            }
            return null;
        }
        CloseoutWebRoute? LookupRoute(string prefix,CloseoutWebArea area,string[] allowed)
        {
            if(!Query("handler"))return null;
            var effective=handler;
            if(path!=prefix)
            {
                // Razor's optional {handler?} emits a path segment. Never let
                // query or form values override that selected endpoint.
                if(request.Query.ContainsKey("handler"))return null;
                effective=path[(prefix.Length+1)..];
                if(!allowed.Contains(effective,StringComparer.Ordinal))return null;
            }
            return request.Method=="GET"&&effective is null||request.Method=="POST"&&effective is not null&&allowed.Contains(effective,StringComparer.Ordinal)
                ?new(area,effective??""):null;
        }
    }
    internal static bool FormShape(CloseoutWebRoute route,IFormCollection form)
    {
        string[] keys=route.Area switch {
            CloseoutWebArea.Operator=>route.Handler=="Unlock"?["Capability"]:[],
            CloseoutWebArea.Draft=>route.Handler=="Upload"?["Version"]:["Version","DocumentId","PreviewMatches"],
            CloseoutWebArea.Signers=>["Version","Input.Id","Input.FullName","Input.Email","Input.Role"],
            CloseoutWebArea.Review=>["Version","ExclusionsAcknowledged","SendAcknowledged","StatementVersion","RetentionSha256","ReminderSha256","ReminderSchedulingVersion"],
            CloseoutWebArea.Invitation=>["Token"],CloseoutWebArea.Sign=>route.Handler=="Decline"?["Reason"]:["Receipt","Agreement","CanRetain","AccessMethod"],
            CloseoutWebArea.Decline=>["ConfirmDecline","Reason"],CloseoutWebArea.LookupEntry=>route.Handler=="Begin"?["code"]:["nonce"],
            CloseoutWebArea.LookupList=>route.Handler=="Open"?["publicId"]:[],CloseoutWebArea.Complete=>["kind"],_=>[]
        };
        var checkboxes=new[]{"PreviewMatches","ExclusionsAcknowledged","SendAcknowledged","Agreement","CanRetain","ConfirmDecline"};
        if(form.Count>16||form.Any(p=>p.Key!="__RequestVerificationToken"&&!keys.Contains(p.Key,StringComparer.Ordinal)||
            p.Value.Any(v=>v is null||v.Length>8192)||p.Value.Count!=1&&!(checkboxes.Contains(p.Key)&&p.Value.Count==2&&p.Value[0]=="true"&&p.Value[1]=="false")))return false;
        return route is {Area:CloseoutWebArea.Draft,Handler:"Upload"}?form.Files.Count==1&&form.Files[0].Name=="Upload":form.Files.Count==0;
    }
    internal static async Task<bool> InputAsync(IFormFile file,EmailPilotCloseoutWebInput expected,CancellationToken ct)
    {
        if(file.FileName!=expected.Filename||file.Length!=expected.Bytes||file.Length>MaximumBody)return false;
        await using var stream=file.OpenReadStream();
        using var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256);var buffer=new byte[4096];long total=0;
        for(int read;(read=await stream.ReadAsync(buffer,ct))!=0;) {total+=read;if(total>expected.Bytes)return false;hash.AppendData(buffer,0,read);}
        return total==expected.Bytes&&CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(),Convert.FromHexString(expected.Sha256));
    }
    internal static IApplicationBuilder UseCloseoutWebRoutes(this IApplicationBuilder app)=>app.Use(async(http,next)=>{
        var route=Route(http.Request);
        if(route is null||http.Request.ContentLength>MaximumBody){http.Response.StatusCode=404;return;}
        if(http.Features.Get<IHttpMaxRequestBodySizeFeature>() is {IsReadOnly:false} limit)limit.MaxRequestBodySize=MaximumBody;
        http.Items[typeof(CloseoutWebRoute)]=route;
        await next();
    });
    internal static IApplicationBuilder UseCloseoutWebAccess(this IApplicationBuilder app)=>app.Use(async(http,next)=>{
        if(http.Items[typeof(CloseoutWebRoute)] is not CloseoutWebRoute route){http.Response.StatusCode=404;return;}
        if(route.Area==CloseoutWebArea.Static){await next();return;}
        bool allowed;
        try {
            if(http.Request.Method=="POST")
            {
                if(!http.Request.HasFormContentType){http.Response.StatusCode=404;return;}
                var form=await http.Request.ReadFormAsync(new FormOptions{ValueCountLimit=16,ValueLengthLimit=8192,MultipartBodyLengthLimit=MaximumBody},http.RequestAborted);
                if(!FormShape(route,form)){http.Response.StatusCode=404;return;}
            }
            allowed=await http.RequestServices.GetRequiredService<EmailPilotCloseoutWebAccess>().AllowsAsync(http,route,http.RequestAborted);
        } catch(Exception e)when(e is InvalidDataException or InvalidOperationException or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or FormatException or Microsoft.Data.SqlClient.SqlException or Azure.RequestFailedException or IOException or EmailPilotAccessUnavailableException) {allowed=false;}
        if(!allowed){http.Response.StatusCode=404;return;}
        await next();
    });
}
