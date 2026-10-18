using System.Net;
using System.Text;
using System.Xml.Linq;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Storage;
using Run=QuillSign.Tests.DemoPurgeStorageTests.Run;

namespace QuillSign.Tests;

public sealed class DemoPurgeTransportTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("version")][InlineData("snapshot")][InlineData("plain")]
    public async Task SDK_inventory_and_conditional_delete_are_exact_and_never_read_content_or_change_protection(string mode)
    {
        await using var r=await Run.Create(fixture);var cap=await r.Authorize();using var handler=new Handler(r,mode);var store=Store(handler);
        var batch=await store.SweepAsync(cap,3);Assert.True(batch.ReachedEnd);Assert.Equal(1,batch.Deleted);Assert.Equal(1,batch.Examined);
        var delete=Assert.Single(handler.Requests,x=>x.Method==HttpMethod.Delete);
        Assert.Equal(mode=="version" ? Handler.Version : "",delete.Version);Assert.Equal(mode=="snapshot" ? Handler.Version : "",delete.Snapshot);
        Assert.Equal(Handler.Tag,delete.Match);Assert.DoesNotContain(handler.Requests,x=>x.Method==HttpMethod.Put || x.Comp=="immutabilitypolicy" || x.Permanent);
        Assert.All(handler.Requests.Where(x=>x.Comp=="list"),x=>{Assert.Equal($"{r.H.Id:N}/",x.Prefix);Assert.Contains("Versions",x.Include);Assert.Contains("Snapshots",x.Include);});
        Assert.Equal(0,(await store.SweepAsync(cap,3)).Examined);
    }
    [Theory]
    [InlineData("hold",true)][InlineData("future",true)][InlineData("changed",false)][InlineData("server-hold",false)]
    public async Task Held_unexpired_or_changed_objects_remain_incomplete_and_are_never_weakened(string mode,bool protectedBeforeDelete)
    {
        await using var r=await Run.Create(fixture);using var handler=new Handler(r,mode);var result=await Store(handler).SweepAsync(await r.Authorize(),3);
        Assert.Equal(0,result.Deleted);Assert.Equal(protectedBeforeDelete ? 1 : 0,result.Protected);Assert.Equal(protectedBeforeDelete ? 0 : 1,result.Changed);
        Assert.Equal(protectedBeforeDelete ? 0 : 1,handler.Deletes);Assert.DoesNotContain(handler.Requests,x=>x.Method==HttpMethod.Put);
    }
    [Fact]
    public async Task Lost_delete_acknowledgement_propagates_and_explicit_repeat_observes_the_absent_object()
    {
        await using var r=await Run.Create(fixture);using var handler=new Handler(r,"lost");var store=Store(handler);var cap=await r.Authorize();
        await Assert.ThrowsAsync<RequestFailedException>(()=>store.SweepAsync(cap,3));Assert.Equal(1,handler.Deletes);
        Assert.Equal(0,(await store.SweepAsync(cap,3)).Examined);Assert.Equal(1,handler.Deletes);
    }
    [Fact]
    public async Task Expiry_after_an_effective_delete_cannot_report_success_and_a_fresh_verified_scope_recovers()
    {
        await using var r=await Run.Create(fixture);using var handler=new Handler(r,"expire-delete");var store=Store(handler);var cap=await r.Authorize();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>store.SweepAsync(cap,3));Assert.Equal(1,handler.Deletes);
        Assert.Equal(0,(await store.SweepAsync(await r.Authorize(),3)).Examined);
    }
    [Theory]
    [InlineData("expire-list")][InlineData("expire-head")][InlineData("cancel-head")][InlineData("escape")][InlineData("traversal")]
    public async Task Expiry_cancellation_or_escaped_inventory_cannot_reach_delete(string mode)
    {
        await using var r=await Run.Create(fixture);using var cancel=new CancellationTokenSource();using var handler=new Handler(r,mode,cancel);
        var cap=await r.Authorize();var error=await Record.ExceptionAsync(()=>Store(handler).SweepAsync(cap,3,ct:cancel.Token));
        Assert.True(error is UnauthorizedAccessException or OperationCanceledException or InvalidDataException,error?.ToString());Assert.Equal(0,handler.Deletes);
    }
    [Theory]
    [InlineData("missing",true)][InlineData("permission",false)]
    public async Task Missing_is_idempotent_but_permission_failure_cannot_be_reported_as_success(string mode,bool missing)
    {
        await using var r=await Run.Create(fixture);using var handler=new Handler(r,mode);var store=Store(handler);var cap=await r.Authorize();
        if(missing)Assert.Equal(1,(await store.SweepAsync(cap,3)).Missing);
        else await Assert.ThrowsAsync<RequestFailedException>(()=>store.SweepAsync(cap,3));
        Assert.Equal(0,handler.Deletes);
    }
    [Theory]
    [InlineData("current",2)][InlineData("current-new",1)][InlineData("current-absent",1)]
    public async Task Current_version_is_detached_conditionally_before_version_delete_but_newer_root_survives(string mode,int deletes)
    {
        await using var r=await Run.Create(fixture);using var handler=new Handler(r,mode);
        var result=await Store(handler).SweepAsync(await r.Authorize(),3);
        Assert.Equal(1,result.Deleted);Assert.Equal(deletes,handler.Deletes);
        var requests=handler.Requests.Where(x=>x.Method==HttpMethod.Delete).ToArray();
        Assert.Equal(Handler.Version,requests[^1].Version);
        if(mode=="current")Assert.Empty(requests[0].Version);
        Assert.All(requests,x=>Assert.Equal(Handler.Tag,x.Match));
        Assert.DoesNotContain(handler.Requests,x=>x.Method==HttpMethod.Put || x.Comp=="immutabilitypolicy" || x.Permanent);
    }
    [Theory]
    [InlineData("current-race",false,1)][InlineData("current-etag",false,0)]
    [InlineData("current-held-root",true,0)][InlineData("current-future-root",true,0)]
    public async Task Fresh_current_protection_or_concurrent_replacement_cannot_be_deleted(string mode,bool held,int deletes)
    {
        await using var r=await Run.Create(fixture);using var handler=new Handler(r,mode);
        var result=await Store(handler).SweepAsync(await r.Authorize(),3);
        Assert.Equal(0,result.Deleted);Assert.Equal(held ? 1 : 0,result.Protected);Assert.Equal(held ? 0 : 1,result.Changed);
        Assert.Equal(deletes,handler.Deletes);Assert.DoesNotContain(handler.Requests,x=>x.Method==HttpMethod.Delete && x.Version.Length>0);
    }
    [Fact]
    public async Task Lost_root_delete_ack_recovers_without_deleting_any_changed_root_or_reporting_false_success()
    {
        await using var r=await Run.Create(fixture);using var handler=new Handler(r,"current-lost-root");var store=Store(handler);var cap=await r.Authorize();
        await Assert.ThrowsAsync<RequestFailedException>(()=>store.SweepAsync(cap,3));Assert.Equal(1,handler.Deletes);
        Assert.Equal(1,(await store.SweepAsync(cap,3)).Deleted);Assert.Equal(2,handler.Deletes);
    }
    [Fact]
    public async Task Expired_authority_after_root_delete_cannot_continue_to_the_retained_version()
    {
        await using var r=await Run.Create(fixture);using var handler=new Handler(r,"current-expire-root");var store=Store(handler);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(async()=>await store.SweepAsync(await r.Authorize(),3));Assert.Equal(1,handler.Deletes);
        Assert.Equal(1,(await store.SweepAsync(await r.Authorize(),3)).Deleted);
    }
    private static AzureEnvelopePurgeStore Store(Handler handler) {
        var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03) {Transport=new HttpClientTransport(new HttpClient(handler))};
        options.Retry.MaxRetries=0;options.Diagnostics.IsLoggingEnabled=false;options.Diagnostics.IsLoggingContentEnabled=false;options.Diagnostics.IsDistributedTracingEnabled=false;
        return new(new(new Uri("https://storage.example.invalid"),new Credential(),options));
    }
    private sealed class Credential:TokenCredential
    {public override AccessToken GetToken(TokenRequestContext c,CancellationToken ct)=>new("synthetic-no-agreement",DateTimeOffset.UtcNow.AddHours(1));public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext c,CancellationToken ct)=>ValueTask.FromResult(GetToken(c,ct));}
    private sealed record Request(HttpMethod Method,string Comp,string Version,string Snapshot,string Match,string Prefix,string Include,bool Permanent);
    private sealed class Handler(Run run,string mode,CancellationTokenSource? cancel=null):HttpMessageHandler
    {
        internal const string Tag="\"synthetic-etag\"",Version="2028-03-01T00:00:00.0000000Z";
        internal List<Request> Requests=[];internal int Deletes;private bool present=true;private bool rootPresent=mode!="current-absent";
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            var q=QueryHelpers.ParseQuery(request.RequestUri!.Query);string Q(string name)=>q.TryGetValue(name,out var value) ? value.ToString() : "";
            var match=request.Headers.TryGetValues("If-Match",out var values) ? values.Single() : "";
            Requests.Add(new(request.Method,Q("comp"),Q("versionid"),Q("snapshot"),match,Q("prefix"),Q("include"),Q("deletetype")=="permanent"));
            if(Q("comp")=="list") {
                Assert.Equal(HttpMethod.Get,request.Method);Assert.InRange(int.Parse(Q("maxresults")),1,3);
                var name=$"{run.H.Id:N}/{Guid.Empty:N}";
                if(mode=="escape")name=$"{Guid.NewGuid():N}/{Guid.NewGuid():N}";
                if(mode=="traversal")name=$"{run.H.Id:N}/../outside";
                var properties=new XElement("Properties",new XElement("Last-Modified",run.Time.Now.UtcDateTime.ToString("R")),new XElement("Etag",Tag),new XElement("Content-Length",32),new XElement("BlobType","BlockBlob"));
                var blob=new XElement("Blob",new XElement("Name",name),properties);
                if(mode=="version" || mode.StartsWith("current"))blob.Add(new XElement("VersionId",Version));if(mode=="snapshot")blob.Add(new XElement("Snapshot",Version));
                var body=new XElement("EnumerationResults",new XAttribute("ServiceEndpoint","https://storage.example.invalid/"),new XAttribute("ContainerName",request.RequestUri.AbsolutePath.Trim('/')),
                    new XElement("Prefix",Q("prefix")),new XElement("MaxResults",Q("maxresults")),new XElement("Blobs",present && request.RequestUri.AbsolutePath=="/originals" ? blob : null),new XElement("NextMarker",""));
                if(mode=="expire-list")run.Time.Now=run.Time.Now.AddMinutes(3);
                return Task.FromResult(Reply(HttpStatusCode.OK,body.ToString()));
            }
            var versioned=mode=="version" || mode.StartsWith("current");
            var root=versioned && Q("versionid")=="";
            if(request.Method==HttpMethod.Head && root)Assert.Empty(match);else Assert.Equal(Tag,match);
            if(request.Method==HttpMethod.Head) {
                if(root && !rootPresent)return Task.FromResult(Error(HttpStatusCode.NotFound,"BlobNotFound"));
                if(mode=="missing")return Task.FromResult(Error(HttpStatusCode.NotFound,"BlobNotFound"));
                if(mode=="permission")return Task.FromResult(Error(HttpStatusCode.Forbidden,"AuthorizationPermissionMismatch"));
                var result=Reply(HttpStatusCode.OK,"");result.Content.Headers.ContentLength=32;result.Headers.TryAddWithoutValidation("ETag",Tag);
                result.Headers.TryAddWithoutValidation("Last-Modified",run.Time.Now.UtcDateTime.ToString("R"));result.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");
                result.Headers.TryAddWithoutValidation("x-ms-legal-hold",mode=="hold" ? "true" : "false");
                if(versioned)result.Headers.TryAddWithoutValidation("x-ms-version-id",root && (mode=="version" || mode=="current-new") ? Version+"new" : Version);
                if(root && mode=="current-etag") {result.Headers.Remove("ETag");result.Headers.TryAddWithoutValidation("ETag","\"new-etag\"");}
                if(root && mode=="current-held-root") {result.Headers.Remove("x-ms-legal-hold");result.Headers.TryAddWithoutValidation("x-ms-legal-hold","true");}
                if(root && mode=="current-future-root") {result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date",run.Time.Now.AddDays(1).UtcDateTime.ToString("R"));result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode","locked");}
                if(mode=="future") {result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date",run.Time.Now.AddDays(1).UtcDateTime.ToString("R"));result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode","locked");}
                if(mode=="expire-head")run.Time.Now=run.Time.Now.AddMinutes(3);if(mode=="cancel-head")cancel!.Cancel();
                return Task.FromResult(result);
            }
            Assert.Equal(HttpMethod.Delete,request.Method);Deletes++;
            if(root) {
                if(mode=="current-race")return Task.FromResult(Error(HttpStatusCode.PreconditionFailed,"ConditionNotMet"));
                rootPresent=false;
                if(mode=="current-expire-root")run.Time.Now=run.Time.Now.AddMinutes(3);
                if(mode=="current-lost-root")return Task.FromResult(Error(HttpStatusCode.InternalServerError,"SyntheticLostDeleteAcknowledgement"));
                return Task.FromResult(Reply(HttpStatusCode.Accepted,""));
            }
            if(versioned && rootPresent && mode!="version" && mode!="current-new")return Task.FromResult(Error(HttpStatusCode.Forbidden,"OperationNotAllowedOnRootBlob"));
            if(mode=="changed")return Task.FromResult(Error(HttpStatusCode.PreconditionFailed,"ConditionNotMet"));
            if(mode=="server-hold")return Task.FromResult(Error(HttpStatusCode.Conflict,"BlobImmutableDueToLegalHold"));
            present=false;if(mode=="expire-delete")run.Time.Now=run.Time.Now.AddMinutes(3);
            if(mode=="lost")return Task.FromResult(Error(HttpStatusCode.InternalServerError,"SyntheticLostDeleteAcknowledgement"));
            return Task.FromResult(Reply(HttpStatusCode.Accepted,""));
        }
        private static HttpResponseMessage Reply(HttpStatusCode status,string body) {
            var response=new HttpResponseMessage(status) {Content=new StringContent(body,Encoding.UTF8,"application/xml")};
            response.Headers.TryAddWithoutValidation("x-ms-version","2023-11-03");response.Headers.TryAddWithoutValidation("x-ms-request-id","synthetic-no-agreement");return response;
        }
        private static HttpResponseMessage Error(HttpStatusCode status,string code) {
            var result=Reply(status,$"<Error><Code>{code}</Code><Message>Synthetic storage response.</Message></Error>");result.Headers.TryAddWithoutValidation("x-ms-error-code",code);return result;
        }
    }
}
