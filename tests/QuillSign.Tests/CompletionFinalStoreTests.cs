using System.Net;
using System.Reflection;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using QuillSign.Completion;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class CompletionFinalStoreTests
{
    private static byte[] Bytes=>Encoding.UTF8.GetBytes("Opaque synthetic final storage bytes - NO AGREEMENT");
    [Theory]
    [InlineData("fractional")][InlineData("offset")][InlineData("expired")]
    public async Task Fixed_capability_never_rounds_a_frozen_deadline_or_opens_storage_with_an_invalid_one(string kind)
    {
        using var f=new Fake();f.Until=kind switch {"fractional"=>f.Until.AddTicks(1),"offset"=>f.Until.ToOffset(TimeSpan.FromHours(1)),_=>f.Time.GetUtcNow().AddSeconds(-1)};
        var error=await Record.ExceptionAsync(()=>f.WriteFixed());if(error is TargetInvocationException wrapped)error=wrapped.InnerException;
        if(kind=="expired")Assert.IsType<IOException>(error);else Assert.IsType<UnauthorizedAccessException>(error);Assert.Empty(f.Handler.Requests);
    }
    [Theory]
    [InlineData(false,false)][InlineData(true,false)][InlineData(true,true)]
    public async Task Fixed_deadline_commit_and_exact_version_lock_are_verified_and_recovered_without_extending(bool unlocked,bool loseLock)
    {
        using var f=new Fake();f.Handler.Mode=unlocked ? "unlocked" : "locked";f.Handler.LoseLock=loseLock;
        var value=await f.WriteFixed();Assert.Equal(f.Until,value.ProtectedUntil);Assert.Equal(FinalProtection.LockedTime,value.Protection);
        Assert.Equal(Bytes,await f.ReadFixed(value));Assert.Equal(unlocked ? 1 : 0,f.Handler.Locks);Assert.Equal(1,f.Handler.Commits);
        var again=await f.WriteFixed();Assert.Equal(value.ProtectedUntil,again.ProtectedUntil);Assert.Equal(1,f.Handler.Commits);Assert.Equal(unlocked ? 1 : 0,f.Handler.Locks);
        Assert.Equal(f.Until,f.Handler.RequestedUntil);Assert.DoesNotContain(f.Handler.Requests,x=>x.Container && x.Method!=HttpMethod.Head && x.Method!=HttpMethod.Get);
    }
    [Theory]
    [InlineData("short")][InlineData("long")][InlineData("hold")][InlineData("missing")]
    public async Task Fixed_scope_rejects_mismatched_policies_without_shortening_extending_or_removing_them(string mode)
    {
        using var f=new Fake();f.Handler.Mode=mode;
        await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>f.WriteFixed());Assert.Equal(0,f.Handler.Locks);Assert.Equal(1,f.Handler.Commits);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Fixed_version_lock_needs_actual_readback_and_required_permission(bool forbidden)
    {
        using var f=new Fake();f.Handler.Mode="unlocked";f.Handler.KeepUnlocked=!forbidden;f.Handler.DenyLock=forbidden;
        await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>f.WriteFixed());Assert.Equal(1,f.Handler.Locks);Assert.Equal(1,f.Handler.Commits);
    }
    [Fact]
    public async Task Wrong_actual_bytes_never_receive_an_irreversible_fixed_version_lock()
    {
        using var f=new Fake();f.Handler.Mode="unlocked";f.Handler.ReadFault="body";
        await Assert.ThrowsAsync<InvalidDataException>(()=>f.WriteFixed());Assert.Equal(0,f.Handler.Locks);
    }
    [Fact]
    public async Task Fixed_write_expiry_during_staging_cannot_commit_a_version_or_lock_a_policy()
    {
        using var f=new Fake();f.Until=f.Time.GetUtcNow().AddSeconds(5);f.Handler.AfterBlock=()=>f.Time.Advance(TimeSpan.FromSeconds(6));
        await Assert.ThrowsAsync<IOException>(()=>f.WriteFixed());Assert.Equal(0,f.Handler.Commits);Assert.Equal(0,f.Handler.Locks);
    }
    [Fact]
    public async Task Fixed_historical_reads_preserve_exact_bytes_after_expiry_and_reject_an_overlong_changed_policy()
    {
        using var f=new Fake();var value=await f.WriteFixed();f.Time.Advance(TimeSpan.FromDays(8));f.Handler.Mode="missing";
        Assert.Equal(Bytes,await f.ReadFixed(value));f.Handler.Mode="long";await Assert.ThrowsAsync<InvalidDataException>(()=>f.ReadFixed(value));
        Assert.Equal(1,f.Handler.Commits);Assert.Equal(0,f.Handler.Locks);
    }
    [Theory]
    [InlineData("locked",true)][InlineData("hold",true)][InlineData("unlocked",false)][InlineData("missing",false)][InlineData("short",false)][InlineData("indefinite-without-hold",false)]
    public async Task Actual_blob_policy_and_version_are_verified_without_setting_hosted_policies(string mode,bool accepted)
    {
        using var f=new Fake(); f.Handler.Mode=mode;
        var until=mode is "hold" or "indefinite-without-hold" ? (DateTimeOffset?)null : f.Time.GetUtcNow().AddDays(7);
        if(accepted) {
            var value=await f.Write(until:until); Assert.Equal(mode=="hold" ? FinalProtection.LegalHold : FinalProtection.LockedTime,value.Protection);
            Assert.NotEmpty(value.VersionId); Assert.Equal(Bytes,await f.Read(value)); Assert.Equal(1,f.Handler.Commits);
        } else await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>f.Write(until:until));
        Assert.All(f.Handler.Requests.Where(x=>x.Method==HttpMethod.Put),x=>Assert.Contains(x.Comp,new[]{"block","blocklist"}));
        Assert.DoesNotContain(f.Handler.Requests,x=>x.Comp is "immutabilitypolicy" or "legalhold" || x.Container && x.Method!=HttpMethod.Head && x.Method!=HttpMethod.Get);
    }
    [Fact]
    public async Task Conditional_retries_races_and_lost_upload_acknowledgements_recover_one_exact_target()
    {
        using var f=new Fake(); f.Handler.LoseCommit=true;
        var first=await f.Write(); Assert.Equal(1,f.Handler.Commits); Assert.Equal(Bytes,await f.Read(first));
        var again=await f.Write(); Assert.Equal(first.Sha256,again.Sha256); Assert.Equal(first with {Sha256=again.Sha256},again); Assert.Equal(1,f.Handler.Commits);
        using var other=new Fake(); var values=await Task.WhenAll(other.Write(),other.Write());
        Assert.Equal(values[0].Sha256,values[1].Sha256); Assert.Equal(values[0] with {Sha256=values[1].Sha256},values[1]); Assert.Equal(1,other.Handler.Commits); Assert.Equal(Bytes,await other.Read(values[0]));
    }
    [Theory]
    [InlineData("version")][InlineData("etag")][InlineData("length")][InlineData("body")][InlineData("truncated")][InlineData("extra")]
    public async Task Changed_or_inconsistent_final_storage_facts_are_rejected(string change)
    {
        using var f=new Fake(); var value=await f.Write(); f.Handler.ReadFault=change;
        await Assert.ThrowsAsync<InvalidDataException>(()=>f.Read(value)); Assert.Equal(1,f.Handler.Commits);
    }
    [Fact]
    public async Task Weakened_policy_during_the_promised_window_is_rejected_but_exact_historical_bytes_remain_readable_after_expiry()
    {
        using var f=new Fake(); var value=await f.Write(); f.Handler.Mode="unlocked";
        await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>f.Read(value));
        f.Time.Advance(TimeSpan.FromDays(31)); Assert.Equal(Bytes,await f.Read(value)); Assert.Equal(1,f.Handler.Commits);
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Public_containers_or_missing_version_level_support_fail_before_upload(bool publicContainer)
    {
        using var f=new Fake(); f.Handler.Public=publicContainer; f.Handler.VersionSupport=publicContainer;
        await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>f.Write()); Assert.Equal(0,f.Handler.Commits);
        Assert.DoesNotContain(f.Handler.Requests,x=>x.Method==HttpMethod.Put);
    }
    [Fact]
    public async Task Wrong_source_hash_or_size_cannot_commit_a_new_readable_object()
    {
        using var f=new Fake(); var changed=Bytes; changed[0]^=1;
        await Assert.ThrowsAsync<InvalidDataException>(()=>f.Write(source:changed)); Assert.Equal(0,f.Handler.Commits);
        using var shortSource=new Fake(); await Assert.ThrowsAsync<InvalidDataException>(()=>shortSource.Write(source:Bytes[..^1])); Assert.Equal(0,shortSource.Handler.Commits);
        using var longSource=new Fake(); await Assert.ThrowsAsync<InvalidDataException>(()=>longSource.Write(source:[..Bytes,0])); Assert.Equal(0,longSource.Handler.Commits);
    }
    [Fact]
    public async Task Final_capabilities_reject_forged_identities_changed_references_operations_and_expiry_before_io()
    {
        using var f=new Fake(); var value=await f.Write(); var count=f.Handler.Requests.Count; var read=ReadCapability(value,f.Time);
        using var output=new MemoryStream();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.ReadAsync(new ClaimsPrincipal(new ClaimsIdentity([],"QuillSign.InternalCompletionFinal")),value,output));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.ReadAsync(read,value with {Document=value.Document with {EnvelopeId=Guid.NewGuid()}},output));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.ReadAsync(read,value with {Document=value.Document with {ObjectId=Guid.NewGuid()}},output));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.ReadAsync(read,value with {VersionId="different"},output));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.ReadAsync(read,value with {ETag="different"},output));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.ReadAsync(read,value with {Sha256=RandomNumberGenerator.GetBytes(32)},output));
        var write=WriteCapability(f.Target,Bytes.Length,SHA256.HashData(Bytes),f.Until,false,f.Time);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.ReadAsync(write,value,output));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.WriteAsync(read,f.Target,new MemoryStream(Bytes),Bytes.Length,SHA256.HashData(Bytes),f.Until));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.WriteAsync(write,f.Target with {Kind=FinalDocumentKind.Certificate},new MemoryStream(Bytes),Bytes.Length,SHA256.HashData(Bytes),f.Until));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.WriteAsync(write,f.Target,new MemoryStream(Bytes),Bytes.Length,SHA256.HashData(Bytes),null));
        read.AddIdentity(new ClaimsIdentity([new Claim(EnvelopeStorageAuthorization.EnvelopeClaim,f.Target.EnvelopeId.ToString())],EnvelopeStorageAuthorization.SenderScheme));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>f.Store.ReadAsync(read,value,output));
        var expired=ReadCapability(value,f.Time); f.Time.Advance(TimeSpan.FromMinutes(3));
        await Assert.ThrowsAsync<IOException>(()=>f.Store.ReadAsync(expired,value,output)); Assert.Equal(count,f.Handler.Requests.Count);
    }
    [Fact]
    public async Task Development_flags_cannot_relax_production_policy_or_masquerade_a_hosted_endpoint_as_local()
    {
        using var f=new Fake(); f.Handler.Mode="missing";
        await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>f.Store.WriteAsync(
            WriteCapability(f.Target,Bytes.Length,SHA256.HashData(Bytes),f.Until,true,f.Time),f.Target,new MemoryStream(Bytes),Bytes.Length,SHA256.HashData(Bytes),f.Until));
        var local=new AzureCompletionFinalStore(f.Client,f.Time,new EnvironmentStub("Development"),true); var before=f.Handler.Requests.Count;
        await Assert.ThrowsAsync<IOException>(()=>local.WriteAsync(WriteCapability(f.Target,Bytes.Length,SHA256.HashData(Bytes),f.Until,true,f.Time),f.Target,new MemoryStream(Bytes),Bytes.Length,SHA256.HashData(Bytes),f.Until));
        Assert.Equal(before,f.Handler.Requests.Count);
    }
    [Theory]
    [InlineData(55)][InlineData(700003)]
    public async Task Local_Azurite_mode_is_explicit_demo_write_once_and_reads_never_create_resources(int size)
    {
        var connection=Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"); Assert.False(string.IsNullOrEmpty(connection));
        var client=new BlobServiceClient(connection,new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)); var time=new SealFixtures.Clock();
        var store=new AzureCompletionFinalStore(client,time,new EnvironmentStub("Development"),true); var target=new FinalDocument(Guid.NewGuid(),FinalDocumentKind.Executed,Guid.NewGuid());
        var data=Enumerable.Range(0,size).Select(i=>(byte)(i%251)).ToArray();
        var until=time.GetUtcNow().AddDays(7); var hash=SHA256.HashData(data);
        try {
            await Assert.ThrowsAsync<CompletionPublicationUnavailableException>(()=>store.WriteAsync(WriteCapability(target,data.Length,hash,until,false,time),target,new MemoryStream(data),data.Length,hash,until));
            var value=await store.WriteAsync(WriteCapability(target,data.Length,hash,until,true,time),target,new MemoryStream(data),data.Length,hash,until);
            Assert.Equal(FinalProtection.DevelopmentWriteOnce,value.Protection); Assert.Null(value.ProtectedUntil);
            var repeated=await store.WriteAsync(WriteCapability(target,data.Length,hash,until,true,time),target,new MemoryStream(data),data.Length,hash,until);
            Assert.Equal(value.Sha256,repeated.Sha256); Assert.Equal(value with {Sha256=repeated.Sha256},repeated); using var output=new MemoryStream(); await store.ReadAsync(ReadCapability(value,time),value,output); Assert.Equal(data,output.ToArray());
        } finally {await client.GetBlobContainerClient("final").GetBlobClient($"{target.EnvelopeId:N}/executed/{target.ObjectId:N}").DeleteIfExistsAsync();}
    }

    private static ClaimsPrincipal WriteCapability(FinalDocument target,long length,byte[] hash,DateTimeOffset? until,bool development,TimeProvider time)
        =>(ClaimsPrincipal)CapabilityType.GetMethod("Write",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[target,length,hash,until,development,time])!;
    private static ClaimsPrincipal ReadCapability(FinalStoredDocument value,TimeProvider time)
        =>(ClaimsPrincipal)CapabilityType.GetMethod("Read",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[value,time])!;
    private static Type CapabilityType=>typeof(ICompletionFinalStore).Assembly.GetType("QuillSign.Storage.CompletionFinalCapability",true)!;
    private sealed class EnvironmentStub(string name) : IHostEnvironment
    {public string EnvironmentName {get;set;}=name; public string ApplicationName {get;set;}="QuillSign.Tests"; public string ContentRootPath {get;set;}=""; public IFileProvider ContentRootFileProvider {get;set;}=new NullFileProvider();}
    private sealed class Credential : TokenCredential
    {public override AccessToken GetToken(TokenRequestContext c,CancellationToken ct)=>new("synthetic-no-agreement",DateTimeOffset.UtcNow.AddHours(1)); public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext c,CancellationToken ct)=>ValueTask.FromResult(GetToken(c,ct));}
    private sealed class Fake : IDisposable
    {
        public SealFixtures.Clock Time=new(); public Handler Handler; public BlobServiceClient Client; public AzureCompletionFinalStore Store;
        public FinalDocument Target=new(Guid.NewGuid(),FinalDocumentKind.Executed,Guid.NewGuid()); public DateTimeOffset Until;
        public Fake()
        {
            Until=Time.GetUtcNow().AddDays(7); Handler=new(Time); var options=new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03) {Transport=new HttpClientTransport(new HttpClient(Handler))}; options.Retry.MaxRetries=0;
            options.Diagnostics.IsLoggingEnabled=false; options.Diagnostics.IsLoggingContentEnabled=false; options.Diagnostics.IsDistributedTracingEnabled=false;
            Client=new(new Uri("https://storage.example.invalid"),new Credential(),options); Store=new(Client,Time,new EnvironmentStub("Production"));
        }
        public Task<FinalStoredDocument> Write(DateTimeOffset? until=null,byte[]? source=null)
        {var required=Handler.Mode is "hold" or "indefinite-without-hold" ? until : until??Until; var hash=SHA256.HashData(Bytes); return Store.WriteAsync(WriteCapability(Target,Bytes.Length,hash,required,false,Time),Target,new MemoryStream(source??Bytes),Bytes.Length,hash,required);}
        public async Task<byte[]> Read(FinalStoredDocument value) {using var output=new MemoryStream(); await Store.ReadAsync(ReadCapability(value,Time),value,output); return output.ToArray();}
        public Task<FinalStoredDocument> WriteFixed()
        {
            Handler.Fixed=true;var hash=SHA256.HashData(Bytes);var cap=(ClaimsPrincipal)typeof(IBlobStore).Assembly.GetType("QuillSign.Storage.CompletionFinalCapability",true)!
                .GetMethod("WriteFixed",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[Target,(long)Bytes.Length,hash,Until,false,Time])!;
            return Store.WriteAsync(cap,Target,new MemoryStream(Bytes),Bytes.Length,hash,Until);
        }
        public async Task<byte[]> ReadFixed(FinalStoredDocument value)
        {
            var cap=(ClaimsPrincipal)typeof(IBlobStore).Assembly.GetType("QuillSign.Storage.CompletionFinalCapability",true)!
                .GetMethod("ReadFixed",BindingFlags.Static|BindingFlags.NonPublic)!.Invoke(null,[value,Until,Time])!;
            using var bytes=new MemoryStream();await Store.ReadAsync(cap,value,bytes);return bytes.ToArray();
        }
        public void Dispose()=>Handler.Dispose();
    }
    private sealed class Handler(SealFixtures.Clock time) : HttpMessageHandler
    {
        public string Mode="locked"; public string? ReadFault; public bool Public,VersionSupport=true,LoseCommit; public int Commits;
        public bool Fixed,LoseLock,KeepUnlocked,DenyLock;public int Locks;public DateTimeOffset? RequestedUntil;public Action? AfterBlock;
        public List<(HttpMethod Method,string Comp,bool Container)> Requests=[];
        private readonly Dictionary<string,byte[]> blocks=[]; private readonly Dictionary<string,byte[]> objects=[]; private readonly object sync=new();
        private readonly DateTimeOffset expires=time.GetUtcNow().AddDays(30),created=time.GetUtcNow();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            var query=QueryHelpers.ParseQuery(request.RequestUri!.Query); var comp=query.TryGetValue("comp",out var operation) ? operation.ToString() : "";
            var container=query.TryGetValue("restype",out var type) && type=="container"; var path=request.RequestUri.AbsolutePath;
            lock(sync)Requests.Add((request.Method,comp,container));
            if(container) {
                Assert.True(request.Method==HttpMethod.Head || request.Method==HttpMethod.Get); var response=Response(HttpStatusCode.OK,[],0);
                response.Headers.TryAddWithoutValidation("x-ms-immutable-storage-with-versioning-enabled",VersionSupport ? "true" : "false");
                response.Headers.TryAddWithoutValidation("x-ms-has-immutability-policy","true"); response.Headers.TryAddWithoutValidation("x-ms-has-legal-hold","false");
                if(Public)response.Headers.TryAddWithoutValidation("x-ms-blob-public-access","blob"); return response;
            }
            if(request.Method==HttpMethod.Put && comp=="block") {
                Assert.False(request.Headers.Contains("x-ms-immutability-policy-until-date")); Assert.False(request.Headers.Contains("x-ms-legal-hold"));
                var bytes=await request.Content!.ReadAsByteArrayAsync(ct); lock(sync)blocks[path+":"+query["blockid"]]=bytes;AfterBlock?.Invoke();return Response(HttpStatusCode.Created,[],0);
            }
            if(request.Method==HttpMethod.Put && comp=="blocklist") {
                if(Fixed) {
                    Assert.Equal("locked",request.Headers.GetValues("x-ms-immutability-policy-mode").Single(),ignoreCase:true);
                    RequestedUntil=DateTimeOffset.Parse(request.Headers.GetValues("x-ms-immutability-policy-until-date").Single(),System.Globalization.CultureInfo.InvariantCulture);
                } else Assert.False(request.Headers.Contains("x-ms-immutability-policy-until-date"));
                Assert.Contains("*",request.Headers.GetValues("If-None-Match")); var xml=XDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
                lock(sync) {
                    if(objects.ContainsKey(path))return Error(HttpStatusCode.PreconditionFailed,"BlobAlreadyExists");
                    objects[path]=xml.Root!.Elements().SelectMany(x=>blocks[path+":"+x.Value]).ToArray(); Commits++;
                    if(LoseCommit) {LoseCommit=false; return Error(HttpStatusCode.InternalServerError,"SyntheticLostCommitResponse");}
                }
                return Response(HttpStatusCode.Created,[],0);
            }
            if(request.Method==HttpMethod.Put && comp=="immutabilityPolicies") {
                Assert.True(Fixed);Assert.Equal("synthetic-version",query["versionid"].ToString());Assert.True(request.Headers.Contains("If-Unmodified-Since"));Assert.False(request.Headers.Contains("If-Match"));
                var until=DateTimeOffset.Parse(request.Headers.GetValues("x-ms-immutability-policy-until-date").Single(),System.Globalization.CultureInfo.InvariantCulture);Assert.Equal(RequestedUntil,until);Locks++;
                if(DenyLock)return Error(HttpStatusCode.Forbidden,"AuthorizationPermissionMismatch");if(!KeepUnlocked)Mode="locked";
                if(LoseLock) {LoseLock=false;return Error(HttpStatusCode.InternalServerError,"SyntheticLostLockResponse");}
                var locked=Response(HttpStatusCode.OK,[],0);locked.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date",until.UtcDateTime.ToString("R"));locked.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode",Mode);return locked;
            }
            byte[] data; lock(sync) {if(!objects.TryGetValue(path,out var bytes))return Error(HttpStatusCode.NotFound,"BlobNotFound"); data=bytes.ToArray();}
            Assert.True(request.Method==HttpMethod.Head || request.Method==HttpMethod.Get);
            var returned=data;
            if(request.Method==HttpMethod.Get) {
                if(ReadFault=="body")returned=[..data[..^1],(byte)(data[^1]^1)]; else if(ReadFault=="truncated")returned=data[..^1]; else if(ReadFault=="extra")returned=[..data,0];
            }
            var result=Response(HttpStatusCode.OK,request.Method==HttpMethod.Head ? [] : returned,ReadFault=="length" ? data.Length+1 : data.Length);
            if(Mode!="missing") {
                result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode",Mode=="unlocked" ? "unlocked" : "locked");
                var until=Fixed ? RequestedUntil!.Value.AddSeconds(Mode=="long" ? 1 : Mode=="short" ? -1 : 0) : Mode=="short" ? time.GetUtcNow().AddDays(1) : expires;
                result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date",until.UtcDateTime.ToString("R"));
            }
            result.Headers.TryAddWithoutValidation("x-ms-legal-hold",Mode=="hold" ? "true" : "false"); return result;
        }
        private HttpResponseMessage Response(HttpStatusCode status,byte[] body,int length)
        {
            var response=new HttpResponseMessage(status) {Content=new ByteArrayContent(body)}; response.Content.Headers.ContentLength=length; response.Content.Headers.ContentType=new("application/pdf");
            response.Headers.TryAddWithoutValidation("ETag",ReadFault=="etag" ? "\"different\"" : "\"synthetic-etag\"");
            response.Headers.TryAddWithoutValidation("Last-Modified",created.UtcDateTime.ToString("R")); response.Headers.TryAddWithoutValidation("x-ms-creation-time",created.UtcDateTime.ToString("R"));
            response.Headers.TryAddWithoutValidation("x-ms-version-id",ReadFault=="version" ? "different" : "synthetic-version"); response.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");
            response.Headers.TryAddWithoutValidation("x-ms-request-id","synthetic-no-agreement"); response.Headers.TryAddWithoutValidation("x-ms-version","2023-11-03"); return response;
        }
        private static HttpResponseMessage Error(HttpStatusCode status,string code)=>new(status) {Content=new StringContent($"<Error><Code>{code}</Code><Message>Synthetic NO AGREEMENT storage response.</Message></Error>",Encoding.UTF8,"application/xml")};
    }
}
