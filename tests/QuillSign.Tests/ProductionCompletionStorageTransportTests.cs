using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Data;
using QuillSign.Lifecycle;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionCompletionStorageTransportTests
{
    [Theory]
    [InlineData("candidate")][InlineData("input")][InlineData("executed")][InlineData("certificate")][InlineData("forever")]
    public async Task Exact_owned_object_consumes_fixed_mutations_and_reads_pinned_bytes_and_protection(string kind)
    {
        using var p=new Provider(kind:kind);var result=await p.Store.WriteAsync(p.Plan,p.Fence);
        Assert.All(p.Plan.Blocks,id=>Assert.Equal(32,Convert.FromBase64String(id).Length));
        Assert.Equal(1,p.Stages);Assert.Equal(1,p.Commits);Assert.Equal(p.Plan.Effect.Requests.ToArray(),p.Fence.Consumed.ToArray());Assert.Equal(p.Fence.Consumed,p.Fence.Acknowledged);
        Assert.True(p.Fence.Demands>p.Calls.Count*2);Assert.Equal(p.Plan.Final,result.Final is not null);
        if(p.Plan.Final){Assert.Null(result.Receipt);Assert.Equal(p.Plan.FinalTarget,result.Final!.Document);Assert.Equal(p.Plan.Until,result.Final.ProtectedUntil);}
        else{Assert.NotNull(result.Receipt);Assert.Equal(p.Plan.Item,result.Receipt.Item);Assert.Null(result.Final);}
        var readonlyPlan=p.Plan.Final?ProductionCompletionStoragePlan.ReadFinal(p.Scope,p.Context,p.Plan.Effect,p.Plan.FinalTarget!.Value,p.Plan.Until):
            ProductionCompletionStoragePlan.ReadObject(p.Scope,p.Context,p.Plan.Effect,p.Plan.Item!);
        Assert.False(readonlyPlan.MayWrite);var count=p.Calls.Count;
        await Assert.ThrowsAsync<InvalidDataException>(()=>p.Store.WriteAsync(readonlyPlan,p.Fence));Assert.Equal(count,p.Calls.Count);
        var saved=await p.Store.RecoverAsync(readonlyPlan,p.Fence,result);Assert.Equal(result.Receipt,saved.Receipt);
        Assert.All(p.Calls.Skip(count),x=>Assert.True(x==HttpMethod.Head||x==HttpMethod.Get));Assert.Equal(1,p.Commits);
    }
    [Fact]
    public async Task Fixed_blocks_own_original_bytes_and_a_lost_last_ack_is_readonly_reconciled()
    {
        using var p=new Provider("lost-ack",size:ProductionCompletionStoragePlan.BlockBytes+19);
        var result=await p.Store.WriteAsync(p.Plan,p.Fence);Assert.NotNull(result.Receipt);Assert.Equal(2,p.Stages);Assert.Equal(1,p.Commits);
        Assert.Equal(3,p.Fence.Consumed.Count);Assert.Equal(p.Fence.Consumed,p.Fence.Acknowledged);
    }
    [Theory]
    [InlineData("bytes")][InlineData("length")][InlineData("owner")][InlineData("missing-owner")][InlineData("version")]
    [InlineData("etag")][InlineData("root-race")][InlineData("truncated")][InlineData("overlong")][InlineData("public")]
    public async Task Wrong_bytes_ownership_selector_or_private_state_never_acknowledges_commit(string fault)
    {
        using var p=new Provider(fault);await Assert.ThrowsAsync<InvalidDataException>(()=>p.Store.WriteAsync(p.Plan,p.Fence));
        Assert.Equal(fault=="public"?0:1,p.Commits);Assert.True(p.Fence.Acknowledged.Count<=p.Stages);Assert.Equal(0,p.OtherMutations);
    }
    [Theory]
    [InlineData("hold-race")][InlineData("time-race")][InlineData("mode-race")][InlineData("versioning-off")][InlineData("created-late")][InlineData("created-before")]
    public async Task Protection_and_unchanged_ETag_races_are_rechecked_after_exact_bytes(string fault)
    {
        using var p=new Provider(fault,kind:fault=="hold-race"?"forever":"executed");
        await Assert.ThrowsAsync<InvalidDataException>(()=>p.Store.WriteAsync(p.Plan,p.Fence));Assert.Equal(fault=="versioning-off"?0:1,p.Commits);
        Assert.True(p.Fence.Acknowledged.Count<=p.Stages);Assert.Equal(0,p.OtherMutations);
    }
    [Theory]
    [InlineData("stage-denied")][InlineData("commit-denied")][InlineData("unauthorized")][InlineData("redirect")]
    public async Task Unexpected_failure_or_challenge_has_no_hidden_mutation_retry(string fault)
    {
        using var p=new Provider(fault);
        if(fault is "unauthorized" or "redirect")await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>p.Store.WriteAsync(p.Plan,p.Fence));
        else await Assert.ThrowsAsync<Azure.RequestFailedException>(()=>p.Store.WriteAsync(p.Plan,p.Fence));
        Assert.True(p.Stages<=1);Assert.True(p.Commits<=1);if(fault is "unauthorized" or "redirect")Assert.Single(p.Calls);Assert.Equal(0,p.OtherMutations);
    }
    [Theory]
    [InlineData("before")][InlineData("after-stage")][InlineData("after-commit")][InlineData("stream")]
    public async Task Expired_or_revoked_original_fence_stops_further_IO(string phase)
    {
        using var p=new Provider();if(phase=="before")p.Fence.Refused=true;
        p.After=operation=>{if(operation==phase)p.Fence.Refused=true;};
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>p.Store.WriteAsync(p.Plan,p.Fence));
        Assert.Equal(phase=="before"?0:1,p.Stages);Assert.Equal(phase is "before" or "after-stage"?0:1,p.Commits);
    }
    [Fact]
    public async Task Existing_identical_current_bytes_are_not_a_fresh_attempt_permission()
    {
        using var p=new Provider();p.Exists=true;
        await Assert.ThrowsAsync<InvalidDataException>(()=>p.Store.WriteAsync(p.Plan,p.Fence));Assert.Empty(p.Fence.Consumed);Assert.Equal(0,p.Stages);Assert.Equal(0,p.Commits);
    }

    private sealed class Fence:IProductionCompletionStorageFence
    {
        internal readonly List<string> Consumed=[],Acknowledged=[];internal int Demands;internal bool Refused;
        public Task DemandAsync(CancellationToken ct){ct.ThrowIfCancellationRequested();Demands++;if(Refused)throw new UnauthorizedAccessException("Synthetic original fence ended.");return Task.CompletedTask;}
        public async Task ConsumeMutationAsync(string request,CancellationToken ct){await DemandAsync(ct);Assert.DoesNotContain(request,Consumed);Consumed.Add(request);}
        public async Task AcknowledgeMutationAsync(string request,CancellationToken ct){await DemandAsync(ct);Assert.Contains(request,Consumed);Assert.DoesNotContain(request,Acknowledged);Acknowledged.Add(request);}
    }
    private sealed class Provider:HttpMessageHandler
    {
        internal const string Version="2030-01-01T00:00:00.0000000Z",Tag="\"completion-test\"";
        private readonly byte[] bytes;private readonly string mode;private int versionHeads,rootHeads;
        internal readonly ProductionRecordOperation Scope;internal readonly HoldWitnessCompletionContext Context;
        internal readonly ProductionCompletionStoragePlan Plan;internal readonly Fence Fence=new();
        internal readonly List<HttpMethod> Calls=[];internal int Stages,Commits,OtherMutations;internal bool Exists;
        internal Action<string>? After;internal readonly AzureProductionCompletionStore Store;
        internal Provider(string mode="normal",string kind="candidate",int size=1024)
        {
            this.mode=mode;bytes=Enumerable.Range(0,size).Select(x=>(byte)(x%251)).ToArray();var record=Guid.NewGuid();var operation=Guid.NewGuid();var work=Guid.NewGuid();
            Scope=new(record,operation,"work/"+(int)WorkKind.Sealing,work.ToString("N")+"/attempt/1",0,null,new('a',64),new('b',64),2);
            var slot=kind is "executed" or "certificate" or "forever"?CompletionSlot.PublicationResult:CompletionSlot.Candidate;
            var targets=ProductionCompletionProtocol.Effects(slot).Select(x=>new CompletionEffectTarget(x,Guid.NewGuid())).ToImmutableArray();
            var at=new DateTimeOffset(2030,1,1,0,0,0,TimeSpan.Zero);
            Context=new(slot,operation,3,new('b',64),new('a',64),work,1,at.AddMinutes(10),new('c',64),targets,[],new('d',64),at);
            if(slot==CompletionSlot.PublicationResult)
            {
                var effect=kind=="certificate"?CompletionEffect.PublicationCertificateFinal:CompletionEffect.PublicationExecutedFinal;
                var id=targets.Single(x=>x.Effect==effect).TargetId;
                Plan=ProductionCompletionStoragePlan.OwnFinal(Scope,Context,effect,new(record,kind=="certificate"?FinalDocumentKind.Certificate:FinalDocumentKind.Executed,id),bytes,kind=="forever"?null:at.AddDays(365));
            }
            else
            {
                var effect=kind=="input"?CompletionEffect.CandidateInput:CompletionEffect.CandidatePdf;var id=targets.Single(x=>x.Effect==effect).TargetId;
                Plan=ProductionCompletionStoragePlan.Own(Scope,Context,effect,new(new(record,kind=="input"?DocumentBlobKind.CompletionInput:DocumentBlobKind.CompletionCandidate,id),bytes.Length,Convert.ToHexStringLower(SHA256.HashData(bytes))),bytes);
            }
            Store=new(new("https://storage.example.invalid"),new Credential(),new HttpClientTransport(new HttpClient(this,false)));
        }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            Calls.Add(request.Method);var query=QueryHelpers.ParseQuery(request.RequestUri!.Query);string Q(string k)=>query.TryGetValue(k,out var v)?v.ToString():"";
            Assert.Equal("storage.example.invalid",request.RequestUri.Host);
            if(Q("restype")=="container")
            {
                Assert.Equal(HttpMethod.Get,request.Method);Assert.Equal("/"+Plan.Area,request.RequestUri.AbsolutePath);
                if(mode=="unauthorized"){var denied=Error(HttpStatusCode.Unauthorized,"NoAuthenticationInformation");denied.Headers.TryAddWithoutValidation("WWW-Authenticate","Bearer authorization_uri=\"https://login.microsoftonline.com/organizations/oauth2/authorize\", resource_id=\"https://storage.azure.com\"");return denied;}
                if(mode=="redirect"){var redirect=Reply([],HttpStatusCode.TemporaryRedirect);redirect.Headers.Location=new("https://foreign.example.invalid");return redirect;}
                var config=Reply([]);if(mode=="public")config.Headers.TryAddWithoutValidation("x-ms-blob-public-access","blob");
                config.Headers.TryAddWithoutValidation("x-ms-has-immutability-policy",mode=="versioning-off"?"false":"true");
                config.Headers.TryAddWithoutValidation("x-ms-immutable-storage-with-versioning-enabled",mode=="versioning-off"?"false":"true");return config;
            }
            Assert.Equal("/"+Plan.Area+"/"+Plan.Name,request.RequestUri.AbsolutePath);
            if(request.Method==HttpMethod.Put)
            {
                if(Q("comp")=="block")
                {
                    Assert.Equal(Plan.Blocks[Stages],Q("blockid"));var body=await request.Content!.ReadAsByteArrayAsync(ct);var offset=Stages*ProductionCompletionStoragePlan.BlockBytes;
                    Assert.Equal(bytes.Skip(offset).Take(Math.Min(ProductionCompletionStoragePlan.BlockBytes,bytes.Length-offset)),body);Stages++;
                    if(mode=="stage-denied")return Error(HttpStatusCode.Forbidden,"AuthorizationPermissionMismatch");After?.Invoke("after-stage");return Reply([],HttpStatusCode.Created);
                }
                if(Q("comp")!="blocklist"){OtherMutations++;throw new InvalidOperationException("Unexpected SDK mutation.");}
                Assert.Equal("*",request.Headers.GetValues("If-None-Match").Single());Assert.Equal(Plan.Owner,request.Headers.GetValues("x-ms-meta-quillsign_completion").Single());Commits++;
                if(Plan.Final&&Plan.Until is not null)Assert.Equal("Locked",request.Headers.GetValues("x-ms-immutability-policy-mode").Single(),ignoreCase:true);
                if(Plan.Final&&Plan.Until is null)Assert.Equal("true",request.Headers.GetValues("x-ms-legal-hold").Single(),ignoreCase:true);
                if(mode=="commit-denied")return Error(HttpStatusCode.Forbidden,"AuthorizationPermissionMismatch");Exists=true;After?.Invoke("after-commit");
                if(mode=="lost-ack")throw new HttpRequestException("Synthetic lost last request acknowledgment.");return Reply([],HttpStatusCode.Created);
            }
            Assert.True(request.Method==HttpMethod.Get||request.Method==HttpMethod.Head);if(!Exists)return Error(HttpStatusCode.NotFound,"BlobNotFound");
            if(Q("versionid").Length!=0){Assert.Equal(Version,Q("versionid"));Assert.Equal(Tag,request.Headers.GetValues("If-Match").Single());if(request.Method==HttpMethod.Head)versionHeads++;}else rootHeads++;
            var content=request.Method==HttpMethod.Get?mode=="bytes"?new byte[bytes.Length]:mode=="truncated"?bytes[..^1]:mode=="overlong"?bytes.Concat(new byte[]{1}).ToArray():bytes:[];
            var result=Reply(content);result.Content.Headers.ContentLength=mode=="length"?bytes.Length+1:bytes.Length;
            result.Content.Headers.LastModified=Context.RecordedAt;result.Headers.TryAddWithoutValidation("x-ms-creation-time",(mode=="created-late"?Context.RecordedAt.AddMinutes(2):mode=="created-before"?Context.RecordedAt.AddSeconds(-1):Context.RecordedAt).ToString("R"));
            result.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");result.Headers.TryAddWithoutValidation("ETag",mode=="etag"&&Q("versionid").Length!=0?"\"foreign\"":Tag);
            result.Headers.TryAddWithoutValidation("x-ms-version-id",mode=="version"&&Q("versionid").Length!=0||mode=="root-race"&&rootHeads>=2?"foreign":Version);
            if(mode!="missing-owner")result.Headers.TryAddWithoutValidation("x-ms-meta-quillsign_completion",mode=="owner"?new string('f',64):Plan.Owner);
            if(Plan.Final)
            {
                result.Headers.TryAddWithoutValidation("x-ms-legal-hold",Plan.Until is null&&!(mode=="hold-race"&&versionHeads>=2)?"true":"false");
                if(Plan.Until is {} until)
                {result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date",(mode=="time-race"&&versionHeads>=2?until.AddSeconds(-1):until).ToString("R"));result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode",mode=="mode-race"&&versionHeads>=2?"Unlocked":"Locked");}
            }
            if(request.Method==HttpMethod.Get)After?.Invoke("stream");return result;
        }
        private static HttpResponseMessage Reply(byte[] bytes,HttpStatusCode status=HttpStatusCode.OK)
        {var response=new HttpResponseMessage(status){Content=new ByteArrayContent(bytes)};response.Headers.TryAddWithoutValidation("x-ms-version","2023-11-03");return response;}
        private static HttpResponseMessage Error(HttpStatusCode status,string code)
        {var response=Reply(Encoding.UTF8.GetBytes($"<Error><Code>{code}</Code><Message>Synthetic failure.</Message></Error>"),status);response.Headers.TryAddWithoutValidation("x-ms-error-code",code);return response;}
        protected override void Dispose(bool disposing){if(disposing)Store.Dispose();base.Dispose(disposing);}
    }
    private sealed class Credential:TokenCredential
    {public override AccessToken GetToken(TokenRequestContext context,CancellationToken ct)=>new("synthetic",DateTimeOffset.MaxValue);public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context,CancellationToken ct)=>ValueTask.FromResult(GetToken(context,ct));}
}
