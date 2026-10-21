using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Lifecycle;
using QuillSign.Storage;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class ProductionSignerReviewTransportTests
{
    [Theory]
    [InlineData(DocumentBlobKind.ReviewInput)][InlineData(DocumentBlobKind.Normalized)]
    public async Task Actual_SDK_stage_create_only_commit_and_conditional_exact_version_bytes_produce_a_bound_receipt(DocumentBlobKind kind)
    {
        using var test = new Provider(kind: kind); var receipt = await test.Write(true);
        Assert.Equal(test.Item, receipt.Item); Assert.Equal(Provider.Version, receipt.VersionId); Assert.Equal(Provider.Tag, receipt.ETag);
        Assert.Equal(1, test.Stages); Assert.Equal(1, test.Commits); Assert.True(test.Demands >= test.Requests.Count * 2);
        Assert.All(test.Requests.Where(x => x.Version.Length != 0), x => { Assert.Equal(Provider.Version,x.Version); Assert.Equal(Provider.Tag,x.Match); });
        var count = test.Requests.Count; Assert.Equal(receipt,await test.Write(false,receipt));
        Assert.Equal(1,test.Stages); Assert.Equal(1,test.Commits); Assert.True(test.Requests.Count > count);
    }
    [Fact]
    public async Task Lost_commit_acknowledgement_uses_exact_readback_without_a_second_mutation()
    {
        using var test = new Provider("lost-ack"); var receipt = await test.Write(true);
        Assert.Equal(Provider.Version,receipt.VersionId); Assert.Equal(1,test.Commits); Assert.Equal(1,test.Stages);
    }
    [Fact]
    public async Task Recovery_without_saved_receipt_reads_only_the_prior_attempt_and_never_stages_again()
    {
        using var test = new Provider(); _ = await test.Write(true);
        var receipt = await test.Write(false); Assert.Equal(Provider.Version,receipt.VersionId);
        Assert.Equal(1,test.Stages); Assert.Equal(1,test.Commits);
    }
    [Fact]
    public async Task An_absent_uncertain_write_stays_unknown_and_cannot_be_retried()
    {
        using var test = new Provider(); await Assert.ThrowsAsync<InvalidDataException>(()=>test.Write(false));
        Assert.Equal(0,test.Stages); Assert.Equal(0,test.Commits);
    }
    [Fact]
    public async Task A_new_intent_cannot_adopt_an_already_readable_object()
    {
        using var test = new Provider(); _=await test.Write(true);
        await Assert.ThrowsAsync<InvalidDataException>(()=>test.Write(true)); Assert.Equal(1,test.Stages); Assert.Equal(1,test.Commits);
    }
    [Fact]
    public async Task SDK_failures_have_no_hidden_retry_and_do_not_commit_unverified_bytes()
    {
        using var test = new Provider("stage-failure"); await Assert.ThrowsAsync<RequestFailedException>(()=>test.Write(true));
        Assert.Equal(1,test.Stages); Assert.Equal(0,test.Commits);
    }
    [Fact]
    public async Task Authorization_refusal_at_commit_stops_without_readback_or_a_second_mutation()
    {
        using var test=new Provider("commit-denied");
        await Assert.ThrowsAsync<RequestFailedException>(()=>test.Write(true));
        Assert.Equal(1,test.Commits);Assert.Equal(HttpMethod.Put,test.Requests[^1].Method);
    }
    [Fact]
    public async Task A_provider_redirect_cannot_switch_account_or_borrow_the_same_authority_for_another_target()
    {
        using var test=new Provider("redirect");await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>test.Write(true));
        Assert.Single(test.Requests);Assert.Equal(0,test.Stages);
    }
    [Theory]
    [InlineData("public")]
    [InlineData("wrong-version")]
    [InlineData("wrong-tag")]
    [InlineData("wrong-length")]
    [InlineData("wrong-bytes")]
    [InlineData("missing-version")]
    [InlineData("missing-owner")]
    [InlineData("wrong-owner")]
    [InlineData("root-changed")]
    public async Task Provider_scope_byte_and_selector_changes_cannot_be_acknowledged(string mode)
    {
        using var test = new Provider(mode); await Assert.ThrowsAsync<InvalidDataException>(()=>test.Write(true));
        Assert.True(test.Commits <= 1);
    }
    [Fact]
    public async Task A_stored_receipt_cannot_be_rebound_to_another_current_version()
    {
        using var test = new Provider(); var receipt = await test.Write(true); test.ChangeVersion=true;
        await Assert.ThrowsAsync<InvalidDataException>(()=>test.Write(false,receipt)); Assert.Equal(1,test.Commits);
    }
    [Fact]
    public async Task Source_hash_mismatch_never_commits_and_does_not_delete_attempted_blocks()
    {
        using var test = new Provider("wrong-source");
        await Assert.ThrowsAsync<InvalidDataException>(()=>test.Store.WriteAsync(test.Scope,test.Identity,test.Item,
            new MemoryStream(new byte[Provider.Bytes.Length]),true,null,test.Demand));
        Assert.Equal(0,test.Commits); Assert.DoesNotContain(test.Requests,x=>x.Method==HttpMethod.Delete);
    }
    [Fact]
    public async Task Lost_scope_before_or_after_provider_mutation_stops_without_readback_or_replay()
    {
        using var test = new Provider(); test.Refuse=true;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>test.Write(true)); Assert.Empty(test.Requests);
        test.Refuse=false; test.RefuseAfterCommit=true;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>test.Write(true));
        Assert.Equal(1,test.Commits); Assert.Equal(1,test.Stages);
        Assert.DoesNotContain(test.Requests,x=>x.Version.Length!=0);
    }
    [Fact]
    public async Task Invalid_scope_or_configured_bounds_fail_before_any_provider_request()
    {
        using var test = new Provider();
        var foreign=test.Item with { Blob=test.Item.Blob with { EnvelopeId=Guid.NewGuid() } };
        await Assert.ThrowsAsync<InvalidDataException>(()=>test.Store.WriteAsync(test.Scope with {RecordId=foreign.Blob.EnvelopeId},test.Identity,foreign,new MemoryStream(Provider.Bytes),true,null,test.Demand));
        await Assert.ThrowsAsync<InvalidDataException>(()=>test.Store.WriteAsync(test.Scope,test.Identity,test.Item with { Length=ProductionReviewInputCodec.MaximumCipherBytes+1 },new MemoryStream(Provider.Bytes),true,null,test.Demand));
        Assert.Empty(test.Requests);
    }

    internal sealed record Request(HttpMethod Method,string Version,string Match);
    [Theory]
    [InlineData(DocumentBlobKind.Original)][InlineData(DocumentBlobKind.Signature)]
    public async Task Sender_upload_or_Send_object_kinds_cannot_use_the_distinct_mark_store(DocumentBlobKind kind)
    {
        using var test = new Provider(kind: kind); await Assert.ThrowsAsync<InvalidDataException>(() => test.Write(true)); Assert.Empty(test.Requests);
    }
    [Fact]
    public async Task Original_session_expiry_before_or_after_commit_stops_without_retry_or_cleanup()
    {
        using var test = new Provider(); test.Clock.Now = test.Identity.SessionExpiresAt;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => test.Write(true)); Assert.Empty(test.Requests);
        test.Clock.Now = test.Identity.SessionExpiresAt.AddMinutes(-1); test.ExpireAfterCommit = true;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => test.Write(true)); Assert.Equal(1, test.Commits);
        Assert.DoesNotContain(test.Requests, x => x.Method == HttpMethod.Delete || x.Version.Length != 0);
    }
    internal sealed class Provider(string mode="normal", DocumentBlobKind kind=DocumentBlobKind.ReviewInput,
        ProductionRecordWriteDescriptor? suppliedItem=null, ProductionRecordOperation? suppliedScope=null,
        VerifiedSigner? suppliedIdentity=null, ProductionHoldWitnessJournalTests.Clock? suppliedClock=null, byte[]? suppliedBytes=null) : HttpMessageHandler
    {
        internal static readonly byte[] Bytes=SignaturePng.Normalize(SignatureAdoptionTests.Mark()).Bytes;
        internal const string Version="2030-01-01T00:00:00.0000000Z",Tag="\"synthetic-upload-etag\"";
        private readonly byte[] content=suppliedBytes?.ToArray()??Bytes;
        internal readonly ProductionRecordWriteDescriptor Item=suppliedItem??new(new(Guid.NewGuid(),kind,Guid.NewGuid()),Bytes.Length,Convert.ToHexStringLower(SHA256.HashData(Bytes)));
        internal readonly List<Request> Requests=[];
        private readonly Guid operationId=Guid.NewGuid();
        internal ProductionRecordOperation Scope=>suppliedScope??new(Item.Blob.EnvelopeId,operationId,"signer/review-prepare","synthetic-upload",0,null,new string('a',64),new string('b',64),2);
        internal int Stages,Commits,Demands; internal bool ChangeVersion,Refuse,RefuseAfterCommit,ExpireAfterCommit;
        private bool exists; private int rootReads;
        private readonly Guid signerId=Guid.NewGuid(), documentId=Guid.NewGuid(), sessionId=Guid.NewGuid();
        internal readonly ProductionHoldWitnessJournalTests.Clock Clock=suppliedClock??new();
        internal VerifiedSigner Identity=>suppliedIdentity??new(Item.Blob.EnvelopeId,"synthetic-preview",signerId,"synthetic-signer@example.invalid",documentId,new('a',64),new('b',64),new DateTimeOffset(2030,1,1,13,0,0,TimeSpan.Zero)){SessionId=sessionId};
        private AzureProductionSignerReviewStore? store;
        internal AzureProductionSignerReviewStore Store=>store??=new(new Uri("https://storage.example.invalid"),new Credential(),Clock,new HttpClientTransport(new HttpClient(this,false)));
        internal Task Demand(CancellationToken ct)
        { ct.ThrowIfCancellationRequested();Demands++;if(Refuse||RefuseAfterCommit&&Commits>0)throw new UnauthorizedAccessException("Synthetic operation frozen.");return Task.CompletedTask; }
        internal Task<ProductionRecordWriteReceipt> Write(bool mayWrite,ProductionRecordWriteReceipt? saved=null)
            =>Store.WriteAsync(Scope,Identity,Item,new MemoryStream(content,false),mayWrite,saved,Demand);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
        {
            Assert.Equal("storage.example.invalid",request.RequestUri!.Host);
            var query=QueryHelpers.ParseQuery(request.RequestUri.Query);string Q(string key)=>query.TryGetValue(key,out var value)?value.ToString():"";
            var match=request.Headers.TryGetValues("If-Match",out var values)?values.Single():"";
            Requests.Add(new(request.Method,Q("versionid"),match));
            if(Q("restype")=="container")
            {
                Assert.Equal(HttpMethod.Get,request.Method);Assert.Equal("/normalized",request.RequestUri.AbsolutePath);
                if(mode=="redirect"){var redirected=Reply([],HttpStatusCode.TemporaryRedirect);redirected.Headers.Location=new Uri("https://foreign.example.invalid/originals");return redirected;}
                var result=Reply([]);if(mode=="public")result.Headers.TryAddWithoutValidation("x-ms-blob-public-access","blob");return result;
            }
            Assert.Equal("/normalized/"+AzureProductionSignerReviewStore.Path(Item.Blob),request.RequestUri.AbsolutePath);
            if(request.Method==HttpMethod.Put)
            {
                if(Q("comp")=="block")
                {
                    Stages++;var written=await request.Content!.ReadAsByteArrayAsync(ct);if(mode!="wrong-source")Assert.Equal(content,written);
                    if(mode=="stage-failure")return Error(HttpStatusCode.ServiceUnavailable,"ServerBusy");
                    return Reply([],HttpStatusCode.Created);
                }
                Assert.Equal("blocklist",Q("comp"));Assert.Equal("*",request.Headers.GetValues("If-None-Match").Single());
                Assert.Equal(AzureProductionSignerReviewStore.OwnershipBinding(Scope,Identity,Item),request.Headers.GetValues("x-ms-meta-quillsign_signer_review").Single());
                Commits++;if(mode=="commit-denied")return Error(HttpStatusCode.Forbidden,"AuthorizationPermissionMismatch");
                exists=true;if(ExpireAfterCommit)Clock.Now=Identity.SessionExpiresAt;if(mode=="lost-ack")throw new HttpRequestException("Synthetic lost commit acknowledgement.");
                return Reply([],HttpStatusCode.Created);
            }
            Assert.True(request.Method==HttpMethod.Head||request.Method==HttpMethod.Get);
            if(!exists)return Error(HttpStatusCode.NotFound,"BlobNotFound");
            if(Q("versionid").Length==0)rootReads++;
            else {Assert.Equal(Version,Q("versionid"));Assert.Equal(Tag,match);}
            var body=request.Method==HttpMethod.Get?mode=="wrong-bytes"?new byte[content.Length]:content:[];
            var response=Reply(body);response.Content.Headers.ContentLength=mode=="wrong-length"?content.Length+1:content.Length;
            response.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");
            response.Headers.TryAddWithoutValidation("ETag",mode=="wrong-tag"&&Q("versionid").Length>0?"\"changed\"":Tag);
            if(mode!="missing-owner")response.Headers.TryAddWithoutValidation("x-ms-meta-quillsign_signer_review",mode=="wrong-owner"?new string('c',64):AzureProductionSignerReviewStore.OwnershipBinding(Scope,Identity,Item));
            if(mode!="missing-version")response.Headers.TryAddWithoutValidation("x-ms-version-id",ChangeVersion||mode=="wrong-version"&&Q("versionid").Length>0||mode=="root-changed"&&rootReads>=2?"different-version":Version);
            return response;
        }
        private static HttpResponseMessage Reply(byte[] bytes,HttpStatusCode status=HttpStatusCode.OK)
        {
            var result=new HttpResponseMessage(status){Content=new ByteArrayContent(bytes)};
            result.Headers.TryAddWithoutValidation("x-ms-version","2023-11-03");result.Headers.TryAddWithoutValidation("x-ms-request-id","synthetic-upload");return result;
        }
        private static HttpResponseMessage Error(HttpStatusCode status,string code)
        {var result=Reply(Encoding.UTF8.GetBytes($"<Error><Code>{code}</Code><Message>Synthetic upload failure.</Message></Error>"),status);result.Headers.TryAddWithoutValidation("x-ms-error-code",code);return result;}
    }
    private sealed class Credential:TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context,CancellationToken ct)=>new("synthetic-token",DateTimeOffset.MaxValue);
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context,CancellationToken ct)=>ValueTask.FromResult(GetToken(context,ct));
    }
}
