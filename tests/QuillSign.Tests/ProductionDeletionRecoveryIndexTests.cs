using System.Net;
using System.Security.Cryptography;
using System.Text;
using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionDeletionRecoveryIndexTests
{
    [Fact]
    public async Task Encrypted_bounded_storage_only_hint_reopens_after_restart_but_contains_no_delete_authority()
    {
        using var p=new Provider();await p.Index.RememberAsync(p.Scope,p.Hint);Assert.NotNull(p.Bytes);Assert.DoesNotContain(p.Hint.RecordId.ToString(),Encoding.UTF8.GetString(p.Bytes!));
        Assert.Equal(p.Hint,await p.Index.ReadAsync(p.Hint.RecordId,p.Hint.DeletionId));
        using var restarted=p.CreateIndex();Assert.Equal(p.Hint,Assert.Single((await restarted.ListAsync(null,1)).Hints));
        var original=p.Bytes!.ToArray();await p.Index.RememberAsync(p.Scope,p.Hint);Assert.Equal(original,p.Bytes);Assert.All(p.Methods,x=>Assert.True(x==HttpMethod.Get||x==HttpMethod.Head||x==HttpMethod.Put));
    }
    [Theory]
    [InlineData("cipher")][InlineData("future")][InlineData("foreign")][InlineData("oversize")]
    public async Task Changed_unknown_foreign_or_unbounded_hint_never_recovers_an_authorized_scope(string fault)
    {
        using var p=new Provider();await p.Index.RememberAsync(p.Scope,p.Hint);
        if(fault=="cipher")p.Bytes![0]^=1;
        if(fault=="future")p.Bytes=p.Protect($"{{\"Version\":\"production-deletion-recovery-hint-v1\",\"Hint\":{{\"RecordId\":\"{p.Hint.RecordId}\",\"DeletionId\":\"{p.Hint.DeletionId}\",\"PlanSha256\":\"{p.Hint.PlanSha256}\"}},\"Future\":true}}");
        if(fault=="foreign")p.Bytes=p.Protect($"{{\"Version\":\"production-deletion-recovery-hint-v1\",\"Hint\":{{\"RecordId\":\"{Guid.NewGuid()}\",\"DeletionId\":\"{p.Hint.DeletionId}\",\"PlanSha256\":\"{p.Hint.PlanSha256}\"}}}}");
        if(fault=="oversize")p.Bytes=new byte[8193];
        var puts=p.Methods.Count(x=>x==HttpMethod.Put);await Assert.ThrowsAnyAsync<Exception>(()=>p.Index.ReadAsync(p.Hint.RecordId,p.Hint.DeletionId));Assert.Equal(puts,p.Methods.Count(x=>x==HttpMethod.Put));
    }
    [Fact]
    public async Task Foreign_hint_disabled_scope_and_public_container_cannot_publish_a_recovery_marker()
    {
        using var p=new Provider();await Assert.ThrowsAsync<InvalidDataException>(()=>p.Index.RememberAsync(p.Scope,p.Hint with{RecordId=Guid.NewGuid()}));Assert.Empty(p.Methods);
        p.Public=true;await Assert.ThrowsAsync<InvalidDataException>(()=>p.Index.RememberAsync(p.Scope,p.Hint));Assert.DoesNotContain(p.Methods,x=>x==HttpMethod.Put);
        p.Scope.Close();await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>p.Index.RememberAsync(p.Scope,p.Hint));
    }
    [Fact]
    public async Task Unknown_marker_upload_ack_is_only_reconciled_by_exact_readback_without_provider_retry()
    {
        using var p=new Provider{LoseAck=true};await Assert.ThrowsAnyAsync<Exception>(()=>p.Index.RememberAsync(p.Scope,p.Hint));Assert.Single(p.Methods,x=>x==HttpMethod.Put);
        Assert.Equal(p.Hint,await p.Index.ReadAsync(p.Hint.RecordId,p.Hint.DeletionId));Assert.Single(p.Methods,x=>x==HttpMethod.Put);
    }
    private sealed class Provider:HttpMessageHandler
    {
        private static readonly Uri Uri=new("https://storage.example.invalid/private-hints");private const string Installation="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        internal readonly EphemeralDataProtectionProvider Keys=new();internal readonly ProductionDeletionRecoveryHint Hint=new(Guid.NewGuid(),Guid.NewGuid(),new string('b',64));
        internal readonly ProductionDeletionObjectScope Scope;internal readonly AzureProductionDeletionRecoveryIndex Index;internal readonly List<HttpMethod> Methods=[];internal byte[]? Bytes;internal bool Public,LoseAck;
        internal Provider(){var now=TimeProvider.System.GetUtcNow();Scope=ProductionDeletionObjectScope.Create(Hint.RecordId,Hint.DeletionId,[],TimeProvider.System,now.AddMinutes(1),_=>Task.CompletedTask);Index=CreateIndex();}
        internal AzureProductionDeletionRecoveryIndex CreateIndex()=>new(Uri,new Credential(),Keys,Installation,new HttpClientTransport(new HttpClient(this,false)));
        internal byte[] Protect(string json)=>Keys.CreateProtector("production-deletion-recovery-hint-v1",Installation,Uri.AbsoluteUri).Protect(Encoding.UTF8.GetBytes(json));
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r,CancellationToken ct)
        {
            Methods.Add(r.Method);var q=QueryHelpers.ParseQuery(r.RequestUri!.Query);string Q(string n)=>q.TryGetValue(n,out var v)?v.ToString():"";
            if(Q("restype")=="container")
            {
                var result=Reply([]);if(Public)result.Headers.TryAddWithoutValidation("x-ms-blob-public-access","blob");
                if(Q("comp")=="list")result.Content=new StringContent($"<EnumerationResults ServiceEndpoint=\"https://storage.example.invalid/\" ContainerName=\"private-hints\"><Blobs><Blob><Name>production-deletion-recovery/{Installation}/{Hint.RecordId:N}/{Hint.DeletionId:N}</Name><Properties><Content-Length>{Bytes?.Length??0}</Content-Length><BlobType>BlockBlob</BlobType></Properties></Blob></Blobs><NextMarker /></EnumerationResults>");return result;
            }
            if(r.Method==HttpMethod.Put)
            {
                Assert.True(r.Headers.TryGetValues("If-None-Match",out var conditions));Assert.Equal("*",Assert.Single(conditions));if(Bytes is not null)return Error(412,"ConditionNotMet");Bytes=await r.Content!.ReadAsByteArrayAsync(ct);if(LoseAck)throw new IOException("Synthetic marker acknowledgement lost.");var saved=Reply([]);saved.StatusCode=HttpStatusCode.Created;return saved;
            }
            if(Bytes is null)return Error(404,"BlobNotFound");var reply=Reply(r.Method==HttpMethod.Get?Bytes:[]);reply.Content.Headers.ContentLength=Bytes.Length;reply.Headers.TryAddWithoutValidation("ETag","\"hint-etag\"");reply.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");return reply;
        }
        private static HttpResponseMessage Reply(byte[] bytes){var r=new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(bytes)};r.Headers.TryAddWithoutValidation("x-ms-version","2023-11-03");r.Headers.TryAddWithoutValidation("x-ms-request-id","synthetic-index");return r;}
        private static HttpResponseMessage Error(int code,string name){var r=Reply(Encoding.UTF8.GetBytes($"<Error><Code>{name}</Code><Message>Synthetic</Message></Error>"));r.StatusCode=(HttpStatusCode)code;r.Headers.TryAddWithoutValidation("x-ms-error-code",name);return r;}
        protected override void Dispose(bool disposing){if(disposing)Index.Dispose();base.Dispose(disposing);}
    }
    private sealed class Credential:TokenCredential{public override AccessToken GetToken(TokenRequestContext requestContext,CancellationToken ct)=>new("synthetic-index",DateTimeOffset.MaxValue);public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,CancellationToken ct)=>ValueTask.FromResult(GetToken(requestContext,ct));}
}
