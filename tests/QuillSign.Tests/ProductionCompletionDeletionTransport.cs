using System.Globalization;
using System.Net;
using System.Text;
using System.Xml.Linq;
using System.Security.Claims;
using Azure.Core.Pipeline;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Storage;
using QuillSign.Lifecycle;
using QuillSign.Signing;

namespace QuillSign.Tests;

// Intercepts the real deletion SDK, retaining bytes even after exact API deletion.
// This models API-level soft-deleted facts, never a physical-erasure assertion.
internal sealed class ProductionCompletionDeletionTransport(TimeProvider time):HttpMessageHandler
{
    internal sealed class Entry(HoldObjectAddress address,byte[] bytes,DateTimeOffset? until,bool held)
    {
        internal readonly HoldObjectAddress Address=address;
        internal readonly byte[] Bytes=bytes.ToArray();
        internal readonly DateTimeOffset? Until=until;
        internal readonly bool Held=held;
        internal bool Current=true,Deleted;
    }
    internal readonly Dictionary<string,Entry> Objects=[];
    internal readonly HashSet<string> ListedAreas=[];
    internal readonly HashSet<string> ListedPrefixes=[];
    internal readonly List<(string Path,string Version,string Match)> Deletes=[];
    private readonly Dictionary<string,byte[]> hints=[];
    private readonly HashSet<(string,bool)> attempts=[];
    internal HttpClientTransport Transport()=>new(new HttpClient(this,false));
    internal void Seed(HoldObjectAddress address,byte[] bytes,DateTimeOffset? until=null,bool held=false)
    {
        Assert.Equal(address.Length,bytes.LongLength);Assert.NotEmpty(address.VersionId);Assert.Empty(address.Snapshot);
        Objects.Add("/"+address.Area+"/"+address.Name,new(address,bytes,until,held));
    }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();Assert.Equal("storage.example.invalid",request.RequestUri!.Host);
        var path=Uri.UnescapeDataString(request.RequestUri.AbsolutePath);var query=QueryHelpers.ParseQuery(request.RequestUri.Query);
        string Q(string name)=>query.TryGetValue(name,out var value)?value.ToString():"";
        string H(string name)=>request.Headers.TryGetValues(name,out var value)?value.Single():"";
        var area=path.TrimStart('/').Split('/')[0];
        if(Q("restype")=="container")
        {
            Assert.Equal(HttpMethod.Get,request.Method);
            if(Q("comp")!="list")return Reply([]);
            var prefix=Q("prefix");ListedAreas.Add(area);ListedPrefixes.Add(area+"/"+prefix);
            Assert.Contains("versions",Q("include"));Assert.Contains("snapshots",Q("include"));Assert.Contains("deleted",Q("include"));
            var entries=Objects.Values.Where(x=>x.Address.Area==area&&x.Address.Name.StartsWith(prefix,StringComparison.Ordinal)).OrderBy(x=>x.Address.Name,StringComparer.Ordinal).ToArray();
            Assert.InRange(entries.Length,0,int.Parse(Q("maxresults"),CultureInfo.InvariantCulture));Assert.Empty(Q("marker"));
            var xml=new XDocument(new XElement("EnumerationResults",new XAttribute("ServiceEndpoint","https://storage.example.invalid/"),new XAttribute("ContainerName",area),
                new XElement("Blobs",entries.Select(x=>new XElement("Blob",new XElement("Name",x.Address.Name),new XElement("VersionId",x.Address.VersionId),
                    new XElement("IsCurrentVersion",x.Current&&!x.Deleted),new XElement("Deleted",x.Deleted),new XElement("Properties",
                        new XElement("Content-Length",x.Bytes.LongLength),new XElement("BlobType","BlockBlob"),new XElement("Etag",x.Address.ETag),
                        new XElement("Last-Modified","Tue, 01 Jan 2030 00:00:00 GMT"))))),new XElement("NextMarker")));
            return Reply(Encoding.UTF8.GetBytes(xml.ToString(SaveOptions.DisableFormatting)));
        }
        if(area=="recovery-index")
        {
            Assert.StartsWith("/recovery-index/production-deletion-recovery/",path);
            if(request.Method==HttpMethod.Put)
            {
                Assert.Equal("*",H("If-None-Match"));Assert.False(hints.ContainsKey(path));hints.Add(path,await request.Content!.ReadAsByteArrayAsync(ct));return Reply([],HttpStatusCode.Created);
            }
            if(!hints.TryGetValue(path,out var hint))return Error();
            var response=Reply(request.Method==HttpMethod.Get?hint:[]);response.Content.Headers.ContentLength=hint.Length;
            response.Headers.TryAddWithoutValidation("ETag","\"recovery-hint\"");response.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");return response;
        }
        if(!Objects.TryGetValue(path,out var item))return Error();
        var version=Q("versionid");var root=version.Length==0;
        if(item.Deleted||root&&!item.Current)return Error();
        if(!root)Assert.Equal(item.Address.VersionId,version);
        if(H("If-Match").Length>0)Assert.Equal(item.Address.ETag,H("If-Match"));
        if(request.Method==HttpMethod.Delete)
        {
            Assert.Equal(item.Address.ETag,H("If-Match"));Assert.Empty(Q("snapshot"));Assert.Equal("",H("x-ms-delete-snapshots"));
            Assert.False(item.Held);Assert.True(item.Until is null||item.Until<=time.GetUtcNow());Assert.True(attempts.Add((path,root)));
            if(root){Assert.True(item.Current);item.Current=false;}else{Assert.False(item.Current);item.Deleted=true;}
            Deletes.Add((path,version,H("If-Match")));return Reply([],HttpStatusCode.Accepted);
        }
        Assert.True(request.Method==HttpMethod.Get||request.Method==HttpMethod.Head);
        var result=Reply(request.Method==HttpMethod.Get?item.Bytes:[]);result.Content.Headers.ContentLength=item.Bytes.LongLength;
        result.Headers.TryAddWithoutValidation("ETag",item.Address.ETag);result.Headers.TryAddWithoutValidation("x-ms-version-id",item.Address.VersionId);
        result.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");result.Headers.TryAddWithoutValidation("x-ms-legal-hold",item.Held?"true":"false");
        if(item.Until is{} until){result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode","Locked");result.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date",until.ToString("R"));}
        return result;
    }
    private static HttpResponseMessage Reply(byte[] bytes,HttpStatusCode status=HttpStatusCode.OK)
    {var response=new HttpResponseMessage(status){Content=new ByteArrayContent(bytes)};response.Headers.TryAddWithoutValidation("x-ms-version","2023-11-03");return response;}
    private static HttpResponseMessage Error()
    {var response=Reply("<Error><Code>BlobNotFound</Code><Message>Synthetic exact API absence.</Message></Error>"u8.ToArray(),HttpStatusCode.NotFound);response.Headers.TryAddWithoutValidation("x-ms-error-code","BlobNotFound");return response;}
}

public sealed class ProductionCompletionHistoricalMemoryTests
{
    [Fact]
    public async Task Original_fixture_clock_preserves_exact_signer_expiry_document_and_internal_capability_boundaries()
    {
        var time=new Clock{Now=DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.AddDays(-400).ToUnixTimeSeconds())};var record=Guid.NewGuid();var document=Guid.NewGuid();
        var signer=new VerifiedSigner(record,Guid.NewGuid().ToString("N"),Guid.NewGuid(),"synthetic@example.invalid",document,new('a',64),new('b',64),time.Now.AddMinutes(10));
        var principal=SignerAccessConfiguration.Principal(signer);var blob=new DocumentBlob(record,DocumentBlobKind.Normalized,document);
        var memory=new ProductionRecordUploadAdmissionTests.Blobs();memory.Objects.Add(blob,[1,2,3]);
        using var destination=new MemoryStream();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>memory.CopyToAsync(principal,blob,destination));
        memory.SignerReadTime=time;Assert.Equal(3,await memory.CopyToAsync(principal,blob,destination));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>memory.CopyToAsync(principal,blob with{ObjectId=Guid.NewGuid()},destination));
        var mark=new DocumentBlob(record,DocumentBlobKind.Signature,Guid.NewGuid());memory.Objects.Add(mark,[4,5]);
        var capability=SignatureAssetCapability.Create(signer,mark,AssetOperation.Read,time);
        Assert.Equal(2,await memory.CopyToAsync(capability,mark,destination));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>memory.CopyToAsync(new ClaimsPrincipal(capability),mark,destination));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>memory.CopyToAsync(capability,mark with{ObjectId=Guid.NewGuid()},destination));
        time.Now=signer.SessionExpiresAt;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>memory.CopyToAsync(principal,blob,destination));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>memory.CopyToAsync(capability,mark,destination));
        Assert.Equal(signer.SessionExpiresAt,SignerAccessConfiguration.ReadIdentity(principal,time.Now.AddSeconds(-1))!.SessionExpiresAt);
    }
    private sealed class Clock:TimeProvider{internal DateTimeOffset Now;public override DateTimeOffset GetUtcNow()=>Now;}
}
