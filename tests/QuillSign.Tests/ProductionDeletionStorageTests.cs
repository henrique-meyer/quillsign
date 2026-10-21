using System.Net;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class ProductionDeletionStorageTests
{
    [Theory]
    [InlineData("originals")][InlineData("normalized")][InlineData("previews")][InlineData("final")][InlineData("archive")]
    public async Task Complete_census_keeps_current_versions_snapshots_and_deleted_evidence_inside_exact_prefix(string area)
    {
        using var p=new Provider(area:area);var prefix=area=="archive"?p.Archive:$"{p.Record:N}/";
        var page=await p.Store.ListAsync(p.Scope,p.Item.Area,prefix,null,128);
        Assert.Equal(3,page.Objects.Count);Assert.Contains(page.Objects,x=>x.Deleted);Assert.Contains(page.Objects,x=>x.Snapshot.Length>0);
        Assert.All(page.Objects,x=>Assert.StartsWith(prefix,x.Name));Assert.Contains("deletedwithversions",p.LastIncludes,StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(p.Calls,x=>x.Method==HttpMethod.Delete);
    }
    [Fact]
    public async Task Root_demotion_then_exact_historical_delete_preserves_neighbor_and_reports_only_observed_absence()
    {
        using var p=new Provider();var expected=await p.Store.InspectAsync(p.Scope,p.Item);Assert.Null(expected.ImmutableUntil);Assert.Null(expected.ImmutableMode);
        var demoted=await p.Store.DeleteAsync(p.Scope,expected,ProductionDeletionPhase.RootDemotion);
        Assert.True(demoted.RootAbsent);Assert.False(demoted.Absent);Assert.Equal(expected,demoted.Remaining);Assert.True(p.Exists);
        var removed=await p.Store.DeleteAsync(p.Scope,expected,ProductionDeletionPhase.HistoricalDelete);
        Assert.True(removed.Absent);Assert.False(p.Exists);Assert.Equal(2,p.Calls.Count(x=>x.Method==HttpMethod.Delete));
        Assert.All(p.Calls.Where(x=>x.Method==HttpMethod.Delete),x=>Assert.Equal(Provider.Tag,x.Match));Assert.True(p.Neighbor);
        var late=await p.Store.ListAsync(p.Scope,p.Item.Area,$"{p.Record:N}/",null,128);Assert.NotEmpty(late.Objects); // no permanent-absence inference
    }
    [Fact]
    public async Task Current_explicit_version_cannot_skip_demotion_and_snapshot_is_deleted_without_bulk_snapshot_flag()
    {
        using var p=new Provider();var expected=await p.Store.InspectAsync(p.Scope,p.Item);
        await Assert.ThrowsAsync<InvalidDataException>(()=>p.Store.DeleteAsync(p.Scope,expected,ProductionDeletionPhase.HistoricalDelete));Assert.DoesNotContain(p.Calls,x=>x.Method==HttpMethod.Delete);
        using var snapshot=new Provider(snapshot:true);var saved=await snapshot.Store.InspectAsync(snapshot.Scope,snapshot.Item);
        Assert.True((await snapshot.Store.DeleteAsync(snapshot.Scope,saved,ProductionDeletionPhase.HistoricalDelete)).Absent);
        Assert.All(snapshot.Calls.Where(x=>x.Method==HttpMethod.Delete),x=>{Assert.Equal(Provider.Snapshot,x.Snapshot);Assert.Equal("",x.DeleteSnapshots);});
    }
    [Theory]
    [InlineData("held")][InlineData("immutable")][InlineData("same-etag-hold-race")][InlineData("changed-bytes")][InlineData("changed-etag")]
    [InlineData("missing-legal-hold")][InlineData("unknown-mode")][InlineData("partial-policy")]
    public async Task Fresh_protection_or_byte_selector_change_blocks_before_any_delete(string mode)
    {
        using var p=new Provider();var saved=await p.Store.InspectAsync(p.Scope,p.Item);p.Mode=mode;
        await Assert.ThrowsAsync<InvalidDataException>(()=>p.Store.DeleteAsync(p.Scope,saved,ProductionDeletionPhase.RootDemotion));Assert.DoesNotContain(p.Calls,x=>x.Method==HttpMethod.Delete);
    }
    [Theory]
    [InlineData("before")][InlineData("after-head")][InlineData("stream")][InlineData("expired")][InlineData("backwards")]
    public async Task Original_scope_and_head_are_checked_around_each_await_and_stream_read(string fault)
    {
        using var p=new Provider();if(fault=="before")p.Allowed=false;
        else p.After=phase=>{if(phase==(fault=="stream"?"stream":"head")){if(fault=="expired")p.Time.Now=p.Time.Now.AddMinutes(11);else if(fault=="backwards")p.Time.Now=p.Time.Now.AddTicks(-1);else p.Allowed=false;}};
        await Assert.ThrowsAnyAsync<Exception>(()=>p.Store.InspectAsync(p.Scope,p.Item));Assert.DoesNotContain(p.Calls,x=>x.Method==HttpMethod.Delete);
        Assert.InRange(p.Calls.Count,0,fault=="stream"?2:1);
    }
    [Fact]
    public async Task Lost_delete_ack_is_read_only_reconciled_and_never_replays_provider_mutation()
    {
        using var p=new Provider();var expected=await p.Store.InspectAsync(p.Scope,p.Item);p.Mode="lost-delete-ack";
        await Assert.ThrowsAnyAsync<Exception>(()=>p.Store.DeleteAsync(p.Scope,expected,ProductionDeletionPhase.RootDemotion));Assert.Single(p.Calls,x=>x.Method==HttpMethod.Delete);
        p.Mode="normal";Assert.True((await p.Store.ReadDeleteOutcomeAsync(p.Scope,expected,ProductionDeletionPhase.RootDemotion)).RootAbsent);
        var missing=await Assert.ThrowsAsync<RequestFailedException>(()=>p.Store.DeleteAsync(p.Scope,expected,ProductionDeletionPhase.RootDemotion));Assert.Equal(404,missing.Status);Assert.Single(p.Calls,x=>x.Method==HttpMethod.Delete);
    }
    [Theory]
    [InlineData("foreign-record")][InlineData("foreign-archive")][InlineData("witness-prefix")][InlineData("both-selectors")][InlineData("wildcard")][InlineData("deleted")]
    public async Task Foreign_unknown_or_unreadable_selectors_never_mint_delete_authority(string fault)
    {
        using var p=new Provider();var item=p.Item;
        item=fault switch{"foreign-record"=>item with{Name=$"{Guid.NewGuid():N}/object"},"foreign-archive"=>item with{Area="final",Name=$"production-holds/{p.Record:N}/{Guid.NewGuid():N}/{Guid.NewGuid():N}/sql/{new string('a',64)}"},
            "witness-prefix"=>item with{Name=$"production-hold-witnesses/{p.Record:N}/0001"},"both-selectors"=>item with{Snapshot=Provider.Snapshot},"wildcard"=>item with{ETag="*"},_=>item with{Deleted=true}};
        await Assert.ThrowsAsync<InvalidDataException>(()=>p.Store.InspectAsync(p.Scope,item));Assert.Empty(p.Calls);
    }
    [Theory]
    [InlineData("challenge")][InlineData("redirect")][InlineData("busy")]
    public async Task Authentication_redirect_and_transient_errors_have_no_hidden_provider_retry(string mode)
    {
        using var p=new Provider{Mode=mode};await Assert.ThrowsAnyAsync<Exception>(()=>p.Store.InspectAsync(p.Scope,p.Item));Assert.Single(p.Calls);
    }
    [Fact]
    public async Task Scope_owns_archive_prefixes_closes_and_rejects_arbitrary_or_unbounded_paths()
    {
        using var p=new Provider();var prefixes=new[]{p.Archive};var scope=ProductionDeletionObjectScope.Create(p.Record,Guid.NewGuid(),prefixes,p.Time,p.Time.Now.AddMinutes(1),_=>Task.CompletedTask);
        prefixes[0]="unrelated/";Assert.Equal(p.Archive,Assert.Single(scope.ArchivePrefixes));scope.Close();await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>scope.DemandAsync());
        Assert.Throws<InvalidDataException>(()=>ProductionDeletionObjectScope.Create(p.Record,Guid.NewGuid(),["production-holds/"],p.Time,p.Time.Now.AddMinutes(1),_=>Task.CompletedTask));
    }
    private sealed class Clock:TimeProvider{internal DateTimeOffset Now=new(2031,1,1,0,0,0,TimeSpan.Zero);public override DateTimeOffset GetUtcNow()=>Now;}
    private sealed record Call(HttpMethod Method,string Version,string Snapshot,string Match,string DeleteSnapshots);
    private sealed class Provider:HttpMessageHandler
    {
        internal const string Tag="\"synthetic-delete-tag\"",Version="2030-01-01T00:00:00.0000000Z",Snapshot="2030-01-01T01:00:00.0000000Z";
        internal readonly Guid Record=Guid.NewGuid();internal readonly Clock Time=new();internal readonly string Archive;
        internal readonly ProductionDeletionObject Item;internal readonly ProductionDeletionObjectScope Scope;internal readonly AzureProductionDeletionStore Store;
        internal readonly List<Call> Calls=[];internal string LastIncludes="",Mode="normal";internal bool Current=true,Exists=true,Neighbor=true,Allowed=true;internal Action<string>? After;
        private readonly byte[] bytes=Encoding.UTF8.GetBytes("SYNTHETIC PRODUCTION DELETE NO AGREEMENT");private int heads;
        internal Provider(string area="normalized",bool snapshot=false)
        {
            Archive=$"production-holds/{Record:N}/{Guid.NewGuid():N}/{Guid.NewGuid():N}/";
            Item=new(area=="archive"?"final":area,area=="archive"?Archive+"sql/"+new string('a',64):$"{Record:N}/{Guid.NewGuid():N}",snapshot?"":Version,snapshot?Snapshot:"",Tag,bytes.Length,!snapshot,false,false);
            Scope=ProductionDeletionObjectScope.Create(Record,Guid.NewGuid(),[Archive],Time,Time.Now.AddMinutes(10),ct=>{ct.ThrowIfCancellationRequested();if(!Allowed)throw new UnauthorizedAccessException();return Task.CompletedTask;});
            Store=new(new("https://storage.example.invalid"),new Credential(),new HttpClientTransport(new HttpClient(this,false)));
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage r,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();var q=QueryHelpers.ParseQuery(r.RequestUri!.Query);string Q(string n)=>q.TryGetValue(n,out var v)?v.ToString():"";
            var match=r.Headers.TryGetValues("If-Match",out var m)?m.Single():"";Calls.Add(new(r.Method,Q("versionid"),Q("snapshot"),match,r.Headers.TryGetValues("x-ms-delete-snapshots",out var ds)?ds.Single():""));
            if(Mode=="challenge"){var x=Error(401,"AuthenticationFailed");x.Headers.TryAddWithoutValidation("WWW-Authenticate","Bearer authorization_uri=https://login.example.invalid/synthetic/oauth2/authorize resource_id=https://storage.azure.com");return Task.FromResult(x);}
            if(Mode=="redirect"){var x=Reply([]);x.StatusCode=HttpStatusCode.TemporaryRedirect;x.Headers.Location=new("https://foreign.example.invalid");return Task.FromResult(x);}
            if(Mode=="busy")return Task.FromResult(Error(503,"ServerBusy"));
            if(Q("restype")=="container")
            {
                if(Q("comp")=="list")
                {
                    LastIncludes=Q("include");var prefix=Q("prefix");var name=Item.Name;
                    var xml=$"<EnumerationResults ServiceEndpoint=\"https://storage.example.invalid/\" ContainerName=\"{Item.Area}\"><Prefix>{prefix}</Prefix><Blobs>"+
                        Entry(name,Version,"",false)+Entry(name,"",Snapshot,false)+Entry(prefix+"deleted",Version,"",true)+"</Blobs><NextMarker /></EnumerationResults>";
                    return Task.FromResult(Reply(Encoding.UTF8.GetBytes(xml)));
                }
                return Task.FromResult(Reply([]));
            }
            var root=Q("versionid")==""&&Q("snapshot")=="";
            if(!Exists||root&&!Current)return Task.FromResult(Error(404,"BlobNotFound"));
            if(r.Method==HttpMethod.Delete)
            {
                Assert.Equal(Tag,match);if(root&&Item.VersionId.Length>0)Current=false;else Exists=false;
                if(Mode=="lost-delete-ack")throw new IOException("Synthetic deletion committed but acknowledgement lost.");
                var deleted=Reply([]);deleted.StatusCode=HttpStatusCode.Accepted;return Task.FromResult(deleted);
            }
            Assert.Equal(Tag,match==""?Tag:match);var isHead=r.Method==HttpMethod.Head;if(isHead)heads++;
            var content=Mode=="changed-bytes"?new byte[bytes.Length]:bytes;
            var response=Reply([]);if(!isHead)response.Content=new StreamContent(new Observed(content,()=>After?.Invoke("stream")));
            response.Content.Headers.ContentLength=bytes.Length;response.Headers.TryAddWithoutValidation("ETag",Mode=="changed-etag"?"\"changed\"":Tag);
            if(Item.VersionId.Length>0)response.Headers.TryAddWithoutValidation("x-ms-version-id",Version);
            response.Headers.TryAddWithoutValidation("x-ms-blob-type","BlockBlob");if(Mode!="missing-legal-hold")response.Headers.TryAddWithoutValidation("x-ms-legal-hold",Mode=="held"||Mode=="same-etag-hold-race"&&heads>1?"true":"false");
            if(Mode is "immutable" or "unknown-mode" or "partial-policy"){response.Headers.TryAddWithoutValidation("x-ms-immutability-policy-mode",Mode=="unknown-mode"?"Future":"Locked");if(Mode!="partial-policy")response.Headers.TryAddWithoutValidation("x-ms-immutability-policy-until-date","Wed, 01 Jan 2031 01:00:00 GMT");}
            After?.Invoke(isHead?"head":"download");return Task.FromResult(response);
        }
        private static string Entry(string name,string version,string snapshot,bool deleted)=>$"<Blob><Name>{name}</Name><VersionId>{version}</VersionId><Snapshot>{snapshot}</Snapshot><IsCurrentVersion>{(!deleted&&snapshot=="").ToString().ToLowerInvariant()}</IsCurrentVersion><Deleted>{deleted.ToString().ToLowerInvariant()}</Deleted><Properties><Content-Length>39</Content-Length><BlobType>BlockBlob</BlobType><Etag>{Tag}</Etag><Last-Modified>Tue, 01 Jan 2030 00:00:00 GMT</Last-Modified></Properties></Blob>";
        private static HttpResponseMessage Reply(byte[] value){var r=new HttpResponseMessage(HttpStatusCode.OK){Content=new ByteArrayContent(value)};r.Headers.TryAddWithoutValidation("x-ms-version","2023-11-03");r.Headers.TryAddWithoutValidation("x-ms-request-id","synthetic-deletion");return r;}
        private static HttpResponseMessage Error(int code,string name){var r=Reply(Encoding.UTF8.GetBytes($"<Error><Code>{name}</Code><Message>Synthetic deletion failure</Message></Error>"));r.StatusCode=(HttpStatusCode)code;r.Headers.TryAddWithoutValidation("x-ms-error-code",name);return r;}
        protected override void Dispose(bool disposing){if(disposing)Store.Dispose();base.Dispose(disposing);}
    }
    private sealed class Observed(byte[] bytes,Action read):MemoryStream(bytes,false)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,CancellationToken ct=default){read();return base.ReadAsync(buffer,ct);}
        public override Task<int> ReadAsync(byte[] buffer,int offset,int count,CancellationToken ct){read();return base.ReadAsync(buffer,offset,count,ct);}
        public override int Read(byte[] buffer,int offset,int count){read();return base.Read(buffer,offset,count);}
        public override int Read(Span<byte> buffer){read();return base.Read(buffer);}
    }
    private sealed class Credential:TokenCredential{public override AccessToken GetToken(TokenRequestContext requestContext,CancellationToken ct)=>new("synthetic-delete",DateTimeOffset.MaxValue);public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,CancellationToken ct)=>ValueTask.FromResult(GetToken(requestContext,ct));}
}
