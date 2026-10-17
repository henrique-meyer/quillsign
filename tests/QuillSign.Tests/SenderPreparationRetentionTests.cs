using System.Data.Common;
using System.Net;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Signing;
using Retained=QuillSign.Tests.SenderDocumentRetentionTests.Retained;

namespace QuillSign.Tests;

public sealed class SenderPreparationRetentionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("signers",-1)][InlineData("signers",0)][InlineData("signers",1)]
    [InlineData("details",-1)][InlineData("details",0)][InlineData("details",1)]
    [InlineData("fields",-1)][InlineData("fields",0)][InlineData("fields",1)]
    [InlineData("review",-1)][InlineData("review",0)][InlineData("review",1)]
    public async Task All_preparation_snapshots_observe_the_exact_cutoff_without_mutating(string kind,long ticks)
    {
        await using var r=await Start();var before=await r.H.StateAsync();var reads=r.H.Store.Reads;r.Clock.Now=r.Policy.DeleteAfter.AddTicks(ticks);
        if(ticks<0)Assert.NotNull(await Read(r,kind));else await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Read(r,kind));
        Assert.Equal(before.RowVersion,(await r.H.StateAsync()).RowVersion);Assert.Equal(2,await r.AuditCount());Assert.Equal(reads,r.H.Store.Reads);
    }
    [Theory]
    [InlineData("signers")][InlineData("details")][InlineData("fields")][InlineData("review")]
    public async Task Private_collection_read_crossing_cutoff_cannot_return_a_snapshot(string kind)
    {
        await using var r=await Start();var before=await r.H.StateAsync();var cross=new CrossRead(kind=="details" ? "[Recipients]" : kind=="signers" ? "[Signers]" : "[Fields]",()=>r.Clock.Now=r.Policy.DeleteAfter);
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Read(r,kind,cross:cross));Assert.True(cross.Calls>0);Assert.Equal(before.RowVersion,(await r.H.StateAsync()).RowVersion);Assert.Equal(2,await r.AuditCount());
    }
    [Theory]
    [InlineData("signers")][InlineData("details")][InlineData("fields")]
    public async Task Audit_crossing_cutoff_rolls_back_preparation_mutation_and_its_evidence(string kind)
    {
        await using var r=await Start();var before=await r.H.StateAsync();r.H.AuditFailure.AfterInsert=()=>r.Clock.Now=r.Policy.DeleteAfter;
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Change(r,kind,before));var after=await r.H.StateAsync();Assert.Equal(before.RowVersion,after.RowVersion);Assert.Equal(before.Title,after.Title);Assert.Equal(2,await r.AuditCount());
        await using var db=fixture.Open();Assert.Single(await db.Signers.Where(x=>x.EnvelopeId==before.Id).ToArrayAsync());Assert.Single(await db.Fields.Where(x=>x.EnvelopeId==before.Id).ToArrayAsync());
    }
    [Theory]
    [InlineData("missing")][InlineData("policy")][InlineData("provenance")]
    public async Task Corrupt_enrollment_fails_privately_only_after_full_sender_authorization(string kind)
    {
        await using var r=await Start();var before=await r.H.StateAsync();var reads=r.H.Store.Reads;await using(var db=fixture.Open())
        {
            if(kind=="missing")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==before.Id).ExecuteDeleteAsync();
            else if(kind=="policy")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==before.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Days,8).SetProperty(x=>x.DeleteAfter,r.Policy.StartedAt.AddDays(8)));
            else await db.AuditEvents.Where(x=>x.EnvelopeId==before.Id && x.Event=="document_uploaded").ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));
        }
        var wrong=SenderConfiguration.Principal(new(before.Id,before.PublicId,"other@example.invalid"));
        foreach(var service in new[]{"signers","details","fields","review"})
        {Assert.Null(await Read(r,service,wrong));await Assert.ThrowsAsync<PreparationRetentionEvidenceException>(()=>Read(r,service));}
        Assert.Equal(before.RowVersion,(await r.H.StateAsync()).RowVersion);Assert.Equal(reads,r.H.Store.Reads);
    }
    [Theory]
    [InlineData("signers")][InlineData("details")][InlineData("fields")][InlineData("review")]
    public async Task Public_preparation_returns_private_unavailable_or_verification_failure_without_details(string kind)
    {
        await using var b=await SenderDocumentRetentionTests.BrowserSession.Start(fixture);var e=await b.run.H.StateAsync();Assert.True(await b.run.H.WithAsync(w=>w.ConfirmAsync(b.run.H.Sender,e.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default)));
        using(var auth=await b.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,auth.StatusCode);
        // Review may need unrelated Send configuration in this minimal host; the retention failure precedes it.
        b.Expire();using(var auth=await b.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,auth.StatusCode);
        using(var response=await b.Get(b.Path+"/"+kind)) {Assert.Equal(HttpStatusCode.Gone,response.StatusCode);Assert.True(response.Headers.CacheControl!.NoStore);Assert.Contains("no-referrer",response.Headers.GetValues("Referrer-Policy"));var text=await response.Content.ReadAsStringAsync();Assert.DoesNotContain(e.SenderEmail,text);Assert.DoesNotContain(e.Title!,text);Assert.DoesNotContain("<form",text);}
    }
    private async Task<Retained> Start()
    {
        var r=await Retained.Create(fixture);var e=await r.H.StateAsync();Assert.True(await r.H.WithAsync(w=>w.ConfirmAsync(r.H.Sender,e.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default)));
        await using var db=fixture.Open();db.Signers.Add(new(){EnvelopeId=e.Id,FullName="Synthetic signer",Email="signer@example.invalid",Order=1});db.Recipients.Add(new(){EnvelopeId=e.Id,Name="Synthetic recipient",Email="recipient@example.invalid"});db.Fields.Add(new(){EnvelopeId=e.Id,Type=FieldType.Text,Page=1,X=.1m,Y=.1m,Width=.3m,Height=.1m,Value="SYNTHETIC ONLY"});await db.SaveChangesAsync();return r;
    }
    [Fact]
    public async Task Cancellation_grants_no_snapshot_and_a_fresh_explicit_read_recovers()
    {
        await using var r=await Start();var before=await r.H.StateAsync();using var cancel=new CancellationTokenSource();cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>Read(r,"review",ct:cancel.Token));Assert.Equal(before.RowVersion,(await r.H.StateAsync()).RowVersion);Assert.Equal(2,await r.AuditCount());Assert.NotNull(await Read(r,"review"));
    }
    [Fact]
    public async Task Retention_never_extends_an_earlier_expired_sender_cookie()
    {
        await using var b=await SenderDocumentRetentionTests.BrowserSession.Start(fixture);using(var auth=await b.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,auth.StatusCode);
        b.run.Clock.Now=b.run.Clock.Now.AddHours(3);Assert.True(b.run.Clock.Now<b.DeleteAfter);using var response=await b.Get(b.Path+"/details",true);Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);Assert.DoesNotContain(b.run.H.Email,await response.Content.ReadAsStringAsync());Assert.Equal(1,await b.run.AuditCount());
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Field_API_preserves_CSRF_and_returns_private_expiry_or_unverifiable_policy(bool missing)
    {
        await using var b=await SenderDocumentRetentionTests.BrowserSession.Start(fixture);var e=await b.run.H.StateAsync();Assert.True(await b.run.H.WithAsync(w=>w.ConfirmAsync(b.run.H.Sender,e.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default)));
        using(var auth=await b.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,auth.StatusCode);string page;using(var get=await b.Get(b.Path+"/fields")){Assert.Equal(HttpStatusCode.OK,get.StatusCode);page=await get.Content.ReadAsStringAsync();}e=await b.run.H.StateAsync();var save=new FieldSave(Convert.ToBase64String(e.RowVersion),e.PdfBlob!,[]);
        if(missing){await using var db=fixture.Open();await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==e.Id).ExecuteDeleteAsync();}else b.Expire();
        using(var auth=await b.Get("/test-session"))Assert.Equal(HttpStatusCode.OK,auth.StatusCode);
        using(var csrf=await b.SaveFields(page,save,false))Assert.Equal(HttpStatusCode.BadRequest,csrf.StatusCode);
        using(var response=await b.SaveFields(page,save)) {Assert.Equal(missing ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Gone,response.StatusCode);Assert.True(response.Headers.CacheControl!.NoStore);Assert.Contains("no-referrer",response.Headers.GetValues("Referrer-Policy"));var text=await response.Content.ReadAsStringAsync();Assert.DoesNotContain(e.SenderEmail,text);Assert.DoesNotContain(e.Title!,text);}
        using(var response=await b.Get(b.Path+"/details",true)){Assert.Equal(missing ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.Gone,response.StatusCode);Assert.Equal("application/json",response.Content.Headers.ContentType!.MediaType);}
        Assert.Equal(e.RowVersion,(await b.run.H.StateAsync()).RowVersion);Assert.Equal(2,await b.run.AuditCount());
    }
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Ordinary_and_historical_unenrolled_preparation_remains_readable_without_backfill(bool demo)
    {
        await using var h=await DocumentWorkflowTests.Harness.CreateAsync(fixture,demo);Assert.True(await h.UploadAsync(PdfFixtures.Create()));var e=await h.StateAsync();Assert.True(await h.WithAsync(w=>w.ConfirmAsync(h.Sender,e.PublicId,e.RowVersion,e.PdfBlob!,true,null,null,default)));h.Retention.PurgeAfterDays=7;
        var clock=new SenderDocumentRetentionTests.Clock{Now=DateTimeOffset.UtcNow.AddDays(30)};await h.WithDatabaseAsync(async db=>{Assert.NotNull(await new SignerSetup(db,new(db,clock),new(),clock).GetAsync(h.Sender,e.PublicId));Assert.NotNull(await new DraftDetails(db,new(db,clock),new(),clock).GetAsync(h.Sender,e.PublicId));Assert.NotNull(await new FieldEditor(db,new(db,clock),new(),clock).GetAsync(h.Sender,e.PublicId));Assert.NotNull(await new DraftReview(db,clock).GetAsync(h.Sender,e.PublicId));return true;});
        await using var inspect=fixture.Open();Assert.False(await inspect.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==e.Id));
    }
    private async Task<object?> Read(Retained r,string kind,ClaimsPrincipal? principal=null,CrossRead? cross=null,CancellationToken ct=default)
    {
        using var source=fixture.Open();await using var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(cross??new CrossRead("never",()=>{})).Options);var actor=principal??r.H.Sender;var id=r.H.PublicId;
        return kind switch {"signers"=>await new SignerSetup(db,new(db,r.Clock),new(),r.Clock).GetAsync(actor,id,ct),"details"=>await new DraftDetails(db,new(db,r.Clock),new(),r.Clock).GetAsync(actor,id,ct),"fields"=>await new FieldEditor(db,new(db,r.Clock),new(),r.Clock).GetAsync(actor,id,ct),_=>await new DraftReview(db,r.Clock).GetAsync(actor,id,ct)};
    }
    private Task<object> Change(Retained r,string kind,Envelope e)=>r.H.WithDatabaseAsync<object>(async db=>kind switch {
        "signers"=>await new SignerSetup(db,new(db,r.Clock),new(),r.Clock).ChangeAsync(r.H.Sender,e.PublicId,new(SignerChangeKind.Save,Convert.ToBase64String(e.RowVersion),FullName:"Synthetic added",Email:"added@example.invalid"),null,null),
        "details"=>await new DraftDetails(db,new(db,r.Clock),new(),r.Clock).ChangeAsync(r.H.Sender,e.PublicId,new(DetailsChangeKind.SaveDetails,Convert.ToBase64String(e.RowVersion),Title:"Synthetic changed"),null,null),
        _=>await new FieldEditor(db,new(db,r.Clock),new(),r.Clock).SaveAsync(r.H.Sender,e.PublicId,new(Convert.ToBase64String(e.RowVersion),e.PdfBlob!,[]),null,null)});
    private sealed class CrossRead(string marker,Action cross):DbCommandInterceptor
    {
        public int Calls;
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command,CommandExecutedEventData eventData,DbDataReader result,CancellationToken cancellationToken=default)
        {if(command.CommandText.Contains("FROM "+marker,StringComparison.Ordinal)){Calls++;cross();}return ValueTask.FromResult(result);}
    }
}
