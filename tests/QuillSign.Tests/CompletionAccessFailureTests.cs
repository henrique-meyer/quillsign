using Microsoft.EntityFrameworkCore;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Storage;
using Flow=QuillSign.Tests.CompletionDownloadTests.Flow;

namespace QuillSign.Tests;

public sealed class CompletionAccessFailureTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("missing")][InlineData("corrupt")][InlineData("source")][InlineData("token")][InlineData("publication-version")][InlineData("token-version")][InlineData("post-IO-source")][InlineData("expiry-during-read")]
    public async Task Unavailable_changed_or_expired_scope_returns_no_file_or_replacement_and_storage_recovers_explicitly(string fault)
    {
        await using var f=await Flow.Create(fixture); var link=(await Use(f,a=>a.IssueAsync(f.Id,PartyType.Sender,null)))!;
        var session=(await Use(f,a=>a.RedeemAsync(link.RawToken)))!; var p=CompletionAccessProtection.Principal(session.Identity);
        if(fault is "missing" or "corrupt")f.Store.Fault=fault;
        if(fault=="source") {await using var db=fixture.Open(); await db.Recipients.Where(x=>x.EnvelopeId==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Name,"Changed frozen recipient"));}
        if(fault=="token") {await using var db=fixture.Open(); await db.AuthTokens.Where(x=>x.Id==link.TokenId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.UsedAt,f.Clock.GetUtcNow().AddSeconds(-1)));}
        if(fault=="publication-version") {await using var db=fixture.Open(); await db.CompletionPublicationResults.Where(x=>x.EnvelopeId==f.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.CompletedAt,x=>x.CompletedAt));}
        if(fault=="token-version") {await using var db=fixture.Open(); await db.AuthTokens.Where(x=>x.Id==link.TokenId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.UsedAt,x=>x.UsedAt));}
        if(fault=="expiry-during-read") {var changed=false; f.Store.AfterRead=()=> {if(!changed) {changed=true;f.Clock.Advance(TimeSpan.FromHours(2));}return Task.CompletedTask;};}
        if(fault=="post-IO-source") {var changed=false; f.Store.AfterRead=async ()=> {if(changed)return;changed=true;await using var db=fixture.Open();await db.Signers.Where(x=>x.EnvelopeId==f.Id && x.Order==2).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,SignerStatus.Viewed));};}
        if(fault=="missing")await Assert.ThrowsAsync<IOException>(()=>Use(f,a=>a.ReadAsync(p,f.PublicId,session.Receipt,FinalDocumentKind.Executed)));
        else if(fault is "corrupt" or "source" or "post-IO-source")await Assert.ThrowsAsync<InvalidDataException>(()=>Use(f,a=>a.ReadAsync(p,f.PublicId,session.Receipt,FinalDocumentKind.Executed)));
        else {
            try {Assert.Null(await Use(f,a=>a.ReadAsync(p,f.PublicId,session.Receipt,FinalDocumentKind.Executed)));}
            catch(Exception e) when(fault=="expiry-during-read" && e is IOException or InvalidDataException) { }
        }
        if(fault is "missing" or "corrupt") {
            f.Store.Fault=null; Assert.Equal(f.Published.ExecutedBytes,(await Use(f,a=>a.ReadAsync(p,f.PublicId,session.Receipt,FinalDocumentKind.Executed)))!.Pdf);
        }
        Assert.Equal(2,f.Store.Writes); Assert.Equal(2,f.Run.Seal.Requests);
    }

    [Theory]
    [InlineData("issue-audit")][InlineData("issue-lost")][InlineData("redeem-audit")][InlineData("redeem-lost")][InlineData("redeem-uncertain")]
    public async Task Rollback_and_unknown_commits_leak_no_transport_or_session_and_recover_with_honest_single_use_semantics(string failure)
    {
        await using var f=await Flow.Create(fixture); var issuing=failure.StartsWith("issue");
        var faults=new CompletionSealOutputTests.Faults {Event=issuing ? "completion_access_issued" : "completion_access_redeemed",RejectAudit=failure.EndsWith("audit"),LoseCommit=failure.EndsWith("lost"),RejectCommit=failure.EndsWith("uncertain")};
        CompletionAccessLink? link=issuing ? null : (await Use(f,a=>a.IssueAsync(f.Id,PartyType.Sender,null)))!;
        await using var baseline=fixture.Open(); var builder=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(faults);
        await using var db=new QuillSignDbContext(builder.Options); var service=Service(f,db);
        if(failure.EndsWith("audit"))await Assert.ThrowsAsync<DbUpdateException>(async ()=> {if(issuing)_=await service.IssueAsync(f.Id,PartyType.Sender,null);else _=await service.RedeemAsync(link!.RawToken);});
        else await Assert.ThrowsAsync<IOException>(async ()=> {if(issuing)_=await service.IssueAsync(f.Id,PartyType.Sender,null);else _=await service.RedeemAsync(link!.RawToken);});
        Assert.False(db.ChangeTracker.HasChanges()); faults.RejectAudit=false; faults.Event="";
        if(!issuing && failure.EndsWith("lost")) {
            Assert.Null(await service.RedeemAsync(link!.RawToken)); link=(await service.IssueAsync(f.Id,PartyType.Sender,null))!;
        } else if(issuing)link=(await service.IssueAsync(f.Id,PartyType.Sender,null))!;
        var recovered=(await service.RedeemAsync(link!.RawToken))!; Assert.NotNull(recovered);
        Assert.Equal(f.Published.CertificateBytes,(await service.ReadAsync(CompletionAccessProtection.Principal(recovered.Identity),f.PublicId,recovered.Receipt,FinalDocumentKind.Certificate))!.Pdf);
        Assert.Null(await service.RedeemAsync(link.RawToken)); Assert.Equal(2,f.Store.Writes); Assert.Equal(2,f.Run.Seal.Requests);
    }

    private async Task<T> Use<T>(Flow f,Func<CompletionAccess,Task<T>> operation) {await using var db=fixture.Open();return await operation(Service(f,db));}
    private static CompletionAccess Service(Flow f,QuillSignDbContext db)=>CompletionAccessTests.Service(f,db);
}
