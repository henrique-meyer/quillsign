using System.Security.Claims;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Storage;
using Flow=QuillSign.Tests.CompletionDownloadTests.Flow;

namespace QuillSign.Tests;

public sealed class CompletionAccessTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task All_frozen_parties_retrieve_exact_final_pair_after_signing_expiry_without_edit_authority_or_new_seals()
    {
        await using var f=await Flow.Create(fixture); f.Clock.Advance(TimeSpan.FromHours(2));
        Assert.Null(await f.Run.Signing.Use((SignerAccess a)=>a.GetContextAsync(f.Run.Signing.LastSigner,f.PublicId)));
        var acquired=f.Run.Seal.Certificates.Calls; f.Run.Seal.Options.Pfx.Path="unavailable";
        var parties=new List<(PartyType Type,Guid? Id)> {(PartyType.Sender,null)};
        await using(var db=fixture.Open()) {
            parties.AddRange(await db.Signers.Where(x=>x.EnvelopeId==f.Id).Select(x=>new ValueTuple<PartyType,Guid?>(PartyType.Signer,x.Id)).ToArrayAsync());
            parties.AddRange(await db.Recipients.Where(x=>x.EnvelopeId==f.Id).Select(x=>new ValueTuple<PartyType,Guid?>(PartyType.Recipient,x.Id)).ToArrayAsync());
        }
        Assert.Equal(4,parties.Count);
        foreach(var party in parties) {
            var link=(await Use(f,a=>a.IssueAsync(f.Id,party.Type,party.Id)))!; Assert.NotNull(link); Assert.Equal(43,link.RawToken.Length);
            var session=(await Use(f,a=>a.RedeemAsync(link.RawToken)))!; Assert.NotNull(session); var principal=CompletionAccessProtection.Principal(session.Identity);
            Assert.Equal(party.Type,session.Identity.Party); Assert.Equal(party.Id,session.Identity.PartyId);
            foreach(var kind in new[]{FinalDocumentKind.Executed,FinalDocumentKind.Certificate}) {
                var file=(await Use(f,a=>a.ReadAsync(principal,f.PublicId,session.Receipt,kind)))!;
                Assert.Equal(kind==FinalDocumentKind.Executed ? f.Published.ExecutedBytes : f.Published.CertificateBytes,file.Pdf);
                Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(file.Pdf)),file.Sha256);
            }
            Assert.Null(await Use(f,a=>a.RedeemAsync(link.RawToken)));
            Assert.Null(SignerAccessConfiguration.ReadIdentity(principal,f.Clock.GetUtcNow()));
            Assert.Null(await f.Run.Signing.Use((SignerAccess a)=>a.GetContextAsync(principal,f.PublicId)));
            Assert.Throws<UnauthorizedAccessException>(()=>EnvelopeStorageAuthorization.DemandRead(principal,new(f.Id,DocumentBlobKind.Normalized,Guid.NewGuid())));
            await using var verify=fixture.Open(); var record=await verify.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==link.TokenId);
            Assert.Equal(TokenPurpose.CompletionAccess,record.Purpose); Assert.NotNull(record.UsedAt); Assert.Equal(f.Published.PublicationId,record.CompletionPublicationId);
            Assert.Null(record.DocumentId); Assert.Null(record.DocumentSha256); Assert.Null(record.DisclosureSha256);
            Assert.Equal(SHA256.HashData(Encoding.UTF8.GetBytes(link.RawToken)),record.TokenSha256);
            Assert.DoesNotContain(link.RawToken,JsonSerializer.Serialize(record));
            var evidence=await verify.AuditEvents.Where(x=>x.EnvelopeId==f.Id && (x.Event=="completion_access_issued" || x.Event=="completion_access_redeemed")).ToArrayAsync();
            Assert.All(evidence,x=> {Assert.DoesNotContain(link.RawToken,x.DataJson); Assert.DoesNotContain(session.Receipt,x.DataJson);});
        }
        Assert.Equal(acquired,f.Run.Seal.Certificates.Calls); Assert.Equal(2,f.Run.Seal.Requests); Assert.Equal(2,f.Store.Writes);
        await using(var db=fixture.Open())Assert.Equal(8,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==f.Id && x.Event.StartsWith("completion_access_")));
    }

    [Fact]
    public async Task Concurrent_redemption_is_once_only_and_legacy_tokens_wrong_scope_principals_and_renamed_proofs_cannot_read()
    {
        await using var f=await Flow.Create(fixture); var link=(await Use(f,a=>a.IssueAsync(f.Id,PartyType.Sender,null)))!;
        var results=await Task.WhenAll(Use(f,a=>a.RedeemAsync(link.RawToken)),Use(f,a=>a.RedeemAsync(link.RawToken)));
        var session=Assert.Single(results,x=>x is not null)!; var principal=CompletionAccessProtection.Principal(session.Identity);
        Assert.Null(await Use(f,a=>a.AuthenticateAsync(principal,Guid.NewGuid().ToString("N"),session.Receipt)));
        Assert.Null(await Use(f,a=>a.AuthenticateAsync(f.Run.Signing.Sender,f.PublicId,session.Receipt)));
        Assert.Null(await Use(f,a=>a.AuthenticateAsync(f.Run.Signing.LastSigner,f.PublicId,session.Receipt)));
        foreach(var bad in new string?[]{null,"forged",new string('x',4000)})Assert.Null(await Use(f,a=>a.AuthenticateAsync(principal,f.PublicId,bad)));
        var mixed=principal.Clone(); mixed.AddIdentity(new ClaimsIdentity([new Claim("synthetic","other")],"other"));
        Assert.Null(await Use(f,a=>a.AuthenticateAsync(mixed,f.PublicId,session.Receipt)));
        foreach(var altered in new[]{session.Identity with {SessionId=Guid.NewGuid()},session.Identity with {RecipeSha256=new string('0',64)},session.Identity with {PartySha256=new string('0',64)},session.Identity with {ExpiresAt=session.Identity.ExpiresAt.AddMinutes(1)}}) {
            var proof=Receipt(f,altered); Assert.Null(await Use(f,a=>a.AuthenticateAsync(CompletionAccessProtection.Principal(altered),f.PublicId,proof)));
        }
        var reads=f.Store.Reads;
        foreach(var raw in new string?[]{null,"forged",new string('a',43),link.RawToken})Assert.Null(await Use(f,a=>a.RedeemAsync(raw)));
        Assert.Equal(reads,f.Store.Reads);
        var legacy=Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        await using(var db=fixture.Open()) {
            db.AuthTokens.Add(new() {EnvelopeId=f.Id,PartyType=PartyType.Sender,Purpose=TokenPurpose.SenderVerify,Email=f.Run.Signing.Envelope.SenderEmail,
                TokenSha256=SHA256.HashData(Encoding.UTF8.GetBytes(legacy)),ExpiresAt=f.Clock.GetUtcNow().AddHours(1)}); await db.SaveChangesAsync();
        }
        Assert.Null(await Use(f,a=>a.RedeemAsync(legacy))); Assert.Equal(reads,f.Store.Reads);
        Assert.Null(await Use(f,a=>a.IssueAsync(f.Id,PartyType.System,null)));
        Assert.Null(await Use(f,a=>a.IssueAsync(f.Id,PartyType.Sender,Guid.NewGuid())));
        Assert.Null(await Use(f,a=>a.IssueAsync(f.Id,PartyType.Recipient,Guid.NewGuid())));
        await using(var db=fixture.Open())Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==f.Id && x.Event=="completion_access_redeemed").ToArrayAsync());
        var unused=(await Use(f,a=>a.IssueAsync(f.Id,PartyType.Sender,null)))!;
        f.Clock.Advance(unused.ExpiresAt-f.Clock.GetUtcNow()+TimeSpan.FromMilliseconds(1)); reads=f.Store.Reads;
        Assert.Null(await Use(f,a=>a.RedeemAsync(unused.RawToken))); Assert.Equal(reads,f.Store.Reads);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Link_and_session_lifetimes_are_bounded_by_retention_and_invalidated_without_extending_authority(bool retention)
    {
        await using var f=await Flow.Create(fixture); if(retention)f.Clock.Advance(TimeSpan.FromDays(6)+TimeSpan.FromHours(23.5));
        var link=(await Use(f,a=>a.IssueAsync(f.Id,PartyType.Sender,null)))!; var session=(await Use(f,a=>a.RedeemAsync(link.RawToken)))!;
        var end=(await f.Run.Signing.Refresh()).PurgeAfter!.Value;
        Assert.True(link.ExpiresAt<=end); Assert.True(session.Identity.ExpiresAt<=end);
        if(retention)Assert.Equal(end,session.Identity.ExpiresAt);
        f.Clock.Advance(session.Identity.ExpiresAt-f.Clock.GetUtcNow()+TimeSpan.FromMilliseconds(1));
        var reads=f.Store.Reads; Assert.Null(await Use(f,a=>a.AuthenticateAsync(CompletionAccessProtection.Principal(session.Identity),f.PublicId,session.Receipt)));
        Assert.Null(await Use(f,a=>a.RedeemAsync(link.RawToken))); Assert.Equal(reads,f.Store.Reads);
        if(retention)Assert.Null(await Use(f,a=>a.IssueAsync(f.Id,PartyType.Sender,null)));
    }

    [Fact]
    public async Task Completion_binding_constraints_preserve_legacy_tokens_and_reject_mixed_bindings_and_EF_changes()
    {
        await using var f=await Flow.Create(fixture); var link=(await Use(f,a=>a.IssueAsync(f.Id,PartyType.Sender,null)))!;
        await using var db=fixture.Open(); var record=await db.AuthTokens.SingleAsync(x=>x.Id==link.TokenId); record.ExpiresAt=record.ExpiresAt.AddHours(1);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>db.SaveChangesAsync()); db.ChangeTracker.Clear();
        foreach(var wrong in new[]{"missing","mixed","system","sender-id"}) {
            var bad=new AuthToken {EnvelopeId=f.Id,Purpose=TokenPurpose.CompletionAccess,PartyType=PartyType.Sender,Email=f.Run.Signing.Envelope.SenderEmail,
                TokenSha256=RandomNumberGenerator.GetBytes(32),ExpiresAt=f.Clock.GetUtcNow().AddHours(1),CompletionPublicationId=f.Published.PublicationId,
                CompletionRecipeSha256=f.Published.PublicationRecipeSha256,CompletionPartySha256=RandomNumberGenerator.GetBytes(32)};
            if(wrong=="missing")bad.CompletionPublicationId=null;
            if(wrong=="mixed") {bad.DocumentId=Guid.NewGuid();bad.DocumentSha256=RandomNumberGenerator.GetBytes(32);bad.DisclosureSha256=RandomNumberGenerator.GetBytes(32);}
            if(wrong=="system")bad.PartyType=PartyType.System; if(wrong=="sender-id")bad.PartyId=Guid.NewGuid();
            db.AuthTokens.Add(bad); await Assert.ThrowsAsync<DbUpdateException>(()=>db.SaveChangesAsync()); db.ChangeTracker.Clear();
        }
    }

    [Fact]
    public async Task Caller_owned_preparation_is_atomic_with_rollback_and_does_not_enqueue_unsupported_delivery()
    {
        await using var f=await Flow.Create(fixture); await using var db=fixture.Open(); var service=Service(f,db); var before=await f.Run.Counts();
        var prepare=typeof(CompletionAccess).GetMethod("PrepareAsync",BindingFlags.NonPublic|BindingFlags.Instance)!;
        var task=(Task)prepare.Invoke(service,[f.Id,CancellationToken.None])!; await task;
        var context=task.GetType().GetProperty("Result")!.GetValue(task)!;
        var locked=typeof(CompletionAccess).GetMethod("PrepareLockedAsync",BindingFlags.NonPublic|BindingFlags.Instance)!;
        Task<CompletionAccessLink?> Issue()=>(Task<CompletionAccessLink?>)locked.Invoke(service,[context,PartyType.Sender,null,CancellationToken.None])!;
        await Assert.ThrowsAsync<InvalidOperationException>(()=>Issue());
        CompletionAccessLink abandoned;
        await using(var tx=await db.Database.BeginTransactionAsync()) {abandoned=(await Issue())!; Assert.NotNull(abandoned); await tx.RollbackAsync();}
        db.ChangeTracker.Clear(); Assert.Null(await Use(f,a=>a.RedeemAsync(abandoned.RawToken)));
        CompletionAccessLink committed;
        await using(var tx=await db.Database.BeginTransactionAsync()) {committed=(await Issue())!; await tx.CommitAsync();}
        Assert.NotNull(await service.RedeemAsync(committed.RawToken));
        var after=await f.Run.Counts(); Assert.Equal(before.Work,after.Work); Assert.Equal(before.Mail,after.Mail); Assert.Equal(before.Sent,after.Sent);
        Assert.Equal(before.Audit+2,after.Audit); Assert.Equal(2,f.Store.Writes);
    }

    [Fact]
    public async Task A_consumed_link_expiring_does_not_extend_or_revoke_its_independent_original_readonly_session()
    {
        await using var f=await Flow.Create(fixture); await using var db=fixture.Open(); var service=Service(f,db,new() {LinkHours=1,SessionHours=2});
        var link=(await service.IssueAsync(f.Id,PartyType.Sender,null))!; var session=(await service.RedeemAsync(link.RawToken))!;
        f.Clock.Advance(TimeSpan.FromMinutes(90)); Assert.True(link.ExpiresAt<f.Clock.GetUtcNow());
        Assert.Null(await service.RedeemAsync(link.RawToken));
        Assert.Equal(f.Published.ExecutedBytes,(await service.ReadAsync(CompletionAccessProtection.Principal(session.Identity),f.PublicId,session.Receipt,FinalDocumentKind.Executed))!.Pdf);
        f.Clock.Advance(TimeSpan.FromMinutes(31)); Assert.Null(await service.AuthenticateAsync(CompletionAccessProtection.Principal(session.Identity),f.PublicId,session.Receipt));
    }

    [Theory]
    [InlineData(0,1)][InlineData(169,1)][InlineData(1,0)][InlineData(1,25)]
    public void Unbounded_or_invalid_technical_lifetimes_fail_configuration(int link,int session)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {{"CompletionAccess:LinkHours",link.ToString()},{"CompletionAccess:SessionHours",session.ToString()}}).Build();
        Assert.Throws<InvalidOperationException>(()=>new ServiceCollection().AddCompletionAccess(config));
    }

    private async Task<T> Use<T>(Flow f,Func<CompletionAccess,Task<T>> operation) {await using var db=fixture.Open();return await operation(Service(f,db));}
    internal static CompletionAccess Service(Flow f,QuillSignDbContext db,CompletionAccessOptions? options=null) {
        Func<CompletionPublication> published=()=>new(db,f.Run.Candidates(db),f.Run.Service(db),f.Run.Collector(db),f.Store,new(db,f.Clock),f.Clock,
            new() {DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},f.Run.Seal.App.Environment);
        var provider=f.Run.Signing.H.App.Services.GetRequiredService<IDataProtectionProvider>();
        return new(db,new(db,f.Run.Collector(db),published,f.Clock),new(provider,f.Clock),options??new(),new(db,f.Clock),f.Clock,published);
    }
    private static string Receipt(Flow f,CompletionReaderIdentity identity)=>f.Run.Signing.H.App.Services.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector("QuillSign.CompletionReader.Session.v1").Protect(JsonSerializer.Serialize(new {Version=CompletionAccessProtection.Version,Scheme=CompletionAccessProtection.Scheme,Identity=identity}));
}
