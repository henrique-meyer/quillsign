using System.Security.Cryptography;
using System.Text.Json;
using System.Net;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Storage;
using QuillSign.Work;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class RetentionSigningDeadlineTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData("earlier")][InlineData("absent")][InlineData("later")][InlineData("equal")]
    public async Task Review_and_Send_use_the_same_verified_effective_deadline_and_once_only_schedule(string requested)
    {
        await using var run=await Retained.Create(fixture,requested);var before=await run.State();var review=(await run.Review())!;
        var expected=requested=="earlier" ? run.H.Clock.GetUtcNow().AddDays(2) : run.Policy.DeleteAfter;
        Assert.Equal(expected,review.ExpiresAt);Assert.Equal(run.Policy.DeleteAfter,review.RetentionDeleteAfter);Assert.Equal(UploadRetention.Digest(run.Policy),review.RetentionSha256);
        Assert.Equal(before.RowVersion,(await run.State()).RowVersion);Assert.Equal(before.ExpiresAt,(await run.State()).ExpiresAt);Assert.True(review.ChecksPassed);
        var sent=(await run.H.Send(reviewedRetentionSha256:review.RetentionSha256))!;var after=await run.State();Assert.Equal(expected,after.ExpiresAt);Assert.Equal(EnvelopeStatus.Sent,after.Status);
        await using var db=fixture.Open();var expiry=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==after.Id && x.Kind==WorkKind.Expiry);Assert.Equal(expected,expiry.AvailableAt);
        var entry=await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==after.Id && x.Event=="sent");using var json=JsonDocument.Parse(entry.DataJson);var cap=json.RootElement.GetProperty("retentionSigning");
        Assert.Equal("retention-signing-v1",cap.GetProperty("version").GetString());Assert.Equal(review.RetentionSha256,cap.GetProperty("uploadRetentionSha256").GetString());Assert.Equal(expected,cap.GetProperty("effectiveDeadline").GetDateTimeOffset());Assert.Equal(expected,json.RootElement.GetProperty("signingDeadline").GetDateTimeOffset());
        Assert.Equal(requested=="absent" ? JsonValueKind.Null : JsonValueKind.String,cap.GetProperty("requestedDeadline").ValueKind);Assert.Equal(AuditHash.Compute(entry),entry.Hash);
        var bytes=await run.H.Read(Guid.ParseExact(after.SentPdfBlob!,"N"));Assert.Equal(sent.DocumentHash,Convert.ToHexStringLower(SHA256.HashData(bytes)));Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==after.Id));
        Assert.NotNull(await run.H.Send(reviewedRetentionSha256:review.RetentionSha256));Assert.NotNull(await run.H.Send(reviewedRetentionSha256:review.RetentionSha256));Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==after.Id));Assert.Equal(2,run.H.Signals.HintCalls);Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==after.Id && x.Event=="sent"));
    }

    [Theory]
    [InlineData(null)][InlineData("")][InlineData("forged")]
    public async Task Missing_old_or_forged_retention_acknowledgement_cannot_send_or_create_frozen_bytes(string? digest)
    {
        await using var run=await Retained.Create(fixture);var before=await run.State();var writes=run.H.Blobs.Created.Count;
        await Assert.ThrowsAsync<DocumentConflictException>(()=>run.H.Send(reviewedRetentionSha256:digest));await run.Unsent(before);Assert.Equal(writes,run.H.Blobs.Created.Count);Assert.Equal(0,run.H.Signals.HintCalls);
    }

    [Fact]
    public async Task Settings_changes_do_not_extend_the_snapshot_and_stale_draft_versions_require_fresh_review()
    {
        await using var run=await Retained.Create(fixture);var review=(await run.Review())!;run.H.App.Services.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays=30;
        Assert.Equal(review.RetentionSha256,(await run.Review())!.RetentionSha256);Assert.Equal(run.Policy.DeleteAfter,(await run.Review())!.ExpiresAt);
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==run.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Title,"Updated synthetic NO AGREEMENT"));
        await Assert.ThrowsAsync<DocumentConflictException>(()=>run.H.Send(reviewedRetentionSha256:review.RetentionSha256));run.H.Version=(await run.State()).RowVersion;var fresh=(await run.Review())!;
        Assert.NotNull(await run.H.Send(reviewedRetentionSha256:fresh.RetentionSha256));Assert.Equal(run.Policy.DeleteAfter,(await run.State()).ExpiresAt);
    }

    [Theory]
    [InlineData("before")][InlineData("storage")][InlineData("fields_finalized")][InlineData("sent")]
    public async Task Exact_cutoff_and_slow_storage_or_audit_crossings_leave_the_request_unsent(string crossing)
    {
        await using var run=await Retained.Create(fixture);var review=(await run.Review())!;var before=await run.State();
        void Cross()=>run.H.Clock.Advance(run.Policy.DeleteAfter-run.H.Clock.GetUtcNow());
        if(crossing=="before")Cross();if(crossing=="storage")run.H.Blobs.AfterWrite=Cross;
        if(crossing is "fields_finalized" or "sent") {run.H.Faults.Event=crossing;run.H.Faults.BeforeAudit=_=> {Cross();return Task.CompletedTask;};}
        await Assert.ThrowsAsync<DocumentRejectedException>(()=>run.H.Send(reviewedRetentionSha256:review.RetentionSha256));await run.Unsent(before);
        if(crossing!="before")Assert.Single(run.H.Blobs.Deleted);Assert.Equal(0,run.H.Sender.Calls);Assert.Equal(0,run.H.Signals.Published);
        var expired=(await run.Review())!;Assert.False(expired.ChecksPassed);Assert.Contains(expired.Errors,x=>x.Message.Contains("retention deadline",StringComparison.Ordinal));
    }

    [Fact]
    public async Task Missing_frozen_policy_cannot_fall_back_to_an_ordinary_unbounded_request()
    {
        await using var run=await Retained.Create(fixture,"absent");var review=(await run.Review())!;
        await using(var db=fixture.Open())await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==run.H.Envelope.Id).ExecuteDeleteAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Review());await Assert.ThrowsAsync<InvalidDataException>(()=>run.H.Send(reviewedRetentionSha256:review.RetentionSha256));Assert.Equal(0,run.H.Signals.HintCalls);
    }

    [Fact]
    public async Task Lost_Send_acknowledgement_preserves_one_capped_source_invitation_and_schedule()
    {
        await using var run=await Retained.Create(fixture);var review=(await run.Review())!;run.H.Faults.Event="sent";run.H.Faults.FailCommit=true;
        await Assert.ThrowsAsync<IOException>(()=>run.H.Send(reviewedRetentionSha256:review.RetentionSha256));var current=await run.State();Assert.Equal(EnvelopeStatus.Sent,current.Status);Assert.Equal(run.Policy.DeleteAfter,current.ExpiresAt);
        run.H.Faults.FailCommit=false;var recovered=(await run.H.Send(reviewedRetentionSha256:review.RetentionSha256))!;Assert.Equal(recovered.DocumentHash,Convert.ToHexStringLower(current.SentPdfSha256!));
        await using var db=fixture.Open();Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==current.Id).ToArrayAsync());Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==current.Id));Assert.Equal(2,run.H.Signals.HintCalls);Assert.Empty(run.H.Blobs.Deleted);
    }

    [Theory]
    [InlineData("digest")][InlineData("deadline")][InlineData("cutoff")][InlineData("version")]
    public async Task Rehashed_retention_evidence_tampering_is_rejected_by_Send_replay(string changed)
    {
        await using var run=await Retained.Create(fixture);var review=(await run.Review())!;Assert.NotNull(await run.H.Send(reviewedRetentionSha256:review.RetentionSha256));
        await using(var db=fixture.Open())
        {
            var entry=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==run.H.Envelope.Id && x.Event=="sent");var root=System.Text.Json.Nodes.JsonNode.Parse(entry.DataJson)!;var cap=root["retentionSigning"]!;
            if(changed=="digest")cap["uploadRetentionSha256"]=new string('0',64);if(changed=="deadline")cap["effectiveDeadline"]=run.Policy.DeleteAfter.AddDays(1);if(changed=="cutoff")cap["deleteAfter"]=run.Policy.DeleteAfter.AddDays(1);if(changed=="version")cap["version"]="unknown";
            entry.DataJson=root.ToJsonString();entry.Hash=AuditHash.Compute(entry);await db.AuditEvents.Where(x=>x.EnvelopeId==entry.EnvelopeId && x.Sequence==entry.Sequence).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,entry.DataJson).SetProperty(x=>x.Hash,entry.Hash));
        }
        var published=run.H.Signals.Published;await Assert.ThrowsAsync<InvalidDataException>(()=>run.H.Send(reviewedRetentionSha256:review.RetentionSha256));Assert.Equal(published,run.H.Signals.Published);
    }

    [Fact]
    public async Task The_first_invitation_activation_uses_the_remaining_capped_signing_window()
    {
        await using var run=await Retained.Create(fixture);var review=(await run.Review())!;Assert.NotNull(await run.H.Send(reviewedRetentionSha256:review.RetentionSha256));
        run.H.Clock.Advance(run.Policy.DeleteAfter-run.H.Clock.GetUtcNow()-TimeSpan.FromMinutes(1));Assert.True(await run.H.Once());Assert.Equal(1,run.H.Sender.Calls);
        await using var db=fixture.Open();var token=Assert.Single(await db.AuthTokens.Where(x=>x.EnvelopeId==run.H.Envelope.Id).ToArrayAsync());Assert.Equal(run.Policy.DeleteAfter,token.ExpiresAt);
    }

    [Theory]
    [InlineData("missing")][InlineData("forged")][InlineData("csrf")][InlineData("expired")][InlineData("success")][InlineData("lost")]
    public async Task Public_review_requires_current_retention_acknowledgement_and_recovers_only_committed_Send(string outcome)
    {
        await using var run=await Retained.Create(fixture,browser:true);
        using var client=run.H.App.GetTestClient();var flow=new SenderSendPageTests.Flow{H=run.H,Client=client};
        using(var session=await client.GetAsync("/test-session"))flow.Take(session);
        var page=await flow.Page();var digest=SenderSendPageTests.Flow.Value(page,"RetentionSha256");
        Assert.Equal(UploadRetention.Digest(run.Policy),digest);Assert.Contains(run.Policy.DeleteAfter.ToString("u"),page);Assert.Contains("fixed retention ends",page);
        var before=await run.State();var values=new Dictionary<string,string>{["RetentionSha256"]=outcome=="missing" ? "" : outcome=="forged" ? "forged" : digest};
        if(outcome=="expired")
        {
            run.H.Clock.Advance(run.Policy.DeleteAfter-run.H.Clock.GetUtcNow());
            using var session=await client.GetAsync("/test-session");flow.Take(session);
        }
        if(outcome=="lost"){run.H.Faults.Event="sent";run.H.Faults.FailCommit=true;}
        using var result=await flow.Send(page,values,csrf:outcome!="csrf");
        if(outcome is "success" or "lost")
        {
            Assert.Equal(HttpStatusCode.Redirect,result.StatusCode);Assert.Equal(flow.Status,result.Headers.Location!.ToString());Assert.DoesNotContain("?",result.Headers.Location.ToString());
            var status=await flow.Page(flow.Status);Assert.Contains("The request was sent.",status);Assert.Contains(run.Policy.DeleteAfter.ToString("u"),status);
            Assert.DoesNotContain("The request was sent.",await flow.Page(flow.Status));Assert.Equal(run.Policy.DeleteAfter,(await run.State()).ExpiresAt);
            await using var db=fixture.Open();Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==before.Id).ToArrayAsync());Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==before.Id));
        }
        else
        {
            Assert.Equal(outcome is "missing" or "forged" ? HttpStatusCode.Conflict : HttpStatusCode.BadRequest,result.StatusCode);await run.Unsent(before);Assert.Equal(0,run.H.Signals.HintCalls);
        }
    }

    [Fact]
    public async Task Concurrent_retained_Send_requests_freeze_one_source_and_one_expiry_schedule()
    {
        await using var run=await Retained.Create(fixture);var review=(await run.Review())!;
        var results=await Task.WhenAll(run.H.Send(reviewedRetentionSha256:review.RetentionSha256),run.H.Send(reviewedRetentionSha256:review.RetentionSha256));
        Assert.Equal(results[0],results[1]);var state=await run.State();Assert.Equal(run.Policy.DeleteAfter,state.ExpiresAt);
        await using var db=fixture.Open();Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==state.Id).ToArrayAsync());Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==state.Id));Assert.Equal(3,run.H.Blobs.Created.Count);
    }

    // Test-assembly-only host for manual desktop/mobile/keyboard checks. It uses
    // the same isolated SQL/Azurite fixture and fake mail provider as the tests.
    public sealed class BrowserSession:IAsyncDisposable
    {
        private readonly Retained run;
        private BrowserSession(Retained run)=>this.run=run;
        public string PublicId=>run.H.Envelope.PublicId;
        public DateTimeOffset DeleteAfter=>run.Policy.DeleteAfter;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port,string requested="later")=>new(await Retained.Create(fixture,requested,port));
        public async Task ChangeDraft()
        {await using var db=run.fixture.Open();await db.Envelopes.Where(x=>x.Id==run.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Title,"Updated synthetic NO AGREEMENT"));}
        public void Expire()=>run.H.Clock.Advance(run.Policy.DeleteAfter-run.H.Clock.GetUtcNow());
        public void LoseCommitAcknowledgement() {run.H.Faults.Event="sent";run.H.Faults.FailCommit=true;}
        public ValueTask DisposeAsync()=>run.DisposeAsync();
    }

    internal sealed class Retained:IAsyncDisposable
    {
        public Shared H=null!;public DocumentRetentionSnapshot Policy=null!;internal SqlDatabaseFixture fixture=null!;
        public static async Task<Retained> Create(SqlDatabaseFixture fixture,string requested="later",int? browserPort=null,bool browser=false,Func<QuillSign.Signing.VerifiedSigner?>? syntheticSigner=null,int retentionDays=7)
        {
            var run=new Retained{fixture=fixture,H=await Shared.Create(fixture,browser:browser || browserPort is not null,browserPort:browserPort,syntheticSigner:syntheticSigner)};var h=run.H;var old=Guid.ParseExact(h.Envelope.PdfBlob!,"N");h.App.Services.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays=retentionDays;
            await using(var db=fixture.Open())
            {
                var e=await db.Envelopes.SingleAsync(x=>x.Id==h.Envelope.Id);e.IsDemo=true;e.PdfBlob=null;e.PdfSha256=null;e.PageCount=null;e.PageSizesJson=null;e.PreviewConfirmedAt=null;
                e.ExpiresAt=requested=="absent" ? null : h.Clock.GetUtcNow().AddDays(requested=="earlier" ? 2 : requested=="equal" ? 7 : 30);await db.Fields.Where(x=>x.EnvelopeId==e.Id).ExecuteDeleteAsync();await db.SaveChangesAsync();
            }
            await h.Blobs.Inner.DeleteAsync(h.Principal,new(h.Envelope.Id,DocumentBlobKind.Normalized,old));var before=await run.State();
            using(var scope=h.App.Services.CreateScope())
            {
                var documents=scope.ServiceProvider.GetRequiredService<DocumentWorkflow>();using var original=new MemoryStream(PdfFixtures.Create(text:"SYNTHETIC RETENTION - NO AGREEMENT"));
                Assert.True(await documents.UploadAsync(h.Principal,h.Envelope.PublicId,before.RowVersion,"Synthetic NO AGREEMENT.pdf",original,original.Length,null,null,default));
            }
            before=await run.State();using(var scope=h.App.Services.CreateScope())Assert.True(await scope.ServiceProvider.GetRequiredService<DocumentWorkflow>().ConfirmAsync(h.Principal,before.PublicId,before.RowVersion,before.PdfBlob!,true,null,null,default));
            await using(var db=fixture.Open()) {db.Fields.Add(new(){EnvelopeId=h.Envelope.Id,SignerId=h.First.Id,Type=FieldType.Signature,Page=1,X=.1m,Y=.4m,Width=.4m,Height=.1m});await db.SaveChangesAsync();run.Policy=await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Envelope.Id);}
            h.Envelope=await run.State();h.Version=h.Envelope.RowVersion;h.Source=await h.Read(Guid.ParseExact(h.Envelope.PdfBlob!,"N"));return run;
        }
        public async Task<Envelope> State() {await using var db=fixture.Open();return await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==H.Envelope.Id);}
        public async Task<DraftReviewSnapshot?> Review() {using var scope=H.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<DraftReview>().GetAsync(H.Principal,H.Envelope.PublicId);}
        public async Task Unsent(Envelope before)
        {var e=await State();Assert.Equal(EnvelopeStatus.Draft,e.Status);Assert.Equal(before.RowVersion,e.RowVersion);Assert.Equal(before.ExpiresAt,e.ExpiresAt);Assert.Null(e.SentPdfBlob);await using var db=fixture.Open();Assert.False(await db.EmailOutbox.AnyAsync(x=>x.EnvelopeId==e.Id));Assert.False(await db.WorkItems.AnyAsync(x=>x.EnvelopeId==e.Id));Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==e.Id && x.Event=="sent"));}
        public ValueTask DisposeAsync()=>H.DisposeAsync();
    }
}
