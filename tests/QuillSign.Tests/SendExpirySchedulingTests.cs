using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Work;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SendExpirySchedulingTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task A_request_without_a_finite_deadline_queues_only_the_first_invitation()
    {
        await using var h=await Shared.Create(fixture);await using var db=fixture.Open();
        await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,(DateTimeOffset?)null));
        h.Version=(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).RowVersion;
        Assert.NotNull(await h.Send());var work=Assert.Single(await db.WorkItems.AsNoTracking().Where(x=>x.EnvelopeId==h.Envelope.Id).ToArrayAsync());
        Assert.Equal(WorkKind.Email,work.Kind);Assert.Equal(1,h.Signals.Published);Assert.Equal(1,h.Signals.HintCalls);
        using var evidence=System.Text.Json.JsonDocument.Parse((await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="sent")).DataJson);
        Assert.Equal(System.Text.Json.JsonValueKind.Null,evidence.RootElement.GetProperty("expiryWorkId").ValueKind);
        Assert.Equal(System.Text.Json.JsonValueKind.Null,evidence.RootElement.GetProperty("signingDeadline").ValueKind);
    }

    [Fact]
    public async Task Lost_expiry_hint_acknowledgement_rolls_back_the_whole_send_and_cleans_only_its_frozen_file()
    {
        await using var h=await Shared.Create(fixture);h.Signals.FailHintAfterWriteAt=2;
        await Assert.ThrowsAsync<IOException>(()=>h.Send());await h.AssertUnsent(fixture);Assert.Single(h.Blobs.Created);Assert.Single(h.Blobs.Deleted);
        Assert.Equal(h.Source,await h.Read(Guid.Parse(h.Envelope.PdfBlob!)));Assert.Equal(0,h.Signals.Published);
        h.Signals.FailHintAfterWriteAt=0;Assert.Equal(1,await h.Signals.RecoverAsync(h.Clock.GetUtcNow(),default));
        Assert.True(await h.Once());Assert.Equal(0,h.Sender.Calls);Assert.NotNull(await h.Send());
        await using var db=fixture.Open();Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==h.Envelope.Id));
    }

    [Fact]
    public async Task Lost_expiry_queue_publication_recovers_and_automatically_records_the_due_expiration()
    {
        await using var h=await Shared.Create(fixture);h.Signals.FailPublishAt=2;var sent=(await h.Send())!;
        await using var db=fixture.Open();var expiry=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Kind==WorkKind.Expiry);
        using var evidence=System.Text.Json.JsonDocument.Parse((await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="sent")).DataJson);
        Assert.Equal(expiry.Id,evidence.RootElement.GetProperty("expiryWorkId").GetGuid());Assert.Equal(h.Envelope.ExpiresAt,evidence.RootElement.GetProperty("signingDeadline").GetDateTimeOffset());
        Assert.True(await h.Once());Assert.Equal(1,h.Sender.Calls);h.Clock.Advance(h.Envelope.ExpiresAt!.Value-h.Clock.GetUtcNow()+TimeSpan.FromTicks(1));
        Assert.Equal(1,await h.Signals.RecoverAsync(h.Clock.GetUtcNow(),default));Assert.True(await h.Once());
        Assert.Equal(EnvelopeStatus.Expired,(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
        Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==expiry.Id)).Status);
        Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="expired").ToArrayAsync());
        var frozen=(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).SentPdfBlob!;
        var bytes=await h.Read(Guid.Parse(frozen));Assert.Equal(sent.DocumentHash,Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes)));
        Assert.Single(h.Blobs.Created);Assert.Empty(h.Blobs.Deleted);
        Assert.Equal(1,h.Sender.Calls);
    }

    [Fact]
    public async Task Lost_Send_commit_replay_reuses_both_jobs_and_the_same_frozen_document_without_recreating_hints()
    {
        await using var h=await Shared.Create(fixture);h.Faults.FailCommit=true;await Assert.ThrowsAsync<IOException>(()=>h.Send());
        await using var db=fixture.Open();var expiry=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Kind==WorkKind.Expiry);
        h.Faults.FailCommit=false;Assert.NotNull(await h.Send());Assert.NotNull(await h.Send());
        var after=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==expiry.Id);Assert.Equal(expiry.PayloadJson,after.PayloadJson);Assert.Equal(expiry.AvailableAt,after.AvailableAt);Assert.Equal(0,after.Attempts);
        Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==h.Envelope.Id));Assert.Single(h.Blobs.Created);Assert.Empty(h.Blobs.Deleted);
        Assert.Equal(2,h.Signals.HintCalls);Assert.Single(await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Event=="sent").ToArrayAsync());
        Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id));
    }

    [Theory]
    [InlineData("missing")][InlineData("payload")][InlineData("kind")][InlineData("deadline")]
    public async Task Replayed_Send_never_confirms_a_missing_or_rebound_recorded_schedule(string kind)
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await using var db=fixture.Open();
        var query=db.WorkItems.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Kind==WorkKind.Expiry);
        if(kind=="missing")await query.ExecuteDeleteAsync();
        if(kind=="payload")await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
        if(kind=="kind")await query.ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Kind,WorkKind.Purge));
        if(kind=="deadline")await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,h.Envelope.ExpiresAt!.Value.AddMinutes(1)));
        var published=h.Signals.Published;await Assert.ThrowsAsync<InvalidDataException>(()=>h.Send());
        Assert.Equal(published,h.Signals.Published);Assert.Single(h.Blobs.Created);Assert.Empty(h.Blobs.Deleted);Assert.Equal(0,h.Sender.Calls);
    }

    [Fact]
    public async Task Legacy_Send_replay_preserves_its_record_without_implicitly_backfilling_expiry()
    {
        await using var h=await Shared.Create(fixture);Assert.NotNull(await h.Send());await SigningExpiryWorkTests.LegacyAsync(h,fixture);
        Assert.NotNull(await h.Send());await using var db=fixture.Open();Assert.False(await db.WorkItems.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id && x.Kind==WorkKind.Expiry));
        Assert.Single(h.Blobs.Created);Assert.Empty(h.Blobs.Deleted);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Send_replay_preserves_live_or_failed_expiry_work_without_reset_or_republication(bool failed)
    {
        await using var h=await Shared.Create(fixture);await using var db=fixture.Open();
        await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,h.Clock.GetUtcNow().AddMinutes(1)));
        h.Version=(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).RowVersion;Assert.NotNull(await h.Send());
        var id=await db.WorkItems.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Kind==WorkKind.Expiry).Select(x=>x.Id).SingleAsync();h.Clock.Advance(TimeSpan.FromMinutes(2));
        var store=new WorkStore(db,new(),h.Clock);var lease=(await store.ClaimAsync(id,default)).Lease!;
        if(failed)await store.FinishAsync(lease,new(WorkOutcome.Failed),default);
        var before=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id);var publications=h.Signals.Published;Assert.NotNull(await h.Send());
        var after=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id);
        Assert.Equal(before.Status,after.Status);Assert.Equal(before.LeaseOwner,after.LeaseOwner);Assert.Equal(before.LeaseExpiresAt,after.LeaseExpiresAt);
        Assert.Equal(before.Attempts,after.Attempts);Assert.Equal(before.PayloadJson,after.PayloadJson);Assert.Equal(publications,h.Signals.Published);
    }

    [Fact]
    public async Task Review_and_private_status_GETs_never_prepare_or_republish_deadline_work()
    {
        await using var f=await SenderSendPageTests.Flow.Create(fixture);var page=await f.Page();_=await f.Page();Assert.Equal(0,f.H.Signals.HintCalls);
        using(var response=await f.Send(page))Assert.Equal(System.Net.HttpStatusCode.Redirect,response.StatusCode);
        var hints=f.H.Signals.HintCalls;var published=f.H.Signals.Published;_=await f.Page(f.Status);_=await f.Page(f.Status);
        Assert.Equal(hints,f.H.Signals.HintCalls);Assert.Equal(published,f.H.Signals.Published);
        await using var db=fixture.Open();Assert.Equal(2,await db.WorkItems.CountAsync(x=>x.EnvelopeId==f.H.Envelope.Id));
    }
}
