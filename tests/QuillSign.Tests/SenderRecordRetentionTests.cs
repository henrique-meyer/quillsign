using System.Data.Common;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Signing;
using Retained=QuillSign.Tests.RetentionSigningDeadlineTests.Retained;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SenderRecordRetentionTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Status_and_void_scope_are_private_at_and_after_the_exact_fixed_deadline_without_mutation()
    {
        await using var r=await Retained.Create(fixture,browser:true);await Sent(r);var h=r.H;
        h.Clock.Advance(r.Policy.DeleteAfter-h.Clock.GetUtcNow()-TimeSpan.FromTicks(1));
        Assert.NotNull(await Status(h));Assert.True((await Preview(h))!.CanVoid);var before=await State(h);var version=(await r.State()).RowVersion;
        h.Clock.Advance(TimeSpan.FromTicks(1));
        for(var i=0;i<2;i++) {
            await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Status(h));
            await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Preview(h));
            await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Void(h,version));
            Assert.Equal(before,await State(h));h.Clock.Advance(TimeSpan.FromTicks(1));
        }
    }

    [Fact]
    public async Task A_private_status_collection_read_crossing_the_cutoff_returns_no_snapshot()
    {
        await using var r=await Retained.Create(fixture,browser:true);await Sent(r);var h=r.H;var before=await State(h);
        using var source=fixture.Open();var cross=new CrossRead(()=>h.Clock.Advance(r.Policy.DeleteAfter-h.Clock.GetUtcNow()));
        await using var db=new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(source.Database.GetConnectionString()).AddInterceptors(cross).Options);
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>new SenderSentStatus(db,h.Clock,new(db,h.Clock)).GetAsync(h.Principal,h.Envelope.PublicId));
        Assert.True(cross.Calls>0);Assert.Equal(before,await State(h));
    }

    [Fact]
    public async Task Void_audit_crossing_rolls_back_action_notifications_and_saved_state()
    {
        await using var r=await Retained.Create(fixture,browser:true);await Sent(r);var h=r.H;
        h.Clock.Advance(r.Policy.DeleteAfter-h.Clock.GetUtcNow()-TimeSpan.FromSeconds(1));var e=await r.State();var before=await State(h);var calls=0;
        h.Faults.Event="voided";h.Faults.BeforeAudit=_=> {calls++;h.Clock.Advance(r.Policy.DeleteAfter-h.Clock.GetUtcNow());return Task.CompletedTask;};
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Void(h,e.RowVersion));Assert.Equal(1,calls);Assert.Equal(before,await State(h));
    }

    [Fact]
    public async Task A_saved_void_cannot_be_recovered_by_an_expired_public_replay()
    {
        await using var r=await Retained.Create(fixture,browser:true);await Sent(r);var e=await r.State();
        Assert.Equal(SenderVoidOutcome.Voided,(await Void(r.H,e.RowVersion)).Outcome);var before=await State(r.H);
        r.H.Clock.Advance(r.Policy.DeleteAfter-r.H.Clock.GetUtcNow());
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Void(r.H,e.RowVersion));
        await Assert.ThrowsAsync<DocumentRetentionExpiredException>(()=>Preview(r.H));Assert.Equal(before,await State(r.H));
    }

    [Theory]
    [InlineData("missing")][InlineData("changed")]
    public async Task Wrong_owner_and_earlier_ticket_expiry_precede_unverifiable_policy(string fault)
    {
        await using var r=await Retained.Create(fixture,browser:true);await Sent(r);var h=r.H;var e=await r.State();
        await using(var db=fixture.Open()) {
            if(fault=="missing")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==e.Id).ExecuteDeleteAsync();
            else await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==e.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.OriginalSha256,new byte[32]));
        }
        var before=await State(h);var wrong=SenderConfiguration.Principal(new(e.Id,e.PublicId,"wrong@example.invalid"));
        using var scope=h.App.Services.CreateScope();
        Assert.Null(await scope.ServiceProvider.GetRequiredService<SenderSentStatus>().GetAsync(wrong,e.PublicId));
        Assert.Null(await scope.ServiceProvider.GetRequiredService<SenderVoidState>().PreviewAsync(wrong,e.PublicId,h.Clock.GetUtcNow().AddHours(1)));
        Assert.Equal(SenderVoidOutcome.InvalidContext,(await scope.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(h.Principal,e.PublicId,h.Clock.GetUtcNow(),e.RowVersion,true,SenderVoidStatement.Version,null,null,null)).Outcome);
        await Assert.ThrowsAsync<PreparationRetentionEvidenceException>(()=>Status(h));
        await Assert.ThrowsAsync<PreparationRetentionEvidenceException>(()=>Preview(h));
        await Assert.ThrowsAsync<PreparationRetentionEvidenceException>(()=>Void(h,e.RowVersion));Assert.Equal(before,await State(h));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Ordinary_or_historical_unenrolled_sent_requests_do_not_acquire_a_new_policy(bool demo)
    {
        await using var h=await Shared.Create(fixture,browser:true);
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.IsDemo,demo));
        await using(var db=fixture.Open())h.Version=(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).RowVersion;
        Assert.NotNull(await h.Send());h.App.Services.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays=7;
        Assert.NotNull(await Status(h));Assert.NotNull(await Preview(h));
        await using var inspect=fixture.Open();Assert.False(await inspect.DocumentRetentionSnapshots.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id));
    }

    private static async Task Sent(Retained r) {var review=(await r.Review())!;Assert.NotNull(await r.H.Send(reviewedRetentionSha256:review.RetentionSha256));}
    private static async Task<SenderSentSnapshot?> Status(Shared h) {using var scope=h.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<SenderSentStatus>().GetAsync(h.Principal,h.Envelope.PublicId);}
    private static async Task<SenderVoidPreview?> Preview(Shared h) {using var scope=h.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<SenderVoidState>().PreviewAsync(h.Principal,h.Envelope.PublicId,h.Clock.GetUtcNow().AddHours(1));}
    private static async Task<SenderVoidResult> Void(Shared h,byte[] version) {using var scope=h.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(h.Principal,h.Envelope.PublicId,h.Clock.GetUtcNow().AddHours(1),version,true,SenderVoidStatement.Version,"Synthetic retention void",null,null);}
    private async Task<string> State(Shared h) {
        await using var db=fixture.Open();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);
        return JsonSerializer.Serialize(new {e.Status,e.RowVersion,e.SentPdfBlob,e.SentPdfSha256,e.ExpiresAt,Audit=await db.AuditEvents.CountAsync(x=>x.EnvelopeId==e.Id),
            Jobs=await db.WorkItems.CountAsync(x=>x.EnvelopeId==e.Id),Mail=await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==e.Id)});
    }
    private sealed class CrossRead(Action cross):DbCommandInterceptor {
        public int Calls;
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command,CommandExecutedEventData data,DbDataReader result,CancellationToken ct=default) {
            if(command.CommandText.Contains("FROM [Recipients]",StringComparison.Ordinal)){Calls++;cross();}return ValueTask.FromResult(result);
        }
    }
}
