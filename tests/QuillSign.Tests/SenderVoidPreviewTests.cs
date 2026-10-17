using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Sender;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SenderVoidPreviewTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Preview_is_readonly_and_returns_current_revision_then_the_exact_recorded_action_after_void()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Envelope(h);var before=await Counts(e.Id);
        for(var i=0;i<2;i++) {using var scope=h.App.Services.CreateScope();var preview=(await scope.ServiceProvider.GetRequiredService<SenderVoidState>().PreviewAsync(h.Principal,e.PublicId,h.Clock.GetUtcNow().AddHours(1)))!;
            Assert.True(preview.CanVoid);Assert.Equal(Convert.ToBase64String(e.RowVersion),preview.Version);Assert.Equal(2,preview.Signers.Count);Assert.Null(preview.Action);}
        Assert.Equal(before,await Counts(e.Id));SenderVoidRecord action;
        using(var scope=h.App.Services.CreateScope())action=(await scope.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(h.Principal,e.PublicId,h.Clock.GetUtcNow().AddHours(1),e.RowVersion,true,SenderVoidStatement.Version,"Synthetic void",null,null)).Action!;
        var after=await Envelope(h);before=await Counts(e.Id);
        for(var i=0;i<2;i++) {using var scope=h.App.Services.CreateScope();var preview=(await scope.ServiceProvider.GetRequiredService<SenderVoidState>().PreviewAsync(h.Principal,e.PublicId,h.Clock.GetUtcNow().AddHours(1)))!;
            Assert.False(preview.CanVoid);Assert.Equal(action,preview.Action);Assert.Equal(Convert.ToBase64String(after.RowVersion),preview.Version);Assert.NotEqual(Convert.ToBase64String(e.RowVersion),preview.Version);}
        Assert.Equal(before,await Counts(e.Id));
    }

    [Fact]
    public async Task Preview_rejects_expired_foreign_mixed_and_missing_original_sender_context_without_writes()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Envelope(h);var before=await Counts(e.Id);
        foreach(var kind in new[]{"expiry","foreign","mixed","missing"}) {
            var principal=h.Principal;var until=h.Clock.GetUtcNow().AddHours(1);
            if(kind=="expiry")until=h.Clock.GetUtcNow();if(kind=="foreign")principal=SenderConfiguration.Principal(new(Guid.NewGuid(),e.PublicId,e.SenderEmail));
            if(kind=="mixed")principal.AddIdentity(new ClaimsIdentity([new Claim("synthetic","value")],"QuillSign.CompletionReader"));if(kind=="missing")principal=new();
            using var scope=h.App.Services.CreateScope();Assert.Null(await scope.ServiceProvider.GetRequiredService<SenderVoidState>().PreviewAsync(principal,e.PublicId,until));
        }
        Assert.Equal(before,await Counts(e.Id));
    }

    [Fact]
    public async Task Elapsed_deadline_is_closed_without_recording_a_void_or_changing_pending_work()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Envelope(h);h.Clock.Advance(e.ExpiresAt!.Value-h.Clock.GetUtcNow());var before=await Counts(e.Id);
        using var scope=h.App.Services.CreateScope();var preview=(await scope.ServiceProvider.GetRequiredService<SenderVoidState>().PreviewAsync(h.Principal,e.PublicId,h.Clock.GetUtcNow().AddHours(1)))!;
        Assert.False(preview.CanVoid);Assert.Null(preview.Action);Assert.Equal(before,await Counts(e.Id));
    }

    [Fact]
    public async Task Closed_pending_Finish_is_reported_as_historical_acceptance_without_promising_more_processing()
    {
        await using var run=await CompletionEvidenceCollectorTests.Run.Create(fixture,publishLast:false);var e=await run.Refresh();var until=run.H.Clock.GetUtcNow().AddHours(1);
        using(var scope=run.H.App.Services.CreateScope())Assert.Equal(SenderVoidOutcome.Voided,(await scope.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(run.Sender,e.PublicId,until,e.RowVersion,true,SenderVoidStatement.Version,null,null,null)).Outcome);
        var before=await Counts(e.Id);
        using(var scope=run.H.App.Services.CreateScope()) {
            var preview=(await scope.ServiceProvider.GetRequiredService<SenderVoidState>().PreviewAsync(run.Sender,e.PublicId,until))!;
            Assert.Equal("Signed",preview.Signers[0].State);Assert.Equal("Finish accepted before void",preview.Signers[1].State);Assert.Null(preview.Signers[1].SignedAt);
            var status=(await scope.ServiceProvider.GetRequiredService<SenderSentStatus>().GetAsync(run.Sender,e.PublicId))!;
            Assert.Equal("Voided",status.State);Assert.Equal("Finish accepted before void",status.Signers[1].State);
        }
        Assert.Equal(before,await Counts(e.Id));
    }

    private async Task<Envelope> Envelope(Shared h) {await using var db=fixture.Open();return await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);}
    private async Task<string> Counts(Guid id) {await using var db=fixture.Open();return string.Join(':',await db.AuditEvents.CountAsync(x=>x.EnvelopeId==id),await db.WorkItems.CountAsync(x=>x.EnvelopeId==id),await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==id),await db.AuthTokens.CountAsync(x=>x.EnvelopeId==id));}
}
