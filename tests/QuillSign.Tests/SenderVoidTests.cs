using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;
using SigningRun=QuillSign.Tests.CompletionEvidenceCollectorTests.Run;

namespace QuillSign.Tests;

public sealed class SenderVoidTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Confirmed_void_preserves_frozen_records_and_stops_the_queued_invitation_with_no_provider_call()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);var before=await Fingerprint(e.Id);var blobs=h.Blobs.Created.Count;
        var result=await Void(h,e,reason:"  synthetic\r\nreason  ");Assert.Equal(SenderVoidOutcome.Voided,result.Outcome);Assert.Equal(h.Clock.GetUtcNow(),result.Action!.VoidedAt);Assert.Equal("synthetic\nreason",result.Action.Reason);
        Assert.Equal(EnvelopeStatus.Voided,(await Load(e.Id)).Status);Assert.Equal(before,await Fingerprint(e.Id));Assert.Equal(blobs,h.Blobs.Created.Count);Assert.Empty(h.Blobs.Deleted);
        Assert.True(await h.Once());Assert.Equal(0,h.Sender.Calls);
        await using var db=fixture.Open();Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==e.Id && x.Purpose==TokenPurpose.SignerAccess));
        Assert.Equal(EmailStatus.Failed,(await db.EmailOutbox.SingleAsync(x=>x.EnvelopeId==e.Id)).Status);
        var entry=await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided");Assert.Equal(PartyType.Sender,entry.ActorType);Assert.Equal(e.SenderEmail,entry.ActorEmail);Assert.Equal(AuditHash.Compute(entry),entry.Hash);
        using var scope=h.App.Services.CreateScope();var status=await scope.ServiceProvider.GetRequiredService<SenderSentStatus>().GetAsync(h.Principal,e.PublicId);Assert.Equal("Voided",status!.State);
    }

    [Fact]
    public async Task Scope_original_ticket_expiry_statement_version_reason_and_row_version_are_required_before_any_void()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);
        foreach(var kind in new[]{"affirmation","statement","version","reason-length","reason-control","public-id","expiry","foreign","mixed","duplicate-email"}) {
            var principal=h.Principal;var id=e.PublicId;var until=h.Clock.GetUtcNow().AddHours(1);var version=e.RowVersion;var affirmed=true;var statement=SenderVoidStatement.Version;string? reason=null;
            if(kind=="affirmation")affirmed=false;if(kind=="statement")statement="old";if(kind=="version")version=new byte[8];
            if(kind=="reason-length")reason=new string('x',513);if(kind=="reason-control")reason="bad\0reason";
            if(kind=="public-id")id=Guid.NewGuid().ToString("N");if(kind=="expiry")until=h.Clock.GetUtcNow();
            if(kind=="foreign")principal=SenderConfiguration.Principal(new(Guid.NewGuid(),e.PublicId,e.SenderEmail));
            if(kind=="mixed")principal.AddIdentity(new ClaimsIdentity([new Claim("synthetic","value")],SignerAccessConfiguration.Scheme));
            if(kind=="duplicate-email")((ClaimsIdentity)principal.Identity!).AddClaim(new(ClaimTypes.Email,e.SenderEmail));
            using var scope=h.App.Services.CreateScope();var result=await scope.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(principal,id,until,version,affirmed,statement,reason,null,null);
            Assert.Equal(kind=="version" ? SenderVoidOutcome.Conflict : kind is "affirmation" or "statement" or "reason-length" or "reason-control" ? SenderVoidOutcome.InvalidConfirmation : SenderVoidOutcome.InvalidContext,result.Outcome);
        }
        Assert.Equal(EnvelopeStatus.Sent,(await Load(e.Id)).Status);await using var db=fixture.Open();Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided"));
    }

    [Fact]
    public async Task Concurrent_identical_confirmation_returns_one_record_and_changed_replay_never_creates_another()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);
        var results=await Task.WhenAll(Void(h,e,reason:"Synthetic reason"),Void(h,e,reason:"Synthetic reason"));
        Assert.Single(results,x=>x.Outcome==SenderVoidOutcome.Voided);Assert.Single(results,x=>x.Outcome==SenderVoidOutcome.AlreadyVoided);Assert.Equal(results[0].Action,results[1].Action);
        Assert.Equal(SenderVoidOutcome.Conflict,(await Void(h,e,reason:"Changed reason")).Outcome);
        Assert.Equal(SenderVoidOutcome.Conflict,(await Void(h,await Load(e.Id),reason:"Synthetic reason")).Outcome);
        await using var db=fixture.Open();Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided"));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Audit_rollback_and_lost_commit_acknowledgement_preserve_truth_and_allow_only_an_explicit_existing_action(bool lostCommit)
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);var before=await Fingerprint(e.Id);
        h.Faults.FailAudit=!lostCommit;h.Faults.FailCommit=lostCommit;
        using(var scope=h.App.Services.CreateScope()) {
            var service=scope.ServiceProvider.GetRequiredService<SenderVoid>();var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
            var operation=()=>service.VoidAsync(h.Principal,e.PublicId,h.Clock.GetUtcNow().AddHours(1),e.RowVersion,true,SenderVoidStatement.Version,null,null,null);
            if(lostCommit)await Assert.ThrowsAsync<IOException>(operation);else await Assert.ThrowsAsync<DbUpdateException>(operation);
            Assert.False(db.ChangeTracker.HasChanges());h.Faults.FailAudit=false;h.Faults.FailCommit=false;await db.SaveChangesAsync();
        }
        Assert.Equal(lostCommit ? EnvelopeStatus.Voided : EnvelopeStatus.Sent,(await Load(e.Id)).Status);Assert.Equal(before,await Fingerprint(e.Id));
        Assert.Equal(lostCommit ? SenderVoidOutcome.AlreadyVoided : SenderVoidOutcome.Voided,(await Void(h,e)).Outcome);
        await using var check=fixture.Open();Assert.Equal(1,await check.AuditEvents.CountAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided"));
    }

    [Theory]
    [InlineData(EnvelopeStatus.Draft)][InlineData(EnvelopeStatus.Declined)][InlineData(EnvelopeStatus.Expired)]
    public async Task Closed_or_unsent_requests_cannot_be_voided(EnvelopeStatus status)
    {
        await using var h=await Shared.Create(fixture,browser:true);if(status!=EnvelopeStatus.Draft)Assert.NotNull(await h.Send());
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,status));
        var e=await Load(h.Envelope.Id);Assert.Equal(SenderVoidOutcome.Closed,(await Void(h,e)).Outcome);Assert.Equal(status,(await Load(e.Id)).Status);
    }

    [Fact]
    public async Task Deadline_passed_while_still_Sent_cannot_be_voided()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);h.Clock.Advance(e.ExpiresAt!.Value-h.Clock.GetUtcNow());
        Assert.Equal(SenderVoidOutcome.Closed,(await Void(h,e)).Outcome);Assert.Equal(EnvelopeStatus.Sent,(await Load(e.Id)).Status);
    }

    [Fact]
    public async Task Voiding_after_first_signature_stops_unfinished_signer_edits_review_and_Finish_without_changing_prior_evidence()
    {
        await using var run=await SigningRun.Create(fixture,finishLast:false);var e=await run.Refresh();var fields=(await run.Use((SignerFields s)=>s.GetAsync(run.LastSigner,e.PublicId)))!;var field=fields.Fields.First(x=>x.Type==FieldType.Signature);var before=await Fingerprint(e.Id);
        Assert.Equal(SenderVoidOutcome.Voided,(await Void(run.H,e,run.Sender)).Outcome);Assert.Equal(before,await Fingerprint(e.Id));
        Assert.Null(await run.Use((SignerAccess s)=>s.GetContextAsync(run.LastSigner,e.PublicId)));
        Assert.Equal(SignerFieldOutcome.NotFound,(await run.Use((SignerFields s)=>s.ChangeAsync(run.LastSigner,e.PublicId,new(field.Id,field.Version,SignerFieldAction.Clear),null,null))).Outcome);
        Assert.Null(await run.Use((SignerReviewCandidates s)=>s.PrepareAsync(run.LastSigner,e.PublicId,null,null)));
        Assert.Equal(SignerFinishOutcome.InvalidContext,(await run.Use((SignerFinish s)=>s.AcceptAsync(run.LastSigner,e.PublicId,run.LastReviewReceipt,true,SignerFinishStatement.Version,null,null))).Outcome);
        Assert.Equal(before,await Fingerprint(e.Id));Assert.Equal(EnvelopeStatus.Voided,(await Load(e.Id)).Status);
    }

    [Fact]
    public async Task Accepted_but_unpublished_Finish_stays_immutable_and_its_checkpoint_worker_cannot_advance_after_void()
    {
        await using var run=await SigningRun.Create(fixture,publishLast:false);var e=await run.Refresh();var before=await Fingerprint(e.Id);var calls=run.H.Sender.Calls;
        Assert.Equal(SenderVoidOutcome.Voided,(await Void(run.H,e,run.Sender)).Outcome);Assert.True(await run.H.Once());Assert.Equal(before,await Fingerprint(e.Id));Assert.Equal(calls,run.H.Sender.Calls);
        await using var db=fixture.Open();Assert.Equal(1,await db.Signers.CountAsync(x=>x.EnvelopeId==e.Id && x.Status==SignerStatus.Signed));
        Assert.Equal(1,await db.SignerFinishAcceptances.CountAsync(x=>x.EnvelopeId==e.Id && x.ProcessedAt==null));Assert.False(await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==e.Id));
        Assert.Equal(WorkStatus.Failed,(await db.WorkItems.SingleAsync(x=>x.EnvelopeId==e.Id && x.Kind==WorkKind.Rendering && x.Status==WorkStatus.Failed)).Status);
    }

    [Fact]
    public async Task Concurrent_Finish_and_void_preserve_any_accepted_act_but_prevent_later_progression()
    {
        await using var run=await SigningRun.Create(fixture,finishLast:false);var e=await run.Refresh();var calls=run.H.Sender.Calls;var blobs=run.H.Blobs.Created.Count;
        var voiding=Void(run.H,e,run.Sender);var finishing=run.Use((SignerFinish s)=>s.AcceptAsync(run.LastSigner,e.PublicId,run.LastReviewReceipt,true,SignerFinishStatement.Version,null,null));
        await Task.WhenAll(voiding,finishing);Assert.Equal(SenderVoidOutcome.Voided,(await voiding).Outcome);var finish=(await finishing).Outcome;Assert.True(finish is SignerFinishOutcome.Accepted or SignerFinishOutcome.InvalidContext);
        Assert.Equal(EnvelopeStatus.Voided,(await Load(e.Id)).Status);await using var db=fixture.Open();Assert.Equal(1,await db.Signers.CountAsync(x=>x.EnvelopeId==e.Id && x.Status==SignerStatus.Signed));
        Assert.Equal(finish==SignerFinishOutcome.Accepted ? 1 : 0,await db.SignerFinishAcceptances.CountAsync(x=>x.EnvelopeId==e.Id && x.ProcessedAt==null));
        if(finish==SignerFinishOutcome.Accepted)Assert.True(await run.H.Once());
        Assert.Equal(calls,run.H.Sender.Calls);Assert.Equal(blobs,run.H.Blobs.Created.Count);Assert.False(await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==e.Id));
        Assert.Equal(1,await db.AuditEvents.CountAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided"));
    }

    [Fact]
    public async Task Previously_prepared_seals_are_retained_and_void_prevents_final_publication()
    {
        await using var run=await CompletionSealOutputTests.Run.Create(fixture);_ = await run.Prepare();var e=await run.Signing.Refresh();var before=await Fingerprint(e.Id);var requests=run.Seal.Requests;var deleted=run.Storage.Deleted.Count;
        Assert.Equal(SenderVoidOutcome.Voided,(await Void(run.Signing.H,e,run.Signing.Sender)).Outcome);
        Assert.Null(await run.Prepare());Assert.Equal(before,await Fingerprint(e.Id));Assert.Equal(requests,run.Seal.Requests);Assert.Equal(deleted,run.Storage.Deleted.Count);
        await using var db=fixture.Open();var store=new CompletionDownloadTests.FinalStore(run.Signing.H.Clock);
        var publication=new CompletionPublication(db,run.Candidates(db),run.Service(db),run.Collector(db),store,new(db,run.Signing.H.Clock),run.Signing.H.Clock,
            new() {DemoPurgeAfterDays=7,AllowDevelopmentWriteOnce=true},run.Seal.App.Environment);
        Assert.Null(await publication.PublishAsync(e.Id));Assert.Equal(0,store.Writes);Assert.False(await db.CompletionPublicationResults.AnyAsync(x=>x.EnvelopeId==e.Id));Assert.Equal(2,await db.CompletionSealOutputs.CountAsync(x=>x.EnvelopeId==e.Id));
    }

    [Fact]
    public async Task Completed_packet_wins_and_cannot_be_voided_or_rewritten()
    {
        await using var flow=await CompletionDownloadTests.Flow.Create(fixture);var e=await Load(flow.Id);var before=await Fingerprint(e.Id);
        Assert.Equal(SenderVoidOutcome.Closed,(await Void(flow.Run.Signing.H,e,flow.Run.Signing.Sender)).Outcome);Assert.Equal(before,await Fingerprint(e.Id));Assert.Equal(EnvelopeStatus.Completed,(await Load(e.Id)).Status);Assert.Equal(2,flow.Store.Writes);Assert.Equal(2,flow.Run.Seal.Requests);
    }

    [Fact]
    public async Task Changed_sent_hash_or_void_audit_cannot_manufacture_confirmation()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,new byte[32]));
        var changed=await Load(e.Id);await Assert.ThrowsAsync<InvalidDataException>(()=>Void(h,changed));Assert.Equal(EnvelopeStatus.Sent,(await Load(e.Id)).Status);
        await using(var db=fixture.Open())await db.Envelopes.Where(x=>x.Id==e.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,e.SentPdfSha256));
        e=await Load(e.Id);Assert.Equal(SenderVoidOutcome.Voided,(await Void(h,e)).Outcome);
        await using(var db=fixture.Open())await db.AuditEvents.Where(x=>x.EnvelopeId==e.Id && x.Event=="voided").ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{}"));
        await Assert.ThrowsAsync<InvalidDataException>(()=>Void(h,e));
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Ticket_or_envelope_expiry_during_audit_storage_rolls_back_without_pending_entities(bool ticket)
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());
        if(!ticket) {await using var update=fixture.Open();await update.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,h.Clock.GetUtcNow().AddSeconds(2)));}
        var e=await Load(h.Envelope.Id);await using var baseline=fixture.Open();
        var options=new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(new AuditExpiry(h.Clock));await using var db=new QuillSignDbContext(options.Options);
        var service=new SenderVoid(db,new(db,h.Clock),new(db,h.Clock),h.Clock);
        var result=await service.VoidAsync(h.Principal,e.PublicId,h.Clock.GetUtcNow().AddSeconds(ticket ? 2 : 3600),e.RowVersion,true,SenderVoidStatement.Version,null,null,null);
        Assert.Equal(ticket ? SenderVoidOutcome.InvalidContext : SenderVoidOutcome.Closed,result.Outcome);Assert.Empty(db.ChangeTracker.Entries());await db.SaveChangesAsync();
        Assert.Equal(EnvelopeStatus.Sent,(await Load(e.Id)).Status);await using var check=fixture.Open();Assert.False(await check.AuditEvents.AnyAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided"));
    }

    [Fact]
    public async Task Recomputed_void_hash_with_a_broken_predecessor_link_cannot_confirm_a_replay()
    {
        await using var h=await Shared.Create(fixture,browser:true);Assert.NotNull(await h.Send());var e=await Load(h.Envelope.Id);Assert.Equal(SenderVoidOutcome.Voided,(await Void(h,e)).Outcome);
        await using(var db=fixture.Open()) {var row=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==e.Id && x.Event=="voided");row.PrevHash=new byte[32];var hash=AuditHash.Compute(row);
            await db.AuditEvents.Where(x=>x.Id==row.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PrevHash,row.PrevHash).SetProperty(x=>x.Hash,hash));}
        await Assert.ThrowsAsync<InvalidDataException>(()=>Void(h,e));Assert.Equal(EnvelopeStatus.Voided,(await Load(e.Id)).Status);
    }

    private sealed class AuditExpiry(SendDraftWorkflowTests.Clock clock) : SaveChangesInterceptor {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData data,InterceptionResult<int> result,CancellationToken ct=default) {
            if(data.Context!.ChangeTracker.Entries<AuditEvent>().Any(x=>x.State==EntityState.Added && x.Entity.Event=="voided"))clock.Advance(TimeSpan.FromSeconds(3));
            return ValueTask.FromResult(result);
        }
    }

    private async Task<Envelope> Load(Guid id) {await using var db=fixture.Open();return await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id);}
    private async Task<SenderVoidResult> Void(Shared h,Envelope e,ClaimsPrincipal? sender=null,string? reason=null) {
        using var scope=h.App.Services.CreateScope();return await scope.ServiceProvider.GetRequiredService<SenderVoid>().VoidAsync(sender??h.Principal,e.PublicId,h.Clock.GetUtcNow().AddHours(1),e.RowVersion,true,SenderVoidStatement.Version,reason,"127.0.0.1","Synthetic sender void");
    }
    private async Task<string> Fingerprint(Guid id) {
        await using var db=fixture.Open();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==id);
        return JsonSerializer.Serialize(new {e.SentPdfBlob,e.SentPdfSha256,e.ErsdVersion,e.ErsdSha256,e.CurrentCopyVersion,e.CurrentFinishId,e.FinalBlob,e.FinalSha256,e.CertificateBlob,e.CertificateSha256,e.CompletedAt,e.PurgeAfter,
            Signers=await db.Signers.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync(),Fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync(),
            Finishes=await db.SignerFinishAcceptances.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync(),Reviews=await db.SignerReviewCandidates.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync(),
            Candidates=await db.CompletionCandidates.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync(),Seals=await db.CompletionSealOutputs.AsNoTracking().Where(x=>x.EnvelopeId==id).OrderBy(x=>x.Id).ToArrayAsync()});
    }
}
