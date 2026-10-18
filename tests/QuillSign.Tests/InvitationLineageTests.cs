using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Shared = QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class InvitationLineageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Original_and_canonical_reminder_are_one_verified_chain_without_any_mail_producer()
    {
        await using var r=await Run.Create(fixture);
        var original=await r.Read();Assert.Single(original!.Entries);Assert.Equal(r.Sent.InvitationWorkId,original.Latest.Id);
        var next=await r.Admit();var history=await r.Read();Assert.Equal(2,history!.Entries.Length);
        Assert.Equal(next.Id,history.Latest.Id);Assert.Equal(InvitationSuccessorReason.Reminder,history.Latest.Reason);
        Assert.Equal(SignerContactEpoch.Legacy,history.Latest.Contact);Assert.Equal(1,r.H.Sender.Calls);
        using var scope=r.H.App.Services.CreateScope();
        var status=await scope.ServiceProvider.GetRequiredService<SenderSentStatus>().GetAsync(r.H.Principal,r.H.Envelope.PublicId);
        Assert.Equal("Reminder invitation queued",status!.Signers[0].Invitation!.State);
        Assert.Equal(InvitationResendOutcome.Busy,await r.RequestResend());Assert.Equal(1,r.H.Sender.Calls);
    }

    [Fact]
    public async Task Existing_manual_resend_keeps_its_canonical_predecessor_and_can_precede_a_reminder()
    {
        await using var r=await Run.Create(fixture);Assert.Equal(InvitationResendOutcome.Queued,await r.RequestResend());
        Assert.True(await r.H.Once());var old=await r.Read();Assert.Equal(2,old!.Entries.Length);
        Assert.Equal(InvitationSuccessorReason.ManualResend,old.Latest.Reason);
        var next=await r.Admit(previous:old.Latest.Id);var current=await r.Read();Assert.Equal(3,current!.Entries.Length);
        Assert.Equal(next.Id,current.Latest.Id);Assert.Equal(old.Latest.Id,current.Latest.PreviousId);Assert.Equal(2,r.H.Sender.Calls);
    }

    [Theory]
    [InlineData("missing-audit")][InlineData("missing-outbox")][InlineData("orphan-outbox")]
    [InlineData("predecessor")][InlineData("recipient")][InlineData("contact")][InlineData("source")][InlineData("actor")]
    public async Task Missing_or_changed_successor_cannot_disappear_and_fall_back_to_original_success(string fault)
    {
        await using var r=await Run.Create(fixture);var p=await r.Admit(change:fault);
        await using(var db=fixture.Open()) {
            if(fault=="missing-audit")await db.AuditEvents.Where(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==InvitationSuccessorProtection.Event).ExecuteDeleteAsync();
            if(fault=="missing-outbox")await db.EmailOutbox.Where(x=>x.Id==p.Id).ExecuteDeleteAsync();
            if(fault=="orphan-outbox")db.EmailOutbox.Add(new() {EnvelopeId=r.H.Envelope.Id,To=p.Recipient,Template=InvitationSuccessorProtection.Template});
            if(fault=="actor") {
                var audit=await db.AuditEvents.AsNoTracking().SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Event==InvitationSuccessorProtection.Event);
                audit.ActorType=PartyType.Sender;audit.ActorEmail=r.H.Envelope.SenderEmail;audit.Hash=AuditHash.Compute(audit);
                await db.AuditEvents.Where(x=>x.Id==audit.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ActorType,audit.ActorType)
                    .SetProperty(x=>x.ActorEmail,audit.ActorEmail).SetProperty(x=>x.Hash,audit.Hash));
            }
            await db.SaveChangesAsync();
        }
        await Assert.ThrowsAnyAsync<Exception>(()=>r.Read());Assert.Equal(1,r.H.Sender.Calls);
    }

    [Fact]
    public async Task A_fork_or_a_pending_predecessor_cannot_be_overtaken()
    {
        await using var r=await Run.Create(fixture);var first=await r.Admit();
        await r.Admit(previous:first.Id);
        await Assert.ThrowsAsync<InvalidDataException>(()=>r.Read());Assert.Equal(1,r.H.Sender.Calls);
    }

    [Fact]
    public async Task Original_payload_preserves_legacy_serialization_and_rejects_cross_purpose_contact_revisions()
    {
        var legacy=new SignerInvitationPayload(Guid.NewGuid(),DocumentId:Guid.NewGuid(),DocumentSha256:new string('a',64),DisclosureSha256:new string('b',64));
        Assert.DoesNotContain("ContactRevision",JsonSerializer.Serialize(legacy));
        await using var r=await Run.Create(fixture);
        using var scope=r.H.App.Services.CreateScope();await using var db=fixture.Open();
        var row=await db.EmailOutbox.SingleAsync(x=>x.Id==r.Sent.InvitationWorkId);
        var protection=scope.ServiceProvider.GetRequiredService<SignerInvitationProtection>();var p=protection.Read(row.PayloadJson);
        row.PayloadJson=protection.Protect(p with {ContactRevisionId=Guid.NewGuid(),ContactRevisionNumber=1});await db.SaveChangesAsync();
        await Assert.ThrowsAsync<InvalidDataException>(()=>r.Read());Assert.Equal(1,r.H.Sender.Calls);
    }

    [Fact]
    public async Task Historical_original_address_is_preserved_and_a_returned_address_does_not_restore_its_epoch()
    {
        await using var r=await Run.Create(fixture);var original=r.H.First.Email;
        await r.Correct("corrected@example.invalid");
        var old=await r.Read();Assert.Equal(original,old!.Latest.Recipient);Assert.Equal(SignerContactEpoch.Legacy,old.Latest.Contact);
        var second=await r.Correct(original);var after=await r.Read();Assert.Equal(SignerContactEpoch.Legacy,after!.Latest.Contact);
        using var scope=r.H.App.Services.CreateScope();
        var status=await scope.ServiceProvider.GetRequiredService<SenderSentStatus>().GetAsync(r.H.Principal,r.H.Envelope.PublicId);
        Assert.Equal("Invitation retired by contact correction",status!.Signers[0].Invitation!.State);
        await using var db=fixture.Open();await using var tx=await db.Database.BeginTransactionAsync();
        var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==r.H.Envelope.Id);
        var oldToken=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==e.Id);
        Assert.False(await new SignerContactState(db,r.H.Clock).TokenMatchesLockedAsync(e,oldToken));
        var factory=scope.ServiceProvider.GetRequiredService<SignerInvitationFactory>();
        var fresh=factory.Create(e.Id,r.H.First.Id,original,e.ExpiresAt,Guid.ParseExact(e.SentPdfBlob!,"N"),e.SentPdfSha256!,e.ErsdSha256!,second.Id);
        db.AuthTokens.Add(fresh.Record);await db.SaveChangesAsync();
        Assert.Equal(second.Id,fresh.Record.SignerContactRevisionId);
        Assert.True(await new SignerContactState(db,r.H.Clock).TokenMatchesLockedAsync(e,fresh.Record));
    }

    // Disposable local-browser harness; never mapped by the production app.
    public sealed class BrowserSession : IAsyncDisposable
    {
        private readonly Run run;
        private BrowserSession(Run run)=>this.run=run;
        public string PublicId=>run.H.Envelope.PublicId;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port)
        {
            var run=await Run.Create(fixture,port);await run.Admit();run.H.Clock.TrackElapsed();return new(run);
        }
        public ValueTask DisposeAsync()=>run.DisposeAsync();
    }

    internal sealed class Run(Shared h,SqlDatabaseFixture fixture,SentDraft sent):IAsyncDisposable
    {
        private SignerContactRevision? correction;
        public Shared H=>h;public SentDraft Sent=>sent;
        public static async Task<Run> Create(SqlDatabaseFixture fixture,int? browserPort=null,Action<IServiceCollection>? configure=null,bool smtp=false,bool dispatch=true,bool browser=false)
        {
            var h=await Shared.Create(fixture,smtp:smtp,browser:browser || browserPort is not null,browserPort:browserPort,
                configure:s=>{s.AddScoped<SenderSentStatus>();configure?.Invoke(s);});
            h.Clock.Advance(new DateTimeOffset(DateTime.UtcNow.Date.AddDays(2),TimeSpan.Zero).AddHours(1)-h.Clock.GetUtcNow());
            using(var scope=h.App.Services.CreateScope()) {
                var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();await using var tx=await db.Database.BeginTransactionAsync();
                await scope.ServiceProvider.GetRequiredService<AuditWriter>().AppendAsync(h.Envelope.Id,"signer_added",h.Envelope.SenderEmail,null,null,default,
                    JsonSerializer.Serialize(new {signers=new[] {h.First,h.Second}.Select(x=>new {x.Id,x.Order,x.FullName,x.Email,x.Role})}));
                await tx.CommitAsync();
            }
            var limits=h.App.Services.GetRequiredService<InvitationResendOptions>();limits.Enabled=true;
            limits.DailyRequests=limits.DailyAddressRequests=limits.DailySenderRequests=limits.DailyIpRequests=1000;
            if(browserPort is { } port)h.App.Services.GetRequiredService<QuillSign.Email.EmailOptions>().BaseUrl="http://localhost:"+port;
            var sent=(await h.Send())!;if(dispatch)Assert.True(await h.Once());return new(h,fixture,sent);
        }
        public async Task<VerifiedInvitationLineage?> Read()
        {
            using var scope=h.App.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
            await using var tx=await db.Database.BeginTransactionAsync();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);
            var history=await new SignerContactState(db,h.Clock).ReadHistoryLockedAsync(e);
            return await scope.ServiceProvider.GetRequiredService<InvitationLineage>().ReadLockedAsync(e,h.First.Id,history);
        }
        public async Task<InvitationSuccessorScope> Admit(Guid? previous=null,string? change=null)
        {
            using var scope=h.App.Services.CreateScope();var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
            await using var tx=await db.Database.BeginTransactionAsync();var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);
            var p=new InvitationSuccessorScope(InvitationSuccessorProtection.Version,Guid.NewGuid(),e.Id,h.First.Id,previous??sent.InvitationWorkId,
                change=="contact" ? new(Guid.NewGuid(),1) : SignerContactEpoch.Legacy,InvitationSuccessorReason.Reminder,
                change=="recipient" ? "other@example.invalid" : h.First.Email,e.SenderEmail,Guid.ParseExact(e.SentPdfBlob!,"N"),
                change=="source" ? new string('f',64) : Convert.ToHexStringLower(e.SentPdfSha256!),Convert.ToHexStringLower(e.ErsdSha256!),
                new string('c',64),h.Clock.GetUtcNow(),h.Clock.GetUtcNow().AddHours(1));
            if(change=="predecessor")p=p with {PreviousId=Guid.NewGuid()};
            db.EmailOutbox.Add(new() {Id=p.Id,EnvelopeId=e.Id,To=p.Recipient,Template=InvitationSuccessorProtection.Template,AvailableAt=p.AdmittedAt,
                PayloadJson=scope.ServiceProvider.GetRequiredService<InvitationSuccessorProtection>().Protect(new(p))});
            db.WorkItems.Add(new() {Id=p.Id,EnvelopeId=e.Id,Kind=WorkKind.Email,AvailableAt=p.AdmittedAt,PayloadJson=JsonSerializer.Serialize(new {emailId=p.Id})});
            await db.SaveChangesAsync();await scope.ServiceProvider.GetRequiredService<AuditWriter>().AppendAsync(e.Id,InvitationSuccessorProtection.Event,null,null,null,default,
                InvitationSuccessorProtection.Canonical(p),PartyType.System);await tx.CommitAsync();return p;
        }
        public async Task<InvitationResendOutcome> RequestResend()
        {
            using var scope=h.App.Services.CreateScope();var service=scope.ServiceProvider.GetRequiredService<InvitationResends>();
            var until=h.Clock.GetUtcNow().AddHours(2);var review=await service.ReviewAsync(h.Principal,h.Envelope.PublicId,until);
            return await service.RequestAsync(h.Principal,h.Envelope.PublicId,until,Guid.NewGuid(),review!,true,InvitationResendStatement.Version,"127.0.0.1","synthetic");
        }
        public async Task<SignerContactRevision> Correct(string recipient)
        {
            h.Clock.Advance(TimeSpan.FromMinutes(1));using var scope=h.App.Services.CreateScope();
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();await using var tx=await db.Database.BeginTransactionAsync();
            var e=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id);
            var signer=await db.Signers.AsNoTracking().SingleAsync(x=>x.Id==h.First.Id);
            var fields=await db.Fields.AsNoTracking().Where(x=>x.EnvelopeId==e.Id && x.SignerId==signer.Id).ToArrayAsync();
            var retired=SignerContactState.RetirementJson(signer,fields);var at=h.Clock.GetUtcNow();
            var change=new SignerContactRevision(SignerContactHistory.Version,Guid.NewGuid(),e.Id,signer.Id,correction?.Id??Guid.Empty,(correction?.Number??0)+1,
                signer.Email,recipient,at,at.AddHours(1),Convert.ToBase64String(e.RowVersion),Convert.ToBase64String(signer.RowVersion),Guid.ParseExact(e.SentPdfBlob!,"N"),
                Convert.ToHexStringLower(e.SentPdfSha256!),Convert.ToHexStringLower(e.ErsdSha256!),SignerContactState.RetirementDigest(retired),
                correction is null ? null : SignerContactHistory.Digest(correction),SignerContactHistory.StatementVersion,SignerContactHistory.StatementSha256);
            db.SignerContactRevisions.Add(new() {Id=change.Id,EnvelopeId=e.Id,SignerId=signer.Id,Number=change.Number,PreviousRevisionId=correction?.Id,
                ChangedAt=at,EvidenceJson=SignerContactHistory.Canonical(change),RetirementJson=retired});
            await db.Signers.Where(x=>x.Id==signer.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Email,recipient).SetProperty(x=>x.Status,SignerStatus.Pending));
            await db.AuthTokens.Where(x=>x.EnvelopeId==e.Id && x.PartyId==signer.Id && x.Purpose==TokenPurpose.SignerAccess && x.UsedAt==null && x.ExpiresAt>at)
                .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ExpiresAt,at));
            await db.SaveChangesAsync();await scope.ServiceProvider.GetRequiredService<AuditWriter>().AppendAsync(e.Id,SignerContactHistory.Event,e.SenderEmail,null,null,default,
                SignerContactHistory.Canonical(change));await tx.CommitAsync();correction=change;return change;
        }
        public async ValueTask DisposeAsync()
        {
            await using(var db=fixture.Open()) {
                var ids=await db.EmailOutbox.Where(x=>x.EnvelopeId==h.Envelope.Id && x.Template!="signer-invitation").Select(x=>x.Id).ToArrayAsync();
                await db.WorkItems.Where(x=>ids.Contains(x.Id)).ExecuteDeleteAsync();await db.EmailOutbox.Where(x=>ids.Contains(x.Id)).ExecuteDeleteAsync();
                await db.AuditEvents.Where(x=>x.EnvelopeId==h.Envelope.Id && (x.Event.StartsWith("invitation_resend_") || x.Event==InvitationSuccessorProtection.Event)).ExecuteDeleteAsync();
            }
            await h.DisposeAsync();
        }
    }
}
