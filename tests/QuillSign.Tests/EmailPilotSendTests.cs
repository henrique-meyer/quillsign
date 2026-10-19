using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotSendTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Live_enrolled_sender_can_freeze_exact_preparation_and_recover_it_while_public_email_stays_off()
    {
        await using var h=await Run.Create(fixture);var result=Assert.IsType<SentDraft>(await h.H.Send());
        Assert.Equal(result,await h.H.Send());Assert.False(h.Email.Enabled);Assert.Equal(0,h.H.Sender.Calls);
        await using var db=fixture.Open();var source=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.H.Envelope.Id);
        Assert.Equal(EnvelopeStatus.Sent,source.Status);Assert.Equal(2,await db.EmailOutbox.CountAsync(x=>x.EnvelopeId==source.Id));
        var first=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==result.InvitationWorkId);
        using var scope=h.H.App.Services.CreateScope();var payload=scope.ServiceProvider.GetRequiredService<SignerInvitationProtection>().Read(first.PayloadJson);
        Assert.Equal(h.H.First.Id,payload.SignerId);Assert.Equal(result.DocumentHash,payload.DocumentSha256);
        Assert.Equal(result.DisclosureHash,payload.DisclosureSha256);Assert.Null(payload.LastTokenId);
        Assert.Empty(await db.AuthTokens.Where(x=>x.EnvelopeId==source.Id).ToArrayAsync());
    }

    [Theory]
    [InlineData("disabled")][InlineData("expiry")][InlineData("run")][InlineData("public-email")][InlineData("recipient")][InlineData("signer")]
    public async Task Stale_or_unapproved_cohort_never_uses_ordinary_send_fallback(string change)
    {
        await using var h=await Run.Create(fixture);
        if(change=="disabled")h.Options.Enabled=false;
        if(change=="expiry")h.H.Clock.Advance(TimeSpan.FromMinutes(60));
        if(change=="run")h.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="public-email")h.Email.Enabled=true;
        await using(var db=fixture.Open()) {
            if(change=="recipient")await db.Recipients.Where(x=>x.EnvelopeId==h.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Email,"unapproved@example.invalid"));
            if(change=="signer")await db.Signers.Where(x=>x.Id==h.H.First.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Email,"unapproved@example.invalid"));
            h.H.Version=(await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.H.Envelope.Id)).RowVersion;
        }
        await Assert.ThrowsAsync<EmailDisabledException>(()=>h.H.Send());await h.AssertDraft(fixture);Assert.Equal(0,h.H.Sender.Calls);
    }

    [Theory]
    [InlineData("expiry")][InlineData("disable")][InlineData("public-email")]
    public async Task Slow_frozen_blob_write_crossing_scope_cutoff_rolls_back_Send(string change)
    {
        await using var h=await Run.Create(fixture);
        h.H.Blobs.AfterWrite=()=>{if(change=="expiry")h.H.Clock.Advance(TimeSpan.FromHours(1));if(change=="disable")h.Options.Enabled=false;if(change=="public-email")h.Email.Enabled=true;};
        await Assert.ThrowsAsync<EmailDisabledException>(()=>h.H.Send());await h.AssertDraft(fixture);
        Assert.Single(h.H.Blobs.Deleted);Assert.Equal(0,h.H.Sender.Calls);
    }

    [Theory]
    [InlineData("expiry")][InlineData("disable")][InlineData("public-email")]
    public async Task Invitation_hint_cannot_commit_a_new_outbox_after_scope_authority_ends(string change)
    {
        await using var h=await Run.Create(fixture);
        h.AfterHint=()=>{if(change=="expiry")h.H.Clock.Advance(TimeSpan.FromHours(1));if(change=="disable")h.Options.Enabled=false;if(change=="public-email")h.Email.Enabled=true;};
        await Assert.ThrowsAsync<EmailDisabledException>(()=>h.H.Send());await h.AssertDraft(fixture);
        Assert.Single(h.H.Blobs.Deleted);Assert.Equal(0,h.H.Sender.Calls);
    }

    [Theory]
    [InlineData("pdf")][InlineData("disclosure")]
    public async Task Final_freeze_verification_rejects_changed_source_after_initial_invitation_preparation(string change)
    {
        await using var h=await Run.Create(fixture);h.H.Faults.Event="fields_finalized";
        h.H.Faults.BeforeAudit=async db=>{
            if(change=="pdf")await db.Envelopes.Where(x=>x.Id==h.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SentPdfSha256,new byte[32]));
            else await db.Envelopes.Where(x=>x.Id==h.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ErsdText,x=>x.ErsdText+" "));
        };
        await Assert.ThrowsAsync<InvalidDataException>(()=>h.H.Send());await h.AssertDraft(fixture);
    }

    [Theory]
    [InlineData("expiry")][InlineData("disable")][InlineData("public-email")]
    public async Task Existing_sent_command_is_not_a_replay_fallback_after_pilot_authority_ends(string change)
    {
        await using var h=await Run.Create(fixture);await h.H.Send();
        if(change=="expiry")h.H.Clock.Advance(TimeSpan.FromHours(1));if(change=="disable")h.Options.Enabled=false;if(change=="public-email")h.Email.Enabled=true;
        var published=h.H.Signals.Published;
        await Assert.ThrowsAsync<EmailDisabledException>(()=>h.H.Send());Assert.Equal(published,h.H.Signals.Published);
    }

    [Fact]
    public async Task Actual_consent_review_Finish_and_checkpoint_prepare_next_invitation_from_accepted_copy_with_public_email_off()
    {
        await using var h=await Run.Create(fixture);var sent=(await h.H.Send())!;
        // The fixture issues a normal source-bound invitation token directly;
        // no mailbox verification/delivery or hosted end-to-end claim is made.
        string raw;
        using(var scope=h.H.App.Services.CreateScope()) {
            var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();
            var parent=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==sent.EnvelopeId);
            var token=scope.ServiceProvider.GetRequiredService<SignerInvitationFactory>().Create(parent.Id,h.H.First.Id,h.H.First.Email,
                h.End,Guid.ParseExact(parent.SentPdfBlob!,"N"),parent.SentPdfSha256!,parent.ErsdSha256!);
            raw=token.RawToken;db.AuthTokens.Add(token.Record);await db.SaveChangesAsync();
        }
        async Task<T> Use<S,T>(Func<S,Task<T>> call)where S:notnull {using var scope=h.H.App.Services.CreateScope();return await call(scope.ServiceProvider.GetRequiredService<S>());}
        var identity=(await Use((SignerAccess s)=>s.RedeemAsync(raw,null,null)))!;Assert.NotNull(identity);
        var principal=SignerAccessConfiguration.Principal(identity);var publicId=h.H.Envelope.PublicId;
        var context=(await Use((SignerAccess s)=>s.GetContextAsync(principal,publicId)))!;
        Assert.NotNull(await Use((SignerPdfAccess s)=>s.PrepareAsync(principal,context)));
        string receipt;using(var scope=h.H.App.Services.CreateScope())receipt=scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(identity);
        Assert.Equal(ConsentResult.Accepted,await Use((SignerConsent s)=>s.AcceptAsync(principal,publicId,receipt,true,true,"download",null,null)));
        var preview=(await Use((SignatureAdoption s)=>s.PrepareAsync(principal,publicId,new(SignatureAdoptionTests.Mark(),SignatureAdoptionTests.Mark(60),SignatureMethod.Drawn))))!;
        Assert.Equal(SignatureAdoptionResult.Adopted,await Use((SignatureAdoption s)=>s.AdoptAsync(principal,publicId,preview.Receipt,true,SignatureAdoptionStatement.Version,null,null)));
        var fields=(await Use((SignerFields s)=>s.GetAsync(principal,publicId)))!;var signature=Assert.Single(fields.Fields);
        Assert.Equal(SignerFieldOutcome.Applied,(await Use((SignerFields s)=>s.ChangeAsync(principal,publicId,new(signature.Id,signature.Version,SignerFieldAction.Apply,AdoptionId:fields.AdoptionId),null,null))).Outcome);
        var review=(await Use((SignerReviewCandidates s)=>s.PrepareAsync(principal,publicId)))!;
        var finish=(await Use((SignerFinish s)=>s.AcceptAsync(principal,publicId,review.Receipt,true,SignerFinishStatement.Version,null,null))).Acceptance!;Assert.NotNull(finish);
        using(var scope=h.H.App.Services.CreateScope()) {
            var store=scope.ServiceProvider.GetRequiredService<WorkStore>();var lease=(await store.ClaimAsync(finish.Id,default)).Lease!;
            var worker=scope.ServiceProvider.GetServices<IWorkHandler>().Single(x=>x.Kind==WorkKind.Rendering);
            var outcome=await worker.ExecuteAsync(lease,default);Assert.Equal(WorkOutcome.Completed,outcome.Outcome);await store.FinishAsync(lease,outcome,default);
        }
        await using var check=fixture.Open();var accepted=await check.SignerFinishAcceptances.SingleAsync(x=>x.Id==finish.Id);
        Assert.NotNull(accepted.ProcessedAt);var next=await check.EmailOutbox.SingleAsync(x=>x.Id==accepted.NextInvitationId);
        using(var scope=h.H.App.Services.CreateScope()) {
            var payload=scope.ServiceProvider.GetRequiredService<SignerInvitationProtection>().Read(next.PayloadJson);
            Assert.Equal(h.H.Second.Id,payload.SignerId);Assert.Equal(h.H.Second.Email,next.To);
            Assert.Equal(accepted.PdfObjectId,payload.DocumentId);Assert.Equal(Convert.ToHexStringLower(accepted.PdfSha256),payload.DocumentSha256);
        }
        Assert.Equal(sent.DocumentHash,Convert.ToHexStringLower((await check.Envelopes.SingleAsync(x=>x.Id==sent.EnvelopeId)).SentPdfSha256!));
        Assert.False(h.Email.Enabled);Assert.Equal(0,h.H.Sender.Calls);
    }

    private sealed class Run:IAsyncDisposable
    {
        internal SendDraftWorkflowTests.Harness H=null!;
        internal EmailPilotOptions Options=>H.App.Services.GetRequiredService<EmailPilotOptions>();
        internal EmailOptions Email=>H.App.Services.GetRequiredService<EmailOptions>();
        internal DateTimeOffset End;
        internal Action? AfterHint;
        internal static async Task<Run> Create(SqlDatabaseFixture fixture)
        {
            const string capability="1234567890123456789012345678901234567890123";var id=Guid.NewGuid().ToString("N");
            var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
                ["EmailPilot:Enabled"]="true",["EmailPilot:RunId"]=id,["EmailPilot:Mailboxes:Sender"]="sender@example.invalid",
                ["EmailPilot:Mailboxes:FirstSigner"]="first@example.invalid",["EmailPilot:Mailboxes:SecondSigner"]="second@example.invalid",
                ["EmailPilot:Mailboxes:Recipient"]="recipient@example.invalid",["EmailPilot:Admission:CapabilitySha256"]=Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(capability))) }).Build();
            var run=new Run();
            var h=await SendDraftWorkflowTests.Harness.Create(fixture,browser:true,configure:services=>{
                services.RemoveAll<EmailOptions>();services.AddSingleton(new EmailOptions{Enabled=false});services.AddEmailPilotWorkScopeFoundation(config);
                var originalSignals=(IWorkSignals)services.Last(x=>x.ServiceType==typeof(IWorkSignals)).ImplementationInstance!;
                services.AddSingleton<IWorkSignals>(new ObservedSignals(originalSignals,()=>run.AfterHint?.Invoke()));
            });
            run.H=h;run.Options.Mailboxes=new(h.Envelope.SenderEmail,h.First.Email,h.Second.Email,"recipient-"+id+"@example.invalid");
            var original=h.Envelope;var oldPrincipal=h.Principal;
            using(var scope=h.App.Services.CreateScope()) {
                var admitted=(await scope.ServiceProvider.GetRequiredService<EmailPilotAdmission>().RequestAsync(capability,EmailPilotScenario.Completion))!;
                var db=scope.ServiceProvider.GetRequiredService<QuillSignDbContext>();var parent=await db.Envelopes.SingleAsync(x=>x.Id==admitted.EnvelopeId);
                // Source-integrity fixture: authentication is represented by a
                // verified marker/principal, rather than a fabricated mail claim.
                parent.SenderVerifiedAt=h.Clock.GetUtcNow();parent.Title=original.Title;parent.Message=original.Message;
                parent.PreviewConfirmedAt=original.PreviewConfirmedAt;parent.PdfBlob=Guid.NewGuid().ToString("N");parent.PdfSha256=original.PdfSha256;
                parent.PageCount=original.PageCount;parent.PageSizesJson=original.PageSizesJson;parent.ExpiresAt=original.ExpiresAt;
                h.First=new(){EnvelopeId=parent.Id,Order=1,FullName="Synthetic first",Email=run.Options.Mailboxes.FirstSigner};
                h.Second=new(){EnvelopeId=parent.Id,Order=2,FullName="Synthetic second",Email=run.Options.Mailboxes.SecondSigner};
                db.AddRange(h.First,h.Second,new Recipient{EnvelopeId=parent.Id,Name="Synthetic recipient",Email=run.Options.Mailboxes.Recipient},
                    new DocumentField{EnvelopeId=parent.Id,SignerId=h.First.Id,Type=FieldType.Signature,Page=1,X=.1m,Y=.5m,Width=.4m,Height=.1m});
                await db.SaveChangesAsync();h.Envelope=parent;h.Version=parent.RowVersion;
                await using var tx=await db.Database.BeginTransactionAsync();
                await scope.ServiceProvider.GetRequiredService<AuditWriter>().AppendAsync(parent.Id,"signer_added",parent.SenderEmail,null,null,default,
                    JsonSerializer.Serialize(new{signers=new[]{h.First,h.Second}.Select(x=>new{x.Id,x.Order,x.FullName,x.Email,x.Role})}));
                await tx.CommitAsync();await tx.DisposeAsync();
                run.End=(await scope.ServiceProvider.GetRequiredService<EmailPilotEnvelopeAccess>().ReadAsync(parent.Id)).RunExpiresAt
                    ?? throw new InvalidOperationException("Synthetic run unavailable.");
            }
            await h.Blobs.Inner.DeleteAsync(oldPrincipal,new(original.Id,DocumentBlobKind.Normalized,Guid.ParseExact(original.PdfBlob!,"N")));
            await h.Blobs.Inner.WriteAsync(h.Principal,new(h.Envelope.Id,DocumentBlobKind.Normalized,Guid.ParseExact(h.Envelope.PdfBlob!,"N")),new MemoryStream(h.Source),h.Source.Length);
            return run;
        }
        internal async Task AssertDraft(SqlDatabaseFixture fixture)
        {
            await using var db=fixture.Open();var parent=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==H.Envelope.Id);
            Assert.Equal(EnvelopeStatus.Draft,parent.Status);Assert.Null(parent.SentPdfBlob);Assert.Null(parent.ErsdText);
            Assert.Single(await db.EmailOutbox.Where(x=>x.EnvelopeId==parent.Id).ToArrayAsync());
            Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==parent.Id && x.Event=="sent"));
        }
        public ValueTask DisposeAsync()=>H.DisposeAsync();
    }

    private sealed class ObservedSignals(IWorkSignals inner,Action afterHint):IWorkSignals
    {
        public async Task PutHintAsync(Guid id,DateTimeOffset due,CancellationToken ct){await inner.PutHintAsync(id,due,ct);afterHint();}
        public Task PublishAsync(Guid id,TimeSpan delay,CancellationToken ct)=>inner.PublishAsync(id,delay,ct);
        public Task RemoveHintAsync(Guid id,CancellationToken ct)=>inner.RemoveHintAsync(id,ct);
        public Task<DateTimeOffset?> ReadDueAsync(Guid id,CancellationToken ct)=>inner.ReadDueAsync(id,ct);
        public Task<WorkDelivery?> ReceiveAsync(CancellationToken ct)=>inner.ReceiveAsync(ct);
        public Task DeferAsync(WorkDelivery d,TimeSpan delay,CancellationToken ct)=>inner.DeferAsync(d,delay,ct);
        public Task AcknowledgeAsync(WorkDelivery d,CancellationToken ct)=>inner.AcknowledgeAsync(d,ct);
        public Task<int> RecoverAsync(DateTimeOffset now,CancellationToken ct)=>inner.RecoverAsync(now,ct);
        public Task VerifyAsync(CancellationToken ct)=>inner.VerifyAsync(ct);
    }
}
