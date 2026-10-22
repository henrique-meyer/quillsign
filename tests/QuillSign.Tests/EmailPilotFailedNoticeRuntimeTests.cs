using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using MimeKit;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Lifecycle;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Shared=QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class EmailPilotFailedNoticeRuntimeTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Copied_payload_alias_without_authenticated_private_fact_never_submits_or_changes_rows(bool completion)
    {
        await using var db=fixture.Open();var now=DateTimeOffset.UtcNow;var keys=new EphemeralDataProtectionProvider();
        var e=new Envelope{SenderEmail="sender@example.invalid",IsDemo=true,Status=completion?EnvelopeStatus.Completed:EnvelopeStatus.Voided};db.Add(e);await db.SaveChangesAsync();
        var id=Guid.NewGuid();var mail=new EmailOutbox{Id=id,EnvelopeId=e.Id,To=e.SenderEmail,AvailableAt=now};
        if(completion)
        {
            var payload=new CompletionNotificationPayload(CompletionNotificationJobs.Version,e.Id,Guid.NewGuid(),new string('a',64),Convert.ToBase64String(new byte[8]),
                PartyType.Sender,null,new string('b',64),new string('c',64),new string('d',64),true);
            Assert.NotEqual(id,CompletionNotificationJobs.Id(payload));mail.Template=CompletionNotificationJobs.Template;mail.PayloadJson=new CompletionNotificationProtection(keys).Protect(payload);
        }
        else
        {
            var payload=new VoidNotificationPayload(VoidNotificationJobs.Version,e.Id,1,new string('a',64),Convert.ToBase64String(new byte[8]),PartyType.Sender,null,new string('b',64),new string('c',64),true);
            Assert.NotEqual(id,VoidNotificationJobs.Id(payload));mail.Template=VoidNotificationJobs.Template;mail.PayloadJson=new VoidNotificationProtection(keys).Protect(payload);
        }
        var lease=new WorkLease(id,Guid.NewGuid(),WorkKind.Email,1,now.AddMinutes(5));
        var item=new WorkItem{Id=id,EnvelopeId=e.Id,Kind=WorkKind.Email,Status=WorkStatus.Leased,Attempts=1,LeaseOwner=lease.Owner,LeaseExpiresAt=lease.Until,AvailableAt=now,
            PayloadJson=completion?CompletionNotificationJobs.WorkJson(id):VoidNotificationJobs.WorkJson(id)};
        db.AddRange(mail,item);await db.SaveChangesAsync();var before=JsonSerializer.Serialize(new{mail,item});
        var options=new EmailOptions{Enabled=true};var noSender=new NoOrdinary();
        var result=completion
            ?await new CompletionNotificationDelivery(db,null!,null!,null!,new(keys),()=>throw new InvalidOperationException(),noSender,options,new(db,TimeProvider.System),TimeProvider.System).ExecuteAsync(lease,default)
            :await new VoidNotificationDelivery(db,null!,new(keys),()=>throw new InvalidOperationException(),noSender,options,new(db,TimeProvider.System),TimeProvider.System).ExecuteAsync(lease,default);
        Assert.Equal(WorkOutcome.Failed,result.Outcome);db.ChangeTracker.Clear();
        Assert.Equal(before,JsonSerializer.Serialize(new{mail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==id),item=await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==id)}));
        Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==e.Id));Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==e.Id));
    }

    // Required disposable-stack CI proof. Reuses existing genuine source/loopback
    // seal helpers ONCE; this case is not run against a stopped local emulator.
    [Fact]
    public Task Genuine_alias_completion_pair_and_void_use_counted_transport_and_preserve_six_failed_originals()=>GenuineAlias(false);

    internal async Task GenuineAlias(bool coexistence)
    {
        await using var completed=await EmailPilotLookupTests.Harness.Create(fixture);
        var t=completed.T;var keys=t.Keys;var clock=t.Run.Signing.H.Clock;var email=t.Email;var work=t.Work;
        await using var db=fixture.Open();
        var completionProtection=new CompletionNotificationProtection(keys);var voidProtection=new VoidNotificationProtection(keys);
        var clockAt=clock.GetUtcNow();var failedPairRequests=t.Run.Seal.Requests;
        var completionState=new CompletionAccessState(db,t.Run.Collector(db),()=>completed.For(db).Publication,clock);
        var completionJobs=new CompletionNotificationJobs(db,completionState,completionProtection,()=>t.Run.Signing.H.Signals,work,new(db,clock),clock);
        Assert.Equal(4,await completionJobs.ResumeAsync(t.Id));
        var expected=(await completed.Publication.ReadAsync(t.Id))!;
        var boxes=t.Options.Mailboxes;
        var voidOptions=new EmailPilotOptions{Enabled=true,RunId=Guid.NewGuid().ToString("N"),Mailboxes=boxes};
        await using var terminal=await Shared.Create(fixture,browser:true,configure:services=>{services.AddSingleton<IDataProtectionProvider>(keys);services.AddSingleton<TimeProvider>(clock);});
        ClaimsPrincipal? cleanupSender=null;Guid? cleanupRecordId=null;
        ServiceProvider? mainProvider=null;IServiceScope? mainScope=null;
        try
        {
        terminal.Clock.Advance(clock.GetUtcNow()-terminal.Clock.GetUtcNow());
        var terminalEmail=terminal.App.Services.GetRequiredService<EmailOptions>();terminalEmail.Enabled=false;
        var terminalWork=terminal.App.Services.GetRequiredService<WorkOptions>();
        using(var services=terminal.App.Services.CreateScope())
        {
            var sp=services.ServiceProvider;var current=sp.GetRequiredService<QuillSignDbContext>();
            var ledger=new EmailPilotLedger(voidOptions,terminalEmail,()=>current,()=>new(keys),clock);
            var admission=new EmailPilotAdmission(voidOptions,HashOptions(),terminalEmail,terminalWork,new(),()=>sp.GetRequiredService<SenderAvailability>(),()=>ledger,
                ()=>sp.GetRequiredService<EmailOutboxWriter>(),()=>new(keys),clock);
            var admitted=(await admission.RequestAsync(Capability,EmailPilotScenario.Void))!;Assert.NotNull(admitted);
        }
        terminalEmail.Enabled=true;Assert.True(await terminal.Once());
        var draft=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.SenderEmail==boxes.Sender&&x.Id!=t.Id&&x.SenderVerifiedAt==null);
        var verification=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.EnvelopeId==draft.Id&&x.Template=="sender-verification");
        ClaimsPrincipal sender;
        using(var services=terminal.App.Services.CreateScope())
        {
            var sp=services.ServiceProvider;var verified=await sp.GetRequiredService<SenderWorkflow>().VerifyAsync(new EmailPayloadProtection(keys).Unprotect(verification.PayloadJson).Token,null,null);Assert.NotNull(verified);
            sender=SenderConfiguration.Principal(verified!);draft=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==draft.Id);
            cleanupSender=sender;cleanupRecordId=draft.Id;
            var source=PdfFixtures.Create(text:"SYNTHETIC CLOSEOUT VOID - NO AGREEMENT");var documents=sp.GetRequiredService<DocumentWorkflow>();
            Assert.True(await documents.UploadAsync(sender,draft.PublicId,draft.RowVersion,"Synthetic.pdf",new MemoryStream(source),source.Length,null,null,default));
            draft=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==draft.Id);
            Assert.True(await documents.ConfirmAsync(sender,draft.PublicId,draft.RowVersion,draft.PdfBlob!,true,null,null,default));
            draft=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==draft.Id);
            Assert.Equal(SignerSetupError.None,(await sp.GetRequiredService<SignerSetup>().ChangeAsync(sender,draft.PublicId,new(SignerChangeKind.Save,Convert.ToBase64String(draft.RowVersion),FullName:"Synthetic first",Email:boxes.FirstSigner),null,null)).Error);
            var editor=sp.GetRequiredService<FieldEditor>();var fields=(await editor.GetAsync(sender,draft.PublicId))!;
            Assert.Equal(FieldEditorError.None,(await editor.SaveAsync(sender,draft.PublicId,new(fields.Version,fields.DocumentId,[new(Guid.NewGuid(),fields.Signers.Single().Id,FieldType.Signature.ToString(),1,.1m,.3m,.5m,.1m,true)]),null,null)).Error);
            draft=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==draft.Id);var review=(await sp.GetRequiredService<DraftReview>().GetAsync(sender,draft.PublicId))!;
            Assert.NotNull(await sp.GetRequiredService<SendDraftWorkflow>().SendAsync(sender,draft.PublicId,draft.RowVersion,true,true,SenderSendStatement.Version,null,null,reviewedRetentionSha256:review.RetentionSha256));
        }
        var voidJobs=new VoidNotificationJobs(db,new(db,new(db,clock),clock),voidProtection,()=>terminal.Signals,work,new(db,clock),clock);
        var voidEnvelope=await db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==draft.Id);
        var action=new SenderVoid(db,new(db,clock),new(db,clock),clock,()=>voidJobs);
        Assert.Equal(SenderVoidOutcome.Voided,(await action.VoidAsync(sender,draft.PublicId,clock.GetUtcNow().AddHours(1),voidEnvelope.RowVersion,true,SenderVoidStatement.Version,"Synthetic",null,null)).Outcome);
        var originalComplete=await db.EmailOutbox.AsNoTracking().Where(x=>x.EnvelopeId==t.Id&&x.Template==CompletionNotificationJobs.Template).ToArrayAsync();
        var originalVoid=await db.EmailOutbox.AsNoTracking().Where(x=>x.EnvelopeId==draft.Id&&x.Template==VoidNotificationJobs.Template).ToArrayAsync();Assert.Equal(2,originalVoid.Length);
        // Create the unchanged selected Decline Draft through actual admission.
        email.Provider="Smtp";
        using(var services=t.Run.Signing.H.App.Services.CreateScope())
        {
            var sp=services.ServiceProvider;var current=sp.GetRequiredService<QuillSignDbContext>();var ledger=t.LedgerFor(current);
            var admission=new EmailPilotAdmission(t.Options,t.Admission,email,work,new(),()=>sp.GetRequiredService<SenderAvailability>(),()=>ledger,
                ()=>sp.GetRequiredService<EmailOutboxWriter>(),()=>t.Payload,clock);
            Assert.NotNull(await admission.RequestAsync(Capability,EmailPilotScenario.Decline));
        }
        email.Provider="Ses";
        var decline=await db.EmailPilotEnrollments.AsNoTracking().SingleAsync(x=>x.RunId==t.RunId&&x.Scenario==EmailPilotScenario.Decline);
        var parentIds=new List<string>{t.Options.RunId,voidOptions.RunId};
        for(var n=0;n<3;n++)
        {
            var options=new EmailPilotOptions{Enabled=true,RunId=Guid.NewGuid().ToString("N"),Mailboxes=boxes};parentIds.Add(options.RunId);
            await new EmailPilotLedger(options,email,()=>db,()=>new(keys),clock).CreateAsync(Capability);
        }
        var budget=(await t.Ledger.ReadBudgetAsync())!;
        Assert.Equal(0,budget.ApplicationAttempts);Assert.Equal(0,budget.SimulatorAttempts);
        for(var n=0;n<12;n++)Assert.Equal(EmailPilotReservationOutcome.Reserved,await t.Ledger.ReserveAsync(new(Guid.NewGuid(),t.Id,Guid.NewGuid(),EmailPilotAttemptKind.Application,EmailPilotRole.Sender,n==0?27903:1,new string('a',64)),boxes.Sender));
        for(var n=0;n<4;n++)Assert.Equal(EmailPilotReservationOutcome.Reserved,await t.Ledger.ReserveAsync(new(Guid.NewGuid(),null,Guid.NewGuid(),EmailPilotAttemptKind.Simulator,EmailPilotRole.Simulator,1,new string('b',64)),null));
        for(var n=budget.TimestampAttempts;n<4;n++)Assert.Equal(EmailPilotReservationOutcome.Reserved,await t.Ledger.ReserveAsync(new(Guid.NewGuid(),t.Id,Guid.NewGuid(),EmailPilotAttemptKind.Timestamp,EmailPilotRole.None,0,new string('c',64)),null));
        Assert.Equal(new EmailPilotBudget(12,4,4,27918),await t.Ledger.ReadBudgetAsync());
        var expiry=await db.EmailPilotRuns.MaxAsync(x=>x.ExpiresAt);clock.Advance(expiry-clock.GetUtcNow()+TimeSpan.FromSeconds(1));terminal.Clock.Advance(clock.GetUtcNow()-terminal.Clock.GetUtcNow());
        var ordinary=new NoOrdinary();var legacyAuthority=new EmailPilotWorkAuthority(t.Options,email,work,t.Admission,()=>t.LedgerFor(db),()=>db,()=>t.Payload,clock);
        var disabled=new EmailPilotDispatch(db,email,()=>legacyAuthority,(_,_,_)=>throw new InvalidOperationException(),ordinary);
        var oldStore=new WorkStore(db,work,clock);
        foreach(var mail in originalComplete.Concat(originalVoid))
        {
            var lease=(await oldStore.ClaimAsync(mail.Id,default)).Lease!;Assert.NotNull(lease);
            var failed=mail.Template==CompletionNotificationJobs.Template
                ?await new CompletionNotificationDelivery(db,null!,null!,null!,completionProtection,()=>throw new InvalidOperationException(),ordinary,email,new(db,clock),clock,disabled).ExecuteAsync(lease,default)
                :await new VoidNotificationDelivery(db,null!,voidProtection,()=>throw new InvalidOperationException(),ordinary,email,new(db,clock),clock,disabled).ExecuteAsync(lease,default);
            Assert.Equal(new WorkResult(WorkOutcome.Failed,"pilot-delivery-unavailable"),failed);await oldStore.FinishAsync(lease,failed,default);
        }
        var originals=await OriginalRows(db,originalComplete.Concat(originalVoid).Select(x=>x.Id));
        var settings=new EmailPilotCloseoutOptions{Enabled=true,AuthorizationId=Guid.NewGuid().ToString("N"),CapabilitySha256=HashOptions().CapabilitySha256,StartsAt=clock.GetUtcNow(),Until=clock.GetUtcNow().AddMinutes(30),AccountingParentRunIds=parentIds.ToArray(),
            CompletionParentRunId=t.Options.RunId,VoidParentRunId=voidOptions.RunId,CompletionRecordId=t.Id.ToString("N"),VoidRecordId=draft.Id.ToString("N"),DeclineRecordId=decline.SubjectEnvelopeId.ToString("N"),
            CompletionWorkIds=originalComplete.Select(x=>x.Id.ToString("N")).ToArray(),VoidWorkIds=originalVoid.Select(x=>x.Id.ToString("N")).ToArray()};
        if(coexistence){settings.HostRole=EmailPilotCloseoutHostRole.Web;settings.PrivateConfigurationSet="synthetic-private-set";email.Enabled=true;email.Ses.ConfigurationSet="synthetic";}
        t.Options.Enabled=false; // The new closeout does not reactivate an old pilot.
        EmailPilotCloseoutLookup? mainLookup=null;var lookupProfile=completed.For(db);
        var core=new EmailPilotCloseout(settings,email,work,()=>db,()=>t.LedgerFor(db),()=>new(keys),clock){ReceiptPilotOptions=t.Options,Payloads=()=>t.Payload,CompletionPayloads=()=>completionProtection,CompletionJobs=()=>completionJobs,VoidPayloads=()=>voidProtection,VoidJobs=()=>voidJobs,Lookup=()=>mainLookup??throw new InvalidOperationException(),LookupPayloads=()=>lookupProfile.Payload};
        var created=await core.CreateAsync(Capability);Assert.Equal(6,created.Manifest.Queue.Length);
        EmailPilotCloseoutCommittedReceipt initialReceipt;
        await using(var receiptTx=await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable)) {
            initialReceipt=await core.ReadCommittedReceiptLockedAsync(db,created.AuthorizationId,default);
            Assert.Equal(5,initialReceipt.OriginalParentIds.Length);Assert.Equal(0,initialReceipt.NewApplication);Assert.True(initialReceipt.OriginalPairsPreserved);
            await receiptTx.RollbackAsync();
        }
        Assert.Equal(originals,await OriginalRows(db,originalComplete.Concat(originalVoid).Select(x=>x.Id)));
        var capture=new Capture();var capturedSets=new List<string>();var closeoutSender=new EmailPilotCloseoutSender(email,()=>core,()=>db,value=>{capturedSets.Add(value.ConfigurationSet);return capture;},clock);
        var authority=new EmailPilotWorkAuthority(t.Options,email,work,t.Admission,()=>t.LedgerFor(db),()=>db,()=>t.Payload,clock){Closeout=()=>core};
        var store=new WorkStore(db,work,clock,core);var beforeReserveChecked=false;
        var pilot=new EmailPilotDispatch(db,email,()=>authority,async(lease,message,ct)=>{
            if(coexistence&&!beforeReserveChecked){beforeReserveChecked=true;Assert.Equal(0,await db.EmailPilotCloseoutOperations.CountAsync(x=>x.CloseoutId==created.AuthorizationId&&x.Kind==1));var beforeReserve=await OriginalRows(db,[lease.Id]);settings.HostRole=EmailPilotCloseoutHostRole.Handoff;settings.Enabled=false;Assert.True((await store.ClaimAsync(lease.Id,ct)).PrivateHandoff);Assert.Equal(beforeReserve,await OriginalRows(db,[lease.Id]));settings.Enabled=true;settings.HostRole=EmailPilotCloseoutHostRole.Pass;}
            return await closeoutSender.SendAsync(lease,message,ct);
        },ordinary);
        using var views=t.Run.Signing.H.App.Services.CreateScope();var razor=views.ServiceProvider.GetRequiredService<RazorEmailViews>();
        var access=new CompletionAccess(db,completionState,new(keys,clock),new(),new(db,clock),clock,()=>completed.For(db).Publication);
        if(coexistence) {
            settings.HostRole=EmailPilotCloseoutHostRole.Handoff;settings.Enabled=false;
            Assert.True((await store.ClaimAsync(created.CompletionWork.First(),default)).PrivateHandoff);
            settings.PrivateConfigurationSet="rotated-private";
            Assert.True((await store.ClaimAsync(created.CompletionWork.First(),default)).PrivateRefused);
            settings.PrivateConfigurationSet="synthetic-private-set";settings.Enabled=true;
            settings.HostRole=EmailPilotCloseoutHostRole.Pass;
            var handler=new EmailWorkHandler(db,email,t.Payload,new(email,razor),ordinary,clock,
                completions:()=>new(db,completionState,access,completionJobs,completionProtection,()=>new(email,razor),ordinary,email,new(db,clock),clock,pilot),
                voids:()=>new(db,voidJobs,voidProtection,()=>new(razor),ordinary,email,new(db,clock),clock,pilot),pilot:pilot);
            var firstLease=(await store.ClaimAsync(created.CompletionWork.First(),default)).Lease!;Assert.NotNull(firstLease);
            var leasedBefore=await OriginalRows(db,[firstLease.Id]);settings.HostRole=EmailPilotCloseoutHostRole.Handoff;settings.Enabled=false;
            Assert.True((await store.ClaimAsync(firstLease.Id,default)).PrivateHandoff);Assert.Equal(leasedBefore,await OriginalRows(db,[firstLease.Id]));settings.Enabled=true;settings.HostRole=EmailPilotCloseoutHostRole.Pass;
            capture.BeforeReceipt=async()=>{capture.BeforeReceipt=null;var intentBefore=await OriginalRows(db,[firstLease.Id]);settings.HostRole=EmailPilotCloseoutHostRole.Handoff;settings.Enabled=false;Assert.True((await store.ClaimAsync(firstLease.Id,default)).PrivateHandoff);Assert.Equal(intentBefore,await OriginalRows(db,[firstLease.Id]));settings.Enabled=true;settings.HostRole=EmailPilotCloseoutHostRole.Pass;};
            var firstResult=await handler.ExecuteAsync(firstLease,default);Assert.Equal(WorkOutcome.Completed,firstResult.Outcome);await store.FinishAsync(firstLease,firstResult,default);
            var pass=new EmailPilotCloseoutPass(core,store,handler);Assert.Equal(new EmailPilotCloseoutPassResult(1,5,0,0),await pass.RunAsync());
            Assert.Equal(new EmailPilotCloseoutPassResult(6,0,0,0),await pass.RunAsync());Assert.Equal(6,capture.Messages.Count);
            settings.HostRole=EmailPilotCloseoutHostRole.Web;Guid verificationWork;
            await using(var prepare=await db.Database.BeginTransactionAsync()) {
                var selected=(await core.ReadLockedAsync(db))!;var outbox=new EmailOutboxWriter(db,t.Run.Signing.H.Signals,t.Payload,work,email,clock);
                var originalScope=new EmailPilotAdmissionScope(db,selected.DeclineRecord,boxes.Sender,()=>{if(!core.CanAdmit)throw new EmailDisabledException();});
                verificationWork=await outbox.PrepareCloseoutVerificationAsync(selected.DeclineRecord,boxes.Sender,originalScope,settings,default);
                await core.BindNewWorkLockedAsync(db,selected,EmailPilotCloseoutStep.DeclineVerification,verificationWork);await prepare.CommitAsync();
            }
            settings.HostRole=EmailPilotCloseoutHostRole.Pass;Assert.Equal(new EmailPilotCloseoutPassResult(6,1,0,0),await pass.RunAsync());Assert.Equal(new EmailPilotCloseoutPassResult(7,0,0,0),await pass.RunAsync());
            var dynamicMail=await db.EmailOutbox.SingleAsync(x=>x.Id==verificationWork);var dynamicPayload=dynamicMail.PayloadJson;dynamicMail.PayloadJson="{}";await db.SaveChangesAsync();db.ChangeTracker.Clear();
            Assert.Equal(1,(await pass.RunAsync()).Refused);Assert.Equal(7,capture.Messages.Count);
            dynamicMail=await db.EmailOutbox.SingleAsync(x=>x.Id==verificationWork);dynamicMail.PayloadJson=dynamicPayload;await db.SaveChangesAsync();db.ChangeTracker.Clear();
            var changed=await db.EmailOutbox.SingleAsync(x=>x.Id==created.CompletionWork.First());var recipient=changed.To;changed.To=boxes.FirstSigner;await db.SaveChangesAsync();db.ChangeTracker.Clear();
            Assert.Equal(1,(await pass.RunAsync()).Refused);Assert.Equal(7,capture.Messages.Count);
            changed=await db.EmailOutbox.SingleAsync(x=>x.Id==created.CompletionWork.First());changed.To=recipient;await db.SaveChangesAsync();db.ChangeTracker.Clear();
            // MAIN-only connected proof: the SAME completed fixture supplies the
            // real null-parent lookup, with no second signing/sealing setup.
            settings.HostRole=EmailPilotCloseoutHostRole.Web;
            var links=new DocumentLookupProtection(keys,clock);var lookupOptions=new DocumentLookupOptions();
            var lookupTemplate=new LookupEmailTemplate(email,razor,links,t.Run.Signing.H.App.Environment);
            mainLookup=new(db,()=>core,completionState,lookupProfile.Payload,lookupProfile.Retention,lookupProfile.Limits,lookupOptions,links,()=>lookupTemplate,()=>closeoutSender,()=>t.Run.Signing.H.Signals,clock);
            Assert.True(await mainLookup.RequestAsync(created.AuthorizationId,null));
            var lookupId=EmailPilotCloseoutLookup.RequestId(created.AuthorizationId);settings.HostRole=EmailPilotCloseoutHostRole.Pass;
            var external=new ProductionHoldWitnessJournalTests.Store();
            var journal=new ProductionHoldWitnessJournal(external,keys,clock,new string('7',64));
            var kernel=new ProductionWorkAdmission(fixture.Open,new ProductionRecordOperationAdmission(fixture.Open,keys,clock,journal));
            var mainServices=new ServiceCollection();mainServices.AddLogging();mainServices.AddSingleton<TimeProvider>(clock);mainServices.AddSingleton<IDataProtectionProvider>(keys);mainServices.AddSingleton(work);
            mainServices.AddScoped<QuillSignDbContext>(_=>db);mainServices.AddScoped<EmailPilotCloseout>(_=>core);mainServices.AddScoped<WorkStore>();
            mainServices.AddScoped<EmailWorkHandler>(_=>new(db,email,t.Payload,null!,ordinary,clock,
                lookups:()=>new LookupLinkDelivery(db,lookupProfile.Limits,lookupProfile.Payload,links,()=>lookupProfile.Lookup,()=>lookupTemplate,ordinary,email,work,clock,lookupProfile.Retention,closeout:mainLookup),pilot:pilot));
            mainServices.AddScoped<IWorkHandler>(sp=>sp.GetRequiredService<EmailWorkHandler>());
            mainServices.AddProductionHoldRuntime(new ConfigurationBuilder().Build());mainServices.AddScoped<IProductionWorkAdmission>(_=>kernel);
            mainProvider=mainServices.BuildServiceProvider();mainScope=mainProvider.CreateScope();
            var mainStore=mainScope.ServiceProvider.GetRequiredService<WorkStore>();
            var route=await core.ReadNullLookupAsync(lookupId,null,default);Assert.NotNull(route);
            await using(var foreign=await db.Database.BeginTransactionAsync()) {Assert.Throws<InvalidDataException>(()=>route.DemandLocked(db));await foreign.RollbackAsync();}
            var lookupLease=(await mainStore.ClaimAsync(lookupId,default)).Lease!;Assert.NotNull(lookupLease);
            await using(var wrongLease=await db.Database.BeginTransactionAsync()) {
                await Assert.ThrowsAsync<InvalidDataException>(()=>core.ReadNullLookupLockedAsync(db,lookupId,lookupLease with{Owner=Guid.NewGuid()},default));
                await Assert.ThrowsAsync<InvalidDataException>(()=>core.ReadNullLookupLockedAsync(db,lookupId,lookupLease with{Until=lookupLease.Until.ToOffset(TimeSpan.FromHours(1))},default));await wrongLease.RollbackAsync();
            }
            var composed=mainScope.ServiceProvider.GetRequiredService<EmailWorkHandler>();
            Assert.Same(composed,mainScope.ServiceProvider.GetRequiredService<IWorkHandler>());Assert.Same(kernel,composed.HoldAdmission);
            var lookupResult=await composed.ExecuteAsync(lookupLease,default);Assert.Equal(WorkOutcome.Completed,lookupResult.Outcome);
            await mainStore.FinishAsync(lookupLease,lookupResult,default);
            Assert.Equal(WorkStatus.Completed,(await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lookupId)).Status);
            Assert.Null((await db.WorkItems.AsNoTracking().SingleAsync(x=>x.Id==lookupId)).EnvelopeId);
            Assert.Equal(new EmailPilotCloseoutPassResult(8,0,0,0),await pass.RunAsync());Assert.Equal(8,capture.Messages.Count);
            Assert.All(capturedSets,x=>Assert.Equal("synthetic-private-set",x));Assert.True(email.Enabled);Assert.Equal("synthetic",email.Ses.ConfigurationSet);
        }
        else foreach(var chosen in new[]{created.CompletionWork.First(),created.VoidWork.First()})
        {
            var lease=(await store.ClaimAsync(chosen,default)).Lease!;Assert.NotNull(lease);
            var aliasMail=await db.EmailOutbox.AsNoTracking().SingleAsync(x=>x.Id==chosen);
            EmailPilotCloseout.AliasFact fact;
            await using(var parent=await db.Database.BeginTransactionAsync())
            {
                fact=(await core.ReadAliasLockedAsync(db,lease,aliasMail.To))!;Assert.NotNull(fact);
                fact.DemandLocked(db,chosen,aliasMail.To,aliasMail.Template);
                await parent.RollbackAsync();
            }
            await using(var replacement=await db.Database.BeginTransactionAsync())
            {
                Assert.Throws<InvalidDataException>(()=>fact.DemandLocked(db,chosen,aliasMail.To,aliasMail.Template));
                await replacement.RollbackAsync();
            }
            var result=created.CompletionWork.Contains(chosen)
                ?await new CompletionNotificationDelivery(db,completionState,access,completionJobs,completionProtection,()=>new(email,razor),ordinary,email,new(db,clock),clock,pilot).ExecuteAsync(lease,default)
                :await new VoidNotificationDelivery(db,voidJobs,voidProtection,()=>new(razor),ordinary,email,new(db,clock),clock,pilot).ExecuteAsync(lease,default);
            Assert.Equal(WorkOutcome.Completed,result.Outcome);await store.FinishAsync(lease,result,default);
        }
        var submitted=coexistence?8:2;
        Assert.Equal(submitted,capture.Messages.Count);using var completedMail=MimeMessage.Load(new MemoryStream(capture.Messages[0]));var attachments=completedMail.Attachments.Cast<MimePart>().ToArray();Assert.Equal(2,attachments.Length);
        foreach(var (part,bytes) in attachments.Zip(new[]{expected.ExecutedBytes,expected.CertificateBytes})){using var target=new MemoryStream();await part.Content!.DecodeToAsync(target);Assert.Equal(bytes,target.ToArray());}
        using var voidMail=MimeMessage.Load(new MemoryStream(capture.Messages[coexistence?4:1]));Assert.Empty(voidMail.Attachments);
        Assert.Equal(submitted,await db.EmailPilotCloseoutOperations.CountAsync(x=>x.CloseoutId==created.AuthorizationId&&x.Kind==1));
        Assert.Equal(originals,await OriginalRows(db,originalComplete.Concat(originalVoid).Select(x=>x.Id)));Assert.Equal(failedPairRequests,t.Run.Seal.Requests);
        if(coexistence){clock.Advance(settings.StartsAt.AddMinutes(25)-clock.GetUtcNow());Assert.False(core.CanAdmit);Assert.True(core.Available);await Assert.ThrowsAsync<InvalidDataException>(()=>core.CreateAsync(Capability));settings.HostRole=EmailPilotCloseoutHostRole.Web;}
        settings.Enabled=false;if(!coexistence)await Assert.ThrowsAsync<InvalidDataException>(()=>store.ClaimAsync(created.CompletionWork.Last(),default));Assert.Equal(submitted,capture.Messages.Count);
        await using(var receiptTx=await db.Database.BeginTransactionAsync(System.Data.IsolationLevel.Serializable)) {
            var finalReceipt=await core.ReadCommittedReceiptLockedAsync(db,created.AuthorizationId,default);
            Assert.Equal(submitted,finalReceipt.NewApplication);Assert.Equal(initialReceipt.HeaderFactsSha256,finalReceipt.HeaderFactsSha256);
            Assert.Equal(initialReceipt.OriginalMailSha256,finalReceipt.OriginalMailSha256);Assert.Equal(initialReceipt.OriginalWorkSha256,finalReceipt.OriginalWorkSha256);
            await receiptTx.RollbackAsync();
        }
        Assert.True(clockAt<clock.GetUtcNow());
        }
        finally
        {
            mainScope?.Dispose();if(mainProvider is not null)await mainProvider.DisposeAsync();
            if(cleanupSender is {} owner&&cleanupRecordId is Guid record)
                foreach(var blob in terminal.Blobs.Created.Where(x=>x.EnvelopeId==record).Distinct().ToArray())
                {
                    await terminal.Blobs.Inner.DeleteAsync(owner,blob);
                    terminal.Blobs.Created.RemoveAll(x=>x==blob);
                }
        }
    }
    private static EmailPilotAdmissionOptions HashOptions()=>new(){CapabilitySha256=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(Capability)))};
    private static async Task<string> OriginalRows(QuillSignDbContext db,IEnumerable<Guid> ids)
    {var selected=ids.ToArray();return JsonSerializer.Serialize(new{Mail=await db.EmailOutbox.AsNoTracking().Where(x=>selected.Contains(x.Id)).OrderBy(x=>x.Id).ToArrayAsync(),Work=await db.WorkItems.AsNoTracking().Where(x=>selected.Contains(x.Id)).OrderBy(x=>x.Id).ToArrayAsync()});}
    private sealed class Capture:IPreparedEmailTransport
    {internal readonly List<byte[]> Messages=[];internal Func<Task>? BeforeReceipt;public async Task<EmailDelivery> SendAsync(PreparedRawMime value,CancellationToken ct){using var input=value.OpenRead();using var target=new MemoryStream();await input.CopyToAsync(target,ct);Messages.Add(target.ToArray());if(BeforeReceipt is {} callback)await callback();return new("Ses","synthetic-alias-"+Messages.Count);}}
    private sealed class NoOrdinary:IEmailSender
    {public Task<EmailDelivery> SendAsync(OutgoingEmail value,CancellationToken ct)=>throw new InvalidOperationException("Ordinary transport must not handle an alias.");}
}
