using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;

namespace QuillSign.Tests;

public sealed class EmailPilotEnvelopeAccessTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";
    private EmailPilotAdmissionTests.Harness New()=>new(fixture.Open());
    private static EmailPilotEnvelopeAccess Access(EmailPilotAdmissionTests.Harness h)=>new(()=>h.Db,()=>h.Ledger,()=>h.Payload,h.Admission,h.Work);
    private static async Task<Envelope> Admit(EmailPilotAdmissionTests.Harness h,EmailPilotScenario scenario=EmailPilotScenario.Completion)
    {
        var admitted=(await h.Service.RequestAsync(Capability,scenario))!;
        return await h.Db.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==admitted.EnvelopeId);
    }

    [Fact]
    public void Disabled_composition_resolves_no_database_key_ring_or_provider()
    {
        var services=new ServiceCollection();services.AddEmailPilotAdmissionFoundation(new ConfigurationBuilder().Build());
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<EmailPilotEnvelopeAccess>());
    }

    [Fact]
    public async Task Missing_and_existing_unenrolled_parents_are_distinct_without_pilot_authority()
    {
        await using var h=New();var access=Access(h);
        var missing=await access.ReadAsync(Guid.NewGuid());
        Assert.False(missing.EnvelopeExists);Assert.False(missing.IsEnrolled);Assert.False(missing.Allowed);
        var ordinary=new Envelope{SenderEmail=h.Options.Mailboxes.Sender};h.Db.Envelopes.Add(ordinary);await h.Db.SaveChangesAsync();
        var result=await access.ReadAsync(ordinary.Id);
        Assert.True(result.EnvelopeExists);Assert.False(result.IsEnrolled);Assert.False(result.Allowed);Assert.Null(result.RunExpiresAt);
    }

    [Fact]
    public async Task Live_authenticated_cohort_allows_incomplete_draft_reads_but_not_send_roster()
    {
        await using var h=New();var parent=await Admit(h);var access=Access(h);
        var result=await access.ReadAsync(parent.Id);
        Assert.True(result.EnvelopeExists);Assert.True(result.IsEnrolled);Assert.True(result.Allowed);
        Assert.Equal(h.RunId,result.RunId);Assert.Equal(EmailPilotScenario.Completion,result.Scenario);
        Assert.Equal(h.Clock.Now.AddMinutes(60),result.RunExpiresAt);
        await using var transaction=await h.Db.Database.BeginTransactionAsync();
        Assert.True((await access.ReadLockedAsync(parent)).Allowed);
        await Assert.ThrowsAsync<EmailDisabledException>(()=>access.RequireSendRosterLockedAsync(parent));
        Assert.Empty(await h.Db.AuthTokens.ToArrayAsync());Assert.False(h.Email.Enabled);
    }

    [Theory]
    [InlineData("disabled")][InlineData("run")][InlineData("empty-run")][InlineData("mailbox")][InlineData("public-email")]
    [InlineData("work")][InlineData("capability")][InlineData("expiry")][InlineData("source")][InlineData("payload")]
    [InlineData("audit")][InlineData("binding")][InlineData("secret")][InlineData("manifest")]
    public async Task Known_cohort_never_falls_back_when_configuration_or_evidence_is_unavailable(string change)
    {
        await using var h=New();var parent=await Admit(h);var access=Access(h);var before=await access.ReadAsync(parent.Id);
        Assert.True(before.Allowed);
        if(change=="disabled")h.Options.Enabled=false;
        if(change=="run")h.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="empty-run"){h.Options.Enabled=false;h.Options.RunId="";}
        if(change=="mailbox")h.Options.Mailboxes=h.Options.Mailboxes with{Recipient="other@example.invalid"};
        if(change=="public-email")h.Email.Enabled=true;
        if(change=="work")h.Work.Enabled=false;
        if(change=="capability")h.Admission.CapabilitySha256=new string('a',64);
        if(change=="expiry")h.Clock.Now=before.RunExpiresAt!.Value;
        if(change=="source")await h.Db.Envelopes.Where(x=>x.Id==parent.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PublicId,Guid.NewGuid().ToString("N")));
        if(change=="payload")await h.Db.EmailOutbox.Where(x=>x.EnvelopeId==parent.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
        if(change=="audit")await h.Db.AuditEvents.Where(x=>x.EnvelopeId==parent.Id && x.Sequence==1).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.DataJson,"{} "));
        if(change=="binding")await h.Db.EmailPilotEnrollments.Where(x=>x.SubjectEnvelopeId==parent.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ProtectedBinding,"damaged"));
        if(change=="secret")await h.Db.EmailPilotSecrets.Where(x=>x.RunId==before.RunId).ExecuteDeleteAsync();
        if(change=="manifest")await h.Db.EmailPilotSecrets.Where(x=>x.RunId==before.RunId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.ProtectedManifest,"damaged"));
        var denied=await access.ReadAsync(parent.Id);
        Assert.True(denied.EnvelopeExists);Assert.True(denied.IsEnrolled);Assert.False(denied.Allowed);Assert.Equal(before.RunId,denied.RunId);
        if(change is "secret" or "manifest")Assert.Null(denied.RunExpiresAt);else Assert.Equal(before.RunExpiresAt,denied.RunExpiresAt);
    }

    [Fact]
    public async Task Standalone_read_preserves_pending_edits_and_existing_transaction()
    {
        await using var h=New();var parent=await Admit(h);var access=Access(h);
        var pending=new Signer{EnvelopeId=parent.Id,Order=1,Email=h.Options.Mailboxes.FirstSigner};h.Db.Signers.Add(pending);
        await Assert.ThrowsAsync<InvalidOperationException>(()=>access.ReadAsync(parent.Id));
        Assert.Equal(EntityState.Added,h.Db.Entry(pending).State);h.Db.Entry(pending).State=EntityState.Detached;
        await using var transaction=await h.Db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(()=>access.ReadAsync(parent.Id));
        Assert.Same(transaction,h.Db.Database.CurrentTransaction);
        Assert.True((await access.ReadLockedAsync(parent)).Allowed);
    }

    [Theory]
    [InlineData(EmailPilotScenario.Completion)][InlineData(EmailPilotScenario.Void)][InlineData(EmailPilotScenario.Decline)]
    public async Task Only_exact_approved_scenario_roster_is_send_eligible(EmailPilotScenario scenario)
    {
        await using var h=New();var parent=await Admit(h,scenario);await Roster(h,parent,scenario);
        await using var transaction=await h.Db.Database.BeginTransactionAsync();
        Assert.True((await Access(h).RequireSendRosterLockedAsync(parent)).Allowed);
        Assert.False(h.Email.Enabled);
    }

    [Theory]
    [InlineData("unverified")][InlineData("extra")][InlineData("first")][InlineData("second")][InlineData("order")]
    [InlineData("recipient")][InlineData("missing-recipient")]
    public async Task Incomplete_or_unapproved_roster_cannot_use_pilot_send_authority(string change)
    {
        await using var h=New();var parent=await Admit(h);await Roster(h,parent,EmailPilotScenario.Completion);
        if(change=="unverified")await h.Db.Envelopes.Where(x=>x.Id==parent.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SenderVerifiedAt,(DateTimeOffset?)null));
        if(change=="extra"){h.Db.Signers.Add(new(){EnvelopeId=parent.Id,Order=3,Email="extra@example.invalid"});await h.Db.SaveChangesAsync();}
        if(change is "first" or "second")await h.Db.Signers.Where(x=>x.EnvelopeId==parent.Id && x.Order==(change=="first"?1:2))
            .ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Email,"other@example.invalid"));
        if(change=="order")await h.Db.Signers.Where(x=>x.EnvelopeId==parent.Id && x.Order==2).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Order,3));
        if(change=="recipient")await h.Db.Recipients.Where(x=>x.EnvelopeId==parent.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Email,"other@example.invalid"));
        if(change=="missing-recipient")await h.Db.Recipients.Where(x=>x.EnvelopeId==parent.Id).ExecuteDeleteAsync();
        await using var transaction=await h.Db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<EmailDisabledException>(()=>Access(h).RequireSendRosterLockedAsync(parent));
    }

    // Source-integrity fixtures only; setting this marker does not claim a
    // mailbox-verification or browser-signing end-to-end flow.
    private static async Task Roster(EmailPilotAdmissionTests.Harness h,Envelope parent,EmailPilotScenario scenario)
    {
        await h.Db.Envelopes.Where(x=>x.Id==parent.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SenderVerifiedAt,h.Clock.Now));
        h.Db.Signers.Add(new(){EnvelopeId=parent.Id,Order=1,Email=h.Options.Mailboxes.FirstSigner,FullName="Synthetic first"});
        if(scenario==EmailPilotScenario.Completion){h.Db.Signers.Add(new(){EnvelopeId=parent.Id,Order=2,Email=h.Options.Mailboxes.SecondSigner,FullName="Synthetic second"});
            h.Db.Recipients.Add(new(){EnvelopeId=parent.Id,Email=h.Options.Mailboxes.Recipient,Name="Synthetic recipient"});}
        await h.Db.SaveChangesAsync();
    }
}
