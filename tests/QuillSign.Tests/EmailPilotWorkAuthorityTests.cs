using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotWorkAuthorityTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Capability="1234567890123456789012345678901234567890123";

    [Fact]
    public async Task Default_disabled_and_malformed_lease_resolve_no_SQL_keys_or_providers()
    {
        var services=new ServiceCollection();services.AddEmailPilotWorkScopeFoundation(new ConfigurationBuilder().Build());
        using var provider=services.BuildServiceProvider();using var scope=provider.CreateScope();
        var lease=new WorkLease(Guid.NewGuid(),Guid.NewGuid(),WorkKind.Email,1,DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Null(await scope.ServiceProvider.GetRequiredService<EmailPilotWorkAuthority>().ReadAsync(lease));
        var options=new EmailPilotOptions{Enabled=true};var email=new EmailOptions();var work=new WorkOptions{Enabled=true};
        var service=new EmailPilotWorkAuthority(options,email,work,new(){CapabilitySha256=new string('a',64)},()=>throw new Exception("No ledger"),()=>throw new Exception("No SQL"),
            ()=>throw new Exception("No key ring"),TimeProvider.System);
        foreach(var invalid in new[]{lease with{Id=Guid.Empty},lease with{Owner=Guid.Empty},lease with{Attempt=0},
            lease with{Kind=WorkKind.Ai},lease with{Until=DateTimeOffset.UtcNow.AddMinutes(-1)}})
            Assert.Null(await service.ReadAsync(invalid));
        email.Enabled=true;Assert.Null(await service.ReadAsync(lease));email.Enabled=false;work.Enabled=false;Assert.Null(await service.ReadAsync(lease));
    }

    [Fact]
    public async Task Actual_admission_and_claim_bind_only_the_same_live_sender_verification_lease()
    {
        await using var h=New();var (admitted,lease)=await Claim(h);
        var authority=Authority(h);var scope=Assert.IsType<EmailPilotWorkScope>(await authority.ReadAsync(lease));
        Assert.Equal(h.RunId,scope.RunId);Assert.Equal(admitted.EnvelopeId,scope.EnvelopeId);Assert.Equal(lease.Until,scope.Until);
        Assert.Equal(EmailPilotRole.Sender,scope.MailRole(h.Options.Mailboxes.Sender));
        Assert.Equal(EmailPilotRole.None,scope.MailRole(h.Options.Mailboxes.FirstSigner));Assert.False(scope.AllowsTimestamp);
        Assert.True(await authority.StillCurrentAsync(scope));Assert.False(h.Email.Enabled);
        Assert.False(await h.Db.AuthTokens.AnyAsync(x=>x.EnvelopeId==admitted.EnvelopeId));
    }

    [Theory]
    [InlineData("owner")][InlineData("attempt")][InlineData("deadline")][InlineData("kind")][InlineData("expiry")][InlineData("terminal")]
    public async Task Forged_reclaimed_expired_or_terminal_leases_have_no_pilot_scope(string change)
    {
        await using var h=New();var (_,lease)=await Claim(h);var altered=lease;
        if(change=="owner")altered=lease with{Owner=Guid.NewGuid()};
        if(change=="attempt")altered=lease with{Attempt=lease.Attempt+1};
        if(change=="deadline")altered=lease with{Until=lease.Until.AddSeconds(1)};
        if(change=="kind")altered=lease with{Kind=WorkKind.Sealing};
        if(change=="expiry")h.Clock.Now=lease.Until;
        if(change=="terminal")await h.Db.WorkItems.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.Status,WorkStatus.Failed));
        Assert.Null(await Authority(h).ReadAsync(altered));
    }

    [Theory]
    [InlineData("run")][InlineData("mailbox")][InlineData("disabled")][InlineData("work-disabled")][InlineData("public-email")][InlineData("source")][InlineData("payload")][InlineData("recipient")][InlineData("run-expiry")][InlineData("operator-capability")]
    public async Task Previously_read_scope_does_not_survive_configuration_or_source_change(string change)
    {
        await using var h=New();var (admitted,lease)=await Claim(h);var authority=Authority(h);
        var scope=Assert.IsType<EmailPilotWorkScope>(await authority.ReadAsync(lease));
        if(change=="run")h.Options.RunId=Guid.NewGuid().ToString("N");
        if(change=="mailbox")h.Options.Mailboxes=h.Options.Mailboxes with{Recipient="other@example.invalid"};
        if(change=="disabled")h.Options.Enabled=false;
        if(change=="work-disabled")h.Work.Enabled=false;
        if(change=="public-email")h.Email.Enabled=true;
        if(change=="source")await h.Db.Envelopes.Where(x=>x.Id==admitted.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PublicId,Guid.NewGuid().ToString("N")));
        if(change=="payload")await h.Db.WorkItems.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.PayloadJson,"{}"));
        if(change=="recipient")await h.Db.EmailOutbox.Where(x=>x.Id==lease.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.To,h.Options.Mailboxes.FirstSigner));
        if(change=="run-expiry")h.Clock.Now+=TimeSpan.FromHours(1);
        if(change=="operator-capability")h.Admission.CapabilitySha256=new string('a',64);
        Assert.False(await authority.StillCurrentAsync(scope));
    }

    [Fact]
    public async Task Unrelated_claimed_backlog_cannot_become_pilot_mail()
    {
        await using var h=New();await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion);
        var other=new Envelope{SenderEmail=h.Options.Mailboxes.Sender,IsDemo=true};var outbox=new EmailOutbox{EnvelopeId=other.Id,To=h.Options.Mailboxes.Sender};
        h.Db.AddRange(other,outbox,new WorkItem{Id=outbox.Id,EnvelopeId=other.Id,Kind=WorkKind.Email,AvailableAt=h.Clock.Now});await h.Db.SaveChangesAsync();
        var lease=(await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(outbox.Id,default)).Lease!;
        Assert.Null(await Authority(h).ReadAsync(lease));
    }

    [Theory]
    [InlineData("pre-verification-party")][InlineData("extra-signer")][InlineData("wrong-first")][InlineData("reordered")][InlineData("extra-recipient")][InlineData("wrong-recipient")]
    [InlineData("unsupported-template")][InlineData("nonsigner-invitation")][InlineData("verification-replay")]
    public async Task Roster_outside_the_three_fixed_scenarios_is_refused(string change)
    {
        await using var h=New();var (admitted,verification)=await Claim(h);
        if(change=="pre-verification-party")
        {
            h.Db.Signers.Add(new(){EnvelopeId=admitted.EnvelopeId,Email=h.Options.Mailboxes.FirstSigner,Order=1});await h.Db.SaveChangesAsync();
            Assert.Null(await Authority(h).ReadAsync(verification));return;
        }
        // These are source-integrity unit fixtures, not mailbox/consent evidence.
        await h.Db.Envelopes.Where(x=>x.Id==admitted.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SenderVerifiedAt,h.Clock.Now).SetProperty(x=>x.Status,EnvelopeStatus.Sent));
        h.Db.Signers.AddRange(new Signer{EnvelopeId=admitted.EnvelopeId,Email=change=="wrong-first"?"other@example.invalid":h.Options.Mailboxes.FirstSigner,Order=change=="reordered"?3:1},
            new Signer{EnvelopeId=admitted.EnvelopeId,Email=h.Options.Mailboxes.SecondSigner,Order=2});
        h.Db.Recipients.Add(new(){EnvelopeId=admitted.EnvelopeId,Email=change=="wrong-recipient"?"other@example.invalid":h.Options.Mailboxes.Recipient});
        if(change=="extra-signer")h.Db.Signers.Add(new(){EnvelopeId=admitted.EnvelopeId,Email="extra@example.invalid",Order=3});
        if(change=="extra-recipient")h.Db.Recipients.Add(new(){EnvelopeId=admitted.EnvelopeId,Email="extra@example.invalid"});
        var outbox=new EmailOutbox{EnvelopeId=admitted.EnvelopeId,To=change=="nonsigner-invitation"?h.Options.Mailboxes.Recipient:h.Options.Mailboxes.FirstSigner,
            Template=change switch {"unsupported-template"=>"unsupported","verification-replay"=>"sender-verification",_=>"signer-invitation"},AvailableAt=h.Clock.Now};
        h.Db.AddRange(outbox,new WorkItem{Id=outbox.Id,EnvelopeId=admitted.EnvelopeId,Kind=WorkKind.Email,AvailableAt=h.Clock.Now});await h.Db.SaveChangesAsync();
        var lease=(await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(outbox.Id,default)).Lease!;
        Assert.Null(await Authority(h).ReadAsync(lease));
    }

    [Fact]
    public async Task Forged_signed_rows_without_accepted_checkpoint_chain_cannot_authorize_timestamps()
    {
        await using var h=New();var (admitted,_)=await Claim(h);
        await h.Db.Envelopes.Where(x=>x.Id==admitted.EnvelopeId).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.SenderVerifiedAt,h.Clock.Now).SetProperty(x=>x.Status,EnvelopeStatus.Sent));
        h.Db.Signers.AddRange(new Signer{EnvelopeId=admitted.EnvelopeId,Email=h.Options.Mailboxes.FirstSigner,Order=1,Status=SignerStatus.Signed},
            new Signer{EnvelopeId=admitted.EnvelopeId,Email=h.Options.Mailboxes.SecondSigner,Order=2,Status=SignerStatus.Signed});
        h.Db.Recipients.Add(new(){EnvelopeId=admitted.EnvelopeId,Email=h.Options.Mailboxes.Recipient});
        var id=CompletionJobs.WorkId(admitted.EnvelopeId);
        h.Db.WorkItems.Add(new(){Id=id,EnvelopeId=admitted.EnvelopeId,Kind=WorkKind.Sealing,AvailableAt=h.Clock.Now,PayloadJson="{}"});await h.Db.SaveChangesAsync();
        var lease=(await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(id,default)).Lease!;
        Assert.Null(await Authority(h).ReadAsync(lease));
    }

    private EmailPilotAdmissionTests.Harness New()=>new(fixture.Open());
    private static EmailPilotWorkAuthority Authority(EmailPilotAdmissionTests.Harness h)=>new(h.Options,h.Email,h.Work,h.Admission,()=>h.Ledger,()=>h.Db,()=>h.Payload,h.Clock);
    private static async Task<(EmailPilotAdmissionResult,WorkLease)> Claim(EmailPilotAdmissionTests.Harness h)
    {
        var admitted=(await h.Service.RequestAsync(Capability,EmailPilotScenario.Completion))!;
        return(admitted,(await new WorkStore(h.Db,h.Work,h.Clock).ClaimAsync(admitted.VerificationWorkId,default)).Lease!);
    }
}
