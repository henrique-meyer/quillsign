using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Work;
using Run=QuillSign.Tests.SignerRetentionAccessTests.Run;

namespace QuillSign.Tests;

public sealed class DemoPurgeEmailRaceTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private async Task<Guid> Decline(Run r)
    {
        await r.Consent();Assert.NotNull(await r.Use<SignerConsent,SignerReadContext?>(s=>s.DeclineAsync(r.Principal,r.PublicId,"Synthetic refusal NO AGREEMENT",null,null)));
        await using var db=fixture.Open();return (await db.EmailOutbox.SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Template=="signer-declined")).Id;
    }
    [Theory]
    [InlineData("expiry")][InlineData("missing")][InlineData("corrupt")]
    public async Task Queued_decline_never_submits_after_cutoff_or_when_enrollment_is_unverifiable(string fault)
    {
        await using var r=await Run.Create(fixture);var id=await Decline(r);
        if(fault=="expiry")r.Expire();
        await using(var db=fixture.Open()) {
            if(fault=="missing")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ExecuteDeleteAsync();
            if(fault=="corrupt")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==r.H.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.OriginalSha256,new byte[32]));
        }
        Assert.True(await r.H.Once());Assert.Equal(0,r.H.Sender.Calls);
        await using var check=fixture.Open();var email=await check.EmailOutbox.SingleAsync(x=>x.Id==id);var work=await check.WorkItems.SingleAsync(x=>x.Id==id);
        Assert.Null(email.SubmissionStartedAt);Assert.Null(email.ProviderMessageId);Assert.Equal(1,work.Attempts);
        Assert.Equal(fault=="expiry" ? WorkStatus.Failed:WorkStatus.Queued,work.Status);
        Assert.Equal(fault=="expiry" ? "email-retention-expired":"email-retention-unavailable",work.LastError);
    }
    [Fact]
    public async Task In_flight_provider_response_after_private_SQL_removal_cannot_recreate_rows_or_send_again()
    {
        await using var r=await Run.Create(fixture,initialTime:DateTimeOffset.UtcNow.AddDays(-8));var emailId=await Decline(r);
        var entered=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);var release=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        r.H.Sender.BeforeReturn=async()=>{entered.TrySetResult();await release.Task;};var sending=r.H.Once();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(15));Assert.Equal(1,r.H.Sender.Calls);
            r.H.Clock.Advance(DateTimeOffset.UtcNow-r.H.Clock.GetUtcNow());Guid purge;
            await using(var db=fixture.Open())purge=(await db.WorkItems.SingleAsync(x=>x.EnvelopeId==r.H.Envelope.Id && x.Kind==WorkKind.Purge)).Id;
            await r.H.Signals.PublishAsync(purge,TimeSpan.Zero,default);Assert.True(await r.H.Once());
            await using(var db=fixture.Open()) {
                Assert.False(await db.Envelopes.AnyAsync(x=>x.Id==r.H.Envelope.Id));Assert.False(await db.EmailOutbox.AnyAsync(x=>x.Id==emailId));
                Assert.False(await db.AuthTokens.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id));Assert.False(await db.AuditEvents.AnyAsync(x=>x.EnvelopeId==r.H.Envelope.Id));
            }
            release.TrySetResult();var result=await Record.ExceptionAsync(()=>sending);Assert.IsType<InvalidOperationException>(result);
            await r.H.Signals.PublishAsync(emailId,TimeSpan.Zero,default);Assert.True(await r.H.Once());Assert.Equal(1,r.H.Sender.Calls);
            await using var final=fixture.Open();Assert.False(await final.EmailOutbox.AnyAsync(x=>x.Id==emailId));Assert.False(await final.Envelopes.AnyAsync(x=>x.Id==r.H.Envelope.Id));
        }
        finally{release.TrySetResult();_ =await Record.ExceptionAsync(()=>sending);}
    }
}
