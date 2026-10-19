using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Email.Pilot;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Tests;

public sealed class EmailPilotSignerReadTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Captured_normal_invitation_creates_a_run_bounded_session_without_rewriting_its_original_token()
    {
        const string capability="1234567890123456789012345678901234567890123";
        var options=new EmailPilotOptions{Enabled=true,RunId=Guid.NewGuid().ToString("N")};
        options.Mailboxes=new("sender-"+options.RunId+"@example.invalid","first@example.invalid","second@example.invalid","recipient@example.invalid");
        var admission=new EmailPilotAdmissionOptions{CapabilitySha256=Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(capability)))};
        EmailOptions email=null!;WorkOptions work=null!;IDataProtectionProvider keys=null!;EmailPayloadProtection payload=null!;
        DateTimeOffset end=default,originalExpiry=default;Guid tokenId=default;
        await using var run=await CompletionEvidenceCollectorTests.Run.Create(fixture,demo:true,mailbox:options.Mailboxes.Sender,firstOnly:true,
            signingLifetime:TimeSpan.FromHours(2),signerMailbox:i=>i==1?options.Mailboxes.FirstSigner:options.Mailboxes.SecondSigner,
            recipientMailbox:options.Mailboxes.Recipient,requestSender:async(h,_)=>{
                email=h.App.Services.GetRequiredService<EmailOptions>();email.Enabled=false;
                work=h.App.Services.GetRequiredService<WorkOptions>();keys=h.App.Services.GetRequiredService<IDataProtectionProvider>();
                using var scope=h.App.Services.CreateScope();var sp=scope.ServiceProvider;var db=sp.GetRequiredService<QuillSignDbContext>();
                payload=sp.GetRequiredService<EmailPayloadProtection>();var ledger=new EmailPilotLedger(options,email,()=>db,()=>new(keys),h.Clock);
                var service=new EmailPilotAdmission(options,admission,email,work,new(),()=>sp.GetRequiredService<SenderAvailability>(),()=>ledger,
                    ()=>sp.GetRequiredService<EmailOutboxWriter>(),()=>payload,h.Clock);
                Assert.NotNull(await service.RequestAsync(capability,EmailPilotScenario.Completion));
                end=(await db.EmailPilotRuns.AsNoTracking().SingleAsync(x=>x.Id==Guid.ParseExact(options.RunId,"N"))).ExpiresAt;
                // Existing local fixture transport captures normal emails in memory.
                // This tests actual link redemption, not full restricted dispatch or inbox delivery.
                email.Enabled=true;
            },signerOverride:async(r,_)=>{
                Assert.True(await r.H.Once());email.Enabled=false;
                var raw=Regex.Match(r.H.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;Assert.Equal(43,raw.Length);
                await using var db=fixture.Open();var token=await db.AuthTokens.AsNoTracking().SingleAsync(x=>x.EnvelopeId==r.Envelope.Id && x.Purpose==TokenPurpose.SignerAccess);
                tokenId=token.Id;originalExpiry=token.ExpiresAt;Assert.True(originalExpiry>end);
                var ledger=new EmailPilotLedger(options,email,()=>db,()=>new(keys),r.H.Clock);
                var bounds=new EmailPilotReadBounds(()=>db,()=>new(()=>db,()=>ledger,()=>payload,admission,work),r.H.Clock);
                var access=new SignerAccess(db,new(db,r.H.Clock),new(),r.H.Clock,bounds);
                var signer=Assert.IsType<VerifiedSigner>(await access.RedeemAsync(raw,null,null));
                Assert.Equal(end,signer.SessionExpiresAt);r.LastSigner=SignerAccessConfiguration.Principal(signer);
                Assert.NotNull(await access.GetContextAsync(r.LastSigner,r.Envelope.PublicId));
                options.Enabled=false;
                await Assert.ThrowsAsync<EmailPilotAccessUnavailableException>(()=>access.GetContextAsync(r.LastSigner,r.Envelope.PublicId));
                options.Enabled=true;r.H.Clock.Advance(end-r.H.Clock.GetUtcNow()+TimeSpan.FromMilliseconds(1));
                Assert.Null(await access.GetContextAsync(r.LastSigner,r.Envelope.PublicId));
                Assert.Null(await access.RedeemAsync(raw,null,null));return true;
            });
        await using var inspect=fixture.Open();var saved=await inspect.AuthTokens.AsNoTracking().SingleAsync(x=>x.Id==tokenId);
        Assert.Equal(originalExpiry,saved.ExpiresAt);Assert.NotNull(saved.UsedAt);Assert.False(email.Enabled);
        Assert.False(await inspect.SignerFinishAcceptances.AnyAsync(x=>x.EnvelopeId==run.Envelope.Id));
    }
}
