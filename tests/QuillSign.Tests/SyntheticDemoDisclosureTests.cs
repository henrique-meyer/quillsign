using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Legal;
using QuillSign.Sender;
using QuillSign.Signing;
using Retained=QuillSign.Tests.RetentionSigningDeadlineTests.Retained;

namespace QuillSign.Tests;

public sealed class SyntheticDemoDisclosureTests(SqlDatabaseFixture fixture):IClassFixture<SqlDatabaseFixture>
{
    private const string Profile="synthetic-demo-v1";
    private static void Select(ElectronicRecordOptions options)
    {
        options.Profile=Profile;options.PaperCopyInstructions="";options.PaperCopyFees="";options.WithdrawalInstructions="";
        options.WithdrawalConsequences="";options.ContactUpdateInstructions="";options.AccessRequirements="";options.RetentionNotice="";
    }

    [Theory]
    [InlineData(1)][InlineData(7)][InlineData(30)]
    public async Task Authorized_review_Send_and_actual_consent_bind_the_same_fixed_demo_snapshot_after_settings_change(int days)
    {
        await using var run=await Retained.Create(fixture,browser:true,retentionDays:days);var h=run.H;
        var options=h.App.Services.GetRequiredService<ElectronicRecordOptions>();Select(options);
        var review=(await run.Review())!;using var scope=h.App.Services.CreateScope();
        var readiness=scope.ServiceProvider.GetRequiredService<SenderSendReadiness>();
        var snapshot=Assert.IsType<DisclosureSnapshot>(readiness.Read(h.Principal,review).Disclosure);
        Assert.Equal("synthetic-demo-2026-10-17.1",snapshot.Version);Assert.True(ElectronicRecordDisclosure.Verify(snapshot));
        Assert.Contains(days+" days",snapshot.Text);Assert.Contains(run.Policy.DeleteAfter.ToString("yyyy-MM-dd HH:mm:ss 'UTC'",System.Globalization.CultureInfo.InvariantCulture),snapshot.Text);
        Assert.Contains("not waive statutory rights",snapshot.Text);Assert.Contains("may decline before Finish",snapshot.Text);
        Assert.Contains("Automatic physical deletion is not implemented yet",snapshot.Text);Assert.Contains("another PDF reader",snapshot.Text);
        Assert.DoesNotContain("{{delete_after}}",snapshot.Text);Assert.DoesNotContain('\r',snapshot.Text);
        h.App.Services.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays=90;
        var fresh=readiness.Read(h.Principal,(await run.Review())!).Disclosure!;Assert.Equal(snapshot.Text,fresh.Text);Assert.Equal(snapshot.Sha256,fresh.Sha256);
        Assert.NotNull(await h.Send(reviewedRetentionSha256:review.RetentionSha256));var sent=await run.State();
        Assert.Equal(snapshot.Text,sent.ErsdText);Assert.Equal(snapshot.Sha256,sent.ErsdSha256);Assert.Equal(run.Policy.DeleteAfter,sent.ExpiresAt);
        options.Profile="unknown";
        Assert.True(await h.Once());var token=Regex.Match(h.Sender.Last!.Text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        var access=scope.ServiceProvider.GetRequiredService<SignerAccess>();var identity=Assert.IsType<VerifiedSigner>(await access.RedeemAsync(token,null,null));
        var principal=SignerAccessConfiguration.Principal(identity);var context=(await access.GetContextAsync(principal,sent.PublicId))!;
        Assert.Equal(snapshot.Text,context.Disclosure.Text);
        var bytes=await scope.ServiceProvider.GetRequiredService<SignerPdfAccess>().PrepareAsync(principal,context);Assert.NotEmpty(bytes);
        var receipt=scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(context);
        var consent=scope.ServiceProvider.GetRequiredService<SignerConsent>();
        Assert.Equal(ConsentResult.InvalidEvidence,await consent.AcceptAsync(principal,sent.PublicId,receipt,false,true,"preview",null,null));
        Assert.Equal(ConsentResult.Accepted,await consent.AcceptAsync(principal,sent.PublicId,receipt,true,true,"preview",null,null));
        await using var db=fixture.Open();var audit=await db.AuditEvents.SingleAsync(x=>x.EnvelopeId==sent.Id && x.Event=="consent_given");
        Assert.Contains(Convert.ToHexStringLower(snapshot.Sha256),audit.DataJson);Assert.Equal(AuditHash.Compute(audit),audit.Hash);
    }

    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Non_demo_or_unenrolled_legacy_scope_cannot_use_profile_even_when_selected(bool isDemo)
    {
        await using var h=await SendDraftWorkflowTests.Harness.Create(fixture,browser:true);Select(h.App.Services.GetRequiredService<ElectronicRecordOptions>());
        await using(var setup=fixture.Open())await setup.Envelopes.Where(x=>x.Id==h.Envelope.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.IsDemo,isDemo));
        await using(var setup=fixture.Open())h.Version=(await setup.Envelopes.AsNoTracking().SingleAsync(x=>x.Id==h.Envelope.Id)).RowVersion;
        using var scope=h.App.Services.CreateScope();var review=(await scope.ServiceProvider.GetRequiredService<DraftReview>().GetAsync(h.Principal,h.Envelope.PublicId))!;
        Assert.Null(scope.ServiceProvider.GetRequiredService<SenderSendReadiness>().Read(h.Principal,review).Disclosure);
        await Assert.ThrowsAsync<DisclosureRejectedException>(()=>h.Send());
        await using var db=fixture.Open();Assert.Equal(EnvelopeStatus.Draft,(await db.Envelopes.SingleAsync(x=>x.Id==h.Envelope.Id)).Status);
        Assert.False(await db.WorkItems.AnyAsync(x=>x.EnvelopeId==h.Envelope.Id));
    }

    [Theory]
    [InlineData("missing")][InlineData("changed")]
    public async Task Enrolled_policy_corruption_cannot_create_demo_disclosure_or_Send(string fault)
    {
        await using var run=await Retained.Create(fixture);Select(run.H.App.Services.GetRequiredService<ElectronicRecordOptions>());
        var review=(await run.Review())!;var before=await run.State();
        await using(var db=fixture.Open()) {
            if(fault=="missing")await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==before.Id).ExecuteDeleteAsync();
            else await db.DocumentRetentionSnapshots.Where(x=>x.EnvelopeId==before.Id).ExecuteUpdateAsync(s=>s.SetProperty(x=>x.OriginalSha256,new byte[32]));
        }
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.Review());
        await Assert.ThrowsAsync<InvalidDataException>(()=>run.H.Send(reviewedRetentionSha256:review.RetentionSha256));await run.Unsent(before);
    }

    [Fact]
    public async Task Actual_source_replacement_and_confirmation_cannot_extend_the_disclosed_upload_deadline()
    {
        await using var run=await Retained.Create(fixture,browser:true);var h=run.H;Select(h.App.Services.GetRequiredService<ElectronicRecordOptions>());
        h.Clock.Advance(TimeSpan.FromDays(1));h.App.Services.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays=90;
        var before=await run.State();using var scope=h.App.Services.CreateScope();var documents=scope.ServiceProvider.GetRequiredService<DocumentWorkflow>();
        using var input=new MemoryStream(PdfFixtures.Create(text:"REPLACEMENT SYNTHETIC NO AGREEMENT"));
        Assert.True(await documents.UploadAsync(h.Principal,before.PublicId,before.RowVersion,"Replacement NO AGREEMENT.pdf",input,input.Length,null,null,default));
        var replaced=await run.State();Assert.Null(replaced.PreviewConfirmedAt);
        Assert.True(await documents.ConfirmAsync(h.Principal,replaced.PublicId,replaced.RowVersion,replaced.PdfBlob!,true,null,null,default));
        var review=(await run.Review())!;var snapshot=scope.ServiceProvider.GetRequiredService<SenderSendReadiness>().Read(h.Principal,review).Disclosure!;
        Assert.True(ElectronicRecordDisclosure.Verify(snapshot));Assert.Equal(run.Policy.DeleteAfter,review.RetentionDeleteAfter);
        Assert.Equal(UploadRetention.Digest(run.Policy),review.RetentionSha256);Assert.Contains("7 days",snapshot.Text);
        Assert.Contains(run.Policy.StartedAt.ToString("yyyy-MM-dd HH:mm:ss 'UTC'",System.Globalization.CultureInfo.InvariantCulture),snapshot.Text);
        Assert.DoesNotContain("90 days",snapshot.Text);Assert.Contains("Replacement NO AGREEMENT.pdf",snapshot.Text);
    }

    [Theory]
    [InlineData("synthetic-demo-v1")][InlineData("unknown")][InlineData("mixed")]
    public void Public_builder_never_infers_enrollment_or_silently_overrides_operator_policies(string selection)
    {
        var options=selection=="mixed" ? ElectronicRecordDisclosureTests.Policy() : new ElectronicRecordOptions();
        options.Profile=selection=="mixed" ? Profile : selection;
        Assert.Throws<DisclosureRejectedException>(()=>new ElectronicRecordDisclosure(options).Build(new('1',32),"Synthetic NO AGREEMENT","sender@example.invalid"));
    }

    // Test assembly only: genuine local browser flow with synthetic mail capture.
    public sealed class BrowserSession:IAsyncDisposable
    {
        private readonly Retained run;
        private BrowserSession(Retained run)=>this.run=run;
        public string PublicId=>run.H.Envelope.PublicId;
        public DateTimeOffset DeleteAfter=>run.Policy.DeleteAfter;
        public static async Task<BrowserSession> Start(SqlDatabaseFixture fixture,int port)
        {
            var run=await Retained.Create(fixture,browserPort:port);
            Select(run.H.App.Services.GetRequiredService<ElectronicRecordOptions>());return new(run);
        }
        public async Task<string> DeliverInvitation()
        {
            Assert.True(await run.H.Once());var text=run.H.Sender.Last?.Text??throw new InvalidOperationException("No synthetic invitation was captured.");
            var token=Regex.Match(text,"token=([A-Za-z0-9_-]{43})").Groups[1].Value;
            if(token.Length!=43)throw new InvalidOperationException("No valid synthetic invitation was captured.");
            return "/sign/invitation?token="+token;
        }
        public void ChangeSettings()=>run.H.App.Services.GetRequiredService<DemoRetentionOptions>().PurgeAfterDays=30;
        public void InvalidateProfile()=>run.H.App.Services.GetRequiredService<ElectronicRecordOptions>().Profile="unknown";
        public ValueTask DisposeAsync()=>run.DisposeAsync();
    }
}
