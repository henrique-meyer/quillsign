using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Work;
using Shared = QuillSign.Tests.SendDraftWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class SignerContactCorrectionsTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Deliberate_correction_revokes_old_authority_preserves_original_and_delivers_one_new_epoch_invitation()
    {
        await using var r = await Run.Create(fixture); var old = r.Token;
        var identity = (await r.Use((SignerAccess s) => s.RedeemAsync(old, "127.0.0.1", "Synthetic old contact")))!;
        var principal = SignerAccessConfiguration.Principal(identity);
        using (var scope = r.H.App.Services.CreateScope())
        {
            var proof = scope.ServiceProvider.GetRequiredService<SignerReceiptProtection>().Create(identity);
            Assert.Equal(ConsentResult.Accepted, await scope.ServiceProvider.GetRequiredService<SignerConsent>().AcceptAsync(principal,
                identity.PublicId, proof, true, true, "preview", "127.0.0.1", "Synthetic old consent"));
        }
        await using var inspect = fixture.Open();
        var before = await inspect.Envelopes.AsNoTracking().SingleAsync(x => x.Id == r.H.Envelope.Id);
        var sent = await inspect.AuditEvents.AsNoTracking().SingleAsync(x => x.EnvelopeId == before.Id && x.Event == "sent");
        var original = await r.H.Read(Guid.Parse(before.SentPdfBlob!));
        var review = await r.Review(); var id = Guid.NewGuid();
        Assert.Equal(SignerContactCorrectionOutcome.Queued, await r.Request(id, review));
        Assert.Equal(SignerContactCorrectionOutcome.AlreadyRequested, await r.Request(id, review));
        Assert.Null(await r.Use((SignerAccess s) => s.GetContextAsync(principal, identity.PublicId)));
        var after = await inspect.Envelopes.AsNoTracking().SingleAsync(x => x.Id == before.Id);
        Assert.NotEqual(Convert.ToBase64String(before.RowVersion), Convert.ToBase64String(after.RowVersion));
        Assert.Equal(before.SentPdfSha256, after.SentPdfSha256); Assert.Equal(before.ErsdText, after.ErsdText);
        Assert.Equal(before.ExpiresAt, after.ExpiresAt); Assert.Equal(original, await r.H.Read(Guid.Parse(after.SentPdfBlob!)));
        Assert.Equal(sent.Hash, (await inspect.AuditEvents.AsNoTracking().SingleAsync(x => x.Id == sent.Id)).Hash);
        var revision = await inspect.SignerContactRevisions.SingleAsync(x => x.Id == id);
        Assert.Contains("ConsentAt", revision.RetirementJson); Assert.Contains(r.H.First.Email, revision.RetirementJson);
        var signer = await inspect.Signers.AsNoTracking().SingleAsync(x => x.Id == r.H.First.Id);
        Assert.Equal(review.NewEmail, signer.Email); Assert.Null(signer.ConsentAt); Assert.Null(signer.SignatureAdoptionId);
        await r.Drain(InvitationSuccessorJobs.CorrectionWorkId(id));
        Assert.Equal(2, r.H.Sender.Calls); Assert.NotEqual(old, r.Token);
        var fresh = await r.Use((SignerAccess s) => s.RedeemAsync(r.Token, "127.0.0.1", "Synthetic corrected contact"));
        Assert.NotNull(fresh); Assert.Equal(review.NewEmail, fresh.Email); Assert.NotEqual(identity.SessionId, fresh.SessionId);
        Assert.Null((await inspect.Signers.AsNoTracking().SingleAsync(x => x.Id == signer.Id)).ConsentAt);
        Assert.Single(await inspect.EmailOutbox.Where(x => x.EnvelopeId == before.Id && x.Template == InvitationSuccessorProtection.Template).ToArrayAsync());
    }

    [Theory][InlineData(true)][InlineData(false)]
    public async Task Concurrent_commands_cannot_duplicate_or_overtake_a_review(bool sameId)
    {
        await using var r = await Run.Create(fixture); var review = await r.Review(); var id = Guid.NewGuid();
        var results = await Task.WhenAll(Enumerable.Range(0, 3).Select(i => r.Request(sameId ? id : Guid.NewGuid(), review)));
        Assert.Single(results, x => x == SignerContactCorrectionOutcome.Queued);
        Assert.Equal(2, results.Count(x => x == (sameId ? SignerContactCorrectionOutcome.AlreadyRequested : SignerContactCorrectionOutcome.Conflict)));
    }

    [Theory][InlineData("confirmation")][InlineData("statement")][InlineData("sender")][InlineData("ticket")]
    [InlineData("version")][InlineData("signer-version")][InlineData("epoch")][InlineData("source")][InlineData("name")][InlineData("duplicate")][InlineData("suppressed")]
    public async Task Admission_rejects_changed_or_missing_authority_without_rewriting_the_signer(string kind)
    {
        await using var r = await Run.Create(fixture); var review = await r.Review();
        if (kind == "version") review = review with { Version = Convert.ToBase64String(new byte[8]) };
        if (kind == "signer-version") review = review with { SignerVersion = Convert.ToBase64String(new byte[8]) };
        if (kind == "epoch") review = review with { ContactRevisionId = Guid.NewGuid(), ContactRevisionNumber = 1 };
        if (kind == "source") review = review with { DocumentId = Guid.NewGuid() };
        if (kind == "name") review = review with { Name = "Different named person" };
        if (kind == "duplicate") review = await r.Review(r.H.Second.Email);
        if (kind == "suppressed") { await using var d = fixture.Open(); d.Suppressions.Add(new() { Email = review.NewEmail, Reason = SuppressionReason.Complaint }); await d.SaveChangesAsync(); }
        var outcome = await r.Use((SignerContactCorrections s) => s.RequestAsync(kind == "sender" ? new ClaimsPrincipal() : r.H.Principal,
            r.H.Envelope.PublicId, kind == "ticket" ? r.H.Clock.GetUtcNow() : r.Until, Guid.NewGuid(), review, kind != "confirmation",
            kind == "statement" ? "other" : SignerContactCorrectionStatement.Version, "127.0.0.1", "Synthetic refused correction"));
        Assert.Equal(kind is "sender" or "ticket" ? SignerContactCorrectionOutcome.InvalidContext :
            kind is "confirmation" or "statement" ? SignerContactCorrectionOutcome.InvalidConfirmation :
            kind == "duplicate" ? SignerContactCorrectionOutcome.DuplicateAddress : kind == "suppressed" ? SignerContactCorrectionOutcome.Suppressed : SignerContactCorrectionOutcome.Conflict, outcome);
        await using var db = fixture.Open(); Assert.False(await db.SignerContactRevisions.AnyAsync(x => x.EnvelopeId == r.H.Envelope.Id));
        Assert.Equal(r.H.First.Email, (await db.Signers.SingleAsync(x => x.Id == r.H.First.Id)).Email);
    }

    [Theory][InlineData("hint")][InlineData("audit")][InlineData("rollback")][InlineData("ticket-crossing")][InlineData("review-crossing")]
    public async Task Known_failure_rolls_back_retirement_entry_reset_and_reservations(string kind)
    {
        await using var r = await Run.Create(fixture, dispatch: false); var review = await r.Review(); var id = Guid.NewGuid();
        r.H.Faults.Event = "signer_contact_correction_requested";
        r.H.Signals.FailHint = kind == "hint"; r.H.Faults.FailAudit = kind == "audit"; r.H.Faults.RejectCommit = kind == "rollback";
        DateTimeOffset? until = kind == "review-crossing" ? r.H.Clock.GetUtcNow().AddMinutes(5) : null;
        if (kind.EndsWith("crossing")) r.H.Faults.BeforeAudit = _ => { r.H.Clock.Advance((until ?? r.Until) - r.H.Clock.GetUtcNow()); return Task.CompletedTask; };
        if (kind.EndsWith("crossing")) Assert.NotEqual(SignerContactCorrectionOutcome.Queued, await r.Request(id, review, reviewUntil: until));
        else Assert.NotNull(await Record.ExceptionAsync(() => r.Request(id, review)));
        await using var db = fixture.Open(); Assert.False(await db.SignerContactRevisions.AnyAsync(x => x.Id == id));
        Assert.False(await db.WorkItems.AnyAsync(x => x.Id == InvitationSuccessorJobs.CorrectionWorkId(id)));
        Assert.Equal(r.H.First.Email, (await db.Signers.SingleAsync(x => x.Id == r.H.First.Id)).Email);
        Assert.Equal(EmailStatus.Queued, (await db.EmailOutbox.SingleAsync(x => x.Id == r.Sent.InvitationWorkId)).Status);
    }

    [Fact]
    public async Task Lost_commit_acknowledgement_reuses_the_saved_correction_and_durable_hint()
    {
        await using var r = await Run.Create(fixture); var review = await r.Review(); var id = Guid.NewGuid();
        r.H.Faults.Event = "signer_contact_correction_requested"; r.H.Faults.FailCommit = true;
        await Assert.ThrowsAsync<IOException>(() => r.Request(id, review)); r.H.Faults.FailCommit = false;
        Assert.Equal(SignerContactCorrectionOutcome.AlreadyRequested, await r.Request(id, review));
        await r.H.Signals.RecoverAsync(r.H.Clock.GetUtcNow(), default); await r.Drain(InvitationSuccessorJobs.CorrectionWorkId(id));
        Assert.Equal(2, r.H.Sender.Calls);
    }

    [Fact]
    public void Disabled_registration_needs_no_database_or_work_services_and_enabled_requires_explicit_caps()
    {
        var services = new ServiceCollection(); services.AddQuillSignSignerContactCorrections(new ConfigurationBuilder().Build());
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
        Assert.Empty(provider.GetServices<IInvitationSuccessorPolicy>());
        using var scope = provider.CreateScope(); Assert.NotNull(scope.ServiceProvider.GetRequiredService<Func<SignerContactCorrections>>());
        Assert.Throws<InvalidOperationException>(() => new SignerContactCorrectionOptions { Enabled = true }.Validate());
    }

    internal sealed class Run(Shared h, SqlDatabaseFixture fixture, SentDraft sent) : IAsyncDisposable
    {
        public Shared H => h; public SentDraft Sent => sent;
        public DateTimeOffset Until = h.Clock.GetUtcNow().AddHours(2);
        public SignerContactCorrectionOptions Options => h.App.Services.GetRequiredService<SignerContactCorrectionOptions>();
        public string Token => Regex.Match(h.Sender.Last?.Text ?? "", "token=([A-Za-z0-9_-]{43})").Groups[1].Value;
        public static async Task<Run> Create(SqlDatabaseFixture fixture, bool dispatch = true)
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["SignerContactCorrection:Enabled"] = "true", ["SignerContactCorrection:DailyAddressRequests"] = "1000",
                ["SignerContactCorrection:DailyIpRequests"] = "1000", ["SignerContactCorrection:DailySenderRequests"] = "1000", ["SignerContactCorrection:DailyRequests"] = "1000" }).Build();
            var h = await Shared.Create(fixture, browser: true, configure: services => services.AddQuillSignSignerContactCorrections(config));
            h.Clock.Advance(new DateTimeOffset(DateTime.UtcNow.Date.AddDays(2), TimeSpan.Zero).AddHours(1) - h.Clock.GetUtcNow());
            await using (var db = fixture.Open())
            {
                await using var tx = await db.Database.BeginTransactionAsync();
                await new AuditWriter(db, h.Clock).AppendAsync(h.Envelope.Id, "signer_added", h.Envelope.SenderEmail, null, null, default,
                    JsonSerializer.Serialize(new { signers = new[] { h.First, h.Second }.Select(x => new { x.Id, x.Order, x.FullName, x.Email, x.Role }) }));
                await tx.CommitAsync();
            }
            var sent = (await h.Send())!; var r = new Run(h, fixture, sent); if (dispatch) await r.Drain(sent.InvitationWorkId); return r;
        }
        public async Task<SignerContactCorrectionReview> Review(string? address = null) =>
            (await Use((SignerContactCorrections s) => s.PreviewAsync(h.Principal, h.Envelope.PublicId, Until, address ?? "corrected-" + h.First.Email)))!.Review;
        public async Task<SignerContactCorrectionOutcome> Request(Guid id, SignerContactCorrectionReview? review = null, string ip = "127.0.0.1", DateTimeOffset? reviewUntil = null)
        {
            review ??= await Review(); return await Use((SignerContactCorrections s) => s.RequestAsync(h.Principal, h.Envelope.PublicId,
                Until, id, review, true, SignerContactCorrectionStatement.Version, ip, "Synthetic correction", reviewExpiresAt: reviewUntil));
        }
        public async Task<T> Use<TService, T>(Func<TService, Task<T>> action) where TService : notnull
        { using var scope = h.App.Services.CreateScope(); return await action(scope.ServiceProvider.GetRequiredService<TService>()); }
        public async Task Drain(Guid id)
        {
            for (var i = 0; i < 12; i++)
            {
                await using var db = fixture.Open(); var status = await db.WorkItems.Where(x => x.Id == id).Select(x => x.Status).SingleAsync();
                if (status is WorkStatus.Completed or WorkStatus.Failed) return;
                Assert.True(await h.Once());
            }
            throw new InvalidOperationException("Synthetic correction work did not settle.");
        }
        public async ValueTask DisposeAsync()
        {
            // Test deployments share an administrator fixture, unlike production.
            // Retire only this fixture's global counter rows after its last read.
            await using var db = fixture.Open();
            await db.AuditEvents.Where(x => x.EnvelopeId == h.Envelope.Id && x.Event == "signer_contact_correction_requested").ExecuteDeleteAsync();
            await h.DisposeAsync();
        }
    }
}
