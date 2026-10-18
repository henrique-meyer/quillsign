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

    [Theory][InlineData("ip")][InlineData("sender")][InlineData("global")][InlineData("address")]
    public async Task Daily_caps_are_immutable_reservations_and_replay_does_not_spend_twice(string cap)
    {
        await using var r = await Run.Create(fixture); var first = await r.Review(); var id = Guid.NewGuid();
        if (cap == "ip") r.Options.DailyIpRequests = 1;
        if (cap == "sender") r.Options.DailySenderRequests = 1;
        if (cap == "address") r.Options.DailyAddressRequests = 1;
        if (cap == "global")
        {
            await using var db = fixture.Open(); var start = new DateTimeOffset(r.H.Clock.GetUtcNow().UtcDateTime.Date, TimeSpan.Zero);
            var count = await db.AuditEvents.CountAsync(x => x.Event == "signer_contact_correction_requested" && x.At >= start && x.At < start.AddDays(1));
            r.Options.DailyRequests = r.Options.DailyAddressRequests = r.Options.DailySenderRequests = r.Options.DailyIpRequests = count + 1;
        }
        var ip = cap == "ip" ? "192.0.2.120" : "127.0.0.1";
        Assert.Equal(SignerContactCorrectionOutcome.Queued, await r.Request(id, first, ip));
        Assert.Equal(SignerContactCorrectionOutcome.AlreadyRequested, await r.Request(id, first, ip));
        var next = await r.Review(r.H.First.Email);
        if (cap == "address")
        {
            Assert.Equal(SignerContactCorrectionOutcome.Queued, await r.Request(Guid.NewGuid(), next));
            next = await r.Review(first.NewEmail);
        }
        Assert.Equal(SignerContactCorrectionOutcome.Capped, await r.Request(Guid.NewGuid(), next, cap == "ip" ? "::ffff:192.0.2.120" : ip));
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Queued_or_unsubmitted_leased_predecessor_is_retired_without_a_message_to_the_old_contact(bool leased)
    {
        await using var r = await Run.Create(fixture, dispatch: false);
        if (leased) using (var scope = r.H.App.Services.CreateScope())
            Assert.NotNull((await scope.ServiceProvider.GetRequiredService<WorkStore>().ClaimAsync(r.Sent.InvitationWorkId, default)).Lease);
        var id = Guid.NewGuid(); Assert.Equal(SignerContactCorrectionOutcome.Queued, await r.Request(id));
        await r.Drain(InvitationSuccessorJobs.CorrectionWorkId(id));
        Assert.Equal(1, r.H.Sender.Calls); Assert.Contains("corrected-" + r.H.First.Email, r.H.Sender.Last!.To);
        await using var db = fixture.Open(); Assert.Equal("contact-corrected-before-submission", (await db.EmailOutbox.SingleAsync(x => x.Id == r.Sent.InvitationWorkId)).LastError);
    }

    [Fact]
    public async Task Ambiguous_provider_submission_cannot_be_bypassed_by_correcting_the_contact()
    {
        await using var r = await Run.Create(fixture, dispatch: false);
        r.H.Sender.Failure = new IOException("Synthetic uncertain provider acknowledgement");
        await Assert.ThrowsAsync<IOException>(() => r.H.Once()); r.H.Sender.Failure = null;
        Assert.Equal(SignerContactCorrectionOutcome.Busy, (await r.Use((SignerContactCorrections s) => s.PreviewAsync(r.H.Principal,
            r.H.Envelope.PublicId, r.Until, "corrected-" + r.H.First.Email)))!.Blocked);
        Assert.Equal(SignerContactCorrectionOutcome.Busy, await r.Request(Guid.NewGuid()));
        await using var db = fixture.Open(); Assert.False(await db.SignerContactRevisions.AnyAsync(x => x.EnvelopeId == r.H.Envelope.Id));
    }

    [Theory][InlineData(false)][InlineData(true)]
    public async Task Genuine_review_and_Finish_serialize_with_correction_and_the_new_mailbox_completes_the_current_copy(bool finishFirst)
    {
        Guid command = Guid.NewGuid(); string oldReceipt = ""; ClaimsPrincipal oldPrincipal = null!;
        await using var run = await CompletionEvidenceCollectorTests.Run.Create(fixture, firstOnly: finishFirst, configure: Run.Register,
            initialTime: new DateTimeOffset(DateTime.UtcNow.Date.AddDays(2), TimeSpan.Zero).AddHours(1), signerOverride: async (r, order) =>
        {
            if (order != 1) return false;
            var until = r.H.Clock.GetUtcNow().AddMinutes(30);
            var old = await r.SignNext(false, finishFirst); oldReceipt = r.LastReviewReceipt; oldPrincipal = SignerAccessConfiguration.Principal(old);
            // Prepare a sender proof even while a signer has populated all entries;
            // accepted Finish, not the mutable Viewed status, closes correction.
            var preview = await r.Use((SignerContactCorrections s) => s.PreviewAsync(r.Sender, r.Envelope.PublicId, until, "corrected-" + old.Email));
            if (finishFirst) { Assert.Null(preview); return true; }
            Assert.NotNull(preview);
            Assert.Equal(SignerContactCorrectionOutcome.Queued, await r.Use((SignerContactCorrections s) => s.RequestAsync(r.Sender,
                r.Envelope.PublicId, until, command, preview.Review, true, SignerContactCorrectionStatement.Version, "127.0.0.1", "Synthetic genuine correction")));
            Assert.Null(await r.Use((SignerReviewCandidates s) => s.ReadAsync(oldPrincipal, r.Envelope.PublicId, oldReceipt)));
            Assert.Equal(SignerFinishOutcome.InvalidContext, (await r.Use((SignerFinish s) => s.AcceptAsync(oldPrincipal, r.Envelope.PublicId,
                oldReceipt, true, SignerFinishStatement.Version, "127.0.0.1", "Synthetic retired review"))).Outcome);
            Assert.True(await r.H.Once());
            var token = Regex.Match(r.H.Sender.Last!.Text, "token=([A-Za-z0-9_-]{43})").Groups[1].Value;
            await r.SignNext(true, true, token); return true;
        });
        await using var db = fixture.Open();
        if (finishFirst)
        {
            Assert.False(await db.SignerContactRevisions.AnyAsync(x => x.EnvelopeId == run.Envelope.Id));
            Assert.NotNull(await db.SignerFinishAcceptances.SingleAsync(x => x.EnvelopeId == run.Envelope.Id)); return;
        }
        var material = await run.Collect(); Assert.NotNull(material);
        Assert.StartsWith("corrected-", material.Evidence.Signers[0].Email);
        Assert.Single(material.Evidence.Events, x => x.ContactCorrection is not null);
        Assert.Equal(2, await db.SignerFinishAcceptances.CountAsync(x => x.EnvelopeId == run.Envelope.Id));
        Assert.NotNull((await db.SignerReviewCandidates.SingleAsync(x => x.EnvelopeId == run.Envelope.Id && x.SupersededAt != null)).SupersededAt);
        // The admission and review metadata survive as immutable evidence; the
        // renderer accepts the complete corrected two-signer audit chain.
        Assert.NotEmpty(new QuillSign.Completion.CompletionCertificateRenderer().PreparePacket(material.Source, material.Pages, material.Evidence).AppendixBytes);
        await db.AuditEvents.Where(x => x.EnvelopeId == run.Envelope.Id && x.Event == "signer_contact_correction_requested").ExecuteDeleteAsync();
    }

    [Fact]
    public async Task Preview_projects_the_verified_retention_deadline_for_metadata_and_review_without_changing_historical_review_bytes()
    {
        await using var run = await CompletionEvidenceCollectorTests.Run.Create(fixture, demo: true, uploadRetentionDays: 7,
            firstOnly: true, configure: Run.Register, signerOverride: (_, _) => Task.FromResult(true));
        await using var db = fixture.Open(); var policy = await db.DocumentRetentionSnapshots.SingleAsync(x => x.EnvelopeId == run.Envelope.Id);
        var until = run.H.Clock.GetUtcNow().AddMinutes(20);
        var metadata = await run.Use((SignerContactCorrections s) => s.PreviewAsync(run.Sender, run.Envelope.PublicId, until, null));
        var review = await run.Use((SignerContactCorrections s) => s.PreviewAsync(run.Sender, run.Envelope.PublicId, until, "corrected-" + metadata!.Review.OldEmail));
        Assert.NotNull(metadata); Assert.NotNull(review); Assert.Equal(policy.DeleteAfter, metadata.RetentionDeadline); Assert.Equal(policy.DeleteAfter, review.RetentionDeadline);
        Assert.DoesNotContain("RetentionDeadline", JsonSerializer.Serialize(review.Review));
    }

    [Fact]
    public async Task Correcting_the_second_signer_preserves_the_first_signed_checkpoint_and_binds_the_correct_current_copy()
    {
        Guid previousFinish = default; Guid correctedCommand = Guid.NewGuid(); byte[] priorPdfHash = [], priorFinishHash = [];
        await using var run = await CompletionEvidenceCollectorTests.Run.Create(fixture, configure: Run.Register,
            initialTime: new DateTimeOffset(DateTime.UtcNow.Date.AddDays(2), TimeSpan.Zero).AddHours(1), signerOverride: async (r, order) =>
        {
            if (order != 2) return false;
            var old = await r.SignNext(false, false); var until = r.H.Clock.GetUtcNow().AddMinutes(30);
            await r.Refresh();
            await using (var db = fixture.Open())
            {
                var prior = await db.SignerFinishAcceptances.SingleAsync(x => x.EnvelopeId == r.Envelope.Id);
                previousFinish = prior.Id; priorPdfHash = prior.PdfSha256.ToArray();
                priorFinishHash = (await db.AuditEvents.SingleAsync(x => x.EnvelopeId == r.Envelope.Id && x.Event == "signer_finish_accepted")).Hash.ToArray();
            }
            var preview = await r.Use((SignerContactCorrections s) => s.PreviewAsync(r.Sender, r.Envelope.PublicId, until, "corrected-" + old.Email));
            Assert.NotNull(preview); Assert.Equal(old.DocumentId, preview.Review.DocumentId);
            Assert.NotEqual(Guid.Parse(r.Envelope.SentPdfBlob!), preview.Review.DocumentId);
            Assert.Equal(SignerContactCorrectionOutcome.Queued, await r.Use((SignerContactCorrections s) => s.RequestAsync(r.Sender,
                r.Envelope.PublicId, until, correctedCommand, preview.Review, true, SignerContactCorrectionStatement.Version, "127.0.0.1", "Synthetic second contact")));
            Assert.True(await r.H.Once());
            var token = Regex.Match(r.H.Sender.Last!.Text, "token=([A-Za-z0-9_-]{43})").Groups[1].Value;
            var fresh = await r.SignNext(true, true, token); Assert.Equal(old.DocumentId, fresh.DocumentId); return true;
        });
        var evidence = await run.Collect(); Assert.NotNull(evidence);
        Assert.StartsWith("corrected-", evidence.Evidence.Signers[1].Email);
        await using var verify = fixture.Open(); Assert.Equal(priorPdfHash, (await verify.SignerFinishAcceptances.SingleAsync(x => x.Id == previousFinish)).PdfSha256);
        Assert.Equal(priorFinishHash, (await verify.AuditEvents.Where(x => x.EnvelopeId == run.Envelope.Id && x.Event == "signer_finish_accepted").OrderBy(x => x.Sequence).FirstAsync()).Hash);
        await verify.AuditEvents.Where(x => x.EnvelopeId == run.Envelope.Id && x.Event == "signer_contact_correction_requested").ExecuteDeleteAsync();
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
            var h = await Shared.Create(fixture, browser: true, configure: Register);
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
        internal static void Register(IServiceCollection services)
        {
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
                ["SignerContactCorrection:Enabled"] = "true", ["SignerContactCorrection:DailyAddressRequests"] = "1000",
                ["SignerContactCorrection:DailyIpRequests"] = "1000", ["SignerContactCorrection:DailySenderRequests"] = "1000", ["SignerContactCorrection:DailyRequests"] = "1000" }).Build();
            services.AddQuillSignSignerContactCorrections(config);
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
