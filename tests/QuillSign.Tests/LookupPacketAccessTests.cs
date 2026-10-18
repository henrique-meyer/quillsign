using System.Data.Common;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Storage;
using Flow = QuillSign.Tests.CompletionDownloadTests.Flow;

namespace QuillSign.Tests;

public sealed class LookupPacketAccessTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Theory]
    [InlineData(false)][InlineData(true)]
    public async Task Every_verified_mailbox_opens_the_exact_pair_with_canonical_role_and_original_bounded_expiry(bool overlap)
    {
        await using var f = await Flow.Create(fixture, senderAlsoSigns: overlap); f.Clock.Advance(TimeSpan.FromHours(2));
        var before = await f.Run.Counts(); var acquired = f.Run.Seal.Certificates.Calls; f.Run.Seal.Options.Pfx.Path = "unavailable";
        await using var db = fixture.Open(); var services = Services(f, db);
        var signers = await db.Signers.AsNoTracking().Where(x => x.EnvelopeId == f.Id).OrderBy(x => x.Order).ToArrayAsync();
        var recipient = await db.Recipients.AsNoTracking().SingleAsync(x => x.EnvelopeId == f.Id);
        var emails = new[] { f.Run.Signing.Envelope.SenderEmail }.Concat(signers.Select(x => x.Email)).Append(recipient.Email).Distinct().ToArray();
        foreach (var email in emails)
        {
            var lookup = await Login(services.Lookup, email); var principal = DocumentLookupProtection.Principal(lookup.Identity);
            f.Clock.Advance(TimeSpan.FromMinutes(20)); // Original lookup link has expired; its live session has not.
            var reader = (await services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId))!; Assert.NotNull(reader);
            var expected = email == f.Run.Signing.Envelope.SenderEmail ? PartyType.Sender : email == recipient.Email ? PartyType.Recipient : PartyType.Signer;
            Assert.Equal(expected, reader.Identity.Party);
            Assert.Equal(expected == PartyType.Sender ? null : expected == PartyType.Recipient ? recipient.Id : (Guid?)signers.Single(x => x.Email == email).Id, reader.Identity.PartyId);
            Assert.Equal(lookup.Identity.ExpiresAt, reader.Identity.ExpiresAt); Assert.Equal(email, reader.Identity.Email);
            var readonlyPrincipal = CompletionAccessProtection.Principal(reader.Identity);
            foreach (var kind in new[] { FinalDocumentKind.Executed, FinalDocumentKind.Certificate })
            {
                var file = (await services.Readers.ReadAsync(readonlyPrincipal, f.PublicId, reader.Receipt, kind))!;
                Assert.Equal(kind == FinalDocumentKind.Executed ? f.Published.ExecutedBytes : f.Published.CertificateBytes, file.Pdf);
            }
            Assert.Null(await services.Readers.AuthenticateAsync(principal, f.PublicId, reader.Receipt));
            Assert.Null(await services.Readers.AuthenticateAsync(readonlyPrincipal, Guid.NewGuid().ToString("N"), reader.Receipt));
            Assert.Null(SignerAccessConfiguration.ReadIdentity(readonlyPrincipal, f.Clock.GetUtcNow()));
            Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(readonlyPrincipal, new(f.Id, DocumentBlobKind.Normalized, Guid.NewGuid())));
            var token = await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == reader.Identity.TokenId);
            Assert.Equal(TokenPurpose.CompletionAccess, token.Purpose); Assert.NotNull(token.UsedAt); Assert.Equal(f.Published.PublicationId, token.CompletionPublicationId);
            var entry = await db.AuditEvents.AsNoTracking().SingleAsync(x => x.EnvelopeId == f.Id && x.Event == "completion_lookup_opened" && x.ActorEmail == email);
            Assert.Equal(expected, entry.ActorType); Assert.Equal(reader.Identity.PartyId, entry.ActorId);
            Assert.Contains("single_use_verified_mailbox_lookup", entry.DataJson); Assert.Contains("session_prepared_not_document_receipt", entry.DataJson);
            using var evidence = JsonDocument.Parse(entry.DataJson);
            Assert.Equal(lookup.Identity.TokenId, evidence.RootElement.GetProperty("lookupTokenId").GetGuid());
            Assert.Equal(reader.Identity.TokenId, evidence.RootElement.GetProperty("readerTokenId").GetGuid());
            Assert.Equal(f.Published.PublicationId, evidence.RootElement.GetProperty("publicationId").GetGuid());
            Assert.DoesNotContain(lookup.Receipt, entry.DataJson); Assert.DoesNotContain(reader.Receipt, entry.DataJson);
            f.Clock.Advance(TimeSpan.FromMinutes(11));
            Assert.Null(await services.Readers.AuthenticateAsync(readonlyPrincipal, f.PublicId, reader.Receipt));
            Assert.Null(await services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId));
        }
        var after = await f.Run.Counts(); Assert.Equal(before.Audit + emails.Length * 3, after.Audit);
        Assert.Equal(before.Work, after.Work); Assert.Equal(before.Mail, after.Mail); Assert.Equal(before.Sent, after.Sent);
        Assert.Equal(acquired, f.Run.Seal.Certificates.Calls); Assert.Equal(2, f.Run.Seal.Requests); Assert.Equal(2, f.Store.Writes);
        Assert.Equal(f.Published.CompletedAt, (await f.Run.Signing.Refresh()).CompletedAt);
    }

    [Fact]
    public async Task Wrong_mailbox_scope_proof_and_dirty_or_nested_calls_cannot_prepare_a_reader_or_read_storage()
    {
        await using var f = await Flow.Create(fixture); await using var db = fixture.Open(); var services = Services(f, db);
        var lookup = await Login(services.Lookup, f.Run.Signing.Envelope.SenderEmail); var principal = DocumentLookupProtection.Principal(lookup.Identity);
        var other = await Login(services.Lookup, "unrelated@example.invalid"); var reads = f.Store.Reads; var count = await FinalTokens(db, f.Id);
        Assert.Null(await services.Handoff.OpenAsync(DocumentLookupProtection.Principal(other.Identity), other.Receipt, f.PublicId));
        foreach (var id in new string?[] { null, "", "invalid", Guid.NewGuid().ToString("N"), f.PublicId.ToUpperInvariant(), lookup.Receipt })
            Assert.Null(await services.Handoff.OpenAsync(principal, lookup.Receipt, id!));
        foreach (var proof in new string?[] { null, "forged", lookup.Receipt + "x", other.Receipt })
            Assert.Null(await services.Handoff.OpenAsync(principal, proof, f.PublicId));
        foreach (var wrong in new[] { new ClaimsPrincipal(), f.Run.Signing.Sender, f.Run.Signing.LastSigner })
            Assert.Null(await services.Handoff.OpenAsync(wrong, lookup.Receipt, f.PublicId));
        var mixed = principal.Clone(); mixed.AddIdentity(new ClaimsIdentity([new("synthetic", "other")], "other"));
        Assert.Null(await services.Handoff.OpenAsync(mixed, lookup.Receipt, f.PublicId));
        Assert.Equal(reads, f.Store.Reads); Assert.Equal(count, await FinalTokens(db, f.Id));
        var envelope = await db.Envelopes.SingleAsync(x => x.Id == f.Id); envelope.Title = "Unsaved synthetic change";
        await Assert.ThrowsAsync<InvalidOperationException>(() => services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId)); db.ChangeTracker.Clear();
        await using var tx = await db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId));
    }

    [Fact]
    public async Task Storage_failures_and_lookup_revocation_or_expiry_during_IO_never_issue_authority_and_explicit_recovery_works()
    {
        await using var f = await Flow.Create(fixture); await using var db = fixture.Open(); var services = Services(f, db);
        foreach (var fault in new[] { "missing", "corrupt", "revoked", "expired" })
        {
            var lookup = await Login(services.Lookup, f.Run.Signing.Envelope.SenderEmail); var principal = DocumentLookupProtection.Principal(lookup.Identity);
            var count = await FinalTokens(db, f.Id); var before = await f.Run.Counts();
            if (fault is "missing" or "corrupt") f.Store.Fault = fault;
            else
            {
                var changed = false;
                f.Store.AfterRead = async () =>
                {
                    if (changed) return; changed = true;
                    if (fault == "expired") f.Clock.Advance(TimeSpan.FromMinutes(31));
                    else { await using var changedDb = fixture.Open(); await changedDb.AuthTokens.Where(x => x.Id == lookup.Identity.TokenId).ExecuteUpdateAsync(s => s.SetProperty(x => x.UsedAt, (DateTimeOffset?)null)); }
                };
            }
            if (fault == "missing") await Assert.ThrowsAsync<IOException>(() => services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId));
            else if (fault == "corrupt") await Assert.ThrowsAsync<InvalidDataException>(() => services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId));
            else { try { Assert.Null(await services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId)); } catch (IOException) when (fault == "expired") { } }
            Assert.Equal(count, await FinalTokens(db, f.Id)); Assert.Equal(before, await f.Run.Counts());
            f.Store.Fault = null; f.Store.AfterRead = null;
            if (fault is "revoked" or "expired") lookup = await Login(services.Lookup, f.Run.Signing.Envelope.SenderEmail);
            Assert.NotNull(await services.Handoff.OpenAsync(DocumentLookupProtection.Principal(lookup.Identity), lookup.Receipt, f.PublicId));
        }
        Assert.Equal(2, f.Store.Writes); Assert.Equal(2, f.Run.Seal.Requests);
    }

    [Theory]
    [InlineData("source")][InlineData("party")][InlineData("post-IO")]
    public async Task Altered_frozen_source_or_membership_cannot_create_a_final_reader(string fault)
    {
        await using var f = await Flow.Create(fixture); await using var db = fixture.Open(); var services = Services(f, db);
        var lookup = await Login(services.Lookup, f.Run.Signing.Envelope.SenderEmail);
        if (fault == "source") await db.Envelopes.Where(x => x.Id == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Title, "Changed synthetic title"));
        if (fault == "party") await db.Signers.Where(x => x.EnvelopeId == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.FullName, "Changed synthetic signer"));
        if (fault == "post-IO")
        {
            var changed = false; f.Store.AfterRead = async () => { if (changed) return; changed = true; await using var altered = fixture.Open();
                await altered.Recipients.Where(x => x.EnvelopeId == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Name, "Changed synthetic recipient")); };
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => services.Handoff.OpenAsync(DocumentLookupProtection.Principal(lookup.Identity), lookup.Receipt, f.PublicId));
        Assert.Equal(0, await FinalTokens(db, f.Id)); Assert.Equal(2, f.Store.Writes); Assert.Equal(2, f.Run.Seal.Requests);
    }

    [Fact]
    public async Task First_upload_retention_clips_handoff_and_no_lookup_or_reader_extends_the_saved_deadline()
    {
        await using var f = await Flow.Create(fixture, uploadRetentionDays: 7, afterUploadDelay: TimeSpan.FromDays(2));
        await using var db = fixture.Open(); var services = Services(f, db);
        var until = (await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x => x.EnvelopeId == f.Id)).DeleteAfter;
        f.Clock.Advance(until - f.Clock.GetUtcNow() - TimeSpan.FromMinutes(5));
        var lookup = await Login(services.Lookup, f.Run.Signing.Envelope.SenderEmail); Assert.True(lookup.Identity.ExpiresAt > until);
        var reader = (await services.Handoff.OpenAsync(DocumentLookupProtection.Principal(lookup.Identity), lookup.Receipt, f.PublicId))!;
        Assert.NotNull(reader); Assert.Equal(until, reader.Identity.ExpiresAt);
        f.Clock.Advance(TimeSpan.FromMinutes(5)); var count = await FinalTokens(db, f.Id);
        Assert.Null(await services.Handoff.OpenAsync(DocumentLookupProtection.Principal(lookup.Identity), lookup.Receipt, f.PublicId));
        Assert.Null(await services.Readers.AuthenticateAsync(CompletionAccessProtection.Principal(reader.Identity), f.PublicId, reader.Receipt));
        Assert.Equal(count, await FinalTokens(db, f.Id)); Assert.Equal(until, (await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x => x.EnvelopeId == f.Id)).DeleteAfter);
    }

    [Fact]
    public async Task Audit_rollback_uncertain_commit_lost_acknowledgement_and_cancellation_return_no_session_and_allow_explicit_fresh_retry()
    {
        await using var f = await Flow.Create(fixture); await using var baseline = fixture.Open(); var original = Services(f, baseline);
        var lookup = await Login(original.Lookup, f.Run.Signing.Envelope.SenderEmail); var principal = DocumentLookupProtection.Principal(lookup.Identity);
        foreach (var mode in new[] { "audit", "uncertain", "lost", "cancel", "expired-before-commit", "postcommit-source" })
        {
            using var cancellation = new CancellationTokenSource();
            var faults = new CompletionSealOutputTests.Faults { Event = "completion_lookup_opened", RejectAudit = mode == "audit", RejectCommit = mode == "uncertain",
                LoseCommit = mode == "lost", CancelAfterCommit = mode == "cancel" ? cancellation : null,
                BeforeAudit = mode == "expired-before-commit" ? () => f.Clock.Advance(TimeSpan.FromMinutes(31)) : null };
            var options = new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(faults);
            if (mode == "postcommit-source") options.AddInterceptors(new AfterHandoffCommit(async () => { await using var changed = fixture.Open();
                await changed.Envelopes.Where(x => x.Id == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Title, "Changed immediately after synthetic commit")); }));
            await using var db = new QuillSignDbContext(options.Options);
            var services = Services(f, db); var before = await FinalTokens(baseline, f.Id); var audit = await f.Run.Counts();
            if (mode == "audit") await Assert.ThrowsAsync<DbUpdateException>(() => services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId));
            else if (mode == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(() => services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId, cancellation.Token));
            else if (mode is "expired-before-commit" or "postcommit-source") await Assert.ThrowsAsync<InvalidDataException>(() => services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId));
            else await Assert.ThrowsAsync<IOException>(() => services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId));
            Assert.False(db.ChangeTracker.HasChanges()); faults.RejectAudit = false; faults.Event = ""; faults.BeforeAudit = null;
            var committed = mode is "lost" or "cancel" or "postcommit-source";
            Assert.Equal(before + (committed ? 1 : 0), await FinalTokens(baseline, f.Id));
            Assert.Equal(audit.Audit + (committed ? 3 : 0), (await f.Run.Counts()).Audit);
            if (mode == "postcommit-source") continue;
            if (mode == "expired-before-commit") { lookup = await Login(services.Lookup, f.Run.Signing.Envelope.SenderEmail); principal = DocumentLookupProtection.Principal(lookup.Identity); }
            var fresh = (await services.Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId))!; Assert.NotNull(fresh);
            Assert.Equal(lookup.Identity.ExpiresAt, fresh.Identity.ExpiresAt);
            Assert.Equal(f.Published.CertificateBytes, (await services.Readers.ReadAsync(CompletionAccessProtection.Principal(fresh.Identity), f.PublicId, fresh.Receipt, FinalDocumentKind.Certificate))!.Pdf);
        }
        Assert.Equal(2, f.Store.Writes); Assert.Equal(2, f.Run.Seal.Requests);
    }

    [Fact]
    public async Task Concurrent_explicit_handoffs_create_distinct_narrow_readers_without_reconsuming_or_refreshing_the_lookup()
    {
        await using var f = await Flow.Create(fixture); DocumentLookupSession lookup;
        await using (var db = fixture.Open()) lookup = await Login(Services(f, db).Lookup, f.Run.Signing.Envelope.SenderEmail);
        var principal = DocumentLookupProtection.Principal(lookup.Identity);
        async Task<CompletionReaderSession?> Open() { await using var db = fixture.Open(); return await Services(f, db).Handoff.OpenAsync(principal, lookup.Receipt, f.PublicId); }
        var readers = await Task.WhenAll(Open(), Open()); Assert.All(readers, Assert.NotNull);
        Assert.Equal(2, readers.Select(x => x!.Identity.TokenId).Distinct().Count()); Assert.Equal(2, readers.Select(x => x!.Identity.SessionId).Distinct().Count());
        Assert.All(readers, x => Assert.Equal(lookup.Identity.ExpiresAt, x!.Identity.ExpiresAt));
        await using var verify = fixture.Open(); var services = Services(f, verify);
        Assert.NotNull(await services.Lookup.AuthenticateAsync(principal, lookup.Receipt));
        Assert.Equal(2, await FinalTokens(verify, f.Id)); Assert.Equal(2, await verify.AuditEvents.CountAsync(x => x.EnvelopeId == f.Id && x.Event == "completion_lookup_opened"));
        var token = await verify.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == lookup.Identity.TokenId);
        Assert.Equal(lookup.Identity.TokenRevision, Convert.ToBase64String(token.RowVersion)); Assert.Equal(lookup.Identity.RedeemedAt, token.UsedAt);
    }

    private static Task<int> FinalTokens(QuillSignDbContext db, Guid id) => db.AuthTokens.CountAsync(x => x.EnvelopeId == id && x.Purpose == TokenPurpose.CompletionAccess);
    private static async Task<DocumentLookupSession> Login(DocumentLookup lookup, string email) => (await lookup.RedeemAsync((await lookup.IssueAsync(email)).Transport))!;
    private sealed record Backend(DocumentLookup Lookup, LookupPacketAccess Handoff, CompletionAccess Readers);
    private static Backend Services(Flow f, QuillSignDbContext db)
    {
        var state = new CompletionAccessState(db, f.Run.Collector(db), () => f.Publication(db), f.Clock);
        var lookup = new DocumentLookup(db, state, new(f.Run.Signing.H.App.Services.GetRequiredService<IDataProtectionProvider>(), f.Clock), new(), f.Clock);
        var readers = CompletionAccessTests.Service(f, db);
        return new(lookup, new(db, lookup, readers, state, new(db, f.Clock), f.Clock), readers);
    }
    private sealed class AfterHandoffCommit(Func<Task> change) : DbTransactionInterceptor, ISaveChangesInterceptor
    {
        private bool armed;
        public ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData e, InterceptionResult<int> result, CancellationToken ct = default)
        {
            if (e.Context!.ChangeTracker.Entries<AuditEvent>().Any(x => x.State == EntityState.Added && x.Entity.Event == "completion_lookup_opened")) armed = true;
            return ValueTask.FromResult(result);
        }
        public override async Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData e, CancellationToken ct = default)
        { if (armed) { armed = false; await change(); } }
    }
}
