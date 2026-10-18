using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Signing;
using QuillSign.Storage;
using Flow = QuillSign.Tests.CompletionDownloadTests.Flow;

namespace QuillSign.Tests;

public sealed class DocumentLookupTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Every_frozen_party_can_list_only_its_retained_packet_after_signing_expiry_without_extra_mailbox_storage_or_authority()
    {
        await using var f = await Flow.Create(fixture, senderAlsoSigns: true);
        f.Clock.Advance(TimeSpan.FromHours(2)); var before = await f.Run.Counts();
        await using var db = fixture.Open();
        var emails = new[] { f.Run.Signing.Envelope.SenderEmail }
            .Concat(await db.Signers.Where(x => x.EnvelopeId == f.Id).Select(x => x.Email).ToArrayAsync())
            .Concat(await db.Recipients.Where(x => x.EnvelopeId == f.Id).Select(x => x.Email).ToArrayAsync()).Distinct().ToArray();
        Assert.Equal(3, emails.Length);
        foreach (var email in emails)
        {
            var service = Service(f, db); var link = await service.IssueAsync(email.ToUpperInvariant());
            var token = await db.AuthTokens.AsNoTracking().SingleAsync(x => x.Id == link.TokenId);
            Assert.Equal(TokenPurpose.Lookup, token.Purpose); Assert.Equal("", token.Email);
            Assert.Null(token.EnvelopeId); Assert.Null(token.PartyId); Assert.Equal(PartyType.System, token.PartyType);
            Assert.DoesNotContain(email, JsonSerializer.Serialize(token)); Assert.DoesNotContain(link.Transport, JsonSerializer.Serialize(token));
            var session = (await service.RedeemAsync(link.Transport))!; Assert.NotNull(session);
            Assert.Equal(email, session.Identity.Email); var principal = DocumentLookupProtection.Principal(session.Identity);
            var page = (await service.ListAsync(principal, session.Receipt))!;
            var entry = Assert.Single(page.Entries); Assert.Equal(f.PublicId, entry.PublicId); Assert.Equal(f.Run.Signing.Envelope.Title, entry.Title);
            Assert.Equal(f.Published.CompletedAt, entry.CompletedAt); Assert.Null(page.NextCursor);
            Assert.Null(await service.RedeemAsync(link.Transport)); Assert.Null(SignerAccessConfiguration.ReadIdentity(principal, f.Clock.GetUtcNow()));
            Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(principal, new(f.Id, DocumentBlobKind.Normalized, Guid.NewGuid())));
            Assert.Null(await CompletionAccessTests.Service(f, db).AuthenticateAsync(principal, f.PublicId, session.Receipt));
        }
        var unknown = Service(f, db); var unknownLink = await unknown.IssueAsync("unknown@example.invalid");
        var unknownSession = (await unknown.RedeemAsync(unknownLink.Transport))!;
        var reads = f.Store.Reads; Assert.Empty((await unknown.ListAsync(DocumentLookupProtection.Principal(unknownSession.Identity), unknownSession.Receipt))!.Entries);
        Assert.Equal(reads, f.Store.Reads); Assert.Equal(before, await f.Run.Counts()); Assert.Equal(2, f.Run.Seal.Requests); Assert.Equal(2, f.Store.Writes);
    }

    [Fact]
    public async Task Genuine_multiple_publications_page_once_with_private_session_bound_cursors_and_no_writes()
    {
        var mailbox = "lookup-" + Guid.NewGuid().ToString("N") + "@example.invalid";
        await using var first = await Flow.Create(fixture, mailbox: mailbox);
        await using var second = await Flow.Create(fixture, mailbox: mailbox);
        first.Clock.Advance(new[] { first.Clock.GetUtcNow(), second.Clock.GetUtcNow() }.Max() - first.Clock.GetUtcNow());
        first.Run.Seal.Options.TsaTrustedRootPaths = [.. first.Run.Seal.Options.TsaTrustedRootPaths, .. second.Run.Seal.Options.TsaTrustedRootPaths];
        var store = new ReadOnlyPair(first, second);
        await using var db = fixture.Open(); var service = Service(first, db, new() { PageSize = 1 }, store);
        var link = await service.IssueAsync(mailbox); var session = (await service.RedeemAsync(link.Transport))!;
        var principal = DocumentLookupProtection.Principal(session.Identity);
        var page = (await service.ListAsync(principal, session.Receipt))!;
        Assert.Single(page.Entries); Assert.NotNull(page.NextCursor);
        Assert.DoesNotContain(mailbox, page.NextCursor); Assert.DoesNotContain(page.Entries[0].PublicId, page.NextCursor);
        var next = (await service.ListAsync(principal, session.Receipt, page.NextCursor))!;
        Assert.Single(next.Entries); Assert.Null(next.NextCursor);
        Assert.Equal(new[] { first.PublicId, second.PublicId }.Order(), page.Entries.Concat(next.Entries).Select(x => x.PublicId).Order());
        var replay = (await service.ListAsync(principal, session.Receipt, page.NextCursor))!;
        Assert.Equal(next.Entries, replay.Entries);
        var anotherLink = await service.IssueAsync(mailbox); var another = (await service.RedeemAsync(anotherLink.Transport))!;
        Assert.Null(await service.ListAsync(DocumentLookupProtection.Principal(another.Identity), another.Receipt, page.NextCursor));
        Assert.Null(await service.ListAsync(principal, session.Receipt, page.NextCursor + "x"));
        Assert.Null(await service.ListAsync(principal, session.Receipt, ""));
        Assert.Equal(2, first.Store.Writes); Assert.Equal(2, second.Store.Writes);
    }

    [Fact]
    public async Task Unpublished_envelopes_are_absent_and_later_completion_requires_a_fresh_lookup_snapshot()
    {
        await using var f = await Flow.Create(fixture, publish: false); await using var db = fixture.Open(); var service = Service(f, db);
        var session = (await service.RedeemAsync((await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail)).Transport))!;
        var principal = DocumentLookupProtection.Principal(session.Identity);
        Assert.Empty((await service.ListAsync(principal, session.Receipt))!.Entries); Assert.Equal(0, f.Store.Reads);
        f.Clock.Advance(TimeSpan.FromSeconds(1)); f.Published = (await f.Publication(db).PublishAsync(f.Id))!;
        Assert.Empty((await service.ListAsync(principal, session.Receipt))!.Entries);
        var fresh = (await service.RedeemAsync((await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail)).Transport))!;
        Assert.Single((await service.ListAsync(DocumentLookupProtection.Principal(fresh.Identity), fresh.Receipt))!.Entries);
    }

    [Fact]
    public async Task Redemption_is_atomic_once_only_and_rejects_forged_cross_purpose_and_plain_legacy_tokens_before_document_reads()
    {
        await using var f = await Flow.Create(fixture); var email = f.Run.Signing.Envelope.SenderEmail;
        DocumentLookupLink link; await using (var db = fixture.Open()) link = await Service(f, db).IssueAsync(email);
        async Task<DocumentLookupSession?> Redeem() { await using var db = fixture.Open(); return await Service(f, db).RedeemAsync(link.Transport); }
        var sessions = await Task.WhenAll(Redeem(), Redeem()); var session = Assert.Single(sessions, x => x is not null)!;
        await using var verify = fixture.Open(); var service = Service(f, verify); var principal = DocumentLookupProtection.Principal(session.Identity);
        var reads = f.Store.Reads;
        foreach (var bad in new string?[] { null, "forged", link.Transport + "x", new string('x', 4000) })
            Assert.Null(await service.RedeemAsync(bad));
        var finalLink = (await CompletionAccessTests.Service(f, verify).IssueAsync(f.Id, PartyType.Sender, null))!;
        Assert.Null(await service.RedeemAsync(finalLink.RawToken));
        var raw = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        verify.AuthTokens.Add(new() { Purpose = TokenPurpose.Lookup, Email = email, TokenSha256 = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(raw)), ExpiresAt = f.Clock.GetUtcNow().AddMinutes(15) });
        await verify.SaveChangesAsync(); reads = f.Store.Reads;
        Assert.Null(await service.RedeemAsync(raw));
        Assert.Null(await service.ListAsync(f.Run.Signing.Sender, session.Receipt));
        Assert.Null(await service.ListAsync(f.Run.Signing.LastSigner, session.Receipt));
        foreach (var bad in new string?[] { null, "forged", session.Receipt + "x", finalLink.RawToken })
            Assert.Null(await service.ListAsync(principal, bad));
        var mixed = principal.Clone(); mixed.AddIdentity(new ClaimsIdentity([new("synthetic", "other")], "other"));
        Assert.Null(await service.ListAsync(mixed, session.Receipt));
        var changed = DocumentLookupProtection.Principal(session.Identity with { Email = "other@example.invalid" });
        Assert.Null(await service.ListAsync(changed, session.Receipt)); Assert.Equal(reads, f.Store.Reads);
    }

    [Fact]
    public async Task Altered_persisted_issuance_or_consumption_cannot_authenticate()
    {
        await using var f = await Flow.Create(fixture); await using var db = fixture.Open(); var service = Service(f, db);
        foreach (var fault in new[] { "purpose", "email", "expiry", "used", "hash", "revision" })
        {
            var link = await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail); var session = (await service.RedeemAsync(link.Transport))!;
            var q = db.AuthTokens.Where(x => x.Id == link.TokenId);
            if (fault == "purpose") await q.ExecuteUpdateAsync(s => s.SetProperty(x => x.Purpose, TokenPurpose.SenderVerify).SetProperty(x => x.EnvelopeId, (Guid?)f.Id));
            if (fault == "email") await q.ExecuteUpdateAsync(s => s.SetProperty(x => x.Email, "other@example.invalid"));
            if (fault == "expiry") await q.ExecuteUpdateAsync(s => s.SetProperty(x => x.ExpiresAt, x => x.ExpiresAt.AddMinutes(1)));
            if (fault == "used") await q.ExecuteUpdateAsync(s => s.SetProperty(x => x.UsedAt, (DateTimeOffset?)null));
            if (fault == "hash") await q.ExecuteUpdateAsync(s => s.SetProperty(x => x.TokenSha256, RandomNumberGenerator.GetBytes(32)));
            if (fault == "revision") await q.ExecuteUpdateAsync(s => s.SetProperty(x => x.UsedAt, x => x.UsedAt));
            Assert.Null(await service.AuthenticateAsync(DocumentLookupProtection.Principal(session.Identity), session.Receipt));
            Assert.Null(await service.RedeemAsync(link.Transport));
        }
    }

    [Fact]
    public async Task Session_has_its_original_independent_expiry_and_expired_links_never_redeem()
    {
        await using var f = await Flow.Create(fixture); await using var db = fixture.Open(); var service = Service(f, db, new() { LinkMinutes = 1, SessionMinutes = 3 });
        var link = await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail); var unused = await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail);
        var session = (await service.RedeemAsync(link.Transport))!; var principal = DocumentLookupProtection.Principal(session.Identity);
        f.Clock.Advance(TimeSpan.FromMinutes(2)); Assert.Null(await service.RedeemAsync(unused.Transport));
        Assert.Single((await service.ListAsync(principal, session.Receipt))!.Entries);
        f.Clock.Advance(TimeSpan.FromMinutes(1)); Assert.Null(await service.ListAsync(principal, session.Receipt));
    }

    [Theory]
    [InlineData("missing")][InlineData("corrupt")][InlineData("source")][InlineData("membership")][InlineData("post-IO-source")][InlineData("expiry-during-read")][InlineData("token-during-read")]
    public async Task Storage_source_membership_and_session_changes_never_return_stale_entries_and_storage_retry_recovers(string fault)
    {
        await using var f = await Flow.Create(fixture); await using var db = fixture.Open(); var service = Service(f, db);
        var link = await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail); var session = (await service.RedeemAsync(link.Transport))!;
        var principal = DocumentLookupProtection.Principal(session.Identity);
        if (fault is "missing" or "corrupt") f.Store.Fault = fault;
        if (fault == "source") await db.Envelopes.Where(x => x.Id == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Title, "Altered synthetic title"));
        if (fault == "membership") await db.Signers.Where(x => x.EnvelopeId == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.FullName, "Altered synthetic signer"));
        if (fault is "post-IO-source" or "expiry-during-read" or "token-during-read")
        {
            var changed = false;
            f.Store.AfterRead = async () =>
            {
                if (changed) return; changed = true;
                if (fault == "expiry-during-read") f.Clock.Advance(TimeSpan.FromMinutes(31));
                else { await using var changedDb = fixture.Open();
                    if (fault == "post-IO-source") await changedDb.Recipients.Where(x => x.EnvelopeId == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Name, "Changed synthetic recipient"));
                    else await changedDb.AuthTokens.Where(x => x.Id == link.TokenId).ExecuteUpdateAsync(s => s.SetProperty(x => x.UsedAt, (DateTimeOffset?)null)); }
            };
        }
        if (fault == "missing") await Assert.ThrowsAsync<IOException>(() => service.ListAsync(principal, session.Receipt));
        else if (fault is "source" or "membership" or "post-IO-source" or "corrupt") await Assert.ThrowsAsync<InvalidDataException>(() => service.ListAsync(principal, session.Receipt));
        else { try { Assert.Null(await service.ListAsync(principal, session.Receipt)); } catch (IOException) when (fault == "expiry-during-read") { } }
        if (fault is "missing" or "corrupt") { f.Store.Fault = null; Assert.Single((await service.ListAsync(principal, session.Receipt))!.Entries); }
        Assert.Equal(2, f.Store.Writes); Assert.Equal(2, f.Run.Seal.Requests);
    }

    [Fact]
    public async Task Saved_first_upload_deadline_is_reported_and_excludes_expired_completed_documents()
    {
        await using var f = await Flow.Create(fixture, uploadRetentionDays: 7, afterUploadDelay: TimeSpan.FromDays(2));
        await using var db = fixture.Open(); var service = Service(f, db);
        var deadline = (await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x => x.EnvelopeId == f.Id)).DeleteAfter;
        var session = (await service.RedeemAsync((await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail)).Transport))!;
        Assert.Equal(deadline, Assert.Single((await service.ListAsync(DocumentLookupProtection.Principal(session.Identity), session.Receipt))!.Entries).RetainedUntil);
        f.Clock.Advance(deadline - f.Clock.GetUtcNow());
        var fresh = (await service.RedeemAsync((await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail)).Transport))!;
        var reads = f.Store.Reads; Assert.Empty((await service.ListAsync(DocumentLookupProtection.Principal(fresh.Identity), fresh.Receipt))!.Entries); Assert.Equal(reads, f.Store.Reads);
    }

    [Fact]
    public async Task Failed_or_unknown_commit_returns_no_transport_or_session_and_explicit_fresh_issue_recovers()
    {
        await using var f = await Flow.Create(fixture); await using var baseline = fixture.Open();
        foreach (var (redeem, lost) in new[] { (false, false), (true, false), (false, true), (true, true) })
        {
            var original = redeem ? await Service(f, baseline).IssueAsync(f.Run.Signing.Envelope.SenderEmail) : null;
            var faults = new CommitFault { Lost = lost };
            await using var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>().UseSqlServer(baseline.Database.GetConnectionString()).AddInterceptors(faults).Options);
            var service = Service(f, db);
            await Assert.ThrowsAsync<IOException>(async () => { if (redeem) _ = await service.RedeemAsync(original!.Transport); else _ = await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail); });
            Assert.False(db.ChangeTracker.HasChanges());
            if (redeem && lost) Assert.Null(await service.RedeemAsync(original!.Transport));
            if (redeem && !lost) Assert.NotNull(await service.RedeemAsync(original!.Transport));
            var fresh = await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail); Assert.NotNull(await service.RedeemAsync(fresh.Transport));
        }
    }

    [Fact]
    public async Task Lookup_bindings_cannot_be_rewritten_through_EF_and_cancelled_or_dirty_operations_do_not_issue()
    {
        await using var f = await Flow.Create(fixture); await using var db = fixture.Open(); var service = Service(f, db);
        var link = await service.IssueAsync(f.Run.Signing.Envelope.SenderEmail);
        var record = await db.AuthTokens.SingleAsync(x => x.Id == link.TokenId); record.Email = "other@example.invalid";
        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(f.Run.Signing.Envelope.SenderEmail)); db.ChangeTracker.Clear();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.IssueAsync(f.Run.Signing.Envelope.SenderEmail, new(true)));
        await Assert.ThrowsAsync<ArgumentException>(() => service.IssueAsync("invalid"));
        await using var tx = await db.Database.BeginTransactionAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(() => service.IssueAsync(f.Run.Signing.Envelope.SenderEmail));
    }

    [Theory]
    [InlineData(0, 30, 5)][InlineData(61, 30, 5)][InlineData(15, 0, 5)][InlineData(15, 61, 5)][InlineData(15, 30, 0)][InlineData(15, 30, 11)]
    public void Invalid_or_unbounded_options_fail_configuration(int link, int session, int page)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["DocumentLookup:LinkMinutes"] = link.ToString(), ["DocumentLookup:SessionMinutes"] = session.ToString(), ["DocumentLookup:PageSize"] = page.ToString() }).Build();
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddDocumentLookup(config));
    }

    private static DocumentLookup Service(Flow f, QuillSignDbContext db, DocumentLookupOptions? options = null, ICompletionFinalStore? store = null)
    {
        Func<CompletionPublication> publication = () => new(db, f.Run.Candidates(db), f.Run.Service(db), f.Run.Collector(db), store ?? f.Store,
            new(db, f.Clock), f.Clock, new() { DemoPurgeAfterDays = 7, AllowDevelopmentWriteOnce = true }, f.Run.Seal.App.Environment);
        return new(db, new(db, f.Run.Collector(db), publication, f.Clock), new(f.Run.Signing.H.App.Services.GetRequiredService<IDataProtectionProvider>(), f.Clock), options ?? new(), f.Clock);
    }
    private sealed class ReadOnlyPair(Flow first, Flow second) : ICompletionFinalStore
    {
        public Task ReadAsync(ClaimsPrincipal p, FinalStoredDocument stored, Stream destination, CancellationToken ct = default) =>
            (stored.Document.EnvelopeId == first.Id ? first.Store : stored.Document.EnvelopeId == second.Id ? second.Store : throw new InvalidOperationException()).ReadAsync(p, stored, destination, ct);
        public Task<FinalStoredDocument> WriteAsync(ClaimsPrincipal p, FinalDocument target, Stream source, long length, byte[] hash, DateTimeOffset? until, CancellationToken ct = default) =>
            throw new InvalidOperationException("Lookup must not write final files.");
    }
    private sealed class CommitFault : DbTransactionInterceptor
    {
        public bool Lost; private bool armed = true;
        public override ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData e, InterceptionResult result, CancellationToken ct = default)
        { if (armed && !Lost) { armed = false; throw new IOException("Synthetic rejected lookup commit."); } return ValueTask.FromResult(result); }
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData e, CancellationToken ct = default)
        { if (armed && Lost) { armed = false; throw new IOException("Synthetic lost lookup commit acknowledgement."); } return Task.CompletedTask; }
    }
}
