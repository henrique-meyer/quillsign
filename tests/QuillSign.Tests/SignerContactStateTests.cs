using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Signing;

namespace QuillSign.Tests;

public sealed class SignerContactStateTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Verified_history_resolves_retired_parties_and_address_cycles_without_restoring_old_sessions()
    {
        var f = await Run.Create(fixture); var original = f.Email;
        var legacy = f.Identity(); var legacyBytes = JsonSerializer.SerializeToUtf8Bytes(legacy); var oldToken = await f.SeedUnusedToken(legacy);
        Assert.True(await f.Session(legacy));
        var first = await f.Correct(Address("corrected")); var corrected = f.Identity();
        Assert.False(await f.Session(legacy)); Assert.False(await f.Session(corrected));
        await f.Bind(corrected); Assert.True(await f.Session(corrected));
        var second = await f.Correct(original); var final = f.Identity();
        Assert.False(await f.Session(legacy)); Assert.False(await f.Session(corrected)); Assert.False(await f.Session(final));
        await f.Bind(final); Assert.True(await f.Session(final));
        await f.AssertDelayedLegacyTokenRejected(final, oldToken);
        Assert.Equal(legacyBytes, JsonSerializer.SerializeToUtf8Bytes(legacy));
        await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
        var history = await new SignerContactState(db, f.Time).ReadHistoryLockedAsync(await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == f.Id));
        Assert.Equal(original, history.Resolve(f.SignerId, SignerContactEpoch.Legacy)!.Email);
        Assert.Equal(Address("corrected"), history.Resolve(f.SignerId, new(first.Id, 1))!.Email);
        Assert.Equal(original, history.Resolve(f.SignerId, new(second.Id, 2))!.Email);
        Assert.Null(history.Resolve(f.SignerId, new(first.Id, 2)));
        Assert.Equal(first, history.Revision(first.Id)); Assert.Equal(second, history.Revision(second.Id)); Assert.Null(history.Revision(Guid.NewGuid()));
        Assert.Equal(second.Id, Assert.Single(history.Current).Epoch.RevisionId);
        Assert.Equal(2, await db.SignerContactSessions.CountAsync(x => x.EnvelopeId == f.Id));
    }

    [Theory]
    [InlineData("missing-revision")]
    [InlineData("missing-audit")]
    [InlineData("retirement")]
    [InlineData("retired-definition")]
    [InlineData("projection")]
    [InlineData("current-definition")]
    [InlineData("evidence-index")]
    [InlineData("audit-chain")]
    [InlineData("old-roster")]
    public async Task Corrupt_or_missing_persisted_evidence_fails_closed(string fault)
    {
        var f = await Run.Create(fixture); var revision = await f.Correct(Address("corrected"));
        await using (var db = fixture.Open())
        {
            if (fault == "missing-revision") await db.SignerContactRevisions.Where(x => x.Id == revision.Id).ExecuteDeleteAsync();
            if (fault == "missing-audit") await db.AuditEvents.Where(x => x.EnvelopeId == f.Id && x.Event == SignerContactHistory.Event).ExecuteDeleteAsync();
            if (fault == "retirement") await db.SignerContactRevisions.Where(x => x.Id == revision.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.RetirementJson, "{}"));
            if (fault == "retired-definition")
            {
                var row = await db.SignerContactRevisions.AsNoTracking().SingleAsync(x => x.Id == revision.Id);
                var snapshot = JsonSerializer.Deserialize<RetiredSignerEntries>(row.RetirementJson)!; snapshot.Fields[0].Width = .9m;
                var json = SignerContactState.RetirementJson(snapshot.Signer, snapshot.Fields);
                await db.SignerContactRevisions.Where(x => x.Id == revision.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.RetirementJson, json));
            }
            if (fault == "projection") await db.Signers.Where(x => x.Id == f.SignerId).ExecuteUpdateAsync(s => s.SetProperty(x => x.FullName, "Different person"));
            if (fault == "current-definition") await db.Fields.Where(x => x.EnvelopeId == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Width, .9m));
            if (fault == "evidence-index") await db.SignerContactRevisions.Where(x => x.Id == revision.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.EvidenceJson, "{}"));
            if (fault == "audit-chain") await db.AuditEvents.Where(x => x.EnvelopeId == f.Id && x.Event == SignerContactHistory.Event).ExecuteUpdateAsync(s => s.SetProperty(x => x.PrevHash, new byte[32]));
            if (fault == "old-roster") await db.AuditEvents.Where(x => x.EnvelopeId == f.Id && x.Event == "signer_added").ExecuteUpdateAsync(s => s.SetProperty(x => x.DataJson, "{}"));
        }
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Session(f.Identity()));
    }

    [Fact]
    public async Task Session_binding_requires_consumed_exact_scope_token_and_preserves_immutable_rows()
    {
        var f = await Run.Create(fixture); await f.Correct(Address("corrected")); var session = f.Identity();
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Bind(session, used: false));
        await Assert.ThrowsAsync<InvalidDataException>(() => f.Bind(session, wrongScope: true));
        await f.Bind(session); Assert.True(await f.Session(session));
        Assert.False(await f.Session(session with { SessionId = Guid.NewGuid() }));
        Assert.False(await f.Session(session with { DocumentHash = new string('f', 64) }));
        Assert.False(await f.Session(session with { SessionExpiresAt = session.SessionExpiresAt.AddSeconds(1) }));
        await using var db = fixture.Open(); var row = await db.SignerContactSessions.SingleAsync(x => x.SessionId == session.SessionId);
        row.ExpiresAt = row.ExpiresAt.AddSeconds(1); await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
        db.ChangeTracker.Clear(); var revision = await db.SignerContactRevisions.SingleAsync(x => x.EnvelopeId == f.Id);
        db.Remove(revision); await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task Runtime_can_read_insert_and_cannot_rewrite_or_delete_revision_and_session_evidence()
    {
        var f = await Run.Create(fixture); var revision = await f.Correct(Address("corrected")); var session = f.Identity(); await f.Bind(session);
        await using var db = fixture.Open(); await db.Database.OpenConnectionAsync();
        await db.Database.ExecuteSqlRawAsync("IF DATABASE_PRINCIPAL_ID('app_runtime') IS NULL CREATE USER app_runtime WITHOUT LOGIN");
        await DatabasePermissions.GrantRuntimeAsync((SqlConnection)db.Database.GetDbConnection());
        await db.Database.ExecuteSqlRawAsync("EXECUTE AS USER='app_runtime'");
        try
        {
            Assert.True(await db.SignerContactRevisions.AnyAsync(x => x.Id == revision.Id));
            Assert.True(await db.SignerContactSessions.AnyAsync(x => x.SessionId == session.SessionId));
            var inserted = new SignerContactSession { SessionId = Guid.NewGuid(), EnvelopeId = f.Id, SignerId = f.SignerId, RevisionId = revision.Id,
                SessionSha256 = new byte[32], CreatedAt = f.Time.Now, ExpiresAt = f.Time.Now.AddHours(1) };
            db.SignerContactSessions.Add(inserted); await db.SaveChangesAsync();
            Assert.True(await db.SignerContactSessions.AnyAsync(x => x.SessionId == inserted.SessionId));
            foreach (var command in new[] { "UPDATE dbo.SignerContactRevisions SET Number=1 WHERE 1=0", "DELETE FROM dbo.SignerContactRevisions WHERE 1=0",
                         "UPDATE dbo.SignerContactSessions SET ExpiresAt=CreatedAt WHERE 1=0", "DELETE FROM dbo.SignerContactSessions WHERE 1=0",
                         "UPDATE dbo.AuthTokens SET SignerContactRevisionId=NULL WHERE 1=0" })
                Assert.Equal(command.Contains("dbo.AuthTokens", StringComparison.Ordinal) ? 230 : 229,
                    (await Assert.ThrowsAsync<SqlException>(() => db.Database.ExecuteSqlRawAsync(command))).Number);
        }
        finally { await db.Database.ExecuteSqlRawAsync("REVERT"); }
    }

    [Fact]
    public async Task All_history_operations_require_a_transaction_and_stale_envelope_versions_are_rejected()
    {
        var f = await Run.Create(fixture); await using var db = fixture.Open(); var state = new SignerContactState(db, f.Time);
        var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == f.Id);
        await Assert.ThrowsAsync<InvalidOperationException>(() => state.ReadLockedAsync(envelope));
        await db.Envelopes.Where(x => x.Id == f.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.Message, "changed"));
        await using var tx = await db.Database.BeginTransactionAsync(); await Assert.ThrowsAsync<InvalidDataException>(() => state.ReadLockedAsync(envelope));
    }

    private static string Address(string value) => value + "@" + "example.invalid";
    private sealed class Clock : TimeProvider
    { public DateTimeOffset Now = new(2026, 1, 1, 1, 0, 0, TimeSpan.Zero); public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class Run(SqlDatabaseFixture fixture)
    {
        internal readonly Clock Time = new(); internal Guid Id, SignerId; internal string Email = ""; private Guid? previous;
        internal static async Task<Run> Create(SqlDatabaseFixture fixture)
        {
            var f = new Run(fixture); await using var db = fixture.Open();
            var envelope = new Envelope { Status = EnvelopeStatus.Sent, SenderEmail = Address("sender"), SenderVerifiedAt = f.Time.Now, SentAt = f.Time.Now,
                SentPdfBlob = Guid.NewGuid().ToString("N"), SentPdfSha256 = new byte[32], ErsdSha256 = new byte[32] };
            envelope.PublicId = envelope.Id.ToString("N");
            var signer = new Signer { EnvelopeId = envelope.Id, FullName = "Synthetic same signer", Email = Address("original"), Order = 1 };
            db.AddRange(envelope, signer, new DocumentField { EnvelopeId = envelope.Id, SignerId = signer.Id, Type = FieldType.Text, Page = 1,
                X = .1m, Y = .1m, Width = .2m, Height = .1m, Value = "Retired synthetic entry", FilledBy = PartyType.Signer, FilledAt = f.Time.Now });
            await db.SaveChangesAsync(); f.Id = envelope.Id; f.SignerId = signer.Id; f.Email = signer.Email;
            await using var tx = await db.Database.BeginTransactionAsync(); var audit = new AuditWriter(db, f.Time);
            await audit.AppendAsync(f.Id, "signer_added", envelope.SenderEmail, null, null, default,
                JsonSerializer.Serialize(new { signers = new[] { new { signer.Id, signer.Order, signer.FullName, signer.Email, signer.Role } } }));
            await audit.AppendAsync(f.Id, "sent", envelope.SenderEmail, null, null, default); await tx.CommitAsync();
            return f;
        }
        internal VerifiedSigner Identity() => new(Id, Id.ToString("N"), SignerId, Email, Id, new string('0', 64), new string('0', 64), Time.Now.AddHours(1));
        internal async Task<SignerContactRevision> Correct(string email)
        {
            Time.Now = Time.Now.AddMinutes(1); await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == Id);
            var signer = await db.Signers.SingleAsync(x => x.Id == SignerId);
            var fields = await db.Fields.Where(x => x.EnvelopeId == Id).ToArrayAsync(); var snapshot = SignerContactState.RetirementJson(signer, fields);
            var before = previous is null ? null : await db.SignerContactRevisions.SingleAsync(x => x.Id == previous);
            var last = before is null ? null : JsonSerializer.Deserialize<SignerContactRevision>(before.EvidenceJson, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            var revision = new SignerContactRevision(SignerContactHistory.Version, Guid.NewGuid(), Id, SignerId, previous ?? Guid.Empty, (last?.Number ?? 0) + 1,
                signer.Email, email, Time.Now, Time.Now.AddHours(1), Convert.ToBase64String(envelope.RowVersion), Convert.ToBase64String(signer.RowVersion), Id,
                new string('0', 64), new string('0', 64), SignerContactState.RetirementDigest(snapshot), last is null ? null : SignerContactHistory.Digest(last),
                SignerContactHistory.StatementVersion, SignerContactHistory.StatementSha256);
            db.SignerContactRevisions.Add(new() { Id = revision.Id, EnvelopeId = Id, SignerId = SignerId, Number = revision.Number, PreviousRevisionId = previous,
                ChangedAt = Time.Now, EvidenceJson = SignerContactHistory.Canonical(revision), RetirementJson = snapshot });
            signer.Email = email; foreach (var field in fields) { field.Value = null; field.FilledAt = null; field.FilledBy = null; }
            await db.SaveChangesAsync(); await new AuditWriter(db, Time).AppendAsync(Id, SignerContactHistory.Event, envelope.SenderEmail, null, null, default, SignerContactHistory.Canonical(revision));
            await tx.CommitAsync(); previous = revision.Id; Email = email; return revision;
        }
        internal async Task<bool> Session(VerifiedSigner identity)
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == Id);
            return await new SignerContactState(db, Time).SessionMatchesLockedAsync(envelope, identity);
        }
        internal async Task Bind(VerifiedSigner identity, bool used = true, bool wrongScope = false)
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var token = new AuthToken { EnvelopeId = Id, PartyId = SignerId, PartyType = PartyType.Signer, Purpose = TokenPurpose.SignerAccess, Email = Email,
                UsedAt = used ? Time.Now : null, ExpiresAt = Time.Now.AddHours(1), TokenSha256 = RandomNumberGenerator.GetBytes(32),
                SignerContactRevisionId = previous,
                DocumentId = wrongScope ? Guid.NewGuid() : identity.DocumentId, DocumentSha256 = new byte[32], DisclosureSha256 = new byte[32] };
            db.AuthTokens.Add(token); await db.SaveChangesAsync();
            await new SignerContactState(db, Time).BindRedeemedSessionLockedAsync(await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == Id), identity, token.Id);
            await tx.CommitAsync();
        }
        internal async Task<Guid> SeedUnusedToken(VerifiedSigner identity)
        {
            await using var db = fixture.Open(); var token = new AuthToken { EnvelopeId = Id, PartyId = SignerId, PartyType = PartyType.Signer,
                Purpose = TokenPurpose.SignerAccess, Email = Email, ExpiresAt = Time.Now.AddHours(24), TokenSha256 = RandomNumberGenerator.GetBytes(32),
                DocumentId = identity.DocumentId, DocumentSha256 = new byte[32], DisclosureSha256 = new byte[32] };
            Assert.DoesNotContain("SignerContactRevisionId", JsonSerializer.Serialize(token));
            db.AuthTokens.Add(token); await db.SaveChangesAsync(); return token.Id;
        }
        internal async Task AssertDelayedLegacyTokenRejected(VerifiedSigner identity, Guid tokenId)
        {
            await using var db = fixture.Open(); await using var tx = await db.Database.BeginTransactionAsync();
            var token = await db.AuthTokens.SingleAsync(x => x.Id == tokenId); Assert.True(token.ExpiresAt > Time.Now); Assert.Null(token.UsedAt);
            var envelope = await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == Id); var state = new SignerContactState(db, Time);
            Assert.False(await state.TokenMatchesLockedAsync(envelope, token));
            token.UsedAt = Time.Now; await db.SaveChangesAsync();
            await Assert.ThrowsAsync<InvalidDataException>(() => state.BindRedeemedSessionLockedAsync(envelope, identity with { SessionId = Guid.NewGuid() }, token.Id));
        }
    }
}
