using System.Collections.Concurrent;
using System.Data.Common;
using System.Security.Claims;
using System.Security.Cryptography;
using Azure.Storage.Blobs;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class DocumentWorkflowTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Upload_read_and_confirmation_preserve_hashes_geometry_and_audit_without_sending()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var input = PdfFixtures.Create(rotation: 90);
        await run.UploadAsync(input, filename: "../synthetic.PDF");
        var state = await run.StateAsync();
        Assert.Equal("synthetic.pdf", state.Title); Assert.Equal(2, state.PageCount);
        Assert.Equal(SHA256.HashData(input), state.OriginalSha256);
        Assert.Contains("\"Rotation\":90", state.PageSizesJson);
        Assert.Null(state.PreviewConfirmedAt);
        await using (var read = await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, state.PdfBlob!, default)))
        {
            Assert.NotNull(read);
            Assert.Equal(state.PdfSha256, await SHA256.HashDataAsync(read));
        }
        Assert.True(await run.WithAsync(work => work.ConfirmAsync(run.Sender, run.PublicId, state.RowVersion, state.PdfBlob!, true, null, null, default)));
        var confirmed = await run.StateAsync();
        Assert.NotNull(confirmed.PreviewConfirmedAt); Assert.Equal(EnvelopeStatus.Draft, confirmed.Status);
        Assert.Null(confirmed.SentPdfBlob);
        await using var db = fixture.Open();
        Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == run.Id));
        var events = await db.AuditEvents.Where(x => x.EnvelopeId == run.Id).OrderBy(x => x.Sequence).ToListAsync();
        Assert.Equal(new[] { "document_uploaded", "preview_confirmed" }, events.Select(x => x.Event));
        Assert.Contains(Convert.ToHexStringLower(state.PdfSha256!), events[1].DataJson);
        Assert.Equal(events[0].Hash, events[1].PrevHash);
        Assert.All(events, entry => Assert.Equal(AuditHash.Compute(entry), entry.Hash));
    }

    [Fact]
    public async Task Replacement_clears_obsolete_confirmation_fields_and_suggestions_and_old_version_is_unreadable()
    {
        await using var run = await Harness.CreateAsync(fixture);
        await run.UploadAsync(PdfFixtures.Create());
        var old = await run.StateAsync();
        await run.WithAsync(work => work.ConfirmAsync(run.Sender, run.PublicId, old.RowVersion, old.PdfBlob!, true, null, null, default));
        await using (var seed = fixture.Open())
        {
            var envelope = await seed.Envelopes.SingleAsync(x => x.Id == run.Id);
            envelope.AiRolesJson = "[]"; envelope.AiModel = "synthetic";
            seed.Fields.Add(new() { EnvelopeId = run.Id, Type = FieldType.Text, Width = .2m, Height = .1m });
            await seed.SaveChangesAsync();
        }
        await run.UploadAsync(PdfFixtures.Create(1, text: "Replacement document"));
        var current = await run.StateAsync();
        Assert.NotEqual(old.PdfBlob, current.PdfBlob); Assert.Equal(1, current.PageCount);
        Assert.Null(current.PreviewConfirmedAt); Assert.Null(current.AiRolesJson); Assert.Null(current.AiModel);
        Assert.Null(await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, old.PdfBlob!, default)));
        await Assert.ThrowsAsync<Azure.RequestFailedException>(() => run.Store.Inner.CopyToAsync(run.Sender,
            new(run.Id, DocumentBlobKind.Normalized, Guid.ParseExact(old.PdfBlob!, "N")), new MemoryStream()));
        await using var db = fixture.Open();
        Assert.False(await db.Fields.AnyAsync(x => x.EnvelopeId == run.Id));
        Assert.True(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == run.Id && x.Event == "document_replaced"));
        await Assert.ThrowsAsync<DocumentConflictException>(() => run.WithAsync(work => work.ConfirmAsync(run.Sender,
            run.PublicId, old.RowVersion, old.PdfBlob!, true, null, null, default)));
        Assert.Null((await run.StateAsync()).PreviewConfirmedAt);
    }

    [Fact]
    public async Task Concurrent_replacements_from_one_version_have_one_winner()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var before = await run.StateAsync();
        async Task<bool> TryAsync(byte[] bytes)
        {
            try { return await run.UploadAsync(bytes, before.RowVersion); }
            catch (DocumentConflictException) { return false; }
        }
        var results = await Task.WhenAll(TryAsync(PdfFixtures.Create(1)), TryAsync(PdfFixtures.Create(2)));
        Assert.Single(results, result => result);
        await using var db = fixture.Open();
        Assert.Equal(1, await db.AuditEvents.CountAsync(x => x.EnvelopeId == run.Id && x.Event == "document_uploaded"));
        var current = await run.StateAsync();
        await using var readable = await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, current.PdfBlob!, default));
        Assert.NotNull(readable);
    }

    [Fact]
    public async Task Other_envelope_or_unverified_sender_cannot_access_any_document_operation()
    {
        await using var run = await Harness.CreateAsync(fixture);
        await run.UploadAsync(PdfFixtures.Create());
        var state = await run.StateAsync();
        var stranger = SenderConfiguration.Principal(new(Guid.NewGuid(), run.PublicId, run.Email));
        await run.WithAsync(async work =>
        {
            Assert.Null(await work.GetAsync(stranger, run.PublicId, default));
            Assert.Null(await work.ReadAsync(stranger, run.PublicId, state.PdfBlob!, default));
            using var input = new MemoryStream(PdfFixtures.Create());
            Assert.False(await work.UploadAsync(stranger, run.PublicId, state.RowVersion, "synthetic.pdf", input, input.Length, null, null, default));
            Assert.False(await work.ConfirmAsync(stranger, run.PublicId, state.RowVersion, state.PdfBlob!, true, null, null, default));
            return true;
        });
        await using (var seed = fixture.Open())
        {
            var envelope = await seed.Envelopes.SingleAsync(x => x.Id == run.Id); envelope.SenderVerifiedAt = null;
            await seed.SaveChangesAsync();
        }
        Assert.Null(await run.WithAsync(work => work.GetAsync(run.Sender, run.PublicId, default)));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Failed_blob_writes_leave_the_committed_document_and_confirmation_unchanged(int failure)
    {
        await using var run = await Harness.CreateAsync(fixture);
        await run.UploadAsync(PdfFixtures.Create());
        var state = await run.StateAsync();
        await run.WithAsync(work => work.ConfirmAsync(run.Sender, run.PublicId, state.RowVersion, state.PdfBlob!, true, null, null, default));
        state = await run.StateAsync();
        run.Store.FailWrite = run.Store.Writes + failure;
        await Assert.ThrowsAsync<IOException>(() => run.UploadAsync(PdfFixtures.Create(1)));
        var after = await run.StateAsync();
        Assert.Equal(state.RowVersion, after.RowVersion); Assert.Equal(state.PdfBlob, after.PdfBlob);
        Assert.Equal(state.PreviewConfirmedAt, after.PreviewConfirmedAt);
        await using var read = await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, state.PdfBlob!, default));
        Assert.NotNull(read);
    }

    [Fact]
    public async Task Database_failure_rolls_back_document_references_and_audit()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var before = await run.StateAsync(); run.AuditFailure.Enabled = true;
        var failure = await Assert.ThrowsAsync<DbUpdateException>(() => run.UploadAsync(PdfFixtures.Create()));
        Assert.IsType<IOException>(failure.InnerException);
        var after = await run.StateAsync(); Assert.Equal(before.RowVersion, after.RowVersion); Assert.Null(after.PdfBlob);
        await using var db = fixture.Open(); Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == run.Id));
    }

    [Fact]
    public async Task Uncertain_commit_does_not_delete_blobs_that_were_committed()
    {
        await using var run = await Harness.CreateAsync(fixture);
        run.CommitFailure.Enabled = true;
        await Assert.ThrowsAsync<IOException>(() => run.UploadAsync(PdfFixtures.Create()));
        var state = await run.StateAsync(); Assert.NotNull(state.PdfBlob);
        await using var readable = await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, state.PdfBlob!, default));
        Assert.NotNull(readable);
    }

    [Fact]
    public async Task Declared_size_mismatch_oversize_and_tampered_blob_never_confirm_false_content()
    {
        await using var run = await Harness.CreateAsync(fixture);
        var before = await run.StateAsync(); var bytes = PdfFixtures.Create();
        await Assert.ThrowsAsync<DocumentRejectedException>(() => run.WithAsync(work => work.UploadAsync(run.Sender, run.PublicId,
            before.RowVersion, "synthetic.pdf", new MemoryStream(bytes), bytes.Length + 1, null, null, default)));
        await Assert.ThrowsAsync<DocumentRejectedException>(() => run.WithAsync(work => work.UploadAsync(run.Sender, run.PublicId,
            before.RowVersion, "synthetic.pdf", new MemoryStream(bytes), 11 * 1024 * 1024, null, null, default)));
        using (var undeclaredOversize = new MemoryStream(new byte[10 * 1024 * 1024 + 1]))
            await Assert.ThrowsAsync<DocumentRejectedException>(() => run.WithAsync(work => work.UploadAsync(run.Sender, run.PublicId,
                before.RowVersion, "synthetic.pdf", undeclaredOversize, bytes.Length, null, null, default)));
        Assert.Null((await run.StateAsync()).PdfBlob);
        await run.UploadAsync(bytes); var state = await run.StateAsync(); run.Store.CorruptRead = true;
        await Assert.ThrowsAsync<InvalidDataException>(() => run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, state.PdfBlob!, default)));
        await Assert.ThrowsAsync<InvalidDataException>(() => run.WithAsync(work => work.ConfirmAsync(run.Sender,
            run.PublicId, state.RowVersion, state.PdfBlob!, true, null, null, default)));
        await Assert.ThrowsAsync<DocumentRejectedException>(() => run.WithAsync(work => work.ConfirmAsync(run.Sender,
            run.PublicId, state.RowVersion, state.PdfBlob!, false, null, null, default)));
        Assert.Null((await run.StateAsync()).PreviewConfirmedAt);
    }

    internal sealed class Harness(SqlDatabaseFixture fixture) : IAsyncDisposable
    {
        public Guid Id { get; } = Guid.NewGuid();
        public string PublicId { get; } = Guid.NewGuid().ToString("N");
        public string Email { get; } = "synthetic-" + Guid.NewGuid().ToString("N") + "@example.invalid";
        public ClaimsPrincipal Sender => SenderConfiguration.Principal(new(Id, PublicId, Email));
        public FaultStore Store { get; } = new(new AzureBlobStore(new BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE"),
            new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)), 25 * 1024 * 1024, true));
        public FailAudit AuditFailure { get; } = new();
        public FailCommit CommitFailure { get; } = new();
        public DemoRetentionOptions Retention {get;}=new();
        public TimeProvider Time {get;set;}=TimeProvider.System;
        public static async Task<Harness> CreateAsync(SqlDatabaseFixture fixture,bool demo=false)
        {
            var run = new Harness(fixture);
            await using var db = fixture.Open();
            db.Envelopes.Add(new() { Id = run.Id, PublicId = run.PublicId, SenderEmail = run.Email, SenderVerifiedAt = DateTimeOffset.UtcNow,IsDemo=demo });
            await db.SaveChangesAsync(); return run;
        }
        public async Task<Envelope> StateAsync()
        { await using var db = fixture.Open(); return await db.Envelopes.AsNoTracking().SingleAsync(x => x.Id == Id); }
        public async Task<T> WithAsync<T>(Func<DocumentWorkflow, Task<T>> operation)
        {
            using var source = fixture.Open();
            await using var db = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
                .UseSqlServer(source.Database.GetDbConnection().ConnectionString).AddInterceptors(AuditFailure, CommitFailure).Options);
            var options = new DocumentOptions();
            return await operation(new(db, Store, new(options), options, new(db, Time), Time, NullLogger<DocumentWorkflow>.Instance,Retention));
        }
        public async Task<bool> UploadAsync(byte[] bytes, byte[]? version = null, string filename = "synthetic.pdf")
        {
            version ??= (await StateAsync()).RowVersion;
            using var source = new MemoryStream(bytes);
            return await WithAsync(work => work.UploadAsync(Sender, PublicId, version, filename, source, bytes.Length, null, null, default));
        }
        public async ValueTask DisposeAsync()
        { foreach (var blob in Store.Created) await Store.Inner.DeleteAsync(Sender, blob); }
    }
    internal sealed class FaultStore(IBlobStore inner) : IBlobStore
    {
        private int writes;
        public IBlobStore Inner => inner;
        public ConcurrentBag<DocumentBlob> Created { get; } = [];
        public int Writes => writes;
        public int FailWrite { get; set; }
        public bool CorruptRead { get; set; }
        public async Task WriteAsync(ClaimsPrincipal sender, DocumentBlob blob, Stream source, long length, CancellationToken ct)
        {
            Created.Add(blob);
            await inner.WriteAsync(sender, blob, source, length, ct);
            if (Interlocked.Increment(ref writes) == FailWrite) throw new IOException("Synthetic lost upload response.");
        }
        public async Task<long> CopyToAsync(ClaimsPrincipal sender, DocumentBlob blob, Stream destination, CancellationToken ct)
        { var count = await inner.CopyToAsync(sender, blob, destination, ct); if (CorruptRead) destination.WriteByte(0); return count; }
        public Task DeleteAsync(ClaimsPrincipal sender, DocumentBlob blob, CancellationToken ct) => inner.DeleteAsync(sender, blob, ct);
    }
    internal sealed class FailAudit : DbCommandInterceptor
    {
        public bool Enabled { get; set; }
        public Action? AfterInsert {get;set;}
        public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData, DbDataReader result, CancellationToken ct = default)
        {
            if(command.CommandText.Contains("INSERT INTO [AuditEvents]",StringComparison.Ordinal))AfterInsert?.Invoke();
            if (Enabled && command.CommandText.Contains("INSERT INTO [AuditEvents]", StringComparison.Ordinal))
            { await result.DisposeAsync(); throw new IOException("Synthetic audit response loss."); }
            return await base.ReaderExecutedAsync(command, eventData, result, ct);
        }
    }
    internal sealed class FailCommit : DbTransactionInterceptor
    {
        public bool Enabled { get; set; }
        public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData, CancellationToken ct = default)
        { if (Enabled) throw new IOException("Synthetic lost commit acknowledgement."); return Task.CompletedTask; }
    }
}
