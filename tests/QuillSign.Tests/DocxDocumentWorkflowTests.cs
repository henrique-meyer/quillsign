using System.Data;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Storage;
using Harness = QuillSign.Tests.DocumentWorkflowTests.Harness;

namespace QuillSign.Tests;

public sealed class DocxDocumentWorkflowTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Captured_real_Gotenberg_pair_preserves_source_normalized_content_retention_audit_and_deliberate_confirmation()
    {
        var source=await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory,"Fixtures","synthetic-conversion.docx"));
        var providerPdf=await File.ReadAllBytesAsync(Path.Combine(AppContext.BaseDirectory,"Fixtures","synthetic-conversion.pdf"));
        Assert.Equal("d9d6492b9b753b3697f92dfe1752f5ae37dab2557cb8462ea57557e9a0155fcd",Convert.ToHexStringLower(SHA256.HashData(source)));
        Assert.Equal("aa1cac4c792f473f2fd4fcb4b1f91323c6843d381fb8456520d6822c34d6cd7c",Convert.ToHexStringLower(SHA256.HashData(providerPdf)));
        await using var run=await Harness.CreateAsync(fixture,demo:true);run.Retention.PurgeAfterDays=7;var provider=new Provider {Pdf=providerPdf};
        Assert.True(await Upload(run,provider,source));var state=await run.StateAsync();Assert.Equal(source,provider.LastOriginal);Assert.Equal(source,await Original(run,state));Assert.Equal(DocxDocumentWorkflow.Mime,state.OriginalMime);Assert.Equal(2,state.PageCount);Assert.Null(state.PreviewConfirmedAt);
        await using(var read=await run.WithAsync(work=>work.ReadAsync(run.Sender,run.PublicId,state.PdfBlob!,default)))
        {
            Assert.NotNull(read);Assert.Equal(state.PdfSha256,await SHA256.HashDataAsync(read));read.Position=0;using var pdf=UglyToad.PdfPig.PdfDocument.Open(read);
            Assert.Equal(2,pdf.NumberOfPages);foreach(var page in pdf.GetPages()) {var text=string.Join(' ',page.GetWords().Select(x=>x.Text));Assert.Contains("NO AGREEMENT",text);Assert.InRange(page.Width,611.99,612.01);Assert.InRange(page.Height,791.99,792.01);}
        }
        Assert.True(await run.WithAsync(work=>work.ConfirmAsync(run.Sender,run.PublicId,state.RowVersion,state.PdfBlob!,true,null,null,default)));
        await using var db=fixture.Open();var events=await db.AuditEvents.Where(x=>x.EnvelopeId==run.Id).OrderBy(x=>x.Sequence).ToArrayAsync();Assert.Equal(new[]{"document_uploaded","preview_confirmed"},events.Select(x=>x.Event));Assert.All(events,x=>Assert.Equal(AuditHash.Compute(x),x.Hash));Assert.Equal(events[0].Hash,events[1].PrevHash);
        var policy=await new UploadRetention(db,run.Retention,run.Time).ReadAsync(state);Assert.NotNull(policy);Assert.Equal(policy.StartedAt.AddDays(7),policy.DeleteAfter);Assert.NotNull((await run.StateAsync()).PreviewConfirmedAt);Assert.Equal(1,provider.Calls);
    }
    [Fact]
    public async Task Validated_original_and_normalized_PDF_are_stored_with_exact_hashes_media_geometry_and_conversion_audit()
    {
        await using var run = await Harness.CreateAsync(fixture, demo: true); run.Retention.PurgeAfterDays = 7; run.Time = new Clock();
        var bytes = GotenbergDocxConverterTests.Docx(); var expected = bytes.ToArray(); var provider = new Provider { Before = () => { Array.Clear(bytes); return Task.CompletedTask; } };
        Assert.True(await Upload(run, provider, bytes, filename: "../synthetic.DOCX")); var state = await run.StateAsync();
        Assert.Equal("synthetic.pdf", state.Title); Assert.Equal(DocxDocumentWorkflow.Mime, state.OriginalMime); Assert.Equal(SHA256.HashData(expected), state.OriginalSha256); Assert.Equal(2, state.PageCount); Assert.Contains("\"Rotation\":90", state.PageSizesJson);
        Assert.Null(state.PreviewConfirmedAt); Assert.Null(state.SentPdfBlob); Assert.Equal(1, provider.Calls); Assert.Equal(expected, provider.LastOriginal);
        Assert.Equal(expected, await Original(run, state)); await using (var pdf = await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, state.PdfBlob!, default))) { Assert.NotNull(pdf); Assert.Equal(state.PdfSha256, await SHA256.HashDataAsync(pdf)); }
        await using (var db = fixture.Open())
        {
            var entry = Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == run.Id).ToArrayAsync()); Assert.Equal("document_uploaded", entry.Event); Assert.Equal(AuditHash.Compute(entry), entry.Hash);
            using var json = JsonDocument.Parse(entry.DataJson); var conversion = json.RootElement.GetProperty("conversion"); Assert.Equal("docx-gotenberg-v1", conversion.GetProperty("version").GetString()); Assert.Equal("synthetic.docx", conversion.GetProperty("originalFilename").GetString()); Assert.Equal(expected.Length, conversion.GetProperty("originalBytes").GetInt64()); Assert.Equal(DocxDocumentWorkflow.Mime, conversion.GetProperty("originalMime").GetString());
            var policy = await new UploadRetention(db, run.Retention, run.Time).ReadAsync(state); Assert.NotNull(policy); Assert.Equal(state.OriginalSha256, policy.OriginalSha256); Assert.Equal(state.PdfSha256, policy.PdfSha256); Assert.Equal(policy.StartedAt.AddDays(7), policy.DeleteAfter);
            Assert.False(await db.EmailOutbox.AnyAsync(x => x.EnvelopeId == run.Id));
        }
        Assert.True(await run.WithAsync(work => work.ConfirmAsync(run.Sender, run.PublicId, state.RowVersion, state.PdfBlob!, true, null, null, default))); Assert.NotNull((await run.StateAsync()).PreviewConfirmedAt);
    }

    [Fact]
    public async Task PDF_and_DOCX_replacements_clear_old_preparation_keep_the_first_retention_and_preserve_the_PDF_audit_contract()
    {
        await using var run = await Harness.CreateAsync(fixture, demo: true); var clock = new Clock(); run.Time = clock; run.Retention.PurgeAfterDays = 7; await run.UploadAsync(PdfFixtures.Create()); var first = await run.StateAsync();
        await run.WithAsync(work => work.ConfirmAsync(run.Sender, run.PublicId, first.RowVersion, first.PdfBlob!, true, null, null, default));
        await using (var seed = fixture.Open()) { var e = await seed.Envelopes.SingleAsync(x => x.Id == run.Id); e.AiRolesJson = "[]"; e.AiModel = "synthetic"; seed.Fields.Add(new() { EnvelopeId = run.Id, Type = FieldType.Text, Width = .2m, Height = .1m }); await seed.SaveChangesAsync(); }
        DocumentRetentionSnapshot snapshot; await using (var db = fixture.Open()) snapshot = await db.DocumentRetentionSnapshots.AsNoTracking().SingleAsync(x => x.EnvelopeId == run.Id);
        clock.Now = clock.Now.AddDays(1); run.Retention.PurgeAfterDays = 30; Assert.True(await Upload(run, new())); var docx = await run.StateAsync(); Assert.Equal(DocxDocumentWorkflow.Mime, docx.OriginalMime); Assert.Null(docx.PreviewConfirmedAt); Assert.Null(docx.AiModel); Assert.Null(docx.AiRolesJson);
        Assert.Null(await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, first.PdfBlob!, default))); await Assert.ThrowsAsync<DocumentConflictException>(() => run.WithAsync(work => work.ConfirmAsync(run.Sender, run.PublicId, first.RowVersion, first.PdfBlob!, true, null, null, default)));
        await using (var db = fixture.Open()) { Assert.False(await db.Fields.AnyAsync(x => x.EnvelopeId == run.Id)); var current = await new UploadRetention(db, run.Retention, run.Time).ReadAsync(docx); Assert.Equal(UploadRetention.Digest(snapshot), UploadRetention.Digest(current!)); }
        await run.WithAsync(work => work.ConfirmAsync(run.Sender, run.PublicId, docx.RowVersion, docx.PdfBlob!, true, null, null, default)); await run.UploadAsync(PdfFixtures.Create(1)); var pdf = await run.StateAsync(); Assert.Equal("application/pdf", pdf.OriginalMime); Assert.Null(pdf.PreviewConfirmedAt); Assert.Null(await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, docx.PdfBlob!, default)));
        await using (var db = fixture.Open()) { var last = await db.AuditEvents.Where(x => x.EnvelopeId == run.Id && x.Event == "document_replaced").OrderByDescending(x => x.Sequence).FirstAsync(); using var json = JsonDocument.Parse(last.DataJson); Assert.False(json.RootElement.TryGetProperty("conversion", out _)); Assert.Equal(snapshot.DeleteAfter, (await new UploadRetention(db, run.Retention, run.Time).ReadAsync(pdf))!.DeleteAfter); }
    }

    [Theory]
    [InlineData("filename")]
    [InlineData("package")]
    [InlineData("length")]
    [InlineData("disabled")]
    [InlineData("provider")]
    [InlineData("output")]
    public async Task Invalid_input_or_conversion_failure_does_not_replace_or_unconfirm_the_saved_document(string kind)
    {
        await using var run = await Confirmed(); var before = await run.StateAsync(); var writes = run.Store.Writes; var provider = new Provider { Status = kind == "provider" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK, InvalidPdf = kind == "output" }; var bytes = kind == "package" ? new byte[100] : GotenbergDocxConverterTests.Docx();
        var error = await Record.ExceptionAsync(() => Upload(run, provider, bytes, filename: kind == "filename" ? "private.exe" : "synthetic.docx", declared: kind == "length" ? bytes.Length + 1 : null, enabled: kind != "disabled")); Assert.NotNull(error); Assert.True(error is DocumentRejectedException or DocumentConversionUnavailableException); Assert.DoesNotContain("PRIVATE-MARKER", error.Message); Assert.Null(error.InnerException);
        var after = await run.StateAsync(); Assert.Equal(before.RowVersion, after.RowVersion); Assert.Equal(before.PreviewConfirmedAt, after.PreviewConfirmedAt); Assert.Equal(before.PdfBlob, after.PdfBlob); Assert.Equal(writes, run.Store.Writes); Assert.Equal(kind is "provider" or "output" ? 1 : 0, provider.Calls);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task Lost_storage_write_responses_cleanup_only_new_objects_and_preserve_the_confirmed_document(int failure)
    {
        await using var run = await Confirmed(); var before = await run.StateAsync(); run.Store.FailWrite = run.Store.Writes + failure;
        await Assert.ThrowsAsync<IOException>(() => Upload(run, new())); var after = await run.StateAsync(); Assert.Equal(before.RowVersion, after.RowVersion); Assert.Equal(before.OriginalBlob, after.OriginalBlob); Assert.Equal(before.PreviewConfirmedAt, after.PreviewConfirmedAt);
        await using var read = await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, before.PdfBlob!, default)); Assert.NotNull(read);
    }

    [Fact]
    public async Task Audit_failure_rolls_back_upload_and_retention_while_uncertain_commit_preserves_the_winning_pair_and_rejects_old_revision_retry()
    {
        await using var run = await Harness.CreateAsync(fixture, demo: true); run.Retention.PurgeAfterDays = 7; var before = await run.StateAsync(); run.AuditFailure.Enabled = true;
        await Assert.ThrowsAsync<DbUpdateException>(() => Upload(run, new())); var rolledBack = await run.StateAsync(); Assert.Null(rolledBack.OriginalBlob); Assert.Equal(before.RowVersion, rolledBack.RowVersion);
        await using (var db = fixture.Open()) { Assert.False(await db.DocumentRetentionSnapshots.AnyAsync(x => x.EnvelopeId == run.Id)); Assert.False(await db.AuditEvents.AnyAsync(x => x.EnvelopeId == run.Id)); }
        run.AuditFailure.Enabled = false; run.CommitFailure.Enabled = true; var provider = new Provider(); var original = GotenbergDocxConverterTests.Docx(); await Assert.ThrowsAsync<IOException>(() => Upload(run, provider, original, version: before.RowVersion)); var current = await run.StateAsync(); Assert.NotNull(current.PdfBlob); Assert.Equal(DocxDocumentWorkflow.Mime, current.OriginalMime);
        run.CommitFailure.Enabled = false; await Assert.ThrowsAsync<DocumentConflictException>(() => Upload(run, provider, original, version: before.RowVersion)); Assert.Equal(1, provider.Calls);
        Assert.Equal(SHA256.HashData(original), current.OriginalSha256); Assert.Equal(current.OriginalSha256, SHA256.HashData(await Original(run, current)));
        await using var read = await run.WithAsync(work => work.ReadAsync(run.Sender, run.PublicId, current.PdfBlob!, default)); Assert.NotNull(read);
        await using var check = fixture.Open(); Assert.Single(await check.AuditEvents.Where(x => x.EnvelopeId == run.Id && x.Event == "document_uploaded").ToArrayAsync()); Assert.NotNull(await new UploadRetention(check, run.Retention, run.Time).ReadAsync(current));
    }

    [Theory]
    [InlineData("other")]
    [InlineData("unverified")]
    [InlineData("stale")]
    public async Task Initial_authority_or_revision_failure_never_reads_input_or_calls_the_converter(string kind)
    {
        await using var run = await Harness.CreateAsync(fixture); var state = await run.StateAsync(); var sender = run.Sender;
        if (kind == "other") sender = SenderConfiguration.Principal(new(Guid.NewGuid(), run.PublicId, run.Email));
        if (kind is "unverified" or "stale") { await using var db = fixture.Open(); var e = await db.Envelopes.SingleAsync(x => x.Id == run.Id); if (kind == "unverified") e.SenderVerifiedAt = null; else e.Title = "Concurrent edit"; await db.SaveChangesAsync(); }
        using var source = new MemoryStream(GotenbergDocxConverterTests.Docx()); var provider = new Provider();
        if (kind == "stale") await Assert.ThrowsAsync<DocumentConflictException>(() => Upload(run, provider, source: source, version: state.RowVersion, sender: sender));
        else Assert.False(await Upload(run, provider, source: source, version: state.RowVersion, sender: sender));
        Assert.Equal(0, source.Position); Assert.True(source.CanRead); Assert.Equal(0, provider.Calls); Assert.Equal(0, run.Store.Writes);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Authority_and_revision_are_rechecked_after_HTTP_before_any_object_is_written(bool revoke)
    {
        await using var run = await Harness.CreateAsync(fixture); var state = await run.StateAsync(); var provider = new Provider { Before = async () => { await using var db = fixture.Open(); var e = await db.Envelopes.SingleAsync(x => x.Id == run.Id); if (revoke) e.SenderVerifiedAt = null; else e.Title = "Concurrent edit"; await db.SaveChangesAsync(); } };
        if (revoke) Assert.False(await Upload(run, provider, version: state.RowVersion)); else await Assert.ThrowsAsync<DocumentConflictException>(() => Upload(run, provider, version: state.RowVersion)); Assert.Equal(1, provider.Calls); Assert.Equal(0, run.Store.Writes); Assert.Null((await run.StateAsync()).PdfBlob);
    }

    [Theory]
    [InlineData("before")]
    [InlineData("http")]
    [InlineData("audit")]
    public async Task Fixed_retention_cutoff_is_enforced_before_HTTP_after_HTTP_and_at_the_commit_boundary(string crossing)
    {
        await using var run = await Harness.CreateAsync(fixture, demo: true); var clock = new Clock(); run.Time = clock; run.Retention.PurgeAfterDays = 7; await run.UploadAsync(PdfFixtures.Create()); var before = await run.StateAsync(); DateTimeOffset deadline;
        await using (var db = fixture.Open()) deadline = (await db.DocumentRetentionSnapshots.SingleAsync(x => x.EnvelopeId == run.Id)).DeleteAfter;
        var writes = run.Store.Writes; var provider = new Provider(); if (crossing == "before") clock.Now = deadline; if (crossing == "http") provider.Before = () => { clock.Now = deadline; return Task.CompletedTask; }; if (crossing == "audit") run.AuditFailure.AfterInsert = () => clock.Now = deadline;
        await Assert.ThrowsAsync<DocumentRejectedException>(() => Upload(run, provider)); var after = await run.StateAsync(); Assert.Equal(before.RowVersion, after.RowVersion); Assert.Equal(before.PdfBlob, after.PdfBlob); Assert.Equal(before.OriginalBlob, after.OriginalBlob);
        Assert.Equal(crossing == "before" ? 0 : 1, provider.Calls); if (crossing != "audit") Assert.Equal(writes, run.Store.Writes);
        await using var check = fixture.Open(); Assert.Single(await check.AuditEvents.Where(x => x.EnvelopeId == run.Id).ToArrayAsync()); Assert.Equal(deadline, (await new UploadRetention(check, run.Retention, run.Time).ReadAsync(after))!.DeleteAfter);
    }

    [Fact]
    public async Task Conversion_has_no_open_SQL_connection_or_transaction_and_cancellation_preserves_the_saved_document()
    {
        await using var run = await Confirmed(); var before = await run.StateAsync(); using var cancelled = new CancellationTokenSource(); var provider = new Provider();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WithDatabaseAsync(async db =>
        {
            provider.Before = () => { Assert.Null(db.Database.CurrentTransaction); Assert.Equal(ConnectionState.Closed, db.Database.GetDbConnection().State); cancelled.Cancel(); return Task.CompletedTask; };
            using var source = new MemoryStream(GotenbergDocxConverterTests.Docx()); return await Service(run, db, provider).UploadAsync(run.Sender, run.PublicId, before.RowVersion, "synthetic.docx", source, source.Length, null, null, cancelled.Token);
        })); Assert.Equal(before.RowVersion, (await run.StateAsync()).RowVersion); Assert.Equal(2, run.Store.Writes);
    }

    [Fact]
    public async Task Concurrent_conversions_for_one_revision_have_one_winner_and_one_upload_audit()
    {
        await using var run = await Harness.CreateAsync(fixture); var before = await run.StateAsync(); var arrived = 0; var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var provider = new Provider { Before = async () => { if (Interlocked.Increment(ref arrived) == 2) release.TrySetResult(); await release.Task.WaitAsync(TimeSpan.FromSeconds(15)); } };
        async Task<bool> Attempt() { try { return await Upload(run, provider, version: before.RowVersion); } catch (DocumentConflictException) { return false; } }
        var results = await Task.WhenAll(Attempt(), Attempt()); Assert.Single(results, x => x); Assert.Equal(2, provider.Calls); var current = await run.StateAsync(); Assert.Equal(current.OriginalSha256, SHA256.HashData(await Original(run, current)));
        await using var db = fixture.Open(); Assert.Single(await db.AuditEvents.Where(x => x.EnvelopeId == run.Id).ToArrayAsync());
    }

    private async Task<Harness> Confirmed()
    { var run = await Harness.CreateAsync(fixture); await run.UploadAsync(PdfFixtures.Create()); var state = await run.StateAsync(); await run.WithAsync(work => work.ConfirmAsync(run.Sender, run.PublicId, state.RowVersion, state.PdfBlob!, true, null, null, default)); return run; }

    [Fact]
    public async Task Registered_converter_suppresses_default_request_URL_logging_with_an_active_log_provider()
    {
        var logs = new CapturedLogs(); var services = new ServiceCollection(); services.AddLogging(builder => builder.SetMinimumLevel(LogLevel.Trace).AddProvider(logs)); services.AddSingleton<IHostEnvironment>(new EnvironmentStub());
        services.AddQuillSignDocuments(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Gotenberg:Enabled"] = "true", ["Gotenberg:BaseUrl"] = "https://private-endpoint.example.invalid" }).Build());
        var handler = new Provider(); services.AddHttpClient<GotenbergDocxConverter>().ConfigurePrimaryHttpMessageHandler(() => handler);
        using var provider = services.BuildServiceProvider(); provider.GetRequiredService<ILoggerFactory>().CreateLogger("SyntheticControl").LogInformation("Synthetic logging control");
        using var source = new MemoryStream(GotenbergDocxConverterTests.Docx()); await provider.GetRequiredService<GotenbergDocxConverter>().ConvertAsync(source, source.Length);
        Assert.Contains(logs.Messages, x => x.Contains("Synthetic logging control", StringComparison.Ordinal)); Assert.DoesNotContain(logs.Messages, x => x.Contains("private-endpoint", StringComparison.OrdinalIgnoreCase)); Assert.Equal(1, handler.Calls);
    }
    [Fact]
    public async Task An_external_SQL_transaction_cannot_hold_locks_across_conversion()
    {
        await using var run=await Harness.CreateAsync(fixture);var state=await run.StateAsync();var provider=new Provider();using var source=new MemoryStream(GotenbergDocxConverterTests.Docx());
        await run.WithDatabaseAsync(async db=> {
            await using var transaction=await db.Database.BeginTransactionAsync();
            await Assert.ThrowsAsync<InvalidOperationException>(()=>Service(run,db,provider).UploadAsync(run.Sender,run.PublicId,state.RowVersion,"synthetic.docx",source,source.Length,null,null));
            await transaction.RollbackAsync();return true;
        });
        Assert.Equal(0,source.Position);Assert.Equal(0,provider.Calls);Assert.Equal(0,run.Store.Writes);
    }
    private sealed class CapturedLogs : ILoggerProvider
    {
        public System.Collections.Concurrent.ConcurrentQueue<string> Messages { get; } = new(); public ILogger CreateLogger(string categoryName) => new CapturedLogger(this); public void Dispose() { }
        private sealed class CapturedLogger(CapturedLogs owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null; public bool IsEnabled(LogLevel level) => true;
            public void Log<TState>(LogLevel level, EventId id, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => owner.Messages.Enqueue(formatter(state, exception));
        }
    }
    private static async Task<byte[]> Original(Harness run, Envelope state)
    { using var bytes = new MemoryStream(); await run.Store.Inner.CopyToAsync(run.Sender, new(run.Id, DocumentBlobKind.Original, Guid.ParseExact(state.OriginalBlob!, "N")), bytes); return bytes.ToArray(); }
    private static async Task<bool> Upload(Harness run, Provider provider, byte[]? bytes = null, string filename = "synthetic.docx", byte[]? version = null, long? declared = null, bool enabled = true, MemoryStream? source = null, ClaimsPrincipal? sender = null)
    {
        version ??= (await run.StateAsync()).RowVersion; bytes ??= GotenbergDocxConverterTests.Docx(); using var owned = source is null ? new MemoryStream(bytes) : null; var input = source ?? owned!;
        return await run.WithDatabaseAsync(db => Service(run, db, provider, enabled).UploadAsync(sender ?? run.Sender, run.PublicId, version, filename, input, declared ?? input.Length, null, null));
    }
    private static DocxDocumentWorkflow Service(Harness run, QuillSignDbContext db, Provider provider, bool enabled = true)
    {
        var options = new DocumentOptions(); var documents = new DocumentWorkflow(db, run.Store, new(options), options, new(db, run.Time), run.Time, NullLogger<DocumentWorkflow>.Instance, run.Retention);
        var converter = new GotenbergDocxConverter(new HttpClient(provider, false), new() { Enabled = enabled, BaseUrl = "https://converter.example.invalid" }, options, new(options), new EnvironmentStub());
        return new(documents, new(options), converter);
    }
    private sealed class Provider : HttpMessageHandler
    {
        private int calls; public int Calls => calls; public byte[]? LastOriginal { get; private set; }
        public Func<Task>? Before { get; set; }
        public HttpStatusCode Status { get; set; } = HttpStatusCode.OK; public bool InvalidPdf { get; set; } public byte[]? Pdf {get;set;}
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref calls); var form = Assert.IsType<MultipartFormDataContent>(request.Content); var file = Assert.Single(form, x => x.Headers.ContentDisposition?.Name?.Trim('"') == "files"); LastOriginal = await file.ReadAsByteArrayAsync(ct); if (Before is not null) await Before(); ct.ThrowIfCancellationRequested();
            var response = new HttpResponseMessage(Status) { Content = new ByteArrayContent(InvalidPdf ? "PRIVATE-MARKER"u8.ToArray() : Pdf ?? PdfFixtures.Create(rotation: 90, text: "SYNTHETIC DOCX CONVERSION - NO AGREEMENT")) }; response.Content.Headers.ContentType = new("application/pdf"); return response;
        }
    }
    private sealed class Clock : TimeProvider { public DateTimeOffset Now { get; set; } = DateTimeOffset.UtcNow; public override DateTimeOffset GetUtcNow() => Now; }
    private sealed class EnvironmentStub : IHostEnvironment { public string EnvironmentName { get; set; } = "Development"; public string ApplicationName { get; set; } = "SyntheticDocxWorkflow"; public string ContentRootPath { get; set; } = ""; public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider(); }
}
