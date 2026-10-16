using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class FieldEditorTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Patch_endpoint_requires_sender_cookie_antiforgery_json_and_current_revision()
    {
        var draft = await SeedAsync(); var before = await ReadAsync(draft);
        var builder = WebApplication.CreateBuilder(); builder.WebHost.UseTestServer(); builder.Logging.ClearProviders();
        builder.Services.AddAuthentication(EnvelopeStorageAuthorization.SenderScheme).AddCookie(EnvelopeStorageAuthorization.SenderScheme,
            options => options.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; });
        builder.Services.AddAuthorization(); builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddScoped(_ => fixture.Open()); builder.Services.AddScoped<AuditWriter>();
        builder.Services.AddQuillSignFieldEditor(builder.Configuration);
        await using var app = builder.Build(); app.UseAuthentication(); app.UseAuthorization(); app.MapFieldEditor();
        app.MapGet("/test-session", async (Microsoft.AspNetCore.Http.HttpContext context, IAntiforgery antiforgery) =>
        {
            context.User = Principal(draft);
            await context.SignInAsync(EnvelopeStorageAuthorization.SenderScheme, context.User);
            return antiforgery.GetAndStoreTokens(context).RequestToken;
        });
        await app.StartAsync(); using var client = app.GetTestClient();
        var path = $"/api/envelopes/{draft.PublicId}/fields";
        using (var unauthorized = await client.PatchAsJsonAsync(path, new FieldSave(before.Version, before.DocumentId, [])))
            Assert.Equal(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        using var session = await client.GetAsync("/test-session"); var token = await session.Content.ReadAsStringAsync();
        client.DefaultRequestHeaders.Add("Cookie", string.Join("; ", session.Headers.GetValues("Set-Cookie").Select(x => x.Split(';')[0])));
        using (var noCsrf = await client.PatchAsJsonAsync(path, new FieldSave(before.Version, before.DocumentId, [])))
            Assert.Equal(HttpStatusCode.BadRequest, noCsrf.StatusCode);
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", token);
        using (var malformed = await client.PatchAsync(path, new StringContent("{", Encoding.UTF8, "application/json")))
            Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        using (var wrongType = await client.PatchAsync(path, new StringContent("{}", Encoding.UTF8, "text/plain")))
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, wrongType.StatusCode);
        using (var tooLarge = await client.PatchAsync(path, new StringContent(new string('x', FieldEditorConfiguration.MaximumRequestBytes + 1), Encoding.UTF8, "application/json")))
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, tooLarge.StatusCode);
        var payload = new FieldSave(before.Version, before.DocumentId, [Field(before.Signers[0].Id)]);
        using var saved = await client.PatchAsJsonAsync(path, payload); Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        var result = await saved.Content.ReadFromJsonAsync<JsonElement>(); Assert.NotEqual(before.Version, result.GetProperty("version").GetString());
        Assert.Equal("no-store", saved.Headers.CacheControl!.ToString());
        using var stale = await client.PatchAsJsonAsync(path, payload); Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
    }

    [Fact]
    public async Task Save_replace_delete_and_prefill_preserve_ids_audit_and_shared_revision()
    {
        var draft = await SeedAsync(); var before = await ReadAsync(draft); var signer = before.Signers[0];
        var signature = Field(signer.Id);
        var text = Field(null, "Text") with { Label = " Address ", Value = "Synthetic address\nSecond line" };
        var checkbox = Field(null, "Checkbox") with { Value = "false" };
        var date = Field(null, "Date") with { Value = "2028-02-29" };
        Assert.Equal(FieldEditorError.None, (await SaveAsync(draft, before, [signature, text, checkbox, date])).Error);
        var saved = await ReadAsync(draft); Assert.NotEqual(before.Version, saved.Version); Assert.Equal(4, saved.Fields.Count);
        Assert.Equal("Address", saved.Fields.Single(x => x.Id == text.Id).Label);
        await using (var db = fixture.Open())
        {
            var prefilled = await db.Fields.Where(x => x.EnvelopeId == draft.Id && x.SignerId == null).ToListAsync();
            Assert.All(prefilled, x => { Assert.Equal(PartyType.Sender, x.FilledBy); Assert.NotNull(x.FilledAt); });
            Assert.Null((await db.Fields.SingleAsync(x => x.Id == signature.Id)).FilledAt);
        }
        Assert.Equal(FieldEditorError.None, (await SaveAsync(draft, saved, [signature with { X = .2m }, text with { Value = null }])).Error);
        var final = await ReadAsync(draft); Assert.Equal(2, final.Fields.Count);
        Assert.Equal(.2m, final.Fields.Single(x => x.Id == signature.Id).X);
        await using var inspect = fixture.Open();
        var cleared = await inspect.Fields.SingleAsync(x => x.Id == text.Id);
        Assert.Null(cleared.Value); Assert.Null(cleared.FilledAt); Assert.Null(cleared.FilledBy);
        var events = await inspect.AuditEvents.Where(x => x.EnvelopeId == draft.Id).OrderBy(x => x.Sequence).ToListAsync();
        Assert.Equal(2, events.Count); Assert.Equal(events[0].Hash, events[1].PrevHash);
        Assert.All(events, x => { Assert.Equal("fields_saved", x.Event); Assert.Equal(AuditHash.Compute(x), x.Hash); Assert.Contains(signature.Id.ToString(), x.DataJson); });
        Assert.False(await inspect.EmailOutbox.AnyAsync(x => x.EnvelopeId == draft.Id));
    }

    [Fact]
    public async Task Invalid_geometry_types_owners_values_ids_and_limits_leave_everything_unchanged()
    {
        var draft = await SeedAsync(); var before = await ReadAsync(draft); var good = Field(before.Signers[0].Id);
        var other = await SeedAsync(); var foreign = await ReadAsync(other); var foreignField = Field(foreign.Signers[0].Id);
        Assert.Equal(FieldEditorError.None, (await SaveAsync(other, foreign, [foreignField])).Error);
        foreach (var bad in new[]
        {
            good with { X = -.001m }, good with { Y = 1m }, good with { Width = 0 }, good with { Height = .000000001m },
            good with { X = decimal.MaxValue }, good with { X = .9m, Width = .2m }, good with { Page = 0 }, good with { Page = 6 },
            good with { Type = "signature" }, good with { Type = "99" }, good with { Type = null! }, good with { SignerId = null },
            good with { SignerId = foreign.Signers[0].Id }, good with { Id = Guid.Empty }, good with { Id = foreignField.Id },
            good with { Value = "not signed" }, good with { Label = "bad\nlabel" }, good with { Label = new string('a', 513) },
            good with { SignerId = null, Type = "Text", Value = new string('a', 4001) },
            good with { SignerId = null, Type = "Checkbox", Value = "yes" },
            good with { SignerId = null, Type = "Date", Value = "2026-02-29" },
            good with { SignerId = null, Type = "Date", Value = "10/15/2026" }
        }) Assert.Equal(FieldEditorError.Invalid, (await SaveAsync(draft, before, [bad])).Error);
        Assert.Equal(FieldEditorError.Invalid, (await SaveAsync(draft, before, [good, good])).Error);
        Assert.Equal(FieldEditorError.Invalid, (await SaveAsync(draft, before, [good, good with { Id = Guid.NewGuid() }], maximum: 1)).Error);
        Assert.Equal(FieldEditorError.Invalid, (await SaveAsync(draft, before, null)).Error);
        var after = await ReadAsync(draft); Assert.Empty(after.Fields); Assert.Equal(before.Version, after.Version);
    }

    [Fact]
    public async Task Ownership_confirmation_draft_document_and_signer_revision_are_enforced()
    {
        var draft = await SeedAsync(); var other = await SeedAsync(); var before = await ReadAsync(draft);
        await using (var db = fixture.Open())
        {
            var service = Service(db);
            Assert.Null(await service.GetAsync(Principal(other), draft.PublicId));
            Assert.Null(await service.GetAsync(new ClaimsPrincipal(new ClaimsIdentity()), draft.PublicId));
            Assert.Equal(FieldEditorError.NotFound, (await service.SaveAsync(Principal(other), draft.PublicId,
                new(before.Version, before.DocumentId, []), null, null)).Error);
        }
        Assert.Equal(FieldEditorError.Conflict, (await SaveAsync(draft, before with { DocumentId = Guid.NewGuid().ToString("N") }, [])).Error);
        await using (var db = fixture.Open())
        {
            var setup = new SignerSetup(db, new AuditWriter(db, TimeProvider.System), new SignerSetupOptions());
            Assert.Equal(SignerSetupError.None, (await setup.ChangeAsync(Principal(draft), draft.PublicId,
                new(SignerChangeKind.Save, before.Version, before.Signers[0].Id, "Renamed signer", before.Signers[0].Email), null, null)).Error);
        }
        Assert.Equal(FieldEditorError.Conflict, (await SaveAsync(draft, before, [])).Error);
        var current = await ReadAsync(draft);
        await using (var db = fixture.Open())
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == draft.Id);
            envelope.PreviewConfirmedAt = null; await db.SaveChangesAsync();
        }
        Assert.Equal(FieldEditorError.PreviewRequired, (await SaveAsync(draft, current, [])).Error);
        await using (var db = fixture.Open())
        {
            var envelope = await db.Envelopes.SingleAsync(x => x.Id == draft.Id);
            envelope.PreviewConfirmedAt = DateTimeOffset.UtcNow; envelope.Status = EnvelopeStatus.Sent; await db.SaveChangesAsync();
        }
        Assert.Equal(FieldEditorError.NotFound, (await SaveAsync(draft, current, [])).Error);
    }

    [Fact]
    public async Task Competing_autosaves_have_one_winner_and_audit_failure_rolls_back_all_rows()
    {
        var draft = await SeedAsync(); var before = await ReadAsync(draft);
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => SaveAsync(draft, before, [Field(before.Signers[0].Id)])));
        Assert.Single(results, x => x.Error == FieldEditorError.None); Assert.Equal(3, results.Count(x => x.Error == FieldEditorError.Conflict));
        var saved = await ReadAsync(draft); var field = Assert.Single(saved.Fields);
        await using (var connection = fixture.Open())
        await using (var failing = new QuillSignDbContext(new DbContextOptionsBuilder<QuillSignDbContext>()
            .UseSqlServer(connection.Database.GetConnectionString()).AddInterceptors(new RejectAudit()).Options))
            await Assert.ThrowsAsync<DbUpdateException>(() => Service(failing).SaveAsync(Principal(draft), draft.PublicId,
                new(saved.Version, saved.DocumentId, [field with { X = .4m }, Field(null, "Text")]), null, null));
        var after = await ReadAsync(draft); Assert.Equal(saved.Version, after.Version); Assert.Equal(saved.Fields, after.Fields);
        await using var inspect = fixture.Open(); Assert.Single(await inspect.AuditEvents.Where(x => x.EnvelopeId == draft.Id).ToListAsync());
    }

    [Theory]
    [InlineData(612, 792, 0, 0, 0, 61.2, 475.2, 183.6, 158.4)]
    [InlineData(595, 842, 0, 0, 0, 59.5, 505.2, 178.5, 168.4)]
    [InlineData(792, 612, 0, 0, 0, 79.2, 367.2, 237.6, 122.4)]
    [InlineData(600, 800, 90, 20, 30, 140, 110, 120, 240)]
    [InlineData(600, 800, 180, 20, 30, 380, 190, 180, 160)]
    [InlineData(600, 800, 270, 20, 30, 380, 510, 120, 240)]
    public void Display_rectangles_map_to_expected_pdf_user_space_for_page_sizes_crop_and_rotation(
        double width, double height, int rotation, double left, double bottom, double x, double y, double w, double h)
    {
        // A non-default UserUnit must not multiply the raw PDF content coordinates twice.
        var page = new PageGeometry(width * 2, height * 2, rotation, 2, [0, 0, 2000, 2000], [left, bottom, left + width, bottom + height]);
        var actual = FieldGeometry.ToPdfRectangle(page, .1m, .2m, .3m, .2m);
        Assert.Equal(x, actual.X, 7); Assert.Equal(y, actual.Y, 7); Assert.Equal(w, actual.Width, 7); Assert.Equal(h, actual.Height, 7);
        Assert.True(FieldGeometry.InBounds(.8m, .9m, .2m, .1m));
        Assert.False(FieldGeometry.InBounds(.80000001m, .9m, .2m, .1m));
    }

    private FieldEditor Service(QuillSignDbContext db, int maximum = 200) => new(db, new AuditWriter(db, TimeProvider.System),
        new FieldEditorOptions { MaximumFields = maximum }, TimeProvider.System);
    private static ClaimsPrincipal Principal(Envelope draft) => SenderConfiguration.Principal(new VerifiedSender(draft.Id, draft.PublicId, draft.SenderEmail));
    private static FieldInput Field(Guid? signer, string type = "Signature") => new(Guid.NewGuid(), signer, type, 1, .1m, .2m, .3m, .2m, true);
    private async Task<FieldEditorSnapshot> ReadAsync(Envelope draft) { await using var db = fixture.Open(); return (await Service(db).GetAsync(Principal(draft), draft.PublicId))!; }
    private async Task<FieldSaveResult> SaveAsync(Envelope draft, FieldEditorSnapshot snapshot, IReadOnlyList<FieldInput>? fields, int maximum = 200)
    {
        await using var db = fixture.Open();
        return await Service(db, maximum).SaveAsync(Principal(draft), draft.PublicId, new(snapshot.Version, snapshot.DocumentId, fields), "127.0.0.1", "synthetic-test");
    }
    private async Task<Envelope> SeedAsync()
    {
        await using var db = fixture.Open();
        var envelope = new Envelope { SenderEmail = "sender-" + Guid.NewGuid().ToString("N") + "@example.invalid",
            SenderVerifiedAt = DateTimeOffset.UtcNow, PreviewConfirmedAt = DateTimeOffset.UtcNow,
            PdfBlob = Guid.NewGuid().ToString("N"), PdfSha256 = SHA256.HashData([1]), PageCount = 5,
            PageSizesJson = JsonSerializer.Serialize(Enumerable.Repeat(new PageGeometry(612, 792, 0, 1, [0, 0, 612, 792], [0, 0, 612, 792]), 5)) };
        db.Envelopes.Add(envelope); db.Signers.Add(new Signer { EnvelopeId = envelope.Id, FullName = "Synthetic signer", Email = "signer@example.invalid" });
        await db.SaveChangesAsync(); return envelope;
    }
    private sealed class RejectAudit : SaveChangesInterceptor
    {
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context!.ChangeTracker.Entries<AuditEvent>().Any(x => x.State == EntityState.Added)) throw new DbUpdateException("Synthetic audit failure");
            return ValueTask.FromResult(result);
        }
    }
}
