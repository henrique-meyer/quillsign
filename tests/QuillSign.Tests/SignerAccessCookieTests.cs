using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using QuillSign.Data;
using QuillSign.Signing;
using QuillSign.Storage;

namespace QuillSign.Tests;

public sealed class SignerAccessCookieTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public void Each_session_has_a_nonce_preserved_by_cookie_claims_and_missing_or_duplicate_nonces_are_rejected()
    {
        var identity = new VerifiedSigner(Guid.NewGuid(),Guid.NewGuid().ToString("N"),Guid.NewGuid(),"signer@example.invalid",Guid.NewGuid(),new string('a',64),new string('b',64),DateTimeOffset.UtcNow.AddHours(2));
        var other = new VerifiedSigner(identity.EnvelopeId,identity.PublicId,identity.SignerId,identity.Email,identity.DocumentId,identity.DocumentHash,identity.DisclosureHash,identity.SessionExpiresAt);
        Assert.NotEqual(identity.SessionId,other.SessionId);
        var principal = SignerAccessConfiguration.Principal(identity);
        Assert.Equal(identity.SessionId,SignerAccessConfiguration.ReadIdentity(principal,DateTimeOffset.UtcNow)!.SessionId);
        var claims = (ClaimsIdentity)principal.Identity!; var nonce = claims.FindFirst(SignerAccessConfiguration.SessionClaim)!;
        claims.RemoveClaim(nonce); Assert.Null(SignerAccessConfiguration.ReadIdentity(principal,DateTimeOffset.UtcNow));
        claims.AddClaim(nonce); claims.AddClaim(new Claim(SignerAccessConfiguration.SessionClaim,Guid.NewGuid().ToString("N")));
        Assert.Null(SignerAccessConfiguration.ReadIdentity(principal,DateTimeOffset.UtcNow));
    }
    [Fact]
    public async Task Signer_cookie_is_http_only_non_sliding_expiring_and_isolated_from_sender_authentication()
    {
        var clock = new Clock();
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
        builder.Logging.ClearProviders(); builder.WebHost.UseTestServer(); builder.Services.AddSingleton<TimeProvider>(clock);
        builder.Services.AddScoped(_ => fixture.Open()); builder.Services.AddScoped<AuditWriter>();
        builder.Services.AddAuthentication(EnvelopeStorageAuthorization.SenderScheme).AddCookie(EnvelopeStorageAuthorization.SenderScheme,
            c => c.Events.OnRedirectToLogin = context => { context.Response.StatusCode = 401; return Task.CompletedTask; });
        builder.Services.AddQuillSignSignerAccess(new ConfigurationBuilder().Build(),builder.Environment); builder.Services.AddAuthorization();
        var verified = new VerifiedSigner(Guid.NewGuid(),Guid.NewGuid().ToString("N"),Guid.NewGuid(),"signer@example.invalid",Guid.NewGuid(),new string('a',64),new string('b',64),clock.GetUtcNow().AddHours(2));
        await using var app = builder.Build(); app.UseAuthentication(); app.UseAuthorization();
        app.MapGet("/test-cookie",async (Microsoft.AspNetCore.Http.HttpContext c) =>
        { await c.SignInAsync(SignerAccessConfiguration.Scheme,SignerAccessConfiguration.Principal(verified),SignerAccessConfiguration.Ticket(verified)); return "ok"; });
        app.MapGet("/signer-only",() => "ok").RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = SignerAccessConfiguration.Scheme });
        app.MapGet("/sender-only",() => "ok").RequireAuthorization(new AuthorizeAttribute { AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme });
        await app.StartAsync(); using var client = app.GetTestClient();
        using (var initial = await client.GetAsync("/signer-only")) Assert.Equal(HttpStatusCode.Unauthorized,initial.StatusCode);
        using (var issued = await client.GetAsync("/test-cookie"))
        {
            var cookie = Assert.Single(issued.Headers.GetValues("Set-Cookie"));
            Assert.StartsWith("QuillSign.Signer=",cookie); Assert.Contains("httponly",cookie,StringComparison.OrdinalIgnoreCase);
            Assert.Contains("samesite=lax",cookie,StringComparison.OrdinalIgnoreCase);
            client.DefaultRequestHeaders.Add("Cookie",cookie.Split(';')[0]);
        }
        using (var allowed = await client.GetAsync("/signer-only")) Assert.Equal(HttpStatusCode.OK,allowed.StatusCode);
        using (var sender = await client.GetAsync("/sender-only")) Assert.Equal(HttpStatusCode.Unauthorized,sender.StatusCode);
        clock.Advance(TimeSpan.FromHours(1));
        using (var again = await client.GetAsync("/signer-only")) { Assert.Equal(HttpStatusCode.OK,again.StatusCode); Assert.False(again.Headers.Contains("Set-Cookie")); }
        clock.Advance(TimeSpan.FromHours(1));
        using (var expired = await client.GetAsync("/signer-only")) Assert.Equal(HttpStatusCode.Unauthorized,expired.StatusCode);
        var options = app.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(SignerAccessConfiguration.Scheme);
        Assert.False(options.SlidingExpiration); Assert.Equal(TimeSpan.FromHours(2),options.ExpireTimeSpan); Assert.Equal("/",options.Cookie.Path);
    }

    [Fact]
    public void Signer_blob_scope_allows_only_the_frozen_copy_and_denies_writes_deletes_mixed_or_expired_claims()
    {
        var identity = new VerifiedSigner(Guid.NewGuid(),Guid.NewGuid().ToString("N"),Guid.NewGuid(),"signer@example.invalid",Guid.NewGuid(),new string('a',64),new string('b',64),DateTimeOffset.UtcNow.AddHours(2));
        var principal = SignerAccessConfiguration.Principal(identity);
        var blob = new DocumentBlob(identity.EnvelopeId,DocumentBlobKind.Normalized,identity.DocumentId);
        EnvelopeStorageAuthorization.DemandRead(principal,blob);
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.Demand(principal,blob));
        foreach (var wrong in new[] { blob with { Kind = DocumentBlobKind.Original },blob with { Kind = DocumentBlobKind.Preview },
            blob with { ObjectId = Guid.NewGuid() },blob with { EnvelopeId = Guid.NewGuid() } })
            Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(principal,wrong));
        var expired = SignerAccessConfiguration.Principal(identity with { SessionExpiresAt = DateTimeOffset.UtcNow.AddSeconds(-1) });
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(expired,blob));
        var mixed = SignerAccessConfiguration.Principal(identity); mixed.AddIdentity((ClaimsIdentity)BlobStorageTests.Sender(identity.EnvelopeId).Identity!);
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(mixed,blob));
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.Demand(mixed,blob));
        ((ClaimsIdentity)principal.Identity!).AddClaim(new Claim(SignerAccessConfiguration.DocumentClaim,Guid.NewGuid().ToString("N")));
        Assert.Throws<UnauthorizedAccessException>(() => EnvelopeStorageAuthorization.DemandRead(principal,blob));
    }

    [Fact]
    public async Task A_signer_can_copy_its_frozen_azurite_object_but_cannot_write_or_delete_it()
    {
        var service = new Azure.Storage.Blobs.BlobServiceClient(Environment.GetEnvironmentVariable("QUILLSIGN_TEST_STORAGE") ?? throw new InvalidOperationException("Run the local test helper."),
            new Azure.Storage.Blobs.BlobClientOptions(Azure.Storage.Blobs.BlobClientOptions.ServiceVersion.V2023_11_03));
        var store = new AzureBlobStore(service,1024,true);
        var identity = new VerifiedSigner(Guid.NewGuid(),Guid.NewGuid().ToString("N"),Guid.NewGuid(),"signer@example.invalid",Guid.NewGuid(),new string('a',64),new string('b',64),DateTimeOffset.UtcNow.AddHours(2));
        var blob = new DocumentBlob(identity.EnvelopeId,DocumentBlobKind.Normalized,identity.DocumentId);
        var sender = BlobStorageTests.Sender(identity.EnvelopeId); var signer = SignerAccessConfiguration.Principal(identity);
        byte[] bytes = [1,2,3,4]; using var input = new MemoryStream(bytes);
        try
        {
            await store.WriteAsync(sender,blob,input,bytes.Length); using var output = new MemoryStream();
            Assert.Equal(bytes.Length,await store.CopyToAsync(signer,blob,output)); Assert.Equal(bytes,output.ToArray());
            using var replacement = new MemoryStream([5]);
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.WriteAsync(signer,blob,replacement,1));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() => store.DeleteAsync(signer,blob));
        }
        finally { await store.DeleteAsync(sender,blob); }
    }
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan span) => now += span;
    }
}
