using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using Flow=QuillSign.Tests.CompletionDownloadTests.Flow;

namespace QuillSign.Tests;

public sealed class VerificationPageTests(SqlDatabaseFixture fixture) : IClassFixture<SqlDatabaseFixture>
{
    [Fact]
    public async Task Anonymous_browser_verifies_both_exact_artifacts_without_identity_file_echo_or_new_authority_after_signing_expiry()
    {
        await using var f=await Flow.Create(fixture,verificationBrowser:true);var before=await Counts(f);var keys=f.Run.Seal.Certificates.Calls;
        f.Clock.Advance(TimeSpan.FromDays(3));f.Run.Seal.Options.Pfx.Path="unavailable";
        foreach(var bytes in new[]{f.Published.ExecutedBytes,f.Published.CertificateBytes}) {
            var page=await Page(f);using var response=await Post(f,page,bytes,"SYNTHETIC_PRIVATE_FILENAME<script>.pdf");Assert.Equal(HttpStatusCode.OK,response.StatusCode);
            var html=await response.Content.ReadAsStringAsync();Assert.Contains("File integrity verified",html);Assert.Contains(Convert.ToHexStringLower(SHA256.HashData(bytes)),html);
            Assert.DoesNotContain("SYNTHETIC_PRIVATE_FILENAME",html);Assert.DoesNotContain(f.PublicId,html);Assert.DoesNotContain(f.Run.Signing.Envelope.Title!,html);
            Assert.DoesNotContain(f.Run.Signing.Envelope.SenderEmail,html);Assert.DoesNotContain("/final/",html);Assert.True(response.Headers.CacheControl!.NoStore);
            Assert.DoesNotContain("value=\"verification.pdf\"",html);Assert.False(response.Headers.TryGetValues("Set-Cookie",out var cookies) && cookies.Any(x=>x.StartsWith("QuillSign.")));
        }
        Assert.Equal(before,await Counts(f));Assert.Equal(keys,f.Run.Seal.Certificates.Calls);Assert.Equal(2,f.Run.Seal.Requests);Assert.Equal(2,f.Store.Writes);
    }
    [Fact]
    public async Task JSON_results_contain_only_the_supplied_digest_verified_kind_and_integrity_facts_and_still_require_CSRF()
    {
        await using var f=await Flow.Create(fixture,verificationBrowser:true);var page=await Page(f);f.Client.DefaultRequestHeaders.Accept.ParseAdd("application/json");
        using(var missing=await Post(f,page,f.Published.ExecutedBytes,csrf:false)) {Assert.Equal(HttpStatusCode.BadRequest,missing.StatusCode);Assert.Contains("RejectedInput",await missing.Content.ReadAsStringAsync());}
        using var response=await Post(f,page,f.Published.CertificateBytes);Assert.Equal(HttpStatusCode.OK,response.StatusCode);using var json=JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var result=json.RootElement;Assert.Equal("Verified",result.GetProperty("status").GetString());Assert.Equal("Certificate",result.GetProperty("kind").GetString());
        Assert.Equal(Convert.ToHexStringLower(f.Published.Certificate.Sha256),result.GetProperty("sha256").GetString());Assert.True(result.GetProperty("sealIntegrity").GetBoolean());Assert.True(result.GetProperty("timestampIntegrity").GetBoolean());
        Assert.Equal(new[]{"kind","message","sealIntegrity","sha256","status","timestampIntegrity"},result.EnumerateObject().Select(x=>x.Name).OrderBy(x=>x).ToArray());
        Assert.False(response.Headers.TryGetValues("Set-Cookie",out var cookies) && cookies.Any(x=>x.StartsWith("QuillSign.")));
    }
    [Fact]
    public async Task Unknown_altered_and_retention_expired_files_are_neutral_unrecognized_results_without_private_storage_reads()
    {
        await using var f=await Flow.Create(fixture,verificationBrowser:true);var page=await Page(f);var reads=f.Store.Reads;var changed=f.Published.ExecutedBytes.ToArray();changed[^1]^=1;
        foreach(var bytes in new[]{PdfFixtures.Create(text:"Synthetic unknown NO AGREEMENT"),changed}) {
            using var response=await Post(f,page,bytes);Assert.Equal(HttpStatusCode.OK,response.StatusCode);var html=await response.Content.ReadAsStringAsync();
            Assert.Contains("not recognized",html);Assert.Contains("does not prove an invalid signature",html);Assert.DoesNotContain("File integrity verified",html);
        }
        f.Clock.Advance(TimeSpan.FromDays(8));page=await Page(f);using(var expired=await Post(f,page,f.Published.ExecutedBytes)) {Assert.Equal(HttpStatusCode.OK,expired.StatusCode);Assert.Contains("not recognized",await expired.Content.ReadAsStringAsync());}
        Assert.Equal(reads,f.Store.Reads);Assert.Equal(2,f.Store.Writes);Assert.Equal(2,f.Run.Seal.Requests);
    }
    [Theory]
    [InlineData("missing")][InlineData("corrupt")]
    public async Task Missing_or_damaged_retained_evidence_never_confirms_integrity_or_claims_a_saved_upload(string fault)
    {
        await using var f=await Flow.Create(fixture,verificationBrowser:true);var page=await Page(f);var before=await Counts(f);f.Store.Fault=fault;
        using var response=await Post(f,page,f.Published.ExecutedBytes);Assert.Equal(fault=="missing" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.UnprocessableEntity,response.StatusCode);
        var html=await response.Content.ReadAsStringAsync();Assert.Contains("No ",html);Assert.Contains("integrity result is confirmed",html);Assert.DoesNotContain("File integrity verified",html);Assert.DoesNotContain("synthetic-version",html);
        Assert.Equal(before,await Counts(f));
    }
    private static async Task<string> Page(Flow f) {using var response=await f.Client.GetAsync("/verify");f.Take(response);Assert.Equal(HttpStatusCode.OK,response.StatusCode);return await response.Content.ReadAsStringAsync();}
    private static async Task<HttpResponseMessage> Post(Flow f,string page,byte[] bytes,string name="synthetic.pdf",bool csrf=true) {
        using var form=new MultipartFormDataContent();form.Add(new ByteArrayContent(bytes),"Upload",name);if(csrf)form.Add(new StringContent(SignaturePageTests.Browser.Token(page)),"__RequestVerificationToken");
        var response=await f.Client.PostAsync("/verify",form);f.Take(response);return response;
    }
    private async Task<string> Counts(Flow f) {await using var db=fixture.Open();return string.Join(',',await db.AuditEvents.CountAsync(),await db.AuthTokens.CountAsync(),await db.EmailOutbox.CountAsync(),await db.WorkItems.CountAsync(),f.Store.Writes,f.Run.Storage.Created.Count,f.Run.Storage.Deleted.Count,f.Run.Seal.Requests);}
}
