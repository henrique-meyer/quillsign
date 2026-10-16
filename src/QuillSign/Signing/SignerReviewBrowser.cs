using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Sender;

namespace QuillSign.Signing;

public sealed record SignerReviewAccessProof(VerifiedSigner Identity,Guid CandidateId,string PdfSha256,string ReceiptSha256,
    DateTimeOffset PreparedAt,DateTimeOffset ExpiresAt);

// Cookie lifetime permits recovery of an already accepted Finish after a lost response.
// It never extends a candidate's validity for a new Finish.
public sealed class SignerReviewBrowser(IDataProtectionProvider provider,TimeProvider time,IHostEnvironment environment)
{
    public const string ReviewCookie="QuillSign.Review",AccessCookie="QuillSign.ReviewAccess",AcceptedCookie="QuillSign.Finish";
    private readonly IDataProtector protector=provider.CreateProtector("QuillSign.SignerReviewAccess.v1");
    public VerifiedSigner? Identity(HttpContext http,string publicId)
    {
        var identity=SignerAccessConfiguration.ReadIdentity(http.User,time.GetUtcNow());
        return identity?.PublicId==publicId ? identity : null;
    }
    public string? Get(HttpContext http,string name)=>http.Request.Cookies.TryGetValue(name,out var value) && value.Length is >0 and <=3800 ? value : null;
    public void Put(HttpContext http,string name,string value,VerifiedSigner identity)
    {
        if(value.Length>3800 || identity.SessionExpiresAt<=time.GetUtcNow())throw new InvalidDataException("Invalid private review proof.");
        var options=Options(http,identity.PublicId); options.MaxAge=identity.SessionExpiresAt-time.GetUtcNow();
        http.Response.Cookies.Append(name,value,options);
    }
    public void Clear(HttpContext http,string name,string publicId)=>http.Response.Cookies.Delete(name,Options(http,publicId));
    public void PreparedPdf(HttpContext http,SignerReviewPrepared candidate,VerifiedSigner identity)
        =>Put(http,AccessCookie,protector.Protect(JsonSerializer.Serialize(new SignerReviewAccessProof(identity,candidate.Id,candidate.PdfSha256,
            Hash(candidate.Receipt),time.GetUtcNow(),candidate.ExpiresAt))),identity);
    public bool HasAccess(HttpContext http,SignerReviewReceipt candidate,string receipt,bool accepted)
    {
        var value=Get(http,AccessCookie); if(value is null)return false;
        try {
            var proof=JsonSerializer.Deserialize<SignerReviewAccessProof>(protector.Unprotect(value)); var now=time.GetUtcNow();
            return proof is not null && proof.Identity==candidate.Identity && proof.CandidateId==candidate.Id && proof.PdfSha256==candidate.PdfSha256 &&
                proof.ReceiptSha256==Hash(receipt) && proof.PreparedAt>=candidate.PreparedAt && proof.PreparedAt<proof.ExpiresAt && proof.PreparedAt<=now &&
                proof.ExpiresAt==candidate.ExpiresAt && candidate.Identity.SessionExpiresAt>now && (accepted || proof.ExpiresAt>now);
        }
        catch(Exception e) when(e is CryptographicException or JsonException or ArgumentException) { return false; }
    }
    private CookieOptions Options(HttpContext http,string publicId)=>new() { HttpOnly=true,SameSite=SameSiteMode.Strict,
        Secure=!environment.IsDevelopment() || http.Request.IsHttps,Path="/sign/"+publicId,IsEssential=true };
    private static string Hash(string value)=>Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
public static class SignerReviewBrowserConfiguration
{
    public static IServiceCollection AddSignerReviewBrowser(this IServiceCollection services)
    {
        services.AddScoped<SignerReviewBrowser>(); services.AddScoped<SignerAcceptedFilter>();
        services.Configure<RazorPagesOptions>(o=>o.Conventions.ConfigureFilter(new ServiceFilterAttribute(typeof(SignerAcceptedFilter))));
        return services;
    }
}

// Recover accepted state before opening editable pages, including after a lost Finish response.
public sealed class SignerAcceptedFilter(SignerReviewBrowser browser,SignerCheckpointReads checkpoints) : IAsyncPageFilter
{
    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context)=>Task.CompletedTask;
    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context,PageHandlerExecutionDelegate next)
    {
        var path=context.ActionDescriptor.ViewEnginePath;
        if(path is "/Sign/Index" or "/Sign/Signature" or "/Sign/Fields" or "/Sign/Review" &&
            !(path=="/Sign/Review" && context.HandlerMethod?.Name=="Finish")) {
            var http=context.HttpContext; var id=context.RouteData.Values["publicId"]?.ToString();
            var proof=browser.Get(http,SignerReviewBrowser.AcceptedCookie)??browser.Get(http,SignerReviewBrowser.ReviewCookie);
            if(id is not null && proof is not null && browser.Identity(http,id) is { } identity) {
                http.Response.Headers.CacheControl="no-store"; http.Response.Headers["Referrer-Policy"]="no-referrer";
                try {
                    if(await checkpoints.ConfirmAsync(http.User,id,proof,http.RequestAborted) is not null) {
                        browser.Put(http,SignerReviewBrowser.AcceptedCookie,proof,identity);
                        context.Result=SenderConfiguration.WantsJson(http) ? new JsonResult(new { message="Your Finish was already accepted. Entries are frozen.",confirmation="/sign/"+id+"/confirmed" }) { StatusCode=409 }
                            : new RedirectResult("/sign/"+id+"/confirmed"); return;
                    }
                }
                catch(Exception e) when(QuillSign.Pages.Sign.FieldsModel.StorageError(e)) {
                    context.Result=new ObjectResult("Saved signing state could not be verified. Retry later; do not assume Finish failed.") { StatusCode=503 }; return;
                }
            }
        }
        await next();
    }
}
