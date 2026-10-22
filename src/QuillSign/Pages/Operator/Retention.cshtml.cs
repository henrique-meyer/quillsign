using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QuillSign.Lifecycle;
using QuillSign.Operator;

namespace QuillSign.Pages.Operator;

[RequestSizeLimit(32768)]
[Microsoft.AspNetCore.RateLimiting.EnableRateLimiting("production-operator")]
public sealed class RetentionModel(ProductionOperatorBrowser browser,IProductionOperatorActions actions):PageModel
{
    [BindProperty,StringLength(32)] public string? RecordId {get;set;}="";
    [BindProperty,StringLength(32)] public string? HoldId {get;set;}="";
    [BindProperty,StringLength(8)] public string? Operation {get;set;}="Place";
    [BindProperty,StringLength(256)] public string? Purpose {get;set;}="";
    [BindProperty,StringLength(2048)] public string? Reason {get;set;}="";
    [BindProperty,StringLength(512)] public string? Reference {get;set;}="";
    [BindProperty,StringLength(16384)] public string? Confirmation {get;set;}="";
    [BindProperty] public bool Attested {get;set;}
    [TempData] public string? Notice {get;set;}
    public bool SignedIn {get;private set;}
    public ProductionOperatorView? Current {get;private set;}
    public ProductionOperatorReview? Review {get;private set;}
    public ProductionOperatorDeletionReview? DeletionReview {get;private set;}
    public bool DeletionEnabled=>actions.DeletionEnabled;
    private void Private(){Response.Headers.CacheControl="no-store";Response.Headers["X-Robots-Tag"]="noindex, nofollow";Response.Headers["Referrer-Policy"]="no-referrer";}
    public async Task<IActionResult> OnGetAsync()
    {
        Private();if(!browser.Enabled)return NotFound();var result=await HttpContext.AuthenticateAsync(ProductionOperatorAuthority.CookieScheme);SignedIn=result.Succeeded;return Page();
    }
    public IActionResult OnPostSignIn()
    {
        Private();if(!browser.Enabled||!Request.IsHttps)return NotFound();return Challenge(new AuthenticationProperties{RedirectUri=ProductionOperatorAuthentication.Page},ProductionOperatorAuthority.OidcScheme);
    }
    public async Task<IActionResult> OnPostSignOutAsync()
    {Private();if(!browser.Enabled)return NotFound();browser.Clear(HttpContext);await HttpContext.SignOutAsync(ProductionOperatorAuthority.CookieScheme);return Redirect(ProductionOperatorAuthentication.Page);}
    public Task<IActionResult> OnPostStatusAsync(CancellationToken ct)=>Status(false,ct);
    public Task<IActionResult> OnPostInspectAsync(CancellationToken ct)=>Status(true,ct);
    private async Task<IActionResult> Status(bool inspect,CancellationToken ct)
    {
        Private();if(!browser.Enabled)return NotFound();try{DemandInput();var id=Id(RecordId);var s=await browser.RequireAsync(HttpContext,ProductionOperatorPermission.Status);
            Current=await actions.StatusAsync(HttpContext,id,inspect,ct);browser.Select(HttpContext,s.Ticket,id);SignedIn=true;return Page();}
        catch(Exception e)when(Known(e)){return Unavailable();}
    }
    public async Task<IActionResult> OnPostReviewAsync(CancellationToken ct)
    {
        Private();if(!browser.Enabled)return NotFound();try{DemandInput();Review=await actions.ReviewAsync(HttpContext,Id(RecordId),Operation??"",
            Operation=="Release"?Id(HoldId):null,Purpose??"",Reason??"",Reference??"",ct);SignedIn=true;return Page();}catch(Exception e)when(Known(e)){return Unavailable();}
    }
    public async Task<IActionResult> OnPostConfirmAsync(CancellationToken ct)
    {
        Private();if(!browser.Enabled)return NotFound();try{DemandInput();Notice=await actions.ExecuteAsync(HttpContext,Confirmation??"",ct);return Redirect(ProductionOperatorAuthentication.Page);}
        catch(Exception e)when(Known(e)){Notice="The operation is unavailable or unresolved. Inspect its recorded state before taking further action.";return Redirect(ProductionOperatorAuthentication.Page);}
    }
    public async Task<IActionResult> OnPostReviewDeletionAsync(CancellationToken ct)
    {
        Private();if(!browser.Enabled||!actions.DeletionEnabled)return NotFound();
        try{DemandInput();DeletionReview=await actions.ReviewDeletionAsync(HttpContext,Id(RecordId),Purpose??"",ct);SignedIn=true;return Page();}
        catch(Exception e)when(Known(e)){return Unavailable();}
    }
    public async Task<IActionResult> OnPostConfirmDeletionAsync(CancellationToken ct)
    {
        Private();if(!browser.Enabled||!actions.DeletionEnabled)return NotFound();
        try{DemandInput();if(!Attested)throw ProductionOperatorAuthority.Denied();Notice=await actions.ExecuteDeletionAsync(HttpContext,Confirmation??"",ct);return Redirect(ProductionOperatorAuthentication.Page);}
        catch(Exception e)when(Known(e)){Notice="Deletion authorization is unavailable or unresolved. Inspect recorded status before taking further action.";return Redirect(ProductionOperatorAuthentication.Page);}
    }
    public async Task<IActionResult> OnPostExportAsync(CancellationToken ct)
    {
        Private();if(!browser.Enabled)return NotFound();try{DemandInput();var data=await actions.ExportAsync(HttpContext,Id(RecordId),Purpose??"",ct);return File(data,"application/json","private-evidence-inventory.json");}
        catch(Exception e)when(Known(e)){return Unavailable();}
    }
    private void DemandInput(){if(!ModelState.IsValid)throw ProductionOperatorAuthority.Denied();}
    private static Guid Id(string? raw)=>Guid.TryParseExact(raw,"N",out var id)&&id!=Guid.Empty?id:throw ProductionOperatorAuthority.Denied();
    private IActionResult Unavailable(){Response.StatusCode=404;Notice="Private record access is unavailable.";SignedIn=false;return Page();}
    private static bool Known(Exception e)=>e is UnauthorizedAccessException or InvalidDataException or KeyNotFoundException or InvalidOperationException or
        System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException or Azure.RequestFailedException or IOException or OperationCanceledException or Microsoft.EntityFrameworkCore.DbUpdateException or Microsoft.Data.SqlClient.SqlException or HttpRequestException;
}
