using Azure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using QuillSign.Data;
using QuillSign.Documents;
using QuillSign.Sender;
using QuillSign.Signing;

namespace QuillSign.Pages.Sign;

[Authorize(AuthenticationSchemes = SignerAccessConfiguration.Scheme)]
[RequestSizeLimit(1200000)]
[RequestFormLimits(MultipartBodyLengthLimit = 1200000,ValueLengthLimit = 8192)]
public sealed class SignatureModel(SignerAccess access,SignatureAdoption adoption,BrowserNotices notices) : PageModel
{
    public SignerReadContext Context { get; private set; } = null!;
    public string? Notice { get; private set; }
    [BindProperty] public IFormFile? Signature { get; set; }
    [BindProperty] public IFormFile? Initials { get; set; }
    [BindProperty] public string? Method { get; set; }
    [BindProperty] public string? TypedName { get; set; }
    [BindProperty] public string? TypedInitials { get; set; }
    [BindProperty] public string? Receipt { get; set; }
    [BindProperty] public bool Acknowledged { get; set; }
    [BindProperty] public string? StatementVersion { get; set; }
    private void Private() { Response.Headers.CacheControl="no-store"; Response.Headers["Referrer-Policy"]="no-referrer"; }
    private async Task<bool> Load(string publicId,CancellationToken ct)
    { Private(); var context=await access.GetContextAsync(User,publicId,ct); if(context?.ConsentAt is null)return false; Context=context; return true; }
    public async Task<IActionResult> OnGetAsync(string publicId,CancellationToken ct)
    {
        if(!await Load(publicId,ct))return NotFound(); Notice=notices.Take(HttpContext); TypedName=Context.SignerName; return Page();
    }
    public async Task<IActionResult> OnPostPreviewAsync(string publicId,CancellationToken ct)
    {
        if(!await Load(publicId,ct))return Error(404,"This signing request is unavailable. Reload it or contact the sender.");
        try
        {
            if(!ModelState.IsValid || !Enum.TryParse<SignatureMethod>(Method,false,out var method) || !Enum.IsDefined(method) || method.ToString()!=Method)
                return Error(400,"Choose Type, Draw or Upload and prepare both marks.");
            var request=new SignaturePreviewRequest(await ReadPng(Signature,ct),await ReadPng(Initials,ct),method,TypedName,TypedInitials);
            var prepared=await adoption.PrepareAsync(User,publicId,request,ct);
            if(prepared is null)return Error(409,"Your signing context changed. Reload the request before previewing again.");
            var preview=await adoption.ReadAsync(User,publicId,prepared.Receipt,ct);
            if(preview is null)return Error(409,"This preview is no longer current. Prepare it again.");
            return new JsonResult(new { preview.Receipt,signature=Convert.ToBase64String(preview.Signature),initials=Convert.ToBase64String(preview.Initials),
                preview.ExpiresAt,preview.StatementVersion,preview.Statement,preview.SignatureWidth,preview.SignatureHeight,preview.InitialsWidth,preview.InitialsHeight });
        }
        catch(Exception e) when(e is ArgumentException or SignatureImageRejectedException or InvalidOperationException)
        { return Error(400,e is SignatureImageRejectedException ? e.Message : "Use visible signature and initials within the limits. If the preview limit was reached, reuse a current preview or contact the sender."); }
        catch(Exception e) when(e is RequestFailedException or IOException or DocumentRejectedException or DbUpdateException)
        { return Error(503,"The marks could not be saved or verified. No adoption was recorded. Retry the preview later."); }
    }
    public async Task<IActionResult> OnPostAdoptAsync(string publicId,CancellationToken ct)
    {
        if(!await Load(publicId,ct))return NotFound();
        try
        {
            if(!ModelState.IsValid)return Failure(400,"Prepare a new preview and acknowledge its statement before adopting.");
            var result=await adoption.AdoptAsync(User,publicId,Receipt,Acknowledged,StatementVersion,HttpContext.Connection.RemoteIpAddress?.ToString(),Request.Headers.UserAgent.ToString(),ct);
            if(result==SignatureAdoptionResult.InvalidContext)return NotFound();
            if(result is SignatureAdoptionResult.Adopted or SignatureAdoptionResult.AlreadyAdopted)
            {
                if(SenderConfiguration.WantsJson(HttpContext))return new JsonResult(new { message=BrowserNotices.Text(NoticeCode.SignatureAdopted) });
                notices.Set(HttpContext,NoticeCode.SignatureAdopted); return Redirect("/sign/"+publicId+"/signature");
            }
            return Failure(400,"The preview or acknowledgment is missing, expired or stale. Prepare and review a new preview before adopting.");
        }
        catch(Exception e) when(e is RequestFailedException or IOException or DocumentRejectedException or DbUpdateException)
        { return Failure(503,"Adoption could not be confirmed. Reload to check the saved state before retrying; do not assume the document was signed."); }
    }
    private IActionResult Failure(int status,string message)
    {
        if(SenderConfiguration.WantsJson(HttpContext))return Error(status,message);
        Receipt=null; ModelState.Remove(nameof(Receipt)); ModelState.AddModelError("",message); Response.StatusCode=status; return Page();
    }
    private static JsonResult Error(int status,string message)=>new(new { message }) { StatusCode=status };
    private static async Task<byte[]> ReadPng(IFormFile? file,CancellationToken ct)
    {
        if(file is null || file.Length is <=0 or >SignaturePng.MaximumBytes || file.ContentType!="image/png")throw new ArgumentException("Use a bounded PNG for both marks.");
        using var memory=new MemoryStream(); using var bounded=new BoundedDocumentStream(memory,SignaturePng.MaximumBytes);
        await using var input=file.OpenReadStream(); await input.CopyToAsync(bounded,ct);
        if(memory.Length!=file.Length)throw new InvalidDataException("The image length changed."); return memory.ToArray();
    }
}
