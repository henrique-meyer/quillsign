using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace QuillSign.Verification;

internal sealed class VerificationUploadReadFeature;

// Fail closed before normal form/antiforgery reads if a custom host forgot the
// bounded middleware. The normal antiforgery filter still validates every action.
[AttributeUsage(AttributeTargets.Class)]
public sealed class VerificationUploadRequiredAttribute : Attribute,IAsyncAuthorizationFilter,IOrderedFilter
{
    public int Order=>0;
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var http=context.HttpContext;
        if(!HttpMethods.IsPost(http.Request.Method) || http.Features.Get<VerificationUploadReadFeature>() is not null)return;
        await VerificationBrowser.Error(http,503,"Verification is unavailable. No integrity result is confirmed. Try again later.",http.RequestAborted);
        context.Result=new EmptyResult();
    }
}
