using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using QuillSign.Documents;
using QuillSign.Sender;

namespace QuillSign.Signing;

public sealed class SignerRetentionEvidenceException():Exception("The signing retention evidence could not be verified.");

// Only verified signer retention failures reach this filter. Unknown identities
// retain their existing behavior; no document or party metadata is returned.
public sealed class SignerRetentionExceptionFilter:IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        if(!context.HttpContext.Request.Path.StartsWithSegments("/sign"))return;
        var status=context.Exception switch {DocumentRetentionExpiredException=>410,SignerRetentionEvidenceException=>503,_=>0};
        if(status==0)return;
        var message=status==410 ? "This demo document has reached its retention deadline and is no longer available." : "The saved signing context could not be verified. Retry later or contact the sender.";
        var response=context.HttpContext.Response;response.Headers.CacheControl="no-store";response.Headers["Referrer-Policy"]="no-referrer";
        context.Result=SenderConfiguration.WantsJson(context.HttpContext) ? new JsonResult(new{message}){StatusCode=status} : new ContentResult{Content=message,ContentType="text/plain",StatusCode=status};
        context.ExceptionHandled=true;
    }
}
