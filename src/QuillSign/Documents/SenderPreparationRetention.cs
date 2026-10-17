using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using QuillSign.Data;
using QuillSign.Sender;

namespace QuillSign.Documents;

public sealed class PreparationRetentionEvidenceException():Exception("The preparation retention evidence could not be verified.");

internal static class SenderPreparationRetention
{
    // The caller must first authorize the current sender/envelope and own its lock.
    internal static async Task<DateTimeOffset?> ReadAsync(QuillSignDbContext db,Envelope envelope,TimeProvider time,CancellationToken ct)
    {
        DateTimeOffset? end;
        try {end=await DocumentRetentionAccess.ReadAsync(db,envelope,ct);}
        catch(InvalidDataException) {throw new PreparationRetentionEvidenceException();}
        DocumentRetentionAccess.Check(end,time);return end;
    }
    internal static int Status(Exception error)=>error is DocumentRetentionExpiredException ? 410 : 503;
    internal static string Message(Exception error)=>error is DocumentRetentionExpiredException ?
        "This demo document has reached its retention deadline and is no longer available." :
        "The saved document preparation could not be verified. Retry later.";
}

public sealed class PreparationRetentionExceptionFilter:IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        if(!context.HttpContext.Request.Path.StartsWithSegments("/draft") || context.Exception is not (DocumentRetentionExpiredException or PreparationRetentionEvidenceException))return;
        var status=SenderPreparationRetention.Status(context.Exception);var message=SenderPreparationRetention.Message(context.Exception);
        var response=context.HttpContext.Response;response.Headers.CacheControl="no-store";response.Headers["Referrer-Policy"]="no-referrer";
        context.Result=SenderConfiguration.WantsJson(context.HttpContext) ? new JsonResult(new{message}){StatusCode=status} : new ContentResult{Content=message,ContentType="text/plain",StatusCode=status};context.ExceptionHandled=true;
    }
}
