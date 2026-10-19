using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using QuillSign.Data;
using QuillSign.Sender;

namespace QuillSign.Documents;

public sealed class PreparationRetentionEvidenceException():Exception("The preparation retention evidence could not be verified.");

internal static class SenderPreparationRetention
{
    // The caller must first authorize the exact private party/envelope and own its lock.
    internal static async Task<DateTimeOffset?> ReadAsync(QuillSignDbContext db,Envelope envelope,TimeProvider time,CancellationToken ct,Email.Pilot.EmailPilotReadBounds? pilotBounds=null)
    {
        DateTimeOffset? end;
        try {end=await DocumentRetentionAccess.ReadAsync(db,envelope,ct,pilotBounds);}
        catch(InvalidDataException) {throw new PreparationRetentionEvidenceException();}
        DocumentRetentionAccess.Check(end,time);return end;
    }
    internal static int Status(Exception error)=>error is DocumentRetentionExpiredException ? 410 : 503;
    internal static string Message(Exception error)=>error is DocumentRetentionExpiredException ?
        "This demo document has reached its retention deadline and is no longer available." :
        "The saved document retention could not be verified. Retry later.";
}

public sealed class PreparationRetentionExceptionFilter(Email.Pilot.EmailPilotReadBounds? pilotBounds=null):IExceptionFilter
{
    public void OnException(ExceptionContext context)
    {
        var path=context.HttpContext.Request.Path;
        if(context.ExceptionHandled || (!path.StartsWithSegments("/draft") && !path.StartsWithSegments("/sign") && !path.StartsWithSegments("/complete") && path!="/sender/verify") ||
            context.Exception is not (DocumentRetentionExpiredException or PreparationRetentionEvidenceException or Email.Pilot.EmailPilotAccessUnavailableException))return;
        var pilot=context.Exception is Email.Pilot.EmailPilotAccessUnavailableException || context.Exception is DocumentRetentionExpiredException && pilotBounds?.HasExpiredSnapshot==true;
        var status=pilot ? 410 : SenderPreparationRetention.Status(context.Exception);
        var message=pilot ? "This restricted test access is unavailable or has ended." : SenderPreparationRetention.Message(context.Exception);
        var response=context.HttpContext.Response;response.Headers.CacheControl="no-store";response.Headers["Referrer-Policy"]="no-referrer";
        context.Result=SenderConfiguration.WantsJson(context.HttpContext) ? new JsonResult(new{message}){StatusCode=status} : new ContentResult{Content=message,ContentType="text/plain",StatusCode=status};context.ExceptionHandled=true;
    }
}
