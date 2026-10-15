using System.Net;
using Microsoft.Data.SqlClient;

namespace QuillSign.Email;

public static class SnsEndpoint
{
    public static void MapSesFeedback(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/webhooks/ses", HandleAsync);
    }

    private static async Task<IResult> HandleAsync(HttpContext context, EmailOptions options, SnsMessageValidator validator, IHttpClientFactory clients)
    {
        if (!options.Sns.Enabled) return Results.NotFound();
        try
        {
            const int maximum = 512 * 1024;
            if (context.Request.ContentLength > maximum) return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
            var body = await ReadBoundedAsync(context.Request.Body, maximum, context.RequestAborted);
            var message = await validator.ValidateAsync(body, context.RequestAborted);
            if (message.Type == "Notification")
            {
                var feedback = SesFeedback.Parse(message.Message, options);
                if (feedback is not null)
                    await context.RequestServices.GetRequiredService<SesFeedbackProcessor>().ApplyAsync(feedback, context.RequestAborted);
            }
            else if (message.Type == "SubscriptionConfirmation" && options.Sns.AutoConfirmSubscriptions)
            {
                using var response = await clients.CreateClient("Sns").GetAsync(message.ConfirmationUrl, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
                if (response.StatusCode != HttpStatusCode.OK) throw new FeedbackUnavailableException();
            }
            return Results.Accepted();
        }
        catch (InvalidSnsMessageException) { return Results.BadRequest(); }
        catch (FeedbackUnavailableException) { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
        catch (HttpRequestException) { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
        catch (SqlException) { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
        catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested) { return Results.StatusCode(StatusCodes.Status503ServiceUnavailable); }
    }

    internal static async Task<byte[]> ReadBoundedAsync(Stream stream, int maximum, CancellationToken cancellationToken)
    {
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(buffer, cancellationToken)) != 0)
        {
            if (output.Length + count > maximum) throw new InvalidSnsMessageException();
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }
}
