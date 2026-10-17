using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http.Features;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Documents;

namespace QuillSign.Signing;

public static class FieldEditorConfiguration
{
    public const int MaximumRequestBytes = 2 * 1024 * 1024;
    public static IServiceCollection AddQuillSignFieldEditor(this IServiceCollection services, IConfiguration config)
    {
        var options = config.GetSection("FieldEditor").Get<FieldEditorOptions>() ?? new();
        if (options.MaximumFields is < 1 or > 200) throw new InvalidOperationException("FieldEditor:MaximumFields must be between 1 and 200.");
        services.AddSingleton(options); services.AddScoped<FieldEditor>();
        services.AddAntiforgery(options => options.HeaderName = "X-CSRF-TOKEN");
        return services;
    }

    public static void MapFieldEditor(this WebApplication app)
    {
        app.MapMethods("/api/envelopes/{publicId}/fields", ["PATCH"], async (HttpContext context, string publicId,
            IAntiforgery antiforgery, FieldEditor editor, CancellationToken ct) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["Referrer-Policy"]="no-referrer";
            var body = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
            if (body is { IsReadOnly: false }) body.MaxRequestBodySize = MaximumRequestBytes;
            if (context.Request.ContentLength > MaximumRequestBytes) return Results.StatusCode(413);
            try { await antiforgery.ValidateRequestAsync(context); }
            catch (AntiforgeryValidationException) { return Results.Json(new { message = "Your session changed. Copy or export unsaved edits, then reload." }, statusCode: 400); }
            try
            {
                if (!context.Request.HasJsonContentType()) return Results.StatusCode(415);
                var save = await context.Request.ReadFromJsonAsync<FieldSave>(ct);
                if (save is null) return Results.BadRequest(new { message = "Provide document fields." });
                var result = await editor.SaveAsync(context.User, publicId, save, context.Connection.RemoteIpAddress?.ToString(),
                    context.Request.Headers.UserAgent.ToString(), ct);
                var status = result.Error switch { FieldEditorError.None => 200, FieldEditorError.NotFound => 404,
                    FieldEditorError.Conflict => 409, _ => 400 };
                return Results.Json(new { message = result.Message, version = result.Version }, statusCode: status);
            }
            catch (System.Text.Json.JsonException) { return Results.BadRequest(new { message = "Provide valid document fields." }); }
            catch (BadHttpRequestException error) { return Results.Json(new { message = "The field request is invalid or too large." }, statusCode: error.StatusCode); }
            catch(Exception error) when(error is DocumentRetentionExpiredException or PreparationRetentionEvidenceException)
            {return Results.Json(new{message=SenderPreparationRetention.Message(error)},statusCode:SenderPreparationRetention.Status(error));}
            catch (Exception error) when (error.GetBaseException() is Microsoft.Data.SqlClient.SqlException || SqlResume.IsUnavailable(error))
            { return Results.Json(new { message = "We couldn't confirm that save. Your edits are still here; copy or export them before reloading." }, statusCode: 503); }
        }).RequireAuthorization(new Microsoft.AspNetCore.Authorization.AuthorizeAttribute { AuthenticationSchemes = EnvelopeStorageAuthorization.SenderScheme });
    }
}
