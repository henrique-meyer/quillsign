using Microsoft.AspNetCore.Http.Features;

namespace QuillSign.Documents;

public static class DocumentConfiguration
{
    public static IServiceCollection AddQuillSignDocuments(this IServiceCollection services, IConfiguration config)
    {
        var options = config.GetSection("Documents").Get<DocumentOptions>() ?? new();
        var storageMaximum = config.GetValue<long?>("Storage:MaximumBlobBytes") ?? 25 * 1024 * 1024;
        if (options.MaximumBytes < 1024 || options.MaximumBytes > storageMaximum || options.MaximumPages is < 1 or > 200)
            throw new InvalidOperationException("Document limits must fit configured storage and support 1–200 pages.");
        services.AddSingleton(options); services.AddScoped<PdfValidation>(); services.AddScoped<DocumentWorkflow>();
        services.Configure<FormOptions>(form => { form.MultipartBodyLengthLimit = options.MaximumBytes; form.ValueCountLimit = 16; });
        return services;
    }
}
