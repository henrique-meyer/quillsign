using Microsoft.AspNetCore.Http.Features;
using QuillSign.Legal;
using QuillSign.Signing;

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
        services.AddSingleton<DocxPackageValidation>();
        services.AddScoped<DocxDocumentWorkflow>();
        services.AddScoped<ImagePdfConverter>();
        var conversion=config.GetSection("Gotenberg").Get<GotenbergOptions>() ?? new();
        services.AddSingleton(conversion);
        services.AddHttpClient<GotenbergDocxConverter>(client=>client.Timeout=Timeout.InfiniteTimeSpan)
            .RemoveAllLoggers()
            .ConfigurePrimaryHttpMessageHandler(()=>new HttpClientHandler {AllowAutoRedirect=false,UseProxy=false,AutomaticDecompression=System.Net.DecompressionMethods.None,MaxResponseHeadersLength=16});
        var retention=config.GetSection("Demo").Get<DemoRetentionOptions>() ?? new();retention.Validate();
        services.AddSingleton(retention);services.AddScoped<UploadRetention>();
        var preparation = config.GetSection("Preparation").Get<PreparationOptions>() ?? new();
        if (preparation.MaximumRecipients is < 1 or > 100) throw new InvalidOperationException("Preparation:MaximumRecipients must be between 1 and 100.");
        services.AddSingleton(preparation); services.AddScoped<DraftDetails>(); services.AddScoped<DraftReview>();
        services.AddSingleton(config.GetSection("ElectronicRecords").Get<ElectronicRecordOptions>() ?? new());
        services.AddSingleton<ElectronicRecordDisclosure>();
        services.AddSingleton(sp => new SenderPdfRenderer(storageMaximum, options.MaximumPages,
            sp.GetRequiredService<FieldEditorOptions>().MaximumFields));
        services.AddSingleton(sp => new SignerPdfRenderer(storageMaximum,options.MaximumPages,
            sp.GetRequiredService<FieldEditorOptions>().MaximumFields));
        services.Configure<FormOptions>(form => { form.MultipartBodyLengthLimit = options.MaximumBytes; form.ValueCountLimit = 16; });
        return services;
    }
}
