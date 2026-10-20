using Microsoft.AspNetCore.Http.Features;
using QuillSign.Legal;
using QuillSign.Signing;
using QuillSign.Lifecycle;

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
        services.Configure<Microsoft.AspNetCore.Mvc.MvcOptions>(mvc=>mvc.Filters.Add<PreparationRetentionExceptionFilter>());
        services.AddSingleton<DocxPackageValidation>();
        services.AddSingleton<PptxPackageValidation>();
        services.AddSingleton<XlsxPackageValidation>();
        services.AddSingleton<OdtPackageValidation>();
        services.AddSingleton<RtfPackageValidation>();
        services.AddSingleton(config.GetSection("OfficeConversion").Get<OfficeConversionOptions>()??new());
        services.AddScoped<StaticOfficeConverter>();
        services.AddScoped<OfficeDocumentWorkflow>();
        services.AddScoped<DocxDocumentWorkflow>();
        services.AddScoped<TextPdfConverter>();
        services.AddScoped<TextDocumentWorkflow>();
        services.AddScoped<ImagePdfConverter>();
        services.AddScoped<ImageDocumentWorkflow>();
        var conversion=config.GetSection("Gotenberg").Get<GotenbergOptions>() ?? new();
        services.AddSingleton(conversion);
        services.AddSandboxDocumentConversion(config,conversion,options);
        services.AddHttpClient<GotenbergDocxConverter>(client=>client.Timeout=Timeout.InfiniteTimeSpan)
            .RemoveAllLoggers()
            .ConfigurePrimaryHttpMessageHandler(()=>new HttpClientHandler {AllowAutoRedirect=false,UseProxy=false,AutomaticDecompression=System.Net.DecompressionMethods.None,MaxResponseHeadersLength=16});
        var retention=config.GetSection("Demo").Get<DemoRetentionOptions>() ?? new();retention.Validate();
        services.AddSingleton(retention);services.AddScoped<UploadRetention>();
        var preparation = config.GetSection("Preparation").Get<PreparationOptions>() ?? new();
        if (preparation.MaximumRecipients is < 1 or > 100) throw new InvalidOperationException("Preparation:MaximumRecipients must be between 1 and 100.");
        services.AddSingleton(preparation); services.AddScoped<DraftDetails>(); services.AddScoped<DraftReview>();
        var disclosure=config.GetSection("ElectronicRecords").Get<ElectronicRecordOptions>() ?? new();
        var records=config.GetSection("Records").Get<RecordLifecycleOptions>() ?? new();
        // Pure operator preflight: no record, SQL connection, provider request or email.
        // Production can never inherit the synthetic profile or incomplete policies.
        _=ProductionRetentionAdmission.Prepare("preflight@example.invalid",TimeProvider.System.GetUtcNow(),records,disclosure);
        services.AddSingleton(records);services.AddSingleton(disclosure);
        services.AddSingleton<ElectronicRecordDisclosure>();
        services.AddSingleton(sp => new SenderPdfRenderer(storageMaximum, options.MaximumPages,
            sp.GetRequiredService<FieldEditorOptions>().MaximumFields));
        services.AddSingleton(sp => new SignerPdfRenderer(storageMaximum,options.MaximumPages,
            sp.GetRequiredService<FieldEditorOptions>().MaximumFields));
        services.Configure<FormOptions>(form => { form.MultipartBodyLengthLimit = options.MaximumBytes; form.ValueCountLimit = 16; });
        return services;
    }
}
