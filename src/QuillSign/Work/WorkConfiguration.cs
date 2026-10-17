using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using QuillSign.Signing;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Sealing;

namespace QuillSign.Work;

public static class WorkConfiguration
{
    public static IServiceCollection AddQuillSignWork(this IServiceCollection services, IConfiguration config, IHostEnvironment environment, bool registerHandlers = true)
    {
        var options = config.GetSection("Work").Get<WorkOptions>() ?? new();
        if (options.MaximumAttempts is < 1 or > 10 || options.LeaseSeconds is < 300 or > 3600 ||
            options.VisibilitySeconds < options.LeaseSeconds + 60 || options.VisibilitySeconds > 7200)
            throw new InvalidOperationException("Invalid work retry/lease configuration.");
        services.AddSingleton(options);
        services.AddScoped<Func<IWorkSignals>>(sp => () => sp.GetRequiredService<IWorkSignals>());
        services.AddSingleton(TimeProvider.System);
        if (options.Enabled)
        {
            if (config["Storage:Provider"] is not ("Azure" or "Azurite"))
                throw new InvalidOperationException("Durable work requires persistent configured storage.");
            static bool Name(string value) => System.Text.RegularExpressions.Regex.IsMatch(value, "^[a-z0-9](?:[a-z0-9]|-(?!-)){1,61}[a-z0-9]$");
            if (!Name(options.QueueName) || !Name(options.HintContainer)) throw new InvalidOperationException("Configure valid work queue and hint container names.");
            var local = config["Storage:Provider"] == "Azurite";
            if (local && !environment.IsDevelopment()) throw new InvalidOperationException("Work emulators are Development-only.");
            services.AddSingleton<IWorkSignals>(_ =>
            {
                QueueClient queue;
                BlobContainerClient hints;
                if (local)
                {
                    var connection = config["Storage:ConnectionString"] ?? "";
                    queue = new QueueClient(connection, options.QueueName, new QueueClientOptions(QueueClientOptions.ServiceVersion.V2023_11_03));
                    hints = new BlobServiceClient(connection, new BlobClientOptions(BlobClientOptions.ServiceVersion.V2023_11_03)).GetBlobContainerClient(options.HintContainer);
                    if ((!queue.Uri.IsLoopback && queue.Uri.Host != "azurite") || (!hints.Uri.IsLoopback && hints.Uri.Host != "azurite"))
                        throw new InvalidOperationException("Work emulators must use local endpoints.");
                }
                else
                {
                    var credential = string.IsNullOrWhiteSpace(config["Storage:ManagedIdentityClientId"])
                        ? new ManagedIdentityCredential(ManagedIdentityId.SystemAssigned)
                        : new ManagedIdentityCredential(ManagedIdentityId.FromUserAssignedClientId(config["Storage:ManagedIdentityClientId"]!));
                    queue = new QueueServiceClient(Endpoint(options.QueueServiceUri), credential).GetQueueClient(options.QueueName);
                    hints = new BlobServiceClient(Endpoint(config["Storage:BlobServiceUri"] ?? ""), credential).GetBlobContainerClient(options.HintContainer);
                }
                return new AzureWorkSignals(queue, hints, options, local);
            });
        }
        else services.AddSingleton<IWorkSignals>(_ => throw new InvalidOperationException("Durable work is disabled."));
        if (registerHandlers)
        {
            services.AddCompletionNotificationWork(config);
            services.AddQuillSignSignerAccessCore(config);
            services.AddScoped<SignerInvitationProtection>(); services.AddScoped<SignerInvitationOutbox>(); services.AddScoped<SignerInvitationDelivery>();
            services.AddScoped<DeclinePayloadProtection>();
            services.AddScoped<DeclineNotificationWriter>();
            services.AddScoped<WorkStore>();
            services.AddScoped<WorkProcessor>();
            services.AddScoped<EmailPayloadProtection>();
            services.AddScoped<EmailOutboxWriter>();
            services.AddScoped<IWorkHandler, EmailWorkHandler>();
            services.AddScoped<SignerCheckpointJobs>(); services.AddScoped<SignerCheckpointState>(); services.AddScoped<SignerCheckpointBlobs>();
            services.AddScoped<QuillSign.Completion.CompletionCommitScope>();
            services.AddScoped<CompletionJobs>(); services.AddScoped<CompletionPipeline>();
            services.AddScoped<Func<CompletionPipeline>>(sp=>()=>sp.GetRequiredService<CompletionPipeline>());
            services.AddScoped<IWorkHandler,CompletionWorkHandler>();
            services.AddScoped<QuillSign.Completion.CompletionEvidenceCollector>();
            services.AddSingleton<QuillSign.Completion.CompletionCertificateRenderer>();
            services.AddScoped<QuillSign.Completion.CompletionCandidates>();
            services.AddPlatformPdfSeals(config);
            services.AddScoped<QuillSign.Completion.CompletionSealOutputs>();
            services.AddSingleton(new QuillSign.Completion.CompletionPublicationOptions {
                CompletedDays=config.GetValue<int?>("Retention:CompletedDays"),DemoPurgeAfterDays=config.GetValue<int?>("Demo:PurgeAfterDays"),
                AllowDevelopmentWriteOnce=config.GetValue<bool>("Completion:AllowDevelopmentWriteOnce")});
            // Worker-only/custom storage setups remain lazy. Real storage registration replaces
            // this fallback; publication cannot run until its dedicated final store is configured.
            services.TryAddSingleton<QuillSign.Storage.ICompletionFinalStore>(_=>throw new InvalidOperationException("Configure final packet storage before publication."));
            services.AddScoped<QuillSign.Completion.CompletionPublication>();
            services.AddScoped<IWorkHandler,SignerCheckpointHandler>();
        }
        return services;
    }

    private static Uri Endpoint(string value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.AbsolutePath != "/")
            throw new InvalidOperationException("Work requires HTTPS service endpoints without credentials or paths.");
        return uri;
    }
}

public static class CompletionNotificationWorkConfiguration
{
    public static IServiceCollection AddCompletionNotificationWork(this IServiceCollection services,IConfiguration config)
    {
        QuillSign.Completion.CompletionAccessConfiguration.AddCompletionAccess(services,config);
        services.TryAddScoped<CompletionNotificationProtection>();services.TryAddScoped<CompletionNotificationJobs>();services.TryAddScoped<CompletionNotificationDelivery>();
        services.TryAddScoped<Func<CompletionNotificationJobs>>(sp=>()=>sp.GetRequiredService<CompletionNotificationJobs>());
        services.TryAddScoped<Func<CompletionNotificationDelivery>>(sp=>()=>sp.GetRequiredService<CompletionNotificationDelivery>());
        services.TryAddScoped<Func<QuillSign.Email.CompletionEmailTemplate>>(sp=>()=>sp.GetRequiredService<QuillSign.Email.CompletionEmailTemplate>());
        return services;
    }
}
