using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Queues;
using QuillSign.Signing;
using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Sealing;
using QuillSign.Storage;
using QuillSign.Completion;

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
            services.AddLookupDeliveryWork(config);
            var resendOptions=config.GetSection("InvitationResend").Get<InvitationResendOptions>()??new();resendOptions.Validate();
            services.TryAddSingleton(resendOptions);services.AddScoped<InvitationResendProtection>();
            services.AddScoped<InvitationSuccessorProtection>();services.AddScoped<InvitationLineage>();
            services.AddScoped<InvitationSuccessorJobs>();services.AddScoped<InvitationSuccessorDelivery>();
            services.AddScoped<Func<InvitationSuccessorDelivery>>(sp=>()=>sp.GetRequiredService<InvitationSuccessorDelivery>());
            services.AddScoped<QuillSign.Sender.InvitationResends>();services.AddScoped<InvitationResendDelivery>();
            services.AddScoped<Func<InvitationResendDelivery>>(sp=>()=>sp.GetRequiredService<InvitationResendDelivery>());
            services.AddCompletionNotificationWork(config);
            services.AddVoidNotificationWork();
            services.AddQuillSignSignerAccessCore(config);
            services.AddScoped<SignerInvitationProtection>(); services.AddScoped<SignerInvitationOutbox>(); services.AddScoped<SignerInvitationDelivery>();
            services.AddScoped<DeclinePayloadProtection>();
            services.AddScoped<DeclineNotificationWriter>();
            services.AddScoped<WorkStore>();
            services.AddScoped<WorkProcessor>();
            services.AddDemoPurgeRecovery();services.AddScoped<QuillSign.Storage.DemoPurgeSql>();services.AddScoped<DemoPurgeJobs>();
            services.AddScoped<Func<QuillSign.Storage.DemoPurgeSql>>(sp=>()=>sp.GetRequiredService<QuillSign.Storage.DemoPurgeSql>());
            services.AddScoped<Func<QuillSign.Storage.DemoPurgeRecovery>>(sp=>()=>sp.GetRequiredService<QuillSign.Storage.DemoPurgeRecovery>());
            services.AddScoped<IWorkHandler,DemoPurgeHandler>();
            services.AddScoped<EmailPayloadProtection>();
            services.AddScoped<EmailOutboxWriter>();
            services.AddScoped<IWorkHandler, EmailWorkHandler>();
            services.AddScoped<SignerCheckpointJobs>(); services.AddScoped<SignerCheckpointState>(); services.AddScoped<SignerCheckpointBlobs>();
            services.AddScoped<SigningExpiry>();
            services.AddScoped<SigningExpiryJobs>();services.AddScoped<IWorkHandler,SigningExpiryHandler>();
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

public static class LookupDeliveryWorkConfiguration
{
    public static IServiceCollection AddLookupDeliveryWork(this IServiceCollection services, IConfiguration config)
    {
        var options = config.GetSection("DocumentLookupDelivery").Get<LookupDeliveryOptions>() ?? new(); options.Validate();
        services.TryAddSingleton(options);
        var retention = new LookupContactRetentionOptions { Days = config.GetValue<int?>("Demo:PurgeAfterDays") }; retention.Validate();
        services.TryAddSingleton(retention); services.TryAddScoped<LookupContactRetention>(); services.TryAddScoped<LookupContactCleanup>();
        services.TryAddScoped<Func<LookupContactCleanup>>(sp => () => sp.GetRequiredService<LookupContactCleanup>());
        services.AddDocumentLookup(config);
        services.TryAddScoped<LookupDeliveryProtection>(); services.TryAddScoped<DocumentLookupRequests>(); services.TryAddScoped<LookupLinkDelivery>();
        services.TryAddScoped<QuillSign.Email.LookupEmailTemplate>();
        services.TryAddScoped<Func<QuillSign.Completion.DocumentLookup>>(sp => () => sp.GetRequiredService<QuillSign.Completion.DocumentLookup>());
        services.TryAddScoped<Func<QuillSign.Email.LookupEmailTemplate>>(sp => () => sp.GetRequiredService<QuillSign.Email.LookupEmailTemplate>());
        services.TryAddScoped<Func<LookupLinkDelivery>>(sp => () => sp.GetRequiredService<LookupLinkDelivery>());
        return services;
    }
}

public static class VoidNotificationWorkConfiguration
{
    public static IServiceCollection AddVoidNotificationWork(this IServiceCollection services)
    {
        // Worker-only and scanner-safe hosts resolve SQL dependencies only on use.
        services.TryAddScoped<QuillSign.Sender.SenderVoidState>(sp=> {
            var db=sp.GetRequiredService<QuillSign.Data.QuillSignDbContext>();var clock=sp.GetRequiredService<TimeProvider>();
            return new(db,new(db,clock),clock);
        });
        services.TryAddScoped<VoidNotificationProtection>();
        services.TryAddScoped<VoidNotificationJobs>(sp=>ActivatorUtilities.CreateInstance<VoidNotificationJobs>(sp));
        services.TryAddScoped<VoidNotificationDelivery>(sp=>ActivatorUtilities.CreateInstance<VoidNotificationDelivery>(sp));
        services.TryAddScoped<QuillSign.Email.VoidEmailTemplate>(sp=>ActivatorUtilities.CreateInstance<QuillSign.Email.VoidEmailTemplate>(sp));
        services.TryAddScoped<Func<VoidNotificationJobs>>(sp=>()=>sp.GetRequiredService<VoidNotificationJobs>());
        services.TryAddScoped<Func<VoidNotificationDelivery>>(sp=>()=>sp.GetRequiredService<VoidNotificationDelivery>());
        services.TryAddScoped<Func<QuillSign.Email.VoidEmailTemplate>>(sp=>()=>sp.GetRequiredService<QuillSign.Email.VoidEmailTemplate>());
        return services;
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
