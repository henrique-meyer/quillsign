using Amazon;
using Amazon.SimpleEmailV2;
using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Storage;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

// Scope-owned clients are created only by a counted transport boundary. Never
// reuse the ordinary SDK client: its redirect policy is deliberately separate.
public sealed class EmailPilotTransportFactory:IDisposable
{
    private readonly List<IAmazonSimpleEmailServiceV2> clients=[];
    public IPreparedEmailTransport Create(EmailPilotSesSettings settings)
    {
        var client=new AmazonSimpleEmailServiceV2Client(new AmazonSimpleEmailServiceV2Config {
            RegionEndpoint=RegionEndpoint.GetBySystemName(settings.Region),MaxErrorRetry=0,AllowAutoRedirect=false,UseHttp=false });
        clients.Add(client);return new SesPreparedEmailTransport(client,settings);
    }
    public void Dispose(){foreach(var client in clients)client.Dispose();clients.Clear();}
}

public static class EmailPilotRuntime
{
    // Only the explicit Handoff recovery host needs SQL/key-ring authentication.
    // Register no email transport, work handler, or document workflow here.
    internal static IServiceCollection AddCloseoutHandoffRecovery(this IServiceCollection services,IConfiguration config,IHostEnvironment environment)
    {
        var options=config.GetSection("EmailPilot:Closeout").Get<EmailPilotCloseoutOptions>()??new();options.Validate();
        if(options.HostRole!=EmailPilotCloseoutHostRole.Handoff)return services;
        services.AddQuillSignDatabase(config);services.AddQuillSignStorage(config,environment);services.AddEmailPilotFoundation(config);
        services.AddSingleton(config.GetSection("Email").Get<EmailOptions>()??new());services.AddSingleton(options);
        services.AddScoped<EmailPayloadProtection>();services.AddScoped<CompletionNotificationProtection>();services.AddScoped<SignerInvitationProtection>();services.AddScoped<LookupDeliveryProtection>();
        services.AddScoped<EmailPilotCloseout>(sp=>new(options,sp.GetRequiredService<EmailOptions>(),sp.GetRequiredService<WorkOptions>(),()=>sp.GetRequiredService<QuillSignDbContext>(),()=>sp.GetRequiredService<EmailPilotLedger>(),()=>sp.GetRequiredService<EmailPilotProtection>(),sp.GetRequiredService<TimeProvider>()) {Payloads=()=>sp.GetRequiredService<EmailPayloadProtection>(),CompletionPayloads=()=>sp.GetRequiredService<CompletionNotificationProtection>(),InvitationPayloads=()=>sp.GetRequiredService<SignerInvitationProtection>(),LookupPayloads=()=>sp.GetRequiredService<LookupDeliveryProtection>()});
        return services;
    }
    // Install on normal web/worker hosts even when disabled. Persisted pilot
    // cohorts must keep their denial after disable/rotation. All callbacks use
    // this same scope; no singleton captures SQL, credentials or an operator.
    public static IServiceCollection AddRestrictedEmailPilotRuntime(this IServiceCollection services,IConfiguration config,bool privatePass=false,bool privateWeb=false)
    {
        services.AddEmailPilotReadScopeFoundation(config);
        services.AddEmailPilotSimulatorFoundation(config);
        services.AddPilotTimestampBoundaryFoundation(config);
        services.AddEmailPilotSecretCleanup();
        var closeout=config.GetSection("EmailPilot:Closeout").Get<EmailPilotCloseoutOptions>()??new();closeout.Validate();
        if(closeout.HostRole==EmailPilotCloseoutHostRole.Pass&&!privatePass)throw new InvalidOperationException("Pass configuration requires the dedicated filtered command host.");
        if((closeout.HostRole==EmailPilotCloseoutHostRole.Web)!=privateWeb)throw new InvalidOperationException("Web configuration requires the closed private Web host.");
        services.AddSingleton(closeout);
        services.AddScoped<EmailPilotCloseout>(sp=>new(closeout,sp.GetRequiredService<EmailOptions>(),sp.GetRequiredService<WorkOptions>(),
            ()=>sp.GetRequiredService<QuillSignDbContext>(),()=>sp.GetRequiredService<EmailPilotLedger>(),()=>sp.GetRequiredService<EmailPilotProtection>(),sp.GetRequiredService<TimeProvider>()) {
            ReceiptPilotOptions=sp.GetRequiredService<EmailPilotOptions>(),
            Lookup=()=>sp.GetRequiredService<EmailPilotCloseoutLookup>(),Payloads=()=>sp.GetRequiredService<EmailPayloadProtection>(),CompletionPayloads=()=>sp.GetRequiredService<CompletionNotificationProtection>(), VoidPayloads=()=>sp.GetRequiredService<VoidNotificationProtection>(),
            InvitationPayloads=()=>sp.GetRequiredService<SignerInvitationProtection>(),LookupPayloads=()=>sp.GetRequiredService<LookupDeliveryProtection>(),CompletionJobs=()=>sp.GetRequiredService<CompletionNotificationJobs>(),VoidJobs=()=>sp.GetRequiredService<VoidNotificationJobs>() });
        services.AddScoped<EmailPilotCloseoutSender>(sp=>new(sp.GetRequiredService<EmailOptions>(),()=>sp.GetRequiredService<EmailPilotCloseout>(),()=>sp.GetRequiredService<QuillSignDbContext>(),
            sp.GetRequiredService<Func<EmailPilotSesSettings,IPreparedEmailTransport>>(),sp.GetRequiredService<TimeProvider>()));
        services.AddEmailPilotCloseoutActions();
        services.AddScoped<EmailPilotCloseoutPass>();
        services.AddScoped<EmailPilotTransportFactory>();
        services.AddScoped<Func<EmailPilotSesSettings,IPreparedEmailTransport>>(sp=>settings=>sp.GetRequiredService<EmailPilotTransportFactory>().Create(settings));
        services.AddScoped<EmailPilotSender>(sp=>new(sp.GetRequiredService<EmailPilotOptions>(),sp.GetRequiredService<EmailOptions>(),sp.GetRequiredService<WorkOptions>(),
            ()=>sp.GetRequiredService<EmailPilotWorkAuthority>(),()=>sp.GetRequiredService<EmailPilotLedger>(),()=>sp.GetRequiredService<QuillSignDbContext>(),
            sp.GetRequiredService<Func<EmailPilotSesSettings,IPreparedEmailTransport>>(),sp.GetRequiredService<TimeProvider>()) {Closeout=()=>sp.GetRequiredService<EmailPilotCloseout>(),CloseoutSender=()=>sp.GetRequiredService<EmailPilotCloseoutSender>()});
        services.AddScoped<EmailPilotDispatch>(sp=>new(sp.GetRequiredService<QuillSignDbContext>(),sp.GetRequiredService<EmailOptions>(),
            ()=>sp.GetRequiredService<EmailPilotWorkAuthority>(),(lease,message,ct)=>sp.GetRequiredService<EmailPilotSender>().SendAsync(lease,message,ct),sp.GetRequiredService<IEmailSender>()));
        services.AddScoped<EmailPilotSimulatorSender>(sp=>new(sp.GetRequiredService<EmailPilotOptions>(),sp.GetRequiredService<EmailOptions>(),sp.GetRequiredService<WorkOptions>(),
            ()=>sp.GetRequiredService<EmailPilotSimulatorAuthority>(),()=>sp.GetRequiredService<EmailPilotLedger>(),()=>sp.GetRequiredService<QuillSignDbContext>(),
            sp.GetRequiredService<Func<EmailPilotSesSettings,IPreparedEmailTransport>>(),sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<Func<EmailPilotSimulatorSender>>(sp=>()=>sp.GetRequiredService<EmailPilotSimulatorSender>());
        services.AddScoped<EmailPilotSimulatorDelivery>();
        services.AddScoped<Func<EmailPilotSimulatorDelivery>>(sp=>()=>sp.GetRequiredService<EmailPilotSimulatorDelivery>());
        services.AddScoped<EmailPilotLookupAccess>(sp=>new(()=>sp.GetRequiredService<QuillSignDbContext>(),()=>sp.GetRequiredService<EmailPilotProtection>(),
            ()=>sp.GetRequiredService<EmailPilotEnvelopeAccess>(),()=>sp.GetRequiredService<EmailPilotLedger>(),sp.GetRequiredService<EmailPilotAdmissionOptions>(),
            sp.GetRequiredService<WorkOptions>(),()=>sp.GetRequiredService<LookupDeliveryProtection>(),()=>sp.GetRequiredService<LookupContactRetention>(),
            sp.GetRequiredService<LookupDeliveryOptions>(),()=>sp.GetRequiredService<CompletionAccessState>(),sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<EmailPilotLookupAdmission>(sp=>new(sp.GetRequiredService<EmailPilotOptions>(),sp.GetRequiredService<EmailOptions>(),sp.GetRequiredService<WorkOptions>(),
            sp.GetRequiredService<EmailPilotAdmissionOptions>(),()=>sp.GetRequiredService<QuillSignDbContext>(),()=>sp.GetRequiredService<EmailPilotLedger>(),
            ()=>sp.GetRequiredService<EmailPilotEnvelopeAccess>(),()=>sp.GetRequiredService<CompletionAccessState>(),()=>sp.GetRequiredService<DocumentLookupRequests>(),
            ()=>sp.GetRequiredService<EmailPilotLookupAccess>(),()=>sp.GetRequiredService<EmailPilotProtection>(),()=>sp.GetRequiredService<LookupContactRetention>(),
            ()=>sp.GetRequiredService<IWorkSignals>(),sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<EmailPilotLookupSender>(sp=>new(sp.GetRequiredService<EmailPilotOptions>(),sp.GetRequiredService<EmailOptions>(),sp.GetRequiredService<WorkOptions>(),
            ()=>sp.GetRequiredService<EmailPilotLookupAccess>(),()=>sp.GetRequiredService<EmailPilotLedger>(),()=>sp.GetRequiredService<QuillSignDbContext>(),
            sp.GetRequiredService<Func<EmailPilotSesSettings,IPreparedEmailTransport>>(),sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<Func<EmailPilotLookupSender>>(sp=>()=>sp.GetRequiredService<EmailPilotLookupSender>());
        services.AddScoped<EmailPilotOperatorBrowser>(sp=>new(sp.GetRequiredService<EmailPilotOptions>(),sp.GetRequiredService<EmailPilotAdmissionOptions>(),
            sp.GetRequiredService<EmailOptions>(),sp.GetRequiredService<WorkOptions>(),sp.GetRequiredService<TimeProvider>(),sp.GetRequiredService<IHostEnvironment>(),
            ()=>sp.GetRequiredService<IDataProtectionProvider>()));
        services.AddScoped<EmailPilotOperator>(sp=>new(sp.GetRequiredService<EmailPilotOperatorBrowser>(),()=>sp.GetRequiredService<EmailPilotLedger>(),
            ()=>sp.GetRequiredService<EmailPilotSecretJobs>(),()=>sp.GetRequiredService<EmailPilotAdmission>(),()=>sp.GetRequiredService<EmailPilotLookupAdmission>(),
            ()=>sp.GetRequiredService<EmailPilotSimulatorAdmission>()));
        services.AddScoped<Func<EmailPilotOperator>>(sp=>()=>sp.GetRequiredService<EmailPilotOperator>());
        return services;
    }
}
