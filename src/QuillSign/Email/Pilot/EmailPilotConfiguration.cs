using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public static class EmailPilotConfiguration
{
    // Source-only composition: application/worker startup still does not call it.
    public static IServiceCollection AddEmailPilotWorkScopeFoundation(this IServiceCollection services,IConfiguration configuration)
    {
        services.AddEmailPilotAdmissionFoundation(configuration);
        services.AddScoped<EmailPilotWorkAuthority>(sp=>new(sp.GetRequiredService<EmailPilotOptions>(),sp.GetService<EmailOptions>()??new(),sp.GetService<Work.WorkOptions>()??new(),
            sp.GetRequiredService<EmailPilotAdmissionOptions>(),
            ()=>sp.GetRequiredService<EmailPilotLedger>(),()=>sp.GetRequiredService<QuillSignDbContext>(),
            ()=>sp.GetRequiredService<Work.EmailPayloadProtection>(),sp.GetRequiredService<TimeProvider>()));
        return services;
    }

    // Also unregistered from application startup until full pipeline gating is ready.
    public static IServiceCollection AddEmailPilotAdmissionFoundation(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddEmailPilotFoundation(configuration);
        var admission=configuration.GetSection("EmailPilot:Admission").Get<EmailPilotAdmissionOptions>() ?? new();
        services.AddSingleton(admission);
        services.AddScoped<EmailPilotAdmission>(sp=>new(sp.GetRequiredService<EmailPilotOptions>(),admission,
            sp.GetService<EmailOptions>() ?? new(),sp.GetService<Work.WorkOptions>() ?? new(),sp.GetService<Sender.SenderOptions>() ?? new(),
            ()=>sp.GetRequiredService<Sender.SenderAvailability>(),()=>sp.GetRequiredService<EmailPilotLedger>(),
            ()=>sp.GetRequiredService<Work.EmailOutboxWriter>(),()=>sp.GetRequiredService<Work.EmailPayloadProtection>(),sp.GetRequiredService<TimeProvider>()));
        return services;
    }

    // Not called by application startup until the complete provider/admission
    // integration is checked. Disabled custom hosts resolve no SQL or key ring.
    public static IServiceCollection AddEmailPilotFoundation(this IServiceCollection services, IConfiguration configuration)
    {
        var options = configuration.GetSection("EmailPilot").Get<EmailPilotOptions>() ?? new(); options.Validate();
        services.AddSingleton(options); services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<EmailPilotProtection>();
        services.AddScoped<EmailPilotLedger>(sp => new(options, sp.GetService<EmailOptions>() ?? new(),
            () => sp.GetRequiredService<QuillSignDbContext>(), () => sp.GetRequiredService<EmailPilotProtection>(), sp.GetRequiredService<TimeProvider>()));
        return services;
    }
}
