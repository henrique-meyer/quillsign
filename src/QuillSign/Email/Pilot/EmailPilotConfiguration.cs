using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public static class EmailPilotConfiguration
{
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
