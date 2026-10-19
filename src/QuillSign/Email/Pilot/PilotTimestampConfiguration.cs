using Microsoft.Extensions.DependencyInjection.Extensions;
using QuillSign.Data;

namespace QuillSign.Email.Pilot;

public static class PilotTimestampConfiguration
{
    // Explicit source-only composition. Application/worker startup does not call it.
    public static IServiceCollection AddPilotTimestampBoundaryFoundation(this IServiceCollection services,IConfiguration configuration)
    {
        services.AddEmailPilotWorkScopeFoundation(configuration);
        services.TryAddSingleton<PilotTimestampPolicy>();
        services.AddScoped<PilotTimestampBoundary>(sp=>new(()=>sp.GetRequiredService<QuillSignDbContext>(),
            ()=>sp.GetRequiredService<EmailPilotWorkAuthority>(),()=>sp.GetRequiredService<EmailPilotLedger>(),sp.GetRequiredService<TimeProvider>()));
        return services;
    }
}
