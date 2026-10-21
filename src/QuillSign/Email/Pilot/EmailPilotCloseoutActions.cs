using Microsoft.AspNetCore.DataProtection;
using QuillSign.Completion;
using QuillSign.Data;
using QuillSign.Work;

namespace QuillSign.Email.Pilot;

public static class EmailPilotCloseoutActions
{
    internal static IServiceCollection AddEmailPilotCloseoutActions(this IServiceCollection services)
    {
        services.AddScoped<EmailPilotCloseoutOperatorBrowser>(sp=>new(sp.GetRequiredService<EmailPilotCloseoutOptions>(),sp.GetRequiredService<EmailOptions>(),
            sp.GetRequiredService<WorkOptions>(),sp.GetRequiredService<TimeProvider>(),sp.GetRequiredService<IHostEnvironment>(),()=>sp.GetRequiredService<IDataProtectionProvider>()));
        services.AddScoped<EmailPilotCloseoutLookup>(sp=>new(sp.GetRequiredService<QuillSignDbContext>(),()=>sp.GetRequiredService<EmailPilotCloseout>(),
            sp.GetRequiredService<CompletionAccessState>(),sp.GetRequiredService<LookupDeliveryProtection>(),sp.GetRequiredService<LookupContactRetention>(),
            sp.GetRequiredService<LookupDeliveryOptions>(),sp.GetRequiredService<DocumentLookupOptions>(),sp.GetRequiredService<DocumentLookupProtection>(),
            ()=>sp.GetRequiredService<LookupEmailTemplate>(),()=>sp.GetRequiredService<EmailPilotCloseoutSender>(),()=>sp.GetRequiredService<IWorkSignals>(),sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<EmailPilotCloseoutOperator>(sp=>new(sp.GetRequiredService<EmailPilotCloseoutOperatorBrowser>(),()=>sp.GetRequiredService<EmailPilotCloseout>(),
            ()=>sp.GetRequiredService<QuillSignDbContext>(),()=>sp.GetRequiredService<EmailOutboxWriter>(),()=>sp.GetRequiredService<EmailPilotCloseoutLookup>(),
            ()=>sp.GetRequiredService<IWorkSignals>(),sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<Func<EmailPilotCloseoutOperator>>(sp=>()=>sp.GetRequiredService<EmailPilotCloseoutOperator>());
        return services;
    }
}
