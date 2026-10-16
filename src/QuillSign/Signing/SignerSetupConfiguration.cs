namespace QuillSign.Signing;

public static class SignerSetupConfiguration
{
    public static IServiceCollection AddQuillSignSignerSetup(this IServiceCollection services, IConfiguration config)
    {
        var options = config.GetSection("Signing").Get<SignerSetupOptions>() ?? new();
        if (options.MaximumSigners is < 1 or > 100)
            throw new InvalidOperationException("Signing:MaximumSigners must be between 1 and 100.");
        services.AddSingleton(options);
        services.AddScoped<SignerSetup>();
        return services;
    }
}
