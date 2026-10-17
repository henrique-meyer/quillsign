using Amazon;
using Amazon.SimpleEmailV2;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace QuillSign.Email;

public static class EmailConfiguration
{
    public static IServiceCollection AddQuillSignEmail(this IServiceCollection services, IConfiguration config, IHostEnvironment environment)
    {
        var options = config.GetSection("Email").Get<EmailOptions>() ?? new();
        options.Attachments.Validate();
        if (options.Enabled || options.Sns.Enabled)
        {
            _ = EmailAddress.Normalize(options.FromEmail);
            if (!Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out var url) ||
                (url.Scheme != "https" && !(environment.IsDevelopment() && url.Scheme == "http" && url.IsLoopback)) ||
                url.UserInfo.Length != 0 || url.Query.Length != 0 || url.Fragment.Length != 0)
                throw new InvalidOperationException("Email:BaseUrl must be HTTPS (local HTTP is Development-only).");
            if (options.FromName.Any(c => c is '\r' or '\n')) throw new InvalidOperationException("Invalid email sender name.");
        }
        if (options.Enabled)
        {
            if (options.Provider == "Ses")
            {
                if (string.IsNullOrWhiteSpace(options.Ses.Region) || string.IsNullOrWhiteSpace(options.Ses.ConfigurationSet))
                    throw new InvalidOperationException("Configure the SES region and configuration set.");
            }
            else if (options.Provider == "Smtp")
            {
                var smtp = options.Smtp;
                if (string.IsNullOrWhiteSpace(smtp.Host) || smtp.Port is < 1 or > 65535 ||
                    (!smtp.UseStartTls && !(environment.IsDevelopment() &&
                        (smtp.Host == "mailpit" || (Uri.TryCreate("http://" + smtp.Host, UriKind.Absolute, out var host) && host.IsLoopback)))))
                    throw new InvalidOperationException("Configure SMTP; unencrypted SMTP is limited to local development.");
            }
            else throw new InvalidOperationException("Email:Provider must be Ses or Smtp.");
        }
        if (options.Sns.Enabled)
        {
            _ = SnsMessageValidator.TopicHost(options.Sns.TopicArn);
            if (string.IsNullOrWhiteSpace(options.Ses.ConfigurationSet))
                throw new InvalidOperationException("Configure the SES configuration set for feedback.");
        }
        services.AddSingleton(options);
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IAmazonSimpleEmailServiceV2>(_ => new AmazonSimpleEmailServiceV2Client(
            new AmazonSimpleEmailServiceV2Config { RegionEndpoint = RegionEndpoint.GetBySystemName(options.Ses.Region), MaxErrorRetry = 0 }));
        services.AddScoped<Func<IEmailTransport>>(sp => () => options.Provider == "Smtp"
            ? new SmtpEmailTransport(options)
            : new SesEmailTransport(sp.GetRequiredService<IAmazonSimpleEmailServiceV2>(), options));
        services.AddScoped<IEmailSender>(sp => new EmailSender(options,
            () => sp.GetRequiredService<Data.QuillSignDbContext>(), sp.GetRequiredService<Func<IEmailTransport>>()));
        services.AddScoped<VerificationEmailTemplate>();
        services.AddScoped<RazorEmailViews>();
        services.AddScoped<DeclineEmailTemplate>();
        services.AddScoped<SignerInvitationTemplate>();
        services.AddScoped<SesFeedbackProcessor>();
        services.AddHttpClient("Sns", client => client.Timeout = TimeSpan.FromSeconds(10))
            .RemoveAllLoggers() // Confirmation URLs contain a subscription token.
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        services.TryAddSingleton<ISnsCertificateTrust, SnsCertificateTrust>();
        services.TryAddSingleton<ISnsCertificateSource, SnsCertificateSource>();
        services.AddSingleton<SnsMessageValidator>();
        return services;
    }
}
