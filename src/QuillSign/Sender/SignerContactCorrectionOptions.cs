using QuillSign.Data;
using QuillSign.Email;
using QuillSign.Signing;
using QuillSign.Work;

namespace QuillSign.Sender;

public static class SignerContactCorrectionStatement
{
    public const string Version = SignerContactHistory.StatementVersion;
    public const string Text = SignerContactHistory.Statement;
    public static string Sha256 => SignerContactHistory.StatementSha256;
}
public sealed record SignerContactCorrectionReview(Guid SignerId, string Name, string OldEmail, string NewEmail,
    string Version, string SignerVersion, Guid ContactRevisionId, int ContactRevisionNumber,
    Guid DocumentId, string DocumentSha256, string DisclosureSha256);
public sealed record SignerContactCorrectionPreview(string Title, SignerContactCorrectionReview Review, SignerContactCorrectionOutcome? Blocked);
public enum SignerContactCorrectionOutcome
{
    Queued, AlreadyRequested, Unavailable, InvalidContext, InvalidConfirmation, Conflict, Closed, Busy, Capped, Suppressed, DuplicateAddress
}
public sealed class SignerContactCorrectionOptions
{
    public bool Enabled { get; set; }
    public int? DailyAddressRequests { get; set; }
    public int? DailyIpRequests { get; set; }
    public int? DailySenderRequests { get; set; }
    public int? DailyRequests { get; set; }
    public void Validate()
    {
        if (!Enabled) return;
        if (DailyRequests is null or < 1 or > 1000 || DailyAddressRequests is null or < 1 || DailyIpRequests is null or < 1 ||
            DailySenderRequests is null or < 1 || DailyAddressRequests > DailyRequests || DailyIpRequests > DailyRequests || DailySenderRequests > DailyRequests)
            throw new InvalidOperationException("Configure explicit bounded signer contact correction limits before enabling correction.");
    }
}
public static class SignerContactCorrectionConfiguration
{
    public static IServiceCollection AddQuillSignSignerContactCorrections(this IServiceCollection services, IConfiguration config)
    {
        var options = config.GetSection("SignerContactCorrection").Get<SignerContactCorrectionOptions>() ?? new();
        options.Validate(); services.AddSingleton(options);
        // Disabled scanner/custom hosts do not need SQL, work or transport services.
        services.AddScoped<SignerContactCorrections>(sp => new(sp.GetRequiredService<QuillSignDbContext>(), options,
            sp.GetRequiredService<EmailOptions>(), sp.GetRequiredService<WorkOptions>(), sp.GetRequiredService<SignerAccess>(),
            sp.GetRequiredService<InvitationLineage>(), sp.GetRequiredService<InvitationSuccessorJobs>(),
            sp.GetRequiredService<AuditWriter>(), sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<Func<SignerContactCorrections>>(sp => () => sp.GetRequiredService<SignerContactCorrections>());
        if (options.Enabled)
            services.AddScoped<IInvitationSuccessorPolicy>(sp => new SignerContactCorrectionPolicy(sp.GetRequiredService<QuillSignDbContext>(), options,
                sp.GetRequiredService<EmailOptions>(), sp.GetRequiredService<WorkOptions>(), sp.GetRequiredService<TimeProvider>()));
        return services;
    }
}
