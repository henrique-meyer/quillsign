using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace QuillSign.Documents;

public sealed class SandboxConversionOptions
{
    public string Region { get; set; } = "";
    public string SubscriptionId { get; set; } = "";
    public string ResourceGroup { get; set; } = "";
    public string GroupName { get; set; } = "";
    public string ManagedIdentityClientId { get; set; } = "";
    public int MaximumDailyAttempts { get; set; } = 10;
    public int MaximumMonthlyAttempts { get; set; } = 50;
    public bool MaintenanceEnabled { get; set; }
    public const string Image = "gotenberg/gotenberg@sha256:aa552cc115db488e0f0bcb07446aac13071ad51505b642c84bb894500907b42b";
    internal static readonly IReadOnlyList<string> Arguments = Array.AsReadOnly(new[] { "gotenberg", "--api-bind-ip=127.0.0.1", "--chromium-disable-routes", "--api-disable-download-from", "--webhook-disable", "--libreoffice-deny-list=.*" });
    public void Validate()
    {
        if (Region is null || ResourceGroup is null || GroupName is null || ManagedIdentityClientId is null ||
            !Regex.IsMatch(Region, "^[a-z][a-z0-9]{1,39}$") || !Guid.TryParseExact(SubscriptionId, "D", out _) ||
            !Regex.IsMatch(ResourceGroup, "^[a-zA-Z0-9_().-]{1,90}$") || ResourceGroup.Contains("..", StringComparison.Ordinal) ||
            !Regex.IsMatch(GroupName, "^[a-zA-Z0-9][a-zA-Z0-9-]{1,62}$") ||
            ManagedIdentityClientId.Length != 0 && !Guid.TryParseExact(ManagedIdentityClientId, "D", out _) ||
            MaximumDailyAttempts is < 1 or > 100 || MaximumMonthlyAttempts is < 1 or > 1000 || MaximumDailyAttempts > MaximumMonthlyAttempts)
            throw new InvalidOperationException("Configure supported sandbox conversion scope and attempt limits.");
    }
    internal Uri Origin { get { Validate(); return new($"https://management.{Region}.azuredevcompute.io/"); } }
    internal string GroupPath => $"subscriptions/{SubscriptionId}/resourceGroups/{Uri.EscapeDataString(ResourceGroup)}/sandboxGroups/{GroupName}/";
    internal string ScopeHash => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes((Origin.AbsoluteUri + GroupPath).ToLowerInvariant())));
}

public interface ISandboxDocxTransport
{
    Task<byte[]> ConvertAsync(Stream source, byte[] sourceSha256, long length, CancellationToken ct);
}

internal static class SandboxConversionErrors
{
    internal static DocumentConversionUnavailableException Unavailable() => new("Document conversion is unavailable. Try again later.");
}
