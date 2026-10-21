using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;

namespace QuillSign.Lifecycle;

internal enum ProductionOperatorPermission { Status, PlaceHold, ReleaseHold, ReadEvidence }
internal sealed record ProductionOperatorGrant(string Issuer, string Subject, IReadOnlySet<ProductionOperatorPermission> Permissions);
internal sealed record ProductionOperatorPolicy(bool Enabled, IReadOnlyList<ProductionOperatorGrant> Grants);

// An adapter for the future dedicated authentication handler, not a token validator.
// No route, middleware, DI registration or participant principal calls this yet.
internal sealed class ProductionOperatorAuthority
{
    internal const string CookieScheme = "QuillSign.ProductionOperator.Cookie";
    internal const string OidcScheme = "QuillSign.ProductionOperator.Oidc";
    internal static readonly TimeSpan MaximumSession = TimeSpan.FromMinutes(5);
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    internal string Issuer { get; }
    internal string Subject { get; }
    internal DateTimeOffset ExpiresAt { get; }
    private DateTimeOffset IssuedAt { get; }
    internal ProductionOperatorPermission Permission { get; }

    private ProductionOperatorAuthority(string issuer, string subject, DateTimeOffset issuedAt, DateTimeOffset expiresAt, ProductionOperatorPermission permission)
        => (Issuer, Subject, IssuedAt, ExpiresAt, Permission) = (issuer, subject, issuedAt, expiresAt, permission);

    internal static ProductionOperatorAuthority FromValidatedTicket(AuthenticationTicket ticket, ProductionOperatorPolicy policy,
        ProductionOperatorPermission permission, TimeProvider time)
    {
        var now = time.GetUtcNow();
        if (ticket.AuthenticationScheme != CookieScheme || ticket.Properties.IssuedUtc is not { } issued ||
            ticket.Properties.ExpiresUtc is not { } expiry || issued.Offset != TimeSpan.Zero || expiry.Offset != TimeSpan.Zero ||
            issued > now || expiry <= now || expiry <= issued || expiry - issued > MaximumSession) throw Denied();
        var identities = ticket.Principal.Identities.ToArray();
        if (identities.Length != 1 || !identities[0].IsAuthenticated || identities[0].AuthenticationType != OidcScheme) throw Denied();
        var issuer = One(identities[0], "iss");
        var subject = One(identities[0], "sub");
        if (subject.Issuer != issuer.Value || issuer.Issuer != issuer.Value) throw Denied();
        var result = new ProductionOperatorAuthority(issuer.Value, subject.Value, issued, expiry, permission);
        result.Demand(policy, permission, time);
        return result;
    }

    // Invoke again at each command/commit boundary with the current operator grants.
    // A cached authority cannot outlive its ticket or a revoked permission.
    internal void Demand(ProductionOperatorPolicy policy, ProductionOperatorPermission required, TimeProvider time)
    {
        if (!policy.Enabled || required != Permission || !Enum.IsDefined(required) || ExpiresAt <= time.GetUtcNow() || IssuedAt > time.GetUtcNow() ||
            policy.Grants is null || policy.Grants.Count is < 1 or > 256 || !ValidIssuer(Issuer) || !Text(Subject, 256)) throw Denied();
        var matching = policy.Grants.Where(x => x is not null && x.Issuer == Issuer && x.Subject == Subject).ToArray();
        if (matching.Length != 1 || matching[0].Permissions is null || matching[0].Permissions.Count is < 1 or > 4 ||
            matching[0].Permissions.Any(x => !Enum.IsDefined(x)) || !matching[0].Permissions.Contains(required)) throw Denied();
    }

    private static Claim One(ClaimsIdentity identity, string type)
    {
        var values = identity.FindAll(type).Take(2).ToArray();
        return values.Length == 1 ? values[0] : throw Denied();
    }
    private static bool ValidIssuer(string value) => Text(value, 2048) && Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Query) && string.IsNullOrEmpty(uri.Fragment);
    internal static bool Text(string? value, int maximum)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum || value.Trim() != value || value.Any(char.IsControl)) return false;
        try { _ = StrictUtf8.GetByteCount(value); return true; }
        catch (EncoderFallbackException) { return false; }
    }
    internal static UnauthorizedAccessException Denied() => new("Production operator authority is unavailable.");
}
