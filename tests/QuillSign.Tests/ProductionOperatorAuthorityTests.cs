using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using QuillSign.Lifecycle;

namespace QuillSign.Tests;

public sealed class ProductionOperatorAuthorityTests
{
    private const string Issuer = "https://operator.synthetic.invalid", Subject = "synthetic-operator";
    private static readonly DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
    private static ProductionOperatorPolicy Policy(params ProductionOperatorPermission[] grants) =>
        new(true, [new(Issuer, Subject, grants.ToHashSet())]);
    private static AuthenticationTicket Ticket(string scheme = ProductionOperatorAuthority.CookieScheme,
        string authenticationType = ProductionOperatorAuthority.OidcScheme, string issuer = Issuer, string subject = Subject)
        => new(new ClaimsPrincipal(new ClaimsIdentity([new("iss", issuer, ClaimValueTypes.String, issuer),
            new("sub", subject, ClaimValueTypes.String, issuer)], authenticationType)),
            new AuthenticationProperties { IssuedUtc = Now.AddMinutes(-1), ExpiresUtc = Now.AddMinutes(4) }, scheme);
    private sealed class Clock(DateTimeOffset now) : TimeProvider { public override DateTimeOffset GetUtcNow() => now; }

    [Theory]
    [InlineData("participant", ProductionOperatorAuthority.OidcScheme)]
    [InlineData(ProductionOperatorAuthority.CookieScheme, "participant")]
    [InlineData(ProductionOperatorAuthority.CookieScheme, "QuillSign.PilotOperator")]
    [InlineData(ProductionOperatorAuthority.CookieScheme, "")]
    public void Participant_pilot_and_generic_identity_schemes_never_grant_operator_access(string cookie, string identity)
        => Assert.Throws<UnauthorizedAccessException>(() => ProductionOperatorAuthority.FromValidatedTicket(Ticket(cookie, identity),
            Policy(ProductionOperatorPermission.PlaceHold), ProductionOperatorPermission.PlaceHold, new Clock(Now)));

    [Fact]
    public void Place_permission_grants_neither_release_nor_sensitive_record_reads()
    {
        var policy = Policy(ProductionOperatorPermission.PlaceHold);
        var authority = ProductionOperatorAuthority.FromValidatedTicket(Ticket(), policy, ProductionOperatorPermission.PlaceHold, new Clock(Now));
        Assert.Equal(Now.AddMinutes(4), authority.ExpiresAt);
        foreach (var denied in new[] { ProductionOperatorPermission.ReleaseHold, ProductionOperatorPermission.ReadEvidence, ProductionOperatorPermission.Status })
            Assert.Throws<UnauthorizedAccessException>(() => authority.Demand(policy, denied, new Clock(Now)));
        Assert.Throws<UnauthorizedAccessException>(() => authority.Demand(policy with { Enabled = false }, ProductionOperatorPermission.PlaceHold, new Clock(Now)));
        Assert.Throws<UnauthorizedAccessException>(() => authority.Demand(Policy(ProductionOperatorPermission.Status), ProductionOperatorPermission.PlaceHold, new Clock(Now)));
        Assert.Throws<UnauthorizedAccessException>(() => authority.Demand(policy, ProductionOperatorPermission.PlaceHold, new Clock(Now.AddMinutes(4))));
        Assert.Throws<UnauthorizedAccessException>(() => authority.Demand(policy, ProductionOperatorPermission.PlaceHold, new Clock(Now.AddMinutes(-2))));
    }

    [Theory]
    [InlineData(-6, 1)][InlineData(1, 2)][InlineData(-1, 0)][InlineData(-1, -1)]
    public void Missing_expired_future_or_overlong_tickets_fail_closed(int issued, int expires)
    {
        var ticket = Ticket(); ticket.Properties.IssuedUtc = Now.AddMinutes(issued); ticket.Properties.ExpiresUtc = Now.AddMinutes(expires);
        Reject(ticket);
        ticket = Ticket(); ticket.Properties.ExpiresUtc = null; Reject(ticket);
        ticket = Ticket(); ticket.Properties.IssuedUtc = null; Reject(ticket);
    }

    [Fact]
    public void Wrong_case_duplicate_claims_mixed_identities_and_duplicate_allowlist_entries_are_rejected()
    {
        Reject(Ticket(subject: Subject.ToUpperInvariant()));
        Reject(Ticket(issuer: Issuer + "/"));
        Reject(Ticket(issuer: "http://operator.synthetic.invalid"));
        var ticket = Ticket(); ((ClaimsIdentity)ticket.Principal.Identity!).AddClaim(new("sub", Subject, ClaimValueTypes.String, Issuer)); Reject(ticket);
        ticket = Ticket(); ticket.Principal.AddIdentity(new ClaimsIdentity()); Reject(ticket);
        ticket = Ticket(); ((ClaimsIdentity)ticket.Principal.Identity!).RemoveClaim(ticket.Principal.FindFirst("sub")!);
        ((ClaimsIdentity)ticket.Principal.Identity!).AddClaim(new("sub", Subject, ClaimValueTypes.String, "other-issuer")); Reject(ticket);
        var policy = Policy(ProductionOperatorPermission.PlaceHold);
        Assert.Throws<UnauthorizedAccessException>(() => ProductionOperatorAuthority.FromValidatedTicket(Ticket(),
            policy with { Grants = [policy.Grants[0], policy.Grants[0]] }, ProductionOperatorPermission.PlaceHold, new Clock(Now)));
    }

    private static void Reject(AuthenticationTicket ticket) => Assert.Throws<UnauthorizedAccessException>(() =>
        ProductionOperatorAuthority.FromValidatedTicket(ticket, Policy(ProductionOperatorPermission.PlaceHold), ProductionOperatorPermission.PlaceHold, new Clock(Now)));
}
