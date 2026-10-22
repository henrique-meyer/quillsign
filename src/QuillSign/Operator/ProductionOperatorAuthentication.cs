using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using QuillSign.Lifecycle;
using Microsoft.AspNetCore.RateLimiting;

namespace QuillSign.Operator;

internal static class ProductionOperatorAuthentication
{
    internal const string SessionClaim="quillsign_operator_session";
    internal const string Page="/operator/retention";
    internal static PageActionEndpointConventionBuilder WithProductionOperatorRateLimit(this PageActionEndpointConventionBuilder pages)
    {
        // Program's normal page-wide sender policy is added after Razor
        // attributes. Explicitly keep this private endpoint's own final policy.
        pages.Add(endpoint=>{
            if(endpoint.Metadata.OfType<Microsoft.AspNetCore.Mvc.RazorPages.PageActionDescriptor>().Any(x=>x.ViewEnginePath=="/Operator/Retention"))
                endpoint.Metadata.Add(new EnableRateLimitingAttribute("production-operator"));
        });
        return pages;
    }
    internal static IServiceCollection AddProductionOperator(this IServiceCollection services,IConfiguration configuration)
    {
        var settings=configuration.GetSection("ProductionOperator").Get<ProductionOperatorOptions>()??new();
        _=settings.Policy();services.AddSingleton(settings);services.AddScoped<ProductionOperatorBrowser>();
        if(settings.Enabled!=configuration.GetValue<bool>("ProductionHolds:Enabled"))throw ProductionOperatorOptions.Invalid();
        services.AddProductionHoldRuntime(configuration);
        services.AddScoped<IProductionOperatorActions>(sp=>settings.Enabled?new ProductionOperatorActions(settings,sp.GetRequiredService<ProductionOperatorBrowser>(),sp.GetRequiredService<ProductionHoldCoordinator>(),
            ()=>new QuillSign.Data.QuillSignDbContext(sp.GetRequiredService<Microsoft.EntityFrameworkCore.DbContextOptions<QuillSign.Data.QuillSignDbContext>>()),sp.GetRequiredService<Microsoft.AspNetCore.DataProtection.IDataProtectionProvider>(),
            sp.GetRequiredService<TimeProvider>(),sp.GetRequiredService<QuillSign.Storage.IProductionHoldArchiveInspectionStore>(),configuration.GetValue<bool>("ProductionDeletion:Enabled")?()=>sp.GetRequiredService<ProductionDeletionCoordinator>():null,sp.GetRequiredService<ProductionDeletionOptions>()):new UnavailableOperatorActions());
        services.AddRateLimiter(o=>o.AddFixedWindowLimiter("production-operator",w=>{w.PermitLimit=32;w.Window=TimeSpan.FromMinutes(1);w.QueueLimit=0;}));
        if(!settings.Enabled)return services;
        services.AddAuthentication().AddCookie(ProductionOperatorAuthority.CookieScheme,c=> {
            c.Cookie.Name="__Host-QuillSign.Operator";c.Cookie.Path="/";c.Cookie.HttpOnly=true;c.Cookie.SecurePolicy=CookieSecurePolicy.Always;c.Cookie.SameSite=SameSiteMode.Lax;
            c.ExpireTimeSpan=ProductionOperatorAuthority.MaximumSession;c.SlidingExpiration=false;
            c.Events=new CookieAuthenticationEvents {
                OnRedirectToLogin=x=>{x.Response.StatusCode=404;return Task.CompletedTask;},
                OnRedirectToAccessDenied=x=>{x.Response.StatusCode=404;return Task.CompletedTask;},
                OnValidatePrincipal=x=>{try{DemandPrincipal(x.Principal!,settings);if(x.Properties.IssuedUtc is not{} issued||x.Properties.ExpiresUtc is not{} until||
                    until-issued>ProductionOperatorAuthority.MaximumSession||until<=x.HttpContext.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow())x.RejectPrincipal();}
                    catch(UnauthorizedAccessException){x.RejectPrincipal();}return Task.CompletedTask;}
            };
        }).AddOpenIdConnect(ProductionOperatorAuthority.OidcScheme,o=> {
            o.Authority=settings.Issuer;o.ClientId=settings.ClientId;o.ClientSecret=settings.ClientSecret;
            o.SignInScheme=ProductionOperatorAuthority.CookieScheme;o.CallbackPath=Page+"/signin-oidc";
            o.ResponseType="code";o.UsePkce=true;o.MapInboundClaims=false;o.SaveTokens=false;o.GetClaimsFromUserInfoEndpoint=false;o.RequireHttpsMetadata=true;
            o.ClaimActions.Clear(); // Preserve only the exact normalized iss/sub/session created after token validation.
            o.Scope.Clear();o.Scope.Add("openid");o.RemoteAuthenticationTimeout=TimeSpan.FromMinutes(2);o.ProtocolValidator.NonceLifetime=TimeSpan.FromMinutes(2);
            o.CorrelationCookie.Name="__Host-QuillSign.Operator.Correlation.";o.CorrelationCookie.Path="/";o.CorrelationCookie.SecurePolicy=CookieSecurePolicy.Always;
            o.NonceCookie.Name="__Host-QuillSign.Operator.Nonce.";o.NonceCookie.Path="/";o.NonceCookie.SecurePolicy=CookieSecurePolicy.Always;
            o.TokenValidationParameters=new TokenValidationParameters {ValidateIssuer=true,ValidIssuer=settings.Issuer,ValidateAudience=true,ValidAudience=settings.ClientId,
                ValidateIssuerSigningKey=true,RequireSignedTokens=true,RequireExpirationTime=true,ValidateLifetime=true,ClockSkew=TimeSpan.Zero,AuthenticationType=ProductionOperatorAuthority.OidcScheme};
            o.Events=new OpenIdConnectEvents {
                OnTokenValidated=x=>{
                    var iss=x.Principal?.FindAll("iss").ToArray();var sub=x.Principal?.FindAll("sub").ToArray();
                    if(x.SecurityToken.Issuer!=settings.Issuer||iss is not{Length:1}||iss[0].Value!=settings.Issuer||sub is not{Length:1}||
                        !settings.Policy().Grants.Any(g=>g.Issuer==settings.Issuer&&g.Subject==sub[0].Value))throw ProductionOperatorAuthority.Denied();
                    x.Principal=new(new ClaimsIdentity([new("iss",settings.Issuer,ClaimValueTypes.String,settings.Issuer),new("sub",sub[0].Value,ClaimValueTypes.String,settings.Issuer),
                        new(SessionClaim,Guid.NewGuid().ToString("N"),ClaimValueTypes.String,settings.Issuer)],ProductionOperatorAuthority.OidcScheme));
                    var now=x.HttpContext.RequestServices.GetRequiredService<TimeProvider>().GetUtcNow();var expiry=new DateTimeOffset(x.SecurityToken.ValidTo,TimeSpan.Zero);
                    var properties=x.Properties??throw ProductionOperatorAuthority.Denied();properties.IssuedUtc=now;properties.ExpiresUtc=expiry<now+ProductionOperatorAuthority.MaximumSession?expiry:now+ProductionOperatorAuthority.MaximumSession;
                    properties.IsPersistent=false;properties.AllowRefresh=false;return Task.CompletedTask;},
                OnTicketReceived=x=>{x.ReturnUri=Page;return Task.CompletedTask;},
                OnRemoteFailure=x=>{x.HandleResponse();x.Response.StatusCode=404;return Task.CompletedTask;}
            };
        });
        return services;
    }
    internal static IApplicationBuilder UseProductionOperatorPrivacy(this IApplicationBuilder app)=>app.Use(async(context,next)=>{
        if(context.Request.Path.StartsWithSegments(Page)){
            context.Response.Headers.CacheControl="no-store";context.Response.Headers["X-Robots-Tag"]="noindex, nofollow";context.Response.Headers["Referrer-Policy"]="no-referrer";
            var body=context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpMaxRequestBodySizeFeature>();if(body is {IsReadOnly:false})body.MaxRequestBodySize=32768;
        }
        await next();
    });
    internal static void DemandPrincipal(ClaimsPrincipal principal,ProductionOperatorOptions options)
    {
        var identities=principal.Identities.ToArray();if(identities.Length!=1||identities[0].AuthenticationType!=ProductionOperatorAuthority.OidcScheme||!identities[0].IsAuthenticated)throw ProductionOperatorAuthority.Denied();
        var iss=principal.FindAll("iss").ToArray();var sub=principal.FindAll("sub").ToArray();var session=principal.FindAll(SessionClaim).ToArray();
        if(iss.Length!=1||sub.Length!=1||session.Length!=1||!Guid.TryParseExact(session[0].Value,"N",out var id)||id==Guid.Empty||
            iss[0].Value!=options.Issuer||!options.Policy().Grants.Any(g=>g.Issuer==iss[0].Value&&g.Subject==sub[0].Value))throw ProductionOperatorAuthority.Denied();
    }
}
