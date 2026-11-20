using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace VulnTrack.Api.Auth;

public static class AuthenticationSetup
{
    // The backend is the OIDC client. Tokens stay on the server, and the browser only gets
    // an encrypted, HttpOnly session cookie.
    public static IServiceCollection AddOidcAuthentication(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.Cookie.Name = "__Host-vulntrack";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
                options.SlidingExpiration = true;

                // The SPA talks to the API with fetch, so answer with status codes instead of redirects.
                options.Events.OnRedirectToLogin = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                options.Events.OnRedirectToAccessDenied = context =>
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            })
            .AddOpenIdConnect(options =>
            {
                var oidc = configuration.GetSection("Oidc");
                options.Authority = oidc["Authority"];
                // Inside Docker the backend reaches Keycloak by its service name,
                // while the browser uses localhost. The issuer stays the same.
                options.MetadataAddress = oidc["MetadataAddress"];
                options.RequireHttpsMetadata = oidc.GetValue("RequireHttpsMetadata", true);
                options.ClientId = oidc["ClientId"];
                options.ClientSecret = oidc["ClientSecret"];

                options.ResponseType = OpenIdConnectResponseType.Code;
                options.UsePkce = true;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("email");

                options.MapInboundClaims = false;
                options.TokenValidationParameters.NameClaimType = "preferred_username";
                options.TokenValidationParameters.RoleClaimType = "roles";
                // The id token is kept in the session so logout can send it as id_token_hint.
                options.SaveTokens = true;

                options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;

                // Logout is called with fetch, so return the Keycloak logout URL for the SPA to navigate to.
                options.Events.OnRedirectToIdentityProviderForSignOut = context =>
                {
                    context.HandleResponse();
                    return context.Response.WriteAsJsonAsync(new { url = context.ProtocolMessage.CreateLogoutRequestUrl() });
                };
            });

        services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .Validate(options => !string.IsNullOrEmpty(options.ClientSecret), "Oidc:ClientSecret is not configured.")
            .ValidateOnStart();

        return services;
    }
}
