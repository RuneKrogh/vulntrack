using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace VulnTrack.Api.Auth;

public static class AuthEndpoints
{
    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        // Always return to the start page after login, so the endpoint can't be used as an open redirect.
        app.MapGet("/auth/login", () => Results.Challenge(
                new AuthenticationProperties { RedirectUri = "/" },
                [OpenIdConnectDefaults.AuthenticationScheme]))
            .AllowAnonymous();

        // Ends the local session, then returns the Keycloak logout URL as JSON (see OnRedirectToIdentityProviderForSignOut).
        // The cookie sign-out gets no RedirectUri, because it would then redirect to it itself.
        app.MapPost("/api/auth/logout", async (HttpContext context) =>
        {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/" });
        });
    }
}
