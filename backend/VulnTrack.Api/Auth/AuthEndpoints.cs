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

        app.MapPost("/api/auth/logout", () => Results.SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            [CookieAuthenticationDefaults.AuthenticationScheme, OpenIdConnectDefaults.AuthenticationScheme]));
    }
}
