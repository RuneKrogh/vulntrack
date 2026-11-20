using Microsoft.AspNetCore.Authorization;
using VulnTrack.Api.Auth;
using VulnTrack.Api.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOidcAuthentication(builder.Configuration);

// Every endpoint requires a signed-in user unless it explicitly allows anonymous access.
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

var app = builder.Build();

app.UseSecurityHeaders();
app.UseStaticFiles();
app.UseCsrfHeaderCheck();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapGet("/api/me", CurrentUser.Get);

// Unknown API routes return 404 instead of falling through to the SPA.
app.Map("/api/{**path}", () => Results.NotFound());
app.MapFallbackToFile("index.html").AllowAnonymous();

app.Run();
