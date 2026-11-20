using System.Text.Json.Serialization;
using VulnTrack.Api.Auth;
using VulnTrack.Api.Data;
using VulnTrack.Api.Findings;
using VulnTrack.Api.Security;
using VulnTrack.Api.Users;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOidcAuthentication(builder.Configuration);
builder.Services.AddRolePolicies();
builder.Services.AddDatabase(builder.Configuration);
builder.Services.AddHttpClient<IUserDirectory, KeycloakUserDirectory>();
builder.Services.AddRateLimits();
builder.Services.AddValidation();
// Enums are sent as names. Numbers are rejected, so values outside the enum can't slip through.
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(allowIntegerValues: false)));

var app = builder.Build();

app.UseSecurityHeaders();
app.UseStaticFiles();
app.UseCsrfHeaderCheck();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapGet("/api/me", CurrentUser.Get);
app.MapFindingEndpoints();
app.MapReportEndpoints();

// Unknown API routes return 404 instead of falling through to the SPA.
app.Map("/api/{**path}", () => Results.NotFound());
app.MapFallbackToFile("index.html").AllowAnonymous();

app.Run();
