using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace VulnTrack.Api.Tests;

public sealed class LogoutTests(VulnTrackFactory factory) : IClassFixture<VulnTrackFactory>
{
    private static readonly OpenIdConnectConfiguration Keycloak = new()
    {
        Issuer = "http://localhost:8080/realms/vulntrack",
        EndSessionEndpoint = "http://localhost:8080/realms/vulntrack/protocol/openid-connect/logout",
    };

    [Fact]
    public async Task Logout_ReturnsKeycloakUrl_AndCallbackRedirectsToStartPage()
    {
        var client = CreateClient();

        var response = await client.PostAsync("/api/auth/logout", null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<LogoutResponse>(TestContext.Current.CancellationToken);
        Assert.StartsWith(Keycloak.EndSessionEndpoint + "?", body!.Url);

        // Keycloak sends the state back to the callback, which uses it to redirect to the start page.
        var state = QueryHelpers.ParseQuery(new Uri(body.Url).Query)["state"].ToString();
        var callback = await client.GetAsync($"/signout-callback-oidc?state={Uri.EscapeDataString(state)}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        Assert.Equal("/", callback.Headers.Location?.ToString());
    }

    // A fixed Keycloak configuration, so the OIDC handler doesn't fetch it from a running Keycloak.
    private HttpClient CreateClient()
    {
        var client = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
                services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.Configuration = Keycloak;
                    options.ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(Keycloak);
                })))
            .CreateClient(new() { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Test-User", "alice");
        client.DefaultRequestHeaders.Add("X-CSRF", "1");
        return client;
    }

    private sealed record LogoutResponse(string Url);
}
