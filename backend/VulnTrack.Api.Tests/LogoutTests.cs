using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace VulnTrack.Api.Tests;

public sealed class LogoutTests(VulnTrackFactory factory) : IClassFixture<VulnTrackFactory>
{
    [Fact]
    public async Task Logout_ReturnsKeycloakLogoutUrlAsJson()
    {
        // A fixed Keycloak configuration, so the OIDC handler doesn't need a running Keycloak.
        var client = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
                services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
                    options.Configuration = new OpenIdConnectConfiguration
                    {
                        Issuer = "http://localhost:8080/realms/vulntrack",
                        EndSessionEndpoint = "http://localhost:8080/realms/vulntrack/protocol/openid-connect/logout",
                    })))
            .CreateClient(new() { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add("X-Test-User", "alice");
        client.DefaultRequestHeaders.Add("X-CSRF", "1");

        var response = await client.PostAsync("/api/auth/logout", null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<LogoutResponse>(TestContext.Current.CancellationToken);
        Assert.StartsWith("http://localhost:8080/realms/vulntrack/protocol/openid-connect/logout?", body!.Url);
    }

    private sealed record LogoutResponse(string Url);
}
