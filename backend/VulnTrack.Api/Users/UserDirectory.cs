using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using VulnTrack.Api.Auth;

namespace VulnTrack.Api.Users;

public sealed record AppUser(string Id, string Name);

// Users live in Keycloak, so this is the app's view of them.
public interface IUserDirectory
{
    Task<IReadOnlyList<AppUser>> GetDevelopersAsync(CancellationToken cancellationToken);
}

// Reads users from Keycloak's Admin API with the client's own service account,
// which only has the read-only view-users and view-clients roles.
public sealed class KeycloakUserDirectory(
    HttpClient http,
    IOptionsMonitor<OpenIdConnectOptions> oidcOptions,
    IConfiguration configuration) : IUserDirectory
{
    public async Task<IReadOnlyList<AppUser>> GetDevelopersAsync(CancellationToken cancellationToken)
    {
        var adminUrl = configuration["Keycloak:AdminUrl"];
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", await GetTokenAsync(cancellationToken));

        var clientId = configuration["Oidc:ClientId"];
        var clients = await http.GetFromJsonAsync<List<KeycloakClient>>($"{adminUrl}/clients?clientId={Uri.EscapeDataString(clientId!)}", cancellationToken);
        var users = await http.GetFromJsonAsync<List<KeycloakUser>>($"{adminUrl}/clients/{clients!.Single().Id}/roles/{Roles.Developer}/users", cancellationToken);

        return users!.Select(user => new AppUser(user.Id, user.DisplayName)).OrderBy(user => user.Name).ToList();
    }

    private async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        var options = oidcOptions.Get(OpenIdConnectDefaults.AuthenticationScheme);
        var discovery = await options.ConfigurationManager!.GetConfigurationAsync(cancellationToken);
        using var response = await http.PostAsync(discovery.TokenEndpoint, new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = options.ClientId!,
            ["client_secret"] = options.ClientSecret!,
        }), cancellationToken);
        response.EnsureSuccessStatusCode();
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken);
        return token!.AccessToken;
    }

    private sealed record TokenResponse([property: JsonPropertyName("access_token")] string AccessToken);

    private sealed record KeycloakClient(string Id);

    private sealed record KeycloakUser(string Id, string Username, string? FirstName, string? LastName)
    {
        public string DisplayName => FirstName is null && LastName is null ? Username : $"{FirstName} {LastName}".Trim();
    }
}
