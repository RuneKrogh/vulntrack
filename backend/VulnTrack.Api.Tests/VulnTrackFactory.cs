using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Testcontainers.PostgreSql;
using VulnTrack.Api.Data;
using VulnTrack.Api.Security;
using VulnTrack.Api.Users;

namespace VulnTrack.Api.Tests;

// Runs the real app, but swaps the OIDC/cookie login for a test scheme that reads the user from headers.
// It has no database. Tests that need one use PostgresFactory.
public class VulnTrackFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseSetting("Oidc:ClientSecret", "test-secret");
        builder.UseSetting("Oidc:RequireHttpsMetadata", "false");
        builder.ConfigureServices(services =>
        {
            services.AddAuthentication()
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
            services.PostConfigure<AuthenticationOptions>(options =>
            {
                options.DefaultScheme = TestAuthHandler.SchemeName;
                options.DefaultChallengeScheme = TestAuthHandler.SchemeName;
            });
            services.AddSingleton<IUserDirectory, FakeUserDirectory>();
        });
        ConfigureDatabase(builder);
    }

    protected virtual void ConfigureDatabase(IWebHostBuilder builder) =>
        builder.ConfigureServices(services =>
            services.Remove(services.Single(s => s.ImplementationType == typeof(DatabaseMigrator))));

    // A client for a signed-in user. It sends the CSRF header like the frontend does.
    public HttpClient CreateClientAs(string username, params string[] roles)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, username);
        client.DefaultRequestHeaders.Add(TestAuthHandler.RolesHeader, string.Join(',', roles));
        client.DefaultRequestHeaders.Add(SecurityMiddleware.CsrfHeader, "1");
        return client;
    }
}

// Same as VulnTrackFactory, but with a real Postgres in a container. Needs Docker.
public sealed class PostgresFactory : VulnTrackFactory, IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:18-alpine").Build();

    public async ValueTask InitializeAsync() => await _postgres.StartAsync();

    protected override void ConfigureDatabase(IWebHostBuilder builder) =>
        builder.UseSetting("ConnectionStrings:Default", _postgres.GetConnectionString());

    public override async ValueTask DisposeAsync()
    {
        await base.DisposeAsync();
        await _postgres.DisposeAsync();
    }
}

// Stands in for Keycloak's user list.
public sealed class FakeUserDirectory : IUserDirectory
{
    public static readonly AppUser Developer = new("dev-1", "Dana Developer");

    public Task<IReadOnlyList<AppUser>> GetDevelopersAsync(CancellationToken cancellationToken) =>
        Task.FromResult<IReadOnlyList<AppUser>>([Developer]);
}

public sealed class TestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Test";
    public const string UserHeader = "X-Test-User";
    public const string RolesHeader = "X-Test-Roles";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        string? username = Request.Headers[UserHeader];
        if (string.IsNullOrEmpty(username))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        string roles = Request.Headers[RolesHeader].ToString();
        var claims = new List<Claim> { new("preferred_username", username) };
        claims.AddRange(roles.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(role => new Claim("roles", role)));

        var identity = new ClaimsIdentity(claims, SchemeName, "preferred_username", "roles");
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}
