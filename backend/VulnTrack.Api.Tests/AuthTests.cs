using System.Net;
using System.Net.Http.Json;
using VulnTrack.Api.Auth;

namespace VulnTrack.Api.Tests;

public sealed class AuthTests(VulnTrackFactory factory) : IClassFixture<VulnTrackFactory>
{
    [Fact]
    public async Task Me_WithoutLogin_Returns401()
    {
        var client = factory.CreateClient(new() { AllowAutoRedirect = false });

        var response = await client.GetAsync("/api/me", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Me_WhenLoggedIn_ReturnsNameAndRoles()
    {
        var client = factory.CreateClientAs("alice", "pm", "analyst");

        var me = await client.GetFromJsonAsync<CurrentUser>("/api/me", TestContext.Current.CancellationToken);

        Assert.NotNull(me);
        Assert.Equal("alice", me.Name);
        Assert.Equal(["analyst", "pm"], me.Roles);
    }

    [Fact]
    public async Task UnknownApiRoute_Returns404()
    {
        var client = factory.CreateClientAs("alice", "analyst");

        var response = await client.GetAsync("/api/does-not-exist", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
