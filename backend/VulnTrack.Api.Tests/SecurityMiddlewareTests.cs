using System.Net;
using VulnTrack.Api.Security;

namespace VulnTrack.Api.Tests;

public sealed class SecurityMiddlewareTests(VulnTrackFactory factory) : IClassFixture<VulnTrackFactory>
{
    [Fact]
    public async Task ApiPost_WithoutCsrfHeader_IsRejected()
    {
        var client = factory.CreateClientAs("alice", "analyst");

        var response = await client.PostAsync("/api/auth/logout", null, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ApiPost_WithCsrfHeader_IsNotRejectedByCsrfCheck()
    {
        var client = factory.CreateClientAs("alice", "analyst");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/does-not-exist");
        request.Headers.Add(SecurityMiddleware.CsrfHeader, "1");

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Responses_HaveSecurityHeaders()
    {
        var client = factory.CreateClient();

        var response = await client.GetAsync("/api/me", TestContext.Current.CancellationToken);

        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
    }
}
