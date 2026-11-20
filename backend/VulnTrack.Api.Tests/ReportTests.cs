using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VulnTrack.Api.Data;
using VulnTrack.Api.Findings;
using VulnTrack.Api.Security;

namespace VulnTrack.Api.Tests;

public sealed class ReportTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private static int _nextIp;

    // Every test gets its own client address, so the rate limit of one test doesn't affect another.
    private static string NewIp()
    {
        var n = Interlocked.Increment(ref _nextIp);
        return $"10.0.{n / 256}.{n % 256}";
    }

    private static object ValidReport(string title = "XSS in the comment field") => new
    {
        title,
        description = "A comment containing a script tag runs for every visitor.",
        affectedAsset = "comments",
        severity = "Medium",
        reporterEmail = "reporter@example.com",
    };

    [Fact]
    public async Task Submit_WithoutLogin_StoresNewFindingWithReporterEmail()
    {
        var client = factory.CreateAnonymousClient(NewIp());

        var response = await client.PostAsJsonAsync("/api/reports", ValidReport(), Ct);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var finding = await FindStoredAsync(response);
        Assert.Equal("XSS in the comment field", finding.Title);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingStatus.New, finding.Status);
        Assert.Equal("reporter@example.com", finding.ReporterEmail);
        Assert.Equal(DateOnly.FromDateTime(DateTime.UtcNow), finding.DiscoveredAt);
    }

    [Fact]
    public async Task Submit_ReturnsOnlyAReference()
    {
        var client = factory.CreateAnonymousClient(NewIp());

        var response = await client.PostAsJsonAsync("/api/reports", ValidReport(), Ct);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Ct));
        var property = Assert.Single(body.RootElement.EnumerateObject());
        Assert.Equal("reference", property.Name);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task Submit_IgnoresStatusAssignmentAndDateFromClient()
    {
        var client = factory.CreateAnonymousClient(NewIp());
        var body = new
        {
            title = "Tries to skip triage",
            description = "d",
            affectedAsset = "web",
            severity = "Low",
            reporterEmail = "reporter@example.com",
            status = "Remediated",
            assigneeId = FakeUserDirectory.Developer.Id,
            dueDate = "2999-01-01",
            discoveredAt = "2020-01-01",
        };

        var response = await client.PostAsJsonAsync("/api/reports", body, Ct);

        var finding = await FindStoredAsync(response);
        Assert.Equal(FindingStatus.New, finding.Status);
        Assert.Null(finding.AssigneeId);
        Assert.Null(finding.DueDate);
        Assert.Equal(DateOnly.FromDateTime(DateTime.UtcNow), finding.DiscoveredAt);
    }

    public static TheoryData<string, object> InvalidReports => new()
    {
        { "missing email", new { title = "t", description = "d", affectedAsset = "a", severity = "Low" } },
        { "invalid email", new { title = "t", description = "d", affectedAsset = "a", severity = "Low", reporterEmail = "not-an-email" } },
        { "email too long", new { title = "t", description = "d", affectedAsset = "a", severity = "Low", reporterEmail = new string('x', Finding.EmailMaxLength) + "@example.com" } },
        { "missing title", new { description = "d", affectedAsset = "a", severity = "Low", reporterEmail = "r@example.com" } },
        { "blank title", new { title = "   ", description = "d", affectedAsset = "a", severity = "Low", reporterEmail = "r@example.com" } },
        { "description too long", new { title = "t", description = new string('x', Finding.DescriptionMaxLength + 1), affectedAsset = "a", severity = "Low", reporterEmail = "r@example.com" } },
        { "unknown severity", new { title = "t", description = "d", affectedAsset = "a", severity = "Extreme", reporterEmail = "r@example.com" } },
    };

    [Theory]
    [MemberData(nameof(InvalidReports))]
    public async Task Submit_WithInvalidInput_Returns400(string reason, object body)
    {
        var client = factory.CreateAnonymousClient(NewIp());

        var response = await client.PostAsJsonAsync("/api/reports", body, Ct);

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{reason}: {response.StatusCode}");
    }

    [Theory]
    [InlineData("alice", "analyst", true)]
    [InlineData("paul", "pm", true)]
    [InlineData("audrey", "auditor", false)]
    [InlineData("dev-1", "developer", false)]
    public async Task ReporterEmail_IsOnlyShownToAnalystsAndPms(string username, string role, bool expected)
    {
        var report = await factory.CreateAnonymousClient(NewIp()).PostAsJsonAsync("/api/reports", ValidReport($"Email visible to {role}"), Ct);
        var reference = (await report.Content.ReadFromJsonAsync<ReportReceipt>(Ct))!.Reference;
        // Assigned to dev-1, so the developer can see the finding at all.
        var tomorrow = DateOnly.FromDateTime(DateTime.UtcNow).AddDays(1);
        await factory.CreateClientAs("alice", "analyst")
            .PutAsJsonAsync($"/api/findings/{reference}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate = tomorrow }, Ct);
        var client = factory.CreateClientAs(username, role);

        var single = await client.GetFromJsonAsync<FindingResponse>($"/api/findings/{reference}", Json, Ct);
        var inList = (await client.GetFromJsonAsync<List<FindingResponse>>("/api/findings", Json, Ct))!.Single(f => f.Id == reference);

        var email = expected ? "reporter@example.com" : null;
        Assert.Equal(email, single!.ReporterEmail);
        Assert.Equal(email, inList.ReporterEmail);
    }

    // A cross-site page can send these content types without a CORS preflight. The endpoint must not
    // read them as JSON, so CSRF stays blocked even if the custom header check were gone.
    [Theory]
    [InlineData("text/plain")]
    [InlineData("application/x-www-form-urlencoded")]
    [InlineData("multipart/form-data")]
    public async Task Submit_WithCrossSiteContentType_StoresNothing(string contentType)
    {
        var client = factory.CreateAnonymousClient(NewIp());
        var title = $"Sent as {contentType}";
        var json = JsonSerializer.Serialize(ValidReport(title));

        var response = await client.PostAsync("/api/reports", new StringContent(json, Encoding.UTF8, contentType), Ct);

        Assert.NotEqual(HttpStatusCode.Accepted, response.StatusCode);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.False(await db.Findings.AnyAsync(f => f.Title == title, Ct));
    }

    // The test server can't limit body sizes, so this test runs the app on Kestrel like in production.
    [Fact]
    public async Task Submit_WithTooLargeBody_Returns413()
    {
        await using var kestrel = new VulnTrackFactory();
        kestrel.UseKestrel(0);
        kestrel.StartServer();
        // The app only accepts the host name localhost, so the port is taken from the address Kestrel listens on.
        var address = new Uri(kestrel.Services.GetRequiredService<IServer>().Features.GetRequiredFeature<IServerAddressesFeature>().Addresses.First());
        using var client = new HttpClient { BaseAddress = new UriBuilder(address) { Host = "localhost" }.Uri };
        client.DefaultRequestHeaders.Add(SecurityMiddleware.CsrfHeader, "1");
        var body = new { title = "t", description = new string('x', 100_000), affectedAsset = "a", severity = "Low", reporterEmail = "r@example.com" };

        var response = await client.PostAsJsonAsync("/api/reports", body, Ct);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task Submit_OverTheLimit_Returns429ButOtherClientsCanStillReport()
    {
        var client = factory.CreateAnonymousClient(NewIp());
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/reports", ValidReport(), Ct)).StatusCode);
        }

        var limited = await client.PostAsJsonAsync("/api/reports", ValidReport(), Ct);
        var other = await factory.CreateAnonymousClient(NewIp()).PostAsJsonAsync("/api/reports", ValidReport(), Ct);

        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, other.StatusCode);
    }

    [Fact]
    public async Task Submit_FromSameIpv6Prefix_SharesTheLimit()
    {
        for (var i = 1; i <= 5; i++)
        {
            var client = factory.CreateAnonymousClient($"2001:db8:1:2::{i}");
            Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/api/reports", ValidReport(), Ct)).StatusCode);
        }

        var samePrefix = await factory.CreateAnonymousClient("2001:db8:1:2:ffff::6").PostAsJsonAsync("/api/reports", ValidReport(), Ct);
        var otherPrefix = await factory.CreateAnonymousClient("2001:db8:1:3::1").PostAsJsonAsync("/api/reports", ValidReport(), Ct);

        Assert.Equal(HttpStatusCode.TooManyRequests, samePrefix.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, otherPrefix.StatusCode);
    }

    private async Task<Finding> FindStoredAsync(HttpResponseMessage response)
    {
        var receipt = await response.Content.ReadFromJsonAsync<ReportReceipt>(Ct);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var finding = await db.Findings.FindAsync([receipt!.Reference], Ct);
        Assert.NotNull(finding);
        return finding;
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
