using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Tests;

public sealed class FindingTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private static object ValidFinding(string title = "SQL injection in search") => new
    {
        title,
        description = "The search field is concatenated into the SQL query.",
        affectedAsset = "search-api",
        severity = "High",
        discoveredAt = "2026-11-01",
    };

    [Theory]
    [InlineData("analyst")]
    [InlineData("pm")]
    public async Task Create_AsAnalystOrPm_CreatesFindingWithStatusNew(string role)
    {
        var client = factory.CreateClientAs("alice", role);

        var response = await client.PostAsJsonAsync("/api/findings", ValidFinding(), Ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<FindingResponse>(Json, Ct);
        Assert.NotNull(created);
        Assert.Equal(FindingStatus.New, created.Status);
        Assert.Equal(Severity.High, created.Severity);
        Assert.Equal($"/api/findings/{created.Id}", response.Headers.Location?.ToString());
    }

    [Theory]
    [InlineData("developer")]
    [InlineData("auditor")]
    [InlineData("")]
    public async Task Create_WithoutAnalystOrPmRole_Returns403(string role)
    {
        var client = factory.CreateClientAs("bob", role);

        var response = await client.PostAsJsonAsync("/api/findings", ValidFinding(), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Create_WithoutLogin_Returns401()
    {
        var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/findings") { Content = JsonContent.Create(ValidFinding()) };
        request.Headers.Add("X-CSRF", "1");

        var response = await client.SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Create_IgnoresStatusAndReporterEmailFromClient()
    {
        var client = factory.CreateClientAs("alice", "analyst");
        var body = new
        {
            title = "Status from client",
            description = "Tries to skip triage.",
            affectedAsset = "web",
            severity = "Low",
            discoveredAt = "2026-11-01",
            status = "Remediated",
            reporterEmail = "someone@example.com",
        };

        var response = await client.PostAsJsonAsync("/api/findings", body, Ct);

        var created = await response.Content.ReadFromJsonAsync<FindingResponse>(Json, Ct);
        Assert.Equal(FindingStatus.New, created!.Status);
    }

    public static TheoryData<string, object> InvalidFindings => new()
    {
        { "missing title", new { description = "d", affectedAsset = "a", severity = "Low", discoveredAt = "2026-11-01" } },
        { "title too long", new { title = new string('x', Finding.TitleMaxLength + 1), description = "d", affectedAsset = "a", severity = "Low", discoveredAt = "2026-11-01" } },
        { "description too long", new { title = "t", description = new string('x', Finding.DescriptionMaxLength + 1), affectedAsset = "a", severity = "Low", discoveredAt = "2026-11-01" } },
        { "unknown severity", new { title = "t", description = "d", affectedAsset = "a", severity = "Extreme", discoveredAt = "2026-11-01" } },
        { "numeric severity", new { title = "t", description = "d", affectedAsset = "a", severity = 99, discoveredAt = "2026-11-01" } },
        { "future discovery date", new { title = "t", description = "d", affectedAsset = "a", severity = "Low", discoveredAt = "2999-01-01" } },
    };

    [Theory]
    [MemberData(nameof(InvalidFindings))]
    public async Task Create_WithInvalidInput_Returns400(string reason, object body)
    {
        var client = factory.CreateClientAs("alice", "analyst");

        var response = await client.PostAsJsonAsync("/api/findings", body, Ct);

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, reason);
    }

    [Theory]
    [InlineData("analyst")]
    [InlineData("developer")]
    [InlineData("pm")]
    [InlineData("auditor")]
    public async Task ListAndGet_AsAnyRole_ReturnsFindings(string role)
    {
        var creator = factory.CreateClientAs("alice", "analyst");
        var created = await (await creator.PostAsJsonAsync("/api/findings", ValidFinding($"Visible to {role}"), Ct))
            .Content.ReadFromJsonAsync<FindingResponse>(Json, Ct);
        var client = factory.CreateClientAs("carol", role);

        var list = await client.GetFromJsonAsync<List<FindingResponse>>("/api/findings", Json, Ct);
        var single = await client.GetFromJsonAsync<FindingResponse>($"/api/findings/{created!.Id}", Json, Ct);

        Assert.Contains(list!, f => f.Id == created.Id);
        Assert.Equal(created.Title, single!.Title);
    }

    [Fact]
    public async Task ListAndGet_WithoutRole_Returns403()
    {
        var client = factory.CreateClientAs("mallory");

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/api/findings", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync($"/api/findings/{Guid.NewGuid()}", Ct)).StatusCode);
    }

    [Fact]
    public async Task Get_UnknownId_Returns404()
    {
        var client = factory.CreateClientAs("alice", "analyst");

        var response = await client.GetAsync($"/api/findings/{Guid.NewGuid()}", Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
