using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulnTrack.Api.Findings;
using VulnTrack.Api.Users;

namespace VulnTrack.Api.Tests;

public sealed class AssignmentTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private static string Tomorrow => DateOnly.FromDateTime(DateTime.UtcNow).AddDays(1).ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);

    private async Task<Guid> CreateFindingAsync()
    {
        var client = factory.CreateClientAs("alice", "analyst");
        var response = await client.PostAsJsonAsync("/api/findings", new
        {
            title = "Missing rate limit on login",
            description = "No lockout after many attempts.",
            affectedAsset = "auth-service",
            severity = "Medium",
            discoveredAt = "2026-11-01",
        }, Ct);
        return (await response.Content.ReadFromJsonAsync<FindingResponse>(Json, Ct))!.Id;
    }

    [Theory]
    [InlineData("analyst")]
    [InlineData("pm")]
    public async Task Assign_AsAnalystOrPm_SetsAssigneeAndDueDate(string role)
    {
        var id = await CreateFindingAsync();
        var client = factory.CreateClientAs("alice", role);

        var response = await client.PutAsJsonAsync($"/api/findings/{id}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate = Tomorrow }, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var finding = await client.GetFromJsonAsync<FindingResponse>($"/api/findings/{id}", Json, Ct);
        Assert.Equal(FakeUserDirectory.Developer.Id, finding!.AssigneeId);
        Assert.Equal(FakeUserDirectory.Developer.Name, finding.AssigneeName);
        Assert.Equal(Tomorrow, finding.DueDate?.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
    }

    [Theory]
    [InlineData("developer")]
    [InlineData("auditor")]
    public async Task Assign_WithoutAnalystOrPmRole_Returns403(string role)
    {
        var id = await CreateFindingAsync();
        var client = factory.CreateClientAs("bob", role);

        var response = await client.PutAsJsonAsync($"/api/findings/{id}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate = Tomorrow }, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Assign_ToSomeoneWhoIsNotADeveloper_Returns400()
    {
        var id = await CreateFindingAsync();
        var client = factory.CreateClientAs("alice", "analyst");

        var response = await client.PutAsJsonAsync($"/api/findings/{id}/assignment", new { assigneeId = "not-a-developer", dueDate = Tomorrow }, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Assign_WithDueDateInThePast_Returns400()
    {
        var id = await CreateFindingAsync();
        var client = factory.CreateClientAs("alice", "analyst");

        var response = await client.PutAsJsonAsync($"/api/findings/{id}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate = "2020-01-01" }, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Assign_UnknownFinding_Returns404()
    {
        var client = factory.CreateClientAs("alice", "analyst");

        var response = await client.PutAsJsonAsync($"/api/findings/{Guid.NewGuid()}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate = Tomorrow }, Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Developer_OnlySeesFindingsAssignedToThem()
    {
        var assigned = await CreateFindingAsync();
        var other = await CreateFindingAsync();
        var analyst = factory.CreateClientAs("alice", "analyst");
        await analyst.PutAsJsonAsync($"/api/findings/{assigned}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate = Tomorrow }, Ct);
        var developer = factory.CreateClientAs(FakeUserDirectory.Developer.Id, "developer");

        var list = await developer.GetFromJsonAsync<List<FindingResponse>>("/api/findings", Json, Ct);

        Assert.Contains(list!, f => f.Id == assigned);
        Assert.DoesNotContain(list!, f => f.Id == other);
        Assert.Equal(HttpStatusCode.OK, (await developer.GetAsync($"/api/findings/{assigned}", Ct)).StatusCode);
        // 404 and not 403, so a developer can't tell whether a finding exists.
        Assert.Equal(HttpStatusCode.NotFound, (await developer.GetAsync($"/api/findings/{other}", Ct)).StatusCode);
    }

    [Fact]
    public async Task Developer_WithNoAssignments_SeesNothing()
    {
        await CreateFindingAsync();
        var developer = factory.CreateClientAs("someone-else", "developer");

        var list = await developer.GetFromJsonAsync<List<FindingResponse>>("/api/findings", Json, Ct);

        Assert.Empty(list!);
    }

    [Theory]
    [InlineData("analyst", HttpStatusCode.OK)]
    [InlineData("pm", HttpStatusCode.OK)]
    [InlineData("developer", HttpStatusCode.Forbidden)]
    [InlineData("auditor", HttpStatusCode.Forbidden)]
    public async Task Assignees_OnlyForAnalystAndPm(string role, HttpStatusCode expected)
    {
        var client = factory.CreateClientAs("alice", role);

        var response = await client.GetAsync("/api/assignees", Ct);

        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.OK)
        {
            var assignees = await response.Content.ReadFromJsonAsync<List<AppUser>>(Json, Ct);
            Assert.Equal([FakeUserDirectory.Developer], assignees);
        }
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
