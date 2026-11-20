using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Tests;

public sealed class StatusTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private HttpClient Analyst => factory.CreateClientAs("alice", "analyst");

    // The developer's username doubles as their user id, and dev-1 is the developer findings can be assigned to.
    private HttpClient Developer => factory.CreateClientAs(FakeUserDirectory.Developer.Id, "developer");

    private async Task<Guid> CreateFindingAsync(bool assignToDeveloper)
    {
        var response = await Analyst.PostAsJsonAsync("/api/findings", new
        {
            title = "Session cookie without Secure flag",
            description = "The cookie is also sent over plain HTTP.",
            affectedAsset = "web",
            severity = "Medium",
            discoveredAt = "2026-11-01",
        }, Ct);
        var id = (await response.Content.ReadFromJsonAsync<FindingResponse>(Json, Ct))!.Id;
        if (assignToDeveloper)
        {
            var dueDate = DateOnly.FromDateTime(DateTime.UtcNow).AddDays(7);
            await Analyst.PutAsJsonAsync($"/api/findings/{id}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate }, Ct);
        }

        return id;
    }

    private async Task<FindingStatus> StoredStatusAsync(Guid id) =>
        (await Analyst.GetFromJsonAsync<FindingResponse>($"/api/findings/{id}", Json, Ct))!.Status;

    [Theory]
    [InlineData("analyst", "Triaged")]
    [InlineData("analyst", "AcceptedRisk")]
    [InlineData("analyst", "New")]
    [InlineData("pm", "InProgress")]
    [InlineData("pm", "Remediated")]
    [InlineData("pm", "AcceptedRisk")]
    public async Task AnalystOrPm_CanSetAnyStatus(string role, string status)
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);

        var response = await factory.CreateClientAs("alice", role).PutAsJsonAsync($"/api/findings/{id}/status", new { status }, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Enum.Parse<FindingStatus>(status), await StoredStatusAsync(id));
    }

    [Theory]
    [InlineData("InProgress")]
    [InlineData("Remediated")]
    public async Task Developer_CanStartAndFinishOwnFinding(string status)
    {
        var id = await CreateFindingAsync(assignToDeveloper: true);

        var response = await Developer.PutAsJsonAsync($"/api/findings/{id}/status", new { status }, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Enum.Parse<FindingStatus>(status), await StoredStatusAsync(id));
    }

    [Theory]
    [InlineData("New")]
    [InlineData("Triaged")]
    [InlineData("AcceptedRisk")]
    public async Task Developer_CannotTriageOrAcceptRisk(string status)
    {
        var id = await CreateFindingAsync(assignToDeveloper: true);
        await Developer.PutAsJsonAsync($"/api/findings/{id}/status", new { status = "InProgress" }, Ct);

        var response = await Developer.PutAsJsonAsync($"/api/findings/{id}/status", new { status }, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(FindingStatus.InProgress, await StoredStatusAsync(id));
    }

    [Fact]
    public async Task Developer_GetsNotFoundForFindingsOfOthers()
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);

        var response = await Developer.PutAsJsonAsync($"/api/findings/{id}/status", new { status = "Remediated" }, Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal(FindingStatus.New, await StoredStatusAsync(id));
    }

    [Theory]
    [InlineData("auditor")]
    [InlineData("")]
    public async Task AuditorOrNoRole_Returns403(string role)
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);

        var response = await factory.CreateClientAs("bob", role).PutAsJsonAsync($"/api/findings/{id}/status", new { status = "Remediated" }, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(FindingStatus.New, await StoredStatusAsync(id));
    }

    [Fact]
    public async Task WithoutLogin_Returns401()
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);
        using var request = new HttpRequestMessage(HttpMethod.Put, $"/api/findings/{id}/status") { Content = JsonContent.Create(new { status = "Remediated" }) };
        request.Headers.Add("X-CSRF", "1");

        var response = await factory.CreateClient().SendAsync(request, Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UnknownFinding_Returns404()
    {
        var response = await Analyst.PutAsJsonAsync($"/api/findings/{Guid.NewGuid()}/status", new { status = "Triaged" }, Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    public static TheoryData<string, object> InvalidRequests => new()
    {
        { "unknown status", new { status = "Closed" } },
        { "numeric status", new { status = 3 } },
        { "missing status", new { } },
    };

    [Theory]
    [MemberData(nameof(InvalidRequests))]
    public async Task InvalidStatus_Returns400(string reason, object body)
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);

        var response = await Analyst.PutAsJsonAsync($"/api/findings/{id}/status", body, Ct);

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{reason}: {response.StatusCode}");
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
