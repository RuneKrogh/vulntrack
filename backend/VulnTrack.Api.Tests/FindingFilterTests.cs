using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Tests;

public sealed class FindingFilterTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    // Each test puts a unique marker in the asset and searches for it, so findings from other tests don't interfere.
    private static string NewMarker() => $"asset-{Guid.NewGuid():N}";

    private async Task<FindingResponse> CreateAsync(string title, string asset, string severity = "Medium", string description = "Details.")
    {
        var response = await factory.CreateClientAs("alice", "analyst").PostAsJsonAsync("/api/findings", new
        {
            title,
            description,
            affectedAsset = asset,
            severity,
            discoveredAt = "2026-11-01",
        }, Ct);
        return (await response.Content.ReadFromJsonAsync<FindingResponse>(Json, Ct))!;
    }

    private async Task<List<string>> TitlesAsync(string query, string username = "alice", string role = "analyst")
    {
        var findings = await factory.CreateClientAs(username, role).GetFromJsonAsync<List<FindingResponse>>($"/api/findings?{query}", Json, Ct);
        return findings!.Select(f => f.Title).Order().ToList();
    }

    [Fact]
    public async Task Severity_ReturnsOnlyThatSeverity()
    {
        var marker = NewMarker();
        await CreateAsync("High one", marker, "High");
        await CreateAsync("Low one", marker, "Low");

        Assert.Equal(["High one"], await TitlesAsync($"q={marker}&severity=High"));
    }

    [Fact]
    public async Task Status_ReturnsOnlyThatStatus()
    {
        var marker = NewMarker();
        await CreateAsync("New one", marker);

        Assert.Equal(["New one"], await TitlesAsync($"q={marker}&status=New"));
        Assert.Empty(await TitlesAsync($"q={marker}&status=Remediated"));
    }

    [Fact]
    public async Task AssigneeId_ReturnsAssignedOrUnassignedFindings()
    {
        var marker = NewMarker();
        var assigned = await CreateAsync("Assigned", marker);
        await CreateAsync("Unassigned", marker);
        var dueDate = DateOnly.FromDateTime(DateTime.UtcNow).AddDays(1);
        await factory.CreateClientAs("alice", "analyst")
            .PutAsJsonAsync($"/api/findings/{assigned.Id}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate }, Ct);

        Assert.Equal(["Assigned"], await TitlesAsync($"q={marker}&assigneeId={FakeUserDirectory.Developer.Id}"));
        Assert.Equal(["Unassigned"], await TitlesAsync($"q={marker}&assigneeId=none"));
    }

    [Fact]
    public async Task Q_SearchesTitleAndAssetIgnoringCase()
    {
        var marker = NewMarker();
        await CreateAsync($"Open redirect {marker}-title", "web");
        await CreateAsync("Weak TLS config", $"{marker}-asset");

        Assert.Equal(["Open redirect " + marker + "-title"], await TitlesAsync($"q={marker.ToUpperInvariant()}-TITLE"));
        Assert.Equal(["Weak TLS config"], await TitlesAsync($"q={marker}-asset"));
    }

    [Fact]
    public async Task Q_DoesNotSearchTheDescription()
    {
        var marker = NewMarker();
        await CreateAsync("Unrelated title", "web", description: $"Only the description mentions {marker}.");

        Assert.Empty(await TitlesAsync($"q={marker}"));
    }

    [Theory]
    [InlineData("50%", "50% off", "50 off")]
    [InlineData("a_b", "a_b", "axb")]
    [InlineData(@"a\b", @"a\b", "ab")]
    public async Task Q_TreatsLikeWildcardsAsText(string search, string matching, string notMatching)
    {
        var marker = NewMarker();
        await CreateAsync($"{marker} {matching}", "web");
        await CreateAsync($"{marker} {notMatching}", "web");

        Assert.Equal([$"{marker} {matching}"], await TitlesAsync($"q={Uri.EscapeDataString($"{marker} {search}")}"));
    }

    [Fact]
    public async Task Filters_DoNotShowDevelopersFindingsAssignedToOthers()
    {
        var marker = NewMarker();
        await CreateAsync("Not assigned to the developer", marker);

        Assert.Empty(await TitlesAsync($"q={marker}", "dev-1", "developer"));
        Assert.Empty(await TitlesAsync($"q={marker}&assigneeId=none", "dev-1", "developer"));
    }

    [Theory]
    [InlineData("status=Bogus")]
    [InlineData("severity=Extreme")]
    [InlineData("severity=99")]
    [InlineData("severity=2")]
    [InlineData("severity=High,Low")]
    [InlineData("severity=high")]
    [InlineData("status=99")]
    [InlineData("status=new")]
    public async Task OnlyExactEnumNames_AreAccepted(string query)
    {
        var response = await factory.CreateClientAs("alice", "analyst").GetAsync($"/api/findings?{query}", Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task EmptyValues_MeanNoFilter()
    {
        var marker = NewMarker();
        await CreateAsync("Any finding", marker);

        Assert.Equal(["Any finding"], await TitlesAsync($"q={marker}&status=&severity=&assigneeId="));
    }

    [Fact]
    public async Task TooLongSearchOrAssignee_Returns400()
    {
        var client = factory.CreateClientAs("alice", "analyst");

        var q = await client.GetAsync($"/api/findings?q={new string('x', Finding.TitleMaxLength + 1)}", Ct);
        var assignee = await client.GetAsync($"/api/findings?assigneeId={new string('x', Finding.AssigneeIdMaxLength + 1)}", Ct);

        Assert.Equal(HttpStatusCode.BadRequest, q.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, assignee.StatusCode);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
