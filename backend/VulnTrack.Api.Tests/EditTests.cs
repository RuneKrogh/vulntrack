using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Tests;

public sealed class EditTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private HttpClient Analyst => factory.CreateClientAs("alice", "analyst");

    // The developer's username doubles as their user id, and dev-1 is the developer findings can be assigned to.
    private HttpClient Developer => factory.CreateClientAs(FakeUserDirectory.Developer.Id, "developer");

    private static object Edited(string severity = "High") => new
    {
        title = "Edited title",
        description = "Edited description.",
        affectedAsset = "edited-asset",
        severity,
    };

    private async Task<Guid> CreateFindingAsync(bool assignToDeveloper)
    {
        var response = await Analyst.PostAsJsonAsync("/api/findings", new
        {
            title = "Original title",
            description = "Original description.",
            affectedAsset = "original-asset",
            severity = "High",
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

    private async Task<FindingResponse> StoredAsync(Guid id) =>
        (await Analyst.GetFromJsonAsync<FindingResponse>($"/api/findings/{id}", Json, Ct))!;

    [Theory]
    [InlineData("analyst")]
    [InlineData("pm")]
    public async Task AnalystOrPm_CanEditEverythingIncludingSeverity(string role)
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);

        var response = await factory.CreateClientAs("alice", role).PutAsJsonAsync($"/api/findings/{id}", Edited("Low"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var stored = await StoredAsync(id);
        Assert.Equal("Edited title", stored.Title);
        Assert.Equal("Edited description.", stored.Description);
        Assert.Equal("edited-asset", stored.AffectedAsset);
        Assert.Equal(Severity.Low, stored.Severity);
    }

    [Fact]
    public async Task Developer_CanEditOwnFindingWithSameSeverity()
    {
        var id = await CreateFindingAsync(assignToDeveloper: true);

        var response = await Developer.PutAsJsonAsync($"/api/findings/{id}", Edited("High"), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Edited title", (await StoredAsync(id)).Title);
    }

    [Theory]
    [InlineData("Low")]
    [InlineData("Critical")]
    public async Task Developer_CannotChangeSeverity(string severity)
    {
        var id = await CreateFindingAsync(assignToDeveloper: true);

        var response = await Developer.PutAsJsonAsync($"/api/findings/{id}", Edited(severity), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var stored = await StoredAsync(id);
        Assert.Equal(Severity.High, stored.Severity);
        Assert.Equal("Original title", stored.Title);
    }

    [Fact]
    public async Task Developer_GetsNotFoundForFindingsOfOthers()
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);

        var response = await Developer.PutAsJsonAsync($"/api/findings/{id}", Edited(), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("Original title", (await StoredAsync(id)).Title);
    }

    [Theory]
    [InlineData("auditor")]
    [InlineData("")]
    public async Task AuditorOrNoRole_Returns403(string role)
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);

        var response = await factory.CreateClientAs("bob", role).PutAsJsonAsync($"/api/findings/{id}", Edited(), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal("Original title", (await StoredAsync(id)).Title);
    }

    [Fact]
    public async Task IgnoresStatusAssignmentDateAndReporterEmail()
    {
        var report = await factory.CreateAnonymousClient("10.9.0.1").PostAsJsonAsync("/api/reports", new
        {
            title = "Reported",
            description = "d",
            affectedAsset = "a",
            severity = "High",
            reporterEmail = "reporter@example.com",
        }, Ct);
        var id = (await report.Content.ReadFromJsonAsync<ReportReceipt>(Ct))!.Reference;
        var before = await StoredAsync(id);

        await Analyst.PutAsJsonAsync($"/api/findings/{id}", new
        {
            title = "Edited title",
            description = "d",
            affectedAsset = "a",
            severity = "High",
            status = "Remediated",
            assigneeId = FakeUserDirectory.Developer.Id,
            dueDate = "2999-01-01",
            discoveredAt = "2001-01-01",
            reporterEmail = "attacker@example.com",
        }, Ct);
        var after = await StoredAsync(id);

        Assert.Equal("Edited title", after.Title);
        Assert.Equal(before.Status, after.Status);
        Assert.Null(after.AssigneeId);
        Assert.Null(after.DueDate);
        Assert.Equal(before.DiscoveredAt, after.DiscoveredAt);
        Assert.Equal("reporter@example.com", after.ReporterEmail);
    }

    [Fact]
    public async Task UnknownFinding_Returns404()
    {
        var response = await Analyst.PutAsJsonAsync($"/api/findings/{Guid.NewGuid()}", Edited(), Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    public static TheoryData<string, object> InvalidEdits => new()
    {
        { "missing title", new { description = "d", affectedAsset = "a", severity = "Low" } },
        { "blank title", new { title = " ", description = "d", affectedAsset = "a", severity = "Low" } },
        { "title too long", new { title = new string('x', Finding.TitleMaxLength + 1), description = "d", affectedAsset = "a", severity = "Low" } },
        { "description too long", new { title = "t", description = new string('x', Finding.DescriptionMaxLength + 1), affectedAsset = "a", severity = "Low" } },
        { "missing severity", new { title = "t", description = "d", affectedAsset = "a" } },
        { "numeric severity", new { title = "t", description = "d", affectedAsset = "a", severity = 1 } },
    };

    [Theory]
    [MemberData(nameof(InvalidEdits))]
    public async Task InvalidInput_Returns400(string reason, object body)
    {
        var id = await CreateFindingAsync(assignToDeveloper: false);

        var response = await Analyst.PutAsJsonAsync($"/api/findings/{id}", body, Ct);

        Assert.True(response.StatusCode == HttpStatusCode.BadRequest, $"{reason}: {response.StatusCode}");
        Assert.Equal("Original title", (await StoredAsync(id)).Title);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
