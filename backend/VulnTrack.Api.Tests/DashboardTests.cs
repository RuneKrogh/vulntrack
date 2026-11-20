using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.DependencyInjection;
using VulnTrack.Api.Data;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Tests;

public sealed class DashboardTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private static readonly DateOnly Today = DateOnly.FromDateTime(DateTime.UtcNow);

    // Statuses and past due dates can't be set through the API yet, so the findings are stored directly.
    private async Task SeedAsync(params (Severity Severity, FindingStatus Status, DateOnly? DueDate, string? AssigneeId)[] findings)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Findings.AddRange(findings.Select(f => new Finding
        {
            Title = "Dashboard test",
            Description = "d",
            AffectedAsset = "a",
            Severity = f.Severity,
            Status = f.Status,
            DiscoveredAt = Today,
            DueDate = f.DueDate,
            AssigneeId = f.AssigneeId,
            AssigneeName = f.AssigneeId,
        }));
        await db.SaveChangesAsync(Ct);
    }

    private async Task<DashboardResponse> GetAsync(string username, string role) =>
        (await factory.CreateClientAs(username, role).GetFromJsonAsync<DashboardResponse>("/api/dashboard", Json, Ct))!;

    [Theory]
    [InlineData("analyst")]
    [InlineData("pm")]
    [InlineData("auditor")]
    public async Task Counts_OpenBySeverity_AllByStatus_AndOverdue(string role)
    {
        var before = await GetAsync("alice", role);

        await SeedAsync(
            (Severity.Critical, FindingStatus.New, null, null),
            (Severity.High, FindingStatus.Triaged, null, null),
            (Severity.High, FindingStatus.InProgress, Today.AddDays(-1), null),
            (Severity.Medium, FindingStatus.New, Today, null),
            // Closed findings aren't open, and a closed finding past its due date isn't overdue.
            (Severity.Low, FindingStatus.Remediated, Today.AddDays(-1), null),
            (Severity.Medium, FindingStatus.AcceptedRisk, null, null));
        var after = await GetAsync("alice", role);

        Assert.Equal(1, after.OpenBySeverity[Severity.Critical] - before.OpenBySeverity[Severity.Critical]);
        Assert.Equal(2, after.OpenBySeverity[Severity.High] - before.OpenBySeverity[Severity.High]);
        Assert.Equal(1, after.OpenBySeverity[Severity.Medium] - before.OpenBySeverity[Severity.Medium]);
        Assert.Equal(0, after.OpenBySeverity[Severity.Low] - before.OpenBySeverity[Severity.Low]);
        Assert.Equal(2, after.ByStatus[FindingStatus.New] - before.ByStatus[FindingStatus.New]);
        Assert.Equal(1, after.ByStatus[FindingStatus.Triaged] - before.ByStatus[FindingStatus.Triaged]);
        Assert.Equal(1, after.ByStatus[FindingStatus.InProgress] - before.ByStatus[FindingStatus.InProgress]);
        Assert.Equal(1, after.ByStatus[FindingStatus.Remediated] - before.ByStatus[FindingStatus.Remediated]);
        Assert.Equal(1, after.ByStatus[FindingStatus.AcceptedRisk] - before.ByStatus[FindingStatus.AcceptedRisk]);
        // Due today is not overdue yet.
        Assert.Equal(2, after.OpenWithDueDate - before.OpenWithDueDate);
        Assert.Equal(1, after.Overdue - before.Overdue);
    }

    [Fact]
    public async Task Developer_OnlyCountsOwnFindings()
    {
        var developerId = $"dev-{Guid.NewGuid():N}";
        await SeedAsync(
            (Severity.High, FindingStatus.InProgress, Today.AddDays(-3), developerId),
            (Severity.Critical, FindingStatus.New, Today.AddDays(-3), null),
            (Severity.Critical, FindingStatus.New, null, "someone-else"));

        var dashboard = await GetAsync(developerId, "developer");

        Assert.Equal(1, dashboard.OpenBySeverity.Values.Sum());
        Assert.Equal(1, dashboard.OpenBySeverity[Severity.High]);
        Assert.Equal(1, dashboard.ByStatus.Values.Sum());
        Assert.Equal(1, dashboard.OpenWithDueDate);
        Assert.Equal(1, dashboard.Overdue);
    }

    [Fact]
    public async Task IncludesEverySeverityAndStatus()
    {
        var dashboard = await GetAsync($"dev-{Guid.NewGuid():N}", "developer");

        Assert.Equal(Enum.GetValues<Severity>(), dashboard.OpenBySeverity.Keys.Order());
        Assert.Equal(Enum.GetValues<FindingStatus>(), dashboard.ByStatus.Keys.Order());
        Assert.All(dashboard.OpenBySeverity.Values, count => Assert.Equal(0, count));
    }

    [Fact]
    public async Task WithoutRole_Returns403_AndWithoutLogin_Returns401()
    {
        Assert.Equal(HttpStatusCode.Forbidden, (await factory.CreateClientAs("mallory").GetAsync("/api/dashboard", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateClient().GetAsync("/api/dashboard", Ct)).StatusCode);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
