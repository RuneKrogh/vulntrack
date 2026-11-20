using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulnTrack.Api.Audit;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Tests;

public sealed class AuditLogTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private HttpClient Analyst => factory.CreateClientAs("alice", "analyst");
    private HttpClient Pm => factory.CreateClientAs("paul", "pm");

    private async Task<Guid> CreateFindingAsync(string title = "Audited finding")
    {
        var response = await Analyst.PostAsJsonAsync("/api/findings", new
        {
            title,
            description = "d",
            affectedAsset = "web",
            severity = "High",
            discoveredAt = "2026-11-01",
        }, Ct);
        return (await response.Content.ReadFromJsonAsync<FindingResponse>(Json, Ct))!.Id;
    }

    private async Task SetStatusAsync(Guid id, string status) =>
        (await Analyst.PutAsJsonAsync($"/api/findings/{id}/status", new { status }, Ct)).EnsureSuccessStatusCode();

    private static async Task<AuditPage> GetAsync(HttpClient client, string query) =>
        (await client.GetFromJsonAsync<AuditPage>($"/api/audit?{query}", Json, Ct))!;

    [Theory]
    [InlineData("pm")]
    [InlineData("auditor")]
    public async Task PmOrAuditor_CanReadTheHistoryOfAFinding(string role)
    {
        var id = await CreateFindingAsync();
        await SetStatusAsync(id, "Triaged");

        var page = await GetAsync(factory.CreateClientAs("carol", role), $"findingId={id}");

        Assert.Equal([AuditAction.Updated, AuditAction.Created], page.Entries.Select(e => e.Action));
        Assert.All(page.Entries, e => Assert.Equal(id, e.FindingId));
        Assert.All(page.Entries, e => Assert.Equal("Audited finding", e.FindingTitle));
        Assert.Equal("alice", page.Entries[0].ActorName);
        var change = Assert.Single(page.Entries[0].Changes);
        Assert.Equal(("Status", "New", "Triaged"), (change.Field, change.From, change.To));
        Assert.Null(page.Next);
    }

    [Theory]
    [InlineData("analyst")]
    [InlineData("developer")]
    [InlineData("")]
    public async Task OtherRoles_Get403(string role)
    {
        var response = await factory.CreateClientAs("bob", role).GetAsync("/api/audit", Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task WithoutLogin_Returns401()
    {
        var response = await factory.CreateClient().GetAsync("/api/audit", Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Paging_ReturnsEveryEntryOnceNewestFirst()
    {
        var id = await CreateFindingAsync();
        foreach (var status in new[] { "Triaged", "InProgress", "Remediated", "Triaged" })
        {
            await SetStatusAsync(id, status);
        }

        var first = await GetAsync(Pm, $"findingId={id}&limit=2");
        var second = await GetAsync(Pm, $"findingId={id}&limit=2&before={first.Next}");
        var third = await GetAsync(Pm, $"findingId={id}&limit=2&before={second.Next}");

        var all = first.Entries.Concat(second.Entries).Concat(third.Entries).ToList();
        Assert.Equal(5, all.Count);
        Assert.Equal(all.Select(e => e.Sequence).OrderDescending(), all.Select(e => e.Sequence));
        Assert.Equal(AuditAction.Created, all[^1].Action);
        Assert.Single(third.Entries);
        Assert.Null(third.Next);
    }

    [Fact]
    public async Task WithoutFilter_ShowsAllFindingsNewestFirst()
    {
        var older = await CreateFindingAsync("Older finding");
        var newer = await CreateFindingAsync("Newer finding");

        var page = await GetAsync(Pm, "limit=200");

        var ours = page.Entries.Where(e => e.FindingId == older || e.FindingId == newer).Select(e => e.FindingTitle).ToList();
        Assert.Equal(["Newer finding", "Older finding"], ours);
    }

    [Fact]
    public async Task ShowsTheCurrentTitle()
    {
        var id = await CreateFindingAsync("Before rename");
        await Analyst.PutAsJsonAsync($"/api/findings/{id}", new { title = "After rename", description = "d", affectedAsset = "web", severity = "High" }, Ct);

        var page = await GetAsync(Pm, $"findingId={id}");

        Assert.All(page.Entries, e => Assert.Equal("After rename", e.FindingTitle));
    }

    [Theory]
    [InlineData("limit=0")]
    [InlineData("limit=201")]
    [InlineData("before=0")]
    [InlineData("before=abc")]
    [InlineData("findingId=not-a-guid")]
    public async Task InvalidQuery_Returns400(string query)
    {
        var response = await Pm.GetAsync($"/api/audit?{query}", Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
