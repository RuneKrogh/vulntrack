using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VulnTrack.Api.Audit;
using VulnTrack.Api.Data;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Tests;

public sealed class AuditTests(PostgresFactory factory) : IClassFixture<PostgresFactory>
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
    };

    private const string SecretDescription = "Steps to reproduce that only the finding itself should hold.";

    private HttpClient Analyst => factory.CreateClientAs("alice", "analyst");

    // The developer's username doubles as their user id, and dev-1 is the developer findings can be assigned to.
    private HttpClient Developer => factory.CreateClientAs(FakeUserDirectory.Developer.Id, "developer");

    private async Task<Guid> CreateFindingAsync()
    {
        var response = await Analyst.PostAsJsonAsync("/api/findings", new
        {
            title = "Original title",
            description = SecretDescription,
            affectedAsset = "web",
            severity = "High",
            discoveredAt = "2026-11-01",
        }, Ct);
        return (await response.Content.ReadFromJsonAsync<FindingResponse>(Json, Ct))!.Id;
    }

    private async Task AssignToDeveloperAsync(Guid id)
    {
        var response = await Analyst.PutAsJsonAsync($"/api/findings/{id}/assignment", new { assigneeId = FakeUserDirectory.Developer.Id, dueDate = "2999-01-01" }, Ct);
        response.EnsureSuccessStatusCode();
    }

    private async Task<List<AuditEntry>> EntriesAsync(Guid findingId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        return await db.AuditEntries.Where(e => e.FindingId == findingId).OrderBy(e => e.At).ToListAsync(Ct);
    }

    private static AuditChange Change(AuditEntry entry, string field) => Assert.Single(entry.Changes, c => c.Field == field);

    [Fact]
    public async Task Create_IsLoggedWithTheActor()
    {
        var id = await CreateFindingAsync();

        var entry = Assert.Single(await EntriesAsync(id));
        Assert.Equal(AuditAction.Created, entry.Action);
        Assert.Equal("alice", entry.ActorId);
        Assert.Equal("alice", entry.ActorName);
        Assert.True(DateTimeOffset.UtcNow - entry.At < TimeSpan.FromMinutes(1));
    }

    [Fact]
    public async Task PublicReport_IsLoggedAsAnonymousWithoutTheEmail()
    {
        var response = await factory.CreateAnonymousClient("10.8.0.1").PostAsJsonAsync("/api/reports", new
        {
            title = "Reported",
            description = SecretDescription,
            affectedAsset = "web",
            severity = "Low",
            reporterEmail = "reporter@example.com",
        }, Ct);
        var id = (await response.Content.ReadFromJsonAsync<ReportReceipt>(Ct))!.Reference;

        var entry = Assert.Single(await EntriesAsync(id));
        Assert.Equal(AuditAction.Created, entry.Action);
        Assert.Null(entry.ActorId);
        Assert.Equal("anonymous reporter", entry.ActorName);
        Assert.DoesNotContain("reporter@example.com", JsonSerializer.Serialize(entry));
    }

    [Fact]
    public async Task Edit_LogsOldAndNewValues_ButNotTheDescriptionText()
    {
        var id = await CreateFindingAsync();

        await Analyst.PutAsJsonAsync($"/api/findings/{id}", new
        {
            title = "New title",
            description = "A new description that must not be copied either.",
            affectedAsset = "web",
            severity = "Low",
        }, Ct);

        var entry = (await EntriesAsync(id))[^1];
        Assert.Equal(AuditAction.Updated, entry.Action);
        Assert.Equal(["Description", "Severity", "Title"], entry.Changes.Select(c => c.Field).Order());
        Assert.Equal(("Original title", "New title"), (Change(entry, "Title").From, Change(entry, "Title").To));
        Assert.Equal(("High", "Low"), (Change(entry, "Severity").From, Change(entry, "Severity").To));
        Assert.Null(Change(entry, "Description").From);
        Assert.Null(Change(entry, "Description").To);
        var logged = JsonSerializer.Serialize(await EntriesAsync(id));
        Assert.DoesNotContain(SecretDescription, logged);
        Assert.DoesNotContain("must not be copied", logged);
    }

    [Fact]
    public async Task Assignment_LogsAssigneeAndDueDate()
    {
        var id = await CreateFindingAsync();

        await AssignToDeveloperAsync(id);

        var entry = (await EntriesAsync(id))[^1];
        Assert.Equal(AuditAction.Updated, entry.Action);
        Assert.Equal((null, FakeUserDirectory.Developer.Id), (Change(entry, "AssigneeId").From, Change(entry, "AssigneeId").To));
        Assert.Equal(FakeUserDirectory.Developer.Name, Change(entry, "AssigneeName").To);
        Assert.Equal((null, "2999-01-01"), (Change(entry, "DueDate").From, Change(entry, "DueDate").To));
    }

    [Fact]
    public async Task StatusChange_IsLoggedWithTheDeveloperAsActor()
    {
        var id = await CreateFindingAsync();
        await AssignToDeveloperAsync(id);

        await Developer.PutAsJsonAsync($"/api/findings/{id}/status", new { status = "InProgress" }, Ct);

        var entry = (await EntriesAsync(id))[^1];
        Assert.Equal(FakeUserDirectory.Developer.Id, entry.ActorId);
        var change = Assert.Single(entry.Changes);
        Assert.Equal(("Status", "New", "InProgress"), (change.Field, change.From, change.To));
    }

    [Fact]
    public async Task RejectedOrInvalidChanges_AreNotLogged()
    {
        var id = await CreateFindingAsync();
        await AssignToDeveloperAsync(id);
        var before = (await EntriesAsync(id)).Count;

        // A developer may not change the severity, and the second request fails validation.
        var forbidden = await Developer.PutAsJsonAsync($"/api/findings/{id}", new { title = "t", description = "d", affectedAsset = "a", severity = "Low" }, Ct);
        var invalid = await Analyst.PutAsJsonAsync($"/api/findings/{id}/status", new { status = "Closed" }, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, forbidden.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        Assert.Equal(before, (await EntriesAsync(id)).Count);
    }

    [Fact]
    public async Task SavingTheSameValues_IsNotLogged()
    {
        var id = await CreateFindingAsync();

        await Analyst.PutAsJsonAsync($"/api/findings/{id}/status", new { status = "New" }, Ct);

        Assert.Single(await EntriesAsync(id));
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;
}
