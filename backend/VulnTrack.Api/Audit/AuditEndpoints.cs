using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using VulnTrack.Api.Auth;
using VulnTrack.Api.Data;

namespace VulnTrack.Api.Audit;

public static class AuditEndpoints
{
    public static void MapAuditEndpoints(this IEndpointRouteBuilder app) =>
        app.MapGet("/api/audit", List).RequireAuthorization(Policies.ViewAudit);

    // Newest first. The next page is everything older than the last entry on this one.
    private static async Task<AuditPage> List([AsParameters] AuditQuery query, AppDbContext db, CancellationToken cancellationToken)
    {
        var entries = db.AuditEntries.AsQueryable();
        if (query.FindingId is { } findingId) entries = entries.Where(e => e.FindingId == findingId);
        if (query.Before is { } before) entries = entries.Where(e => e.Sequence < before);

        var limit = query.Limit ?? AuditQuery.DefaultLimit;
        var page = await entries.OrderByDescending(e => e.Sequence).Take(limit).ToListAsync(cancellationToken);

        // The current titles, so the log is readable without opening every finding.
        var findingIds = page.Select(e => e.FindingId).Distinct().ToList();
        var titles = await db.Findings
            .Where(f => findingIds.Contains(f.Id))
            .Select(f => new { f.Id, f.Title })
            .ToDictionaryAsync(f => f.Id, f => f.Title, cancellationToken);

        var response = page
            .Select(e => new AuditEntryResponse(e.Sequence, e.FindingId, titles[e.FindingId], e.ActorId, e.ActorName, e.Action, e.Changes, e.At))
            .ToList();
        return new AuditPage(response, page.Count == limit ? page[^1].Sequence : null);
    }
}

public sealed record AuditQuery(
    Guid? FindingId,
    [property: Range(1, long.MaxValue)] long? Before,
    [property: Range(1, AuditQuery.MaxLimit)] int? Limit)
{
    public const int DefaultLimit = 50;
    public const int MaxLimit = 200;
}

public sealed record AuditEntryResponse(
    long Sequence,
    Guid FindingId,
    string FindingTitle,
    string? ActorId,
    string ActorName,
    AuditAction Action,
    List<AuditChange> Changes,
    DateTimeOffset At);

// Next is the value to send as "before" for the following page, or null on the last page.
public sealed record AuditPage(List<AuditEntryResponse> Entries, long? Next);
