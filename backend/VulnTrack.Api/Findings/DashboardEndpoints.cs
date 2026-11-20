using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using VulnTrack.Api.Auth;
using VulnTrack.Api.Data;

namespace VulnTrack.Api.Findings;

public static class DashboardEndpoints
{
    public static void MapDashboardEndpoints(this IEndpointRouteBuilder app) =>
        app.MapGet("/api/dashboard", Get).RequireAuthorization(Policies.ViewFindings);

    // Counts only the findings the user may see, so a developer's dashboard doesn't reveal
    // how many findings exist outside their own. The counting happens in the database.
    private static async Task<DashboardResponse> Get(ClaimsPrincipal user, AppDbContext db, CancellationToken cancellationToken)
    {
        var findings = db.Findings.VisibleTo(user);
        // Remediated and accepted findings are closed. Everything else still needs work.
        var open = findings.Where(f => f.Status != FindingStatus.Remediated && f.Status != FindingStatus.AcceptedRisk);
        var today = DateOnly.FromDateTime(DateTime.UtcNow);

        var bySeverity = await open
            .GroupBy(f => f.Severity)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(g => g.Key, g => g.Count, cancellationToken);
        var byStatus = await findings
            .GroupBy(f => f.Status)
            .Select(g => new { g.Key, Count = g.Count() })
            .ToDictionaryAsync(g => g.Key, g => g.Count, cancellationToken);
        var withDueDate = await open.CountAsync(f => f.DueDate != null, cancellationToken);
        var overdue = await open.CountAsync(f => f.DueDate < today, cancellationToken);

        // Every severity and status is included, also with a count of zero.
        return new DashboardResponse(
            Enum.GetValues<Severity>().ToDictionary(s => s, bySeverity.GetValueOrDefault),
            Enum.GetValues<FindingStatus>().ToDictionary(s => s, byStatus.GetValueOrDefault),
            withDueDate,
            overdue);
    }
}

public sealed record DashboardResponse(
    Dictionary<Severity, int> OpenBySeverity,
    Dictionary<FindingStatus, int> ByStatus,
    int OpenWithDueDate,
    int Overdue);
