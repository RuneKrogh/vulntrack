using System.Security.Claims;
using VulnTrack.Api.Auth;

namespace VulnTrack.Api.Findings;

public static class FindingAccess
{
    // Analysts, PMs and auditors see every finding. Developers only see the findings assigned to them,
    // so a developer account can't be used to read every open vulnerability.
    public static IQueryable<Finding> VisibleTo(this IQueryable<Finding> findings, ClaimsPrincipal user)
    {
        if (user.IsInRole(Roles.Analyst) || user.IsInRole(Roles.Pm) || user.IsInRole(Roles.Auditor))
        {
            return findings;
        }

        // Without a user id nothing matches, rather than matching the unassigned findings.
        var userId = user.FindFirstValue("sub");
        return string.IsNullOrEmpty(userId) ? findings.Where(_ => false) : findings.Where(f => f.AssigneeId == userId);
    }
}
