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

    // The reporter's email is personal data. Analysts and PMs need it to contact the reporter during triage.
    // Developers and auditors don't, so they never get it.
    public static bool CanSeeReporterEmail(this ClaimsPrincipal user) =>
        user.IsInRole(Roles.Analyst) || user.IsInRole(Roles.Pm);

    // Developers may start and finish the work on their findings. Triage and accepting a risk are decisions
    // for analysts and PMs, so a developer can't make a finding go away by accepting the risk instead of fixing it.
    public static bool CanSetStatus(this ClaimsPrincipal user, FindingStatus status) =>
        user.IsInRole(Roles.Analyst) || user.IsInRole(Roles.Pm) ||
        (user.IsInRole(Roles.Developer) && status is FindingStatus.InProgress or FindingStatus.Remediated);
}
