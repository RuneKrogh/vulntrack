using Microsoft.AspNetCore.Authorization;

namespace VulnTrack.Api.Auth;

// Client roles from Keycloak.
public static class Roles
{
    public const string Analyst = "analyst";
    public const string Developer = "developer";
    public const string Pm = "pm";
    public const string Auditor = "auditor";
}

public static class Policies
{
    public const string ViewFindings = nameof(ViewFindings);
    public const string CreateFindings = nameof(CreateFindings);
    public const string AssignFindings = nameof(AssignFindings);
    public const string ViewAssignees = nameof(ViewAssignees);
    public const string UpdateStatus = nameof(UpdateStatus);
}

public static class AuthorizationSetup
{
    // Who may do what, following the role table in the spec. Endpoints only refer to these policies.
    public static IServiceCollection AddRolePolicies(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            // Every endpoint requires a signed-in user unless it explicitly allows anonymous access.
            .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            .AddPolicy(Policies.ViewFindings, policy => policy.RequireRole(Roles.Analyst, Roles.Developer, Roles.Pm, Roles.Auditor))
            .AddPolicy(Policies.CreateFindings, policy => policy.RequireRole(Roles.Analyst, Roles.Pm))
            .AddPolicy(Policies.AssignFindings, policy => policy.RequireRole(Roles.Analyst, Roles.Pm))
            // For assigning and for the owner filter. Auditors already see every assignee's name on the findings.
            .AddPolicy(Policies.ViewAssignees, policy => policy.RequireRole(Roles.Analyst, Roles.Pm, Roles.Auditor))
            // Which statuses each role may set is checked per request, see FindingAccess.CanSetStatus.
            .AddPolicy(Policies.UpdateStatus, policy => policy.RequireRole(Roles.Analyst, Roles.Pm, Roles.Developer));
        return services;
    }
}
