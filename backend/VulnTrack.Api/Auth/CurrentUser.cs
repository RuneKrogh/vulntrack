using System.Security.Claims;

namespace VulnTrack.Api.Auth;

public sealed record CurrentUser(string Name, IReadOnlyList<string> Roles)
{
    public static CurrentUser Get(ClaimsPrincipal user)
    {
        var identity = (ClaimsIdentity)user.Identity!;
        var roles = user.FindAll(identity.RoleClaimType).Select(claim => claim.Value).Order().ToList();
        return new CurrentUser(user.Identity!.Name ?? "", roles);
    }
}
