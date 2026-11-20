using System.Security.Claims;

namespace VulnTrack.Api.Audit;

public sealed record Actor(string? Id, string Name);

public interface IAuditActor
{
    Actor Current { get; }
}

// The user behind the current request, as the audit trail records them.
public sealed class HttpAuditActor(IHttpContextAccessor httpContextAccessor) : IAuditActor
{
    public Actor Current
    {
        get
        {
            var context = httpContextAccessor.HttpContext;
            // Changes outside a request, like seeding at startup.
            if (context is null) return new Actor(null, "system");

            var user = context.User;
            // Only the public report form changes findings without a login. No IP address is stored, for privacy.
            if (user.Identity?.IsAuthenticated != true) return new Actor(null, "anonymous reporter");

            return new Actor(user.FindFirstValue("sub"), user.Identity.Name ?? "unknown");
        }
    }
}
