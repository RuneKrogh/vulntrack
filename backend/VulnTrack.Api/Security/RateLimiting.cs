using System.Net;
using System.Net.Sockets;
using System.Threading.RateLimiting;

namespace VulnTrack.Api.Security;

public static class RateLimiting
{
    public const string PublicReports = nameof(PublicReports);

    // The limit is per client only. A shared limit for everyone would let a handful of clients
    // use it up and block real reporters, which is worse than a flood of junk reports.
    public static IServiceCollection AddRateLimits(this IServiceCollection services) =>
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(PublicReports, context => RateLimitPartition.GetFixedWindowLimiter(
                ClientKey(context.Connection.RemoteIpAddress),
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromMinutes(10) }));
        });

    // The TCP source address is used and not X-Forwarded-For, which any client can set.
    // IPv6 clients usually get a whole /64, so they are limited per /64 and not per address.
    private static string ClientKey(IPAddress? address)
    {
        if (address is null) return "unknown";
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != AddressFamily.InterNetworkV6) return address.ToString();

        var bytes = address.GetAddressBytes();
        Array.Clear(bytes, 8, 8);
        return $"{new IPAddress(bytes)}/64";
    }
}
