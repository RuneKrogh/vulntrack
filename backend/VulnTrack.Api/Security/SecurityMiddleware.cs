namespace VulnTrack.Api.Security;

public static class SecurityMiddleware
{
    public const string CsrfHeader = "X-CSRF";

    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            var headers = context.Response.Headers;
            headers.ContentSecurityPolicy =
                "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
            headers.XContentTypeOptions = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";
            await next(context);
        });

    // State-changing API calls must carry a custom header. A cross-site form can't add one,
    // and a cross-site fetch with it triggers a CORS preflight that this API never allows.
    public static IApplicationBuilder UseCsrfHeaderCheck(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            var request = context.Request;
            var isSafeMethod = HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method) ||
                               HttpMethods.IsOptions(request.Method);

            if (request.Path.StartsWithSegments("/api") && !isSafeMethod && request.Headers[CsrfHeader] != "1")
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            await next(context);
        });
}
