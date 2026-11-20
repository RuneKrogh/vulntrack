using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using VulnTrack.Api.Data;
using VulnTrack.Api.Security;

namespace VulnTrack.Api.Findings;

// The public form for external reporters. It is the only endpoint that writes without a login.
public static class ReportEndpoints
{
    // A full report is about 9,000 characters. This leaves room for JSON escaping and multi-byte
    // characters, but stops large bodies before they are read into memory.
    private const long MaxBodyBytes = 64 * 1024;

    public static void MapReportEndpoints(this IEndpointRouteBuilder app) =>
        app.MapPost("/api/reports", Submit)
            .AllowAnonymous()
            .RequireRateLimiting(RateLimiting.PublicReports)
            .WithMetadata(new RequestSizeLimitAttribute(MaxBodyBytes));

    private static async Task<IResult> Submit(SubmitReportRequest request, AppDbContext db, CancellationToken cancellationToken)
    {
        // The severity is only the reporter's guess. The finding stays New until an analyst triages it.
        var finding = new Finding
        {
            Title = request.Title!,
            Description = request.Description!,
            AffectedAsset = request.AffectedAsset!,
            Severity = request.Severity!.Value,
            DiscoveredAt = DateOnly.FromDateTime(DateTime.UtcNow),
            ReporterEmail = request.ReporterEmail,
        };
        db.Findings.Add(finding);
        await db.SaveChangesAsync(cancellationToken);

        // External reporters can't view findings, so they only get a reference to quote when following up.
        return Results.Accepted(value: new ReportReceipt(finding.Id));
    }
}

public sealed record SubmitReportRequest(
    [property: Required, MaxLength(Finding.TitleMaxLength)] string? Title,
    [property: Required, MaxLength(Finding.DescriptionMaxLength)] string? Description,
    [property: Required, MaxLength(Finding.AffectedAssetMaxLength)] string? AffectedAsset,
    [property: Required, EnumDataType(typeof(Severity))] Severity? Severity,
    [property: Required, EmailAddress, MaxLength(Finding.EmailMaxLength)] string? ReporterEmail);

public sealed record ReportReceipt(Guid Reference);
