using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using VulnTrack.Api.Auth;
using VulnTrack.Api.Data;
using VulnTrack.Api.Users;

namespace VulnTrack.Api.Findings;

public static class FindingEndpoints
{
    public static void MapFindingEndpoints(this IEndpointRouteBuilder app)
    {
        var findings = app.MapGroup("/api/findings");
        findings.MapGet("/", List).RequireAuthorization(Policies.ViewFindings);
        findings.MapGet("/{id:guid}", Get).RequireAuthorization(Policies.ViewFindings);
        findings.MapPost("/", Create).RequireAuthorization(Policies.CreateFindings);
        findings.MapPut("/{id:guid}/assignment", Assign).RequireAuthorization(Policies.AssignFindings);

        app.MapGet("/api/assignees", (IUserDirectory users, CancellationToken cancellationToken) => users.GetDevelopersAsync(cancellationToken))
            .RequireAuthorization(Policies.AssignFindings);
    }

    private static async Task<List<FindingResponse>> List(AppDbContext db, CancellationToken cancellationToken) =>
        await db.Findings
            .OrderByDescending(f => f.DiscoveredAt)
            .Select(f => FindingResponse.From(f))
            .ToListAsync(cancellationToken);

    private static async Task<IResult> Get(Guid id, AppDbContext db, CancellationToken cancellationToken)
    {
        var finding = await db.Findings.FindAsync([id], cancellationToken);
        return finding is null ? Results.NotFound() : Results.Ok(FindingResponse.From(finding));
    }

    private static async Task<IResult> Create(CreateFindingRequest request, AppDbContext db, CancellationToken cancellationToken)
    {
        // Status always starts as New, and internal findings never have a reporter email.
        var finding = new Finding
        {
            Title = request.Title!,
            Description = request.Description!,
            AffectedAsset = request.AffectedAsset!,
            Severity = request.Severity!.Value,
            DiscoveredAt = request.DiscoveredAt!.Value,
        };
        db.Findings.Add(finding);
        await db.SaveChangesAsync(cancellationToken);
        return Results.Created($"/api/findings/{finding.Id}", FindingResponse.From(finding));
    }

    private static async Task<IResult> Assign(
        Guid id,
        AssignFindingRequest request,
        AppDbContext db,
        IUserDirectory users,
        CancellationToken cancellationToken)
    {
        var finding = await db.Findings.FindAsync([id], cancellationToken);
        if (finding is null) return Results.NotFound();

        // Only developers that exist in Keycloak can be assigned, not any id the client sends.
        var assignee = (await users.GetDevelopersAsync(cancellationToken)).SingleOrDefault(user => user.Id == request.AssigneeId);
        if (assignee is null)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                [nameof(request.AssigneeId)] = ["The assignee must be a developer."],
            });
        }

        finding.AssigneeId = assignee.Id;
        finding.AssigneeName = assignee.Name;
        finding.DueDate = request.DueDate;
        await db.SaveChangesAsync(cancellationToken);
        return Results.Ok(FindingResponse.From(finding));
    }
}

public sealed record AssignFindingRequest(
    [property: Required, MaxLength(Finding.AssigneeIdMaxLength)] string? AssigneeId,
    [property: Required] DateOnly? DueDate) : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (DueDate < DateOnly.FromDateTime(DateTime.UtcNow))
        {
            yield return new ValidationResult("The due date can't be in the past.", [nameof(DueDate)]);
        }
    }
}

public sealed record CreateFindingRequest(
    [property: Required, MaxLength(Finding.TitleMaxLength)] string? Title,
    [property: Required, MaxLength(Finding.DescriptionMaxLength)] string? Description,
    [property: Required, MaxLength(Finding.AffectedAssetMaxLength)] string? AffectedAsset,
    [property: Required, EnumDataType(typeof(Severity))] Severity? Severity,
    [property: Required] DateOnly? DiscoveredAt) : IValidatableObject
{
    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (DiscoveredAt > DateOnly.FromDateTime(DateTime.UtcNow))
        {
            yield return new ValidationResult("The discovery date can't be in the future.", [nameof(DiscoveredAt)]);
        }
    }
}

public sealed record FindingResponse(
    Guid Id,
    string Title,
    string Description,
    string AffectedAsset,
    Severity Severity,
    DateOnly DiscoveredAt,
    FindingStatus Status,
    string? AssigneeId,
    string? AssigneeName,
    DateOnly? DueDate)
{
    public static FindingResponse From(Finding finding) => new(
        finding.Id,
        finding.Title,
        finding.Description,
        finding.AffectedAsset,
        finding.Severity,
        finding.DiscoveredAt,
        finding.Status,
        finding.AssigneeId,
        finding.AssigneeName,
        finding.DueDate);
}
