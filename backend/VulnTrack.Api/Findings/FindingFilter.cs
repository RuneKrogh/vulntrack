using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;

namespace VulnTrack.Api.Findings;

// Optional query parameters for the findings list. Every filter only narrows what the user may already see.
// An empty value means no filter.
public sealed record FindingFilter(
    [property: EnumName(typeof(FindingStatus))] string? Status,
    [property: EnumName(typeof(Severity))] string? Severity,
    // A developer's Keycloak id, or "none" for unassigned findings. Keycloak ids are UUIDs, so they can't clash with it.
    [property: MaxLength(Finding.AssigneeIdMaxLength)] string? AssigneeId,
    [property: MaxLength(Finding.TitleMaxLength)] string? Q)
{
    public const string Unassigned = "none";

    // The search covers title and asset, not the description. The description is meant to be encrypted
    // later, and the database can't search encrypted text.
    public IQueryable<Finding> Apply(IQueryable<Finding> findings)
    {
        if (!string.IsNullOrEmpty(Status))
        {
            var status = Enum.Parse<FindingStatus>(Status);
            findings = findings.Where(f => f.Status == status);
        }

        if (!string.IsNullOrEmpty(Severity))
        {
            var severity = Enum.Parse<Severity>(Severity);
            findings = findings.Where(f => f.Severity == severity);
        }

        if (AssigneeId == Unassigned) findings = findings.Where(f => f.AssigneeId == null);
        else if (!string.IsNullOrEmpty(AssigneeId)) findings = findings.Where(f => f.AssigneeId == AssigneeId);

        if (!string.IsNullOrWhiteSpace(Q))
        {
            var pattern = $"%{EscapeLike(Q.Trim())}%";
            findings = findings.Where(f =>
                EF.Functions.ILike(f.Title, pattern, @"\") || EF.Functions.ILike(f.AffectedAsset, pattern, @"\"));
        }

        return findings;
    }

    // The search text is sent as a parameter, so it can't change the SQL. Escaping % and _ also stops it
    // from being read as LIKE wildcards, so "50%" finds "50%" and not everything that starts with "50".
    private static string EscapeLike(string text) =>
        text.Replace(@"\", @"\\").Replace("%", @"\%").Replace("_", @"\_");
}

// Only the exact names of the enum. Binding to the enum directly would also accept numbers like "2"
// and lists like "High,Low", which the JSON API rejects too.
[AttributeUsage(AttributeTargets.Property)]
public sealed class EnumNameAttribute(Type enumType) : ValidationAttribute
{
    public override bool IsValid(object? value) =>
        value is not string name || name.Length == 0 || Enum.GetNames(enumType).Contains(name);

    public override string FormatErrorMessage(string name) =>
        $"The field {name} must be one of {string.Join(", ", Enum.GetNames(enumType))}.";
}
