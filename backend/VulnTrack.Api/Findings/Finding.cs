namespace VulnTrack.Api.Findings;

public sealed class Finding
{
    // Limits on user input, so the public report form can't be used to fill the database.
    // A title is a one-line summary (GitHub issues allow 256).
    public const int TitleMaxLength = 256;
    // Room for steps to reproduce and a short proof of concept. Long scanner output belongs in attachments.
    public const int DescriptionMaxLength = 8192;
    // A component or system name, like "payment-api".
    public const int AffectedAssetMaxLength = 256;
    // The longest valid email address (RFC 5321, see RFC 3696 errata 1690).
    public const int EmailMaxLength = 254;

    // Random ids, so findings can't be enumerated by counting.
    public Guid Id { get; init; } = Guid.NewGuid();
    public required string Title { get; set; }
    public required string Description { get; set; }
    public required string AffectedAsset { get; set; }
    public Severity Severity { get; set; }
    public DateOnly DiscoveredAt { get; set; }
    public FindingStatus Status { get; set; } = FindingStatus.New;

    // Only set when the finding comes from the public report form.
    public string? ReporterEmail { get; init; }
}

public enum Severity
{
    Low,
    Medium,
    High,
    Critical,
}

public enum FindingStatus
{
    New,
    Triaged,
    InProgress,
    Remediated,
    AcceptedRisk,
}
