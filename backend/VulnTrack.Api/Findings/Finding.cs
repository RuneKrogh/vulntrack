namespace VulnTrack.Api.Findings;

public sealed class Finding
{
    public const int TitleMaxLength = 200;
    public const int DescriptionMaxLength = 10_000;
    public const int AffectedAssetMaxLength = 200;
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
