namespace VulnTrack.Api.Audit;

// One change to a finding: who made it, when, and which fields changed. Entries are only ever added.
public sealed class AuditEntry
{
    public const int ActorIdMaxLength = 64;
    public const int ActorNameMaxLength = 256;

    public Guid Id { get; init; } = Guid.NewGuid();
    public Guid FindingId { get; init; }

    // The Keycloak user id, or null for the public report form.
    public string? ActorId { get; init; }
    public required string ActorName { get; init; }

    public AuditAction Action { get; init; }
    public List<AuditChange> Changes { get; init; } = [];
    public DateTimeOffset At { get; init; }
}

public enum AuditAction
{
    Created,
    Updated,
}

// From and To are null when the field was empty, or when its value isn't copied into the log.
public sealed class AuditChange
{
    public required string Field { get; init; }
    public string? From { get; init; }
    public string? To { get; init; }
}
