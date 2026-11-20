using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using VulnTrack.Api.Audit;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options, IAuditActor auditActor) : DbContext(options)
{
    // Fields whose old and new values are copied into the audit trail. For any other field the log only
    // says that it changed, so the description and the reporter's email never end up there in plain text.
    private static readonly HashSet<string> LoggedValues =
    [
        nameof(Finding.Title),
        nameof(Finding.AffectedAsset),
        nameof(Finding.Severity),
        nameof(Finding.Status),
        nameof(Finding.DiscoveredAt),
        nameof(Finding.AssigneeId),
        nameof(Finding.AssigneeName),
        nameof(Finding.DueDate),
    ];

    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        var finding = modelBuilder.Entity<Finding>();
        finding.Property(f => f.Title).HasMaxLength(Finding.TitleMaxLength);
        finding.Property(f => f.Description).HasMaxLength(Finding.DescriptionMaxLength);
        finding.Property(f => f.AffectedAsset).HasMaxLength(Finding.AffectedAssetMaxLength);
        finding.Property(f => f.ReporterEmail).HasMaxLength(Finding.EmailMaxLength);
        finding.Property(f => f.AssigneeId).HasMaxLength(Finding.AssigneeIdMaxLength);
        finding.Property(f => f.AssigneeName).HasMaxLength(Finding.AssigneeNameMaxLength);
        // Stored as text, so the database stays readable and reordering the enums can't change data.
        finding.Property(f => f.Severity).HasConversion<string>().HasMaxLength(32);
        finding.Property(f => f.Status).HasConversion<string>().HasMaxLength(32);

        var audit = modelBuilder.Entity<AuditEntry>();
        audit.Property(e => e.ActorId).HasMaxLength(AuditEntry.ActorIdMaxLength);
        audit.Property(e => e.ActorName).HasMaxLength(AuditEntry.ActorNameMaxLength);
        audit.Property(e => e.Action).HasConversion<string>().HasMaxLength(32);
        audit.OwnsMany(e => e.Changes, changes => changes.ToJson());
        // A finding with history can't be deleted, so its audit trail can't disappear with it.
        audit.HasOne<Finding>().WithMany().HasForeignKey(e => e.FindingId).OnDelete(DeleteBehavior.Restrict);
        audit.HasIndex(e => new { e.FindingId, e.At });
        audit.HasIndex(e => e.At);
    }

    // Every change to a finding is logged in the same SaveChanges, and so in the same transaction.
    // A change can't be saved without its audit entry, and new endpoints are logged without extra code.
    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        AddAuditEntries();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        AddAuditEntries();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    private void AddAuditEntries()
    {
        ChangeTracker.DetectChanges();
        var actor = auditActor.Current;
        var now = DateTimeOffset.UtcNow;
        var entries = new List<AuditEntry>();

        foreach (var entry in ChangeTracker.Entries<Finding>())
        {
            if (entry.State == EntityState.Added)
            {
                entries.Add(NewEntry(entry.Entity.Id, AuditAction.Created, []));
            }
            else if (entry.State == EntityState.Modified)
            {
                var changes = entry.Properties
                    .Where(p => p.IsModified && !Equals(p.OriginalValue, p.CurrentValue))
                    .Select(Describe)
                    .ToList();
                // Saving the same values again isn't a change.
                if (changes.Count > 0) entries.Add(NewEntry(entry.Entity.Id, AuditAction.Updated, changes));
            }
        }

        AuditEntries.AddRange(entries);

        AuditEntry NewEntry(Guid findingId, AuditAction action, List<AuditChange> changes) => new()
        {
            FindingId = findingId,
            ActorId = actor.Id,
            ActorName = actor.Name,
            Action = action,
            Changes = changes,
            At = now,
        };
    }

    private static AuditChange Describe(PropertyEntry property)
    {
        var field = property.Metadata.Name;
        return LoggedValues.Contains(field)
            ? new AuditChange { Field = field, From = Format(property.OriginalValue), To = Format(property.CurrentValue) }
            : new AuditChange { Field = field };
    }

    private static string? Format(object? value) => value switch
    {
        null => null,
        DateOnly date => date.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture),
    };
}
