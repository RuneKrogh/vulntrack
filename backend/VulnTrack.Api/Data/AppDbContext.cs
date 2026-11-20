using Microsoft.EntityFrameworkCore;
using VulnTrack.Api.Findings;

namespace VulnTrack.Api.Data;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<Finding> Findings => Set<Finding>();

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
    }
}
