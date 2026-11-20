using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using VulnTrack.Api.Audit;

namespace VulnTrack.Api.Data;

public static class DatabaseSetup
{
    public static IServiceCollection AddDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHttpContextAccessor();
        services.AddScoped<IAuditActor, HttpAuditActor>();
        services.AddDbContext<AppDbContext>(options => options.UseNpgsql(configuration.GetConnectionString("Default")));
        services.AddHostedService<DatabaseMigrator>();
        return services;
    }
}

// Applies pending migrations at startup, so `docker compose up` gives a ready database.
public sealed class DatabaseMigrator(IServiceScopeFactory scopeFactory) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        // EF reads the migration history before it creates the history table, which logs a failed query
        // on an empty database. Creating the table first keeps real database errors the only ones in the log.
        await db.GetService<IHistoryRepository>().CreateIfNotExistsAsync(cancellationToken);
        await db.Database.MigrateAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
