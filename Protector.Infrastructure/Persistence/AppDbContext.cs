using Microsoft.EntityFrameworkCore;
using Protector.Infrastructure.Persistence.Entities;

namespace Protector.Infrastructure.Persistence;

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<ScanSessionEntity> ScanSessions => Set<ScanSessionEntity>();
    public DbSet<VulnerabilityRecordEntity> VulnerabilityRecords => Set<VulnerabilityRecordEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<ScanSessionEntity>(e =>
        {
            e.HasKey(s => s.Id);
            e.Property(s => s.Id).ValueGeneratedNever();
            e.HasMany(s => s.Vulnerabilities)
             .WithOne(v => v.ScanSession)
             .HasForeignKey(v => v.ScanSessionId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<VulnerabilityRecordEntity>(e =>
        {
            e.HasKey(v => v.Id);
            e.Property(v => v.Id).ValueGeneratedNever();
        });
    }
}
