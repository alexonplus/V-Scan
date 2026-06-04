using Microsoft.EntityFrameworkCore;
using Protector.Domain.Interfaces;
using Protector.Infrastructure.Persistence.Entities;

namespace Protector.Infrastructure.Persistence.Repositories;

// Inherits GetByIdAsync(Guid), GetAllAsync(), AddAsync(), DeleteAsync() from GenericRepository<T>
// Override GetByIdAsync to Include Vulnerabilities (eager loading)
public sealed class ScanSessionRepository(AppDbContext db)
    : GenericRepository<ScanSessionEntity>(db), IScanSessionRepository
{
    public new async Task<ScanHistoryItem?> GetByIdAsync(Guid id)
    {
        var entity = await Db.ScanSessions
            .Include(s => s.Vulnerabilities)
            .FirstOrDefaultAsync(s => s.Id == id);

        return entity is null ? null : MapToItem(entity);
    }

    public async Task<IReadOnlyList<ScanHistoryItem>> GetRecentAsync(int count = 20)
    {
        var entities = await Db.ScanSessions
            .Include(s => s.Vulnerabilities)
            .OrderByDescending(s => s.StartedAt)
            .Take(count)
            .ToListAsync();

        return entities.Select(MapToItem).ToList();
    }

    public async Task AddAsync(ScanHistoryItem session)
    {
        var entity = new ScanSessionEntity
        {
            Id = session.Id,
            TargetUrl = session.TargetUrl,
            Mode = session.Mode,
            StartedAt = session.StartedAt,
            CompletedAt = session.CompletedAt,
            TotalVulnerabilities = session.TotalVulnerabilities,
            Critical = session.Critical,
            High = session.High,
            Medium = session.Medium,
            Low = session.Low,
            Info = session.Info,
            RiskScore = session.RiskScore,
            Vulnerabilities = session.Findings.Select(f => new VulnerabilityRecordEntity
            {
                Id = f.Id,
                ScanSessionId = session.Id,
                Title = f.Title,
                Description = f.Description,
                Severity = f.Severity,
                Category = f.Category,
                Remediation = f.Remediation,
                Url = f.Url,
                Evidence = f.Evidence,
                CweId = f.CweId,
                OwaspCategory = f.OwaspCategory,
                FoundBy = f.FoundBy,
                LineNumber = f.LineNumber,
                FilePath = f.FilePath,
                DiscoveredAt = f.DiscoveredAt
            }).ToList()
        };

        await Db.ScanSessions.AddAsync(entity);
        await Db.SaveChangesAsync();
    }

    public async Task UpdateAsync(Guid id, string notes)
    {
        var entity = await Db.ScanSessions.FindAsync(id);
        if (entity is null) return;
        entity.Notes = notes;
        await Db.SaveChangesAsync();
    }

    private static ScanHistoryItem MapToItem(ScanSessionEntity e) => new(
        e.Id,
        e.TargetUrl,
        e.Mode,
        e.StartedAt,
        e.CompletedAt,
        e.TotalVulnerabilities,
        e.Critical,
        e.High,
        e.Medium,
        e.Low,
        e.Info,
        e.RiskScore,
        e.Vulnerabilities.Select(v => new ScanHistoryFinding(
            v.Id,
            v.Title,
            v.Description,
            v.Severity,
            v.Category,
            v.Remediation,
            v.Url,
            v.Evidence,
            v.CweId,
            v.OwaspCategory,
            v.FoundBy,
            v.LineNumber,
            v.FilePath,
            v.DiscoveredAt
        )).ToList()
    );
}
