namespace Protector.Domain.Interfaces;

public interface IScanSessionRepository
{
    Task<ScanHistoryItem?> GetByIdAsync(Guid id);
    Task<IReadOnlyList<ScanHistoryItem>> GetRecentAsync(int count = 20);
    Task AddAsync(ScanHistoryItem session);
    Task DeleteAsync(Guid id);
}

public sealed record ScanHistoryItem(
    Guid Id,
    string TargetUrl,
    string Mode,
    DateTime StartedAt,
    DateTime? CompletedAt,
    int TotalVulnerabilities,
    int Critical,
    int High,
    int Medium,
    int Low,
    int Info,
    int RiskScore,
    IReadOnlyList<ScanHistoryFinding> Findings
);

public sealed record ScanHistoryFinding(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Category,
    string Remediation,
    string? Url,
    string? Evidence,
    string? CweId,
    string? OwaspCategory,
    string? FoundBy,
    int? LineNumber,
    string? FilePath,
    DateTime DiscoveredAt
);
