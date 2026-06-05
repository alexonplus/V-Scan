namespace Protector.API.Models;

public sealed record ScanSessionSummaryDto(
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
    string? Notes
);

public sealed record CreateScanSessionRequest(
    string TargetUrl,
    string Mode,
    int RiskScore,
    int TotalVulnerabilities,
    int Critical,
    int High,
    int Medium,
    int Low,
    int Info,
    string? Notes = null
);
