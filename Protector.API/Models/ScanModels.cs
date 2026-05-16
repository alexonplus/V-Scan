namespace Protector.API.Models;

public sealed class StartScanRequest
{
    public required string Url { get; init; }
    public string? SourceCodePath { get; init; }
    public string Mode { get; init; } = "Standard";
    public int TimeoutSeconds { get; init; } = 8;
}

public sealed class ScanStatusResponse
{
    public required string ScanId { get; init; }
    public required string Status { get; init; }
    public string? Message { get; init; }
}

public sealed class VulnerabilityDto
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required string Severity { get; init; }
    public required string Category { get; init; }
    public string? Url { get; init; }
    public string? FilePath { get; init; }
    public int? LineNumber { get; init; }
    public string? Evidence { get; init; }
    public string? CweId { get; init; }
    public string? OwaspCategory { get; init; }
    public required string Remediation { get; init; }
}

public sealed class ScanResultResponse
{
    public required string ScanId { get; init; }
    public required string TargetUrl { get; init; }
    public required DateTime StartedAt { get; init; }
    public DateTime? CompletedAt { get; init; }
    public required int TotalVulnerabilities { get; init; }
    public required int Critical { get; init; }
    public required int High { get; init; }
    public required int Medium { get; init; }
    public required int Low { get; init; }
    public required int Info { get; init; }
    public required int RiskScore { get; init; }
    public required IEnumerable<VulnerabilityDto> Vulnerabilities { get; init; }
    public required IEnumerable<string> ScannedUrls { get; init; }
}
