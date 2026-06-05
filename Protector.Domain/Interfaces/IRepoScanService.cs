namespace Protector.Domain.Interfaces;

public interface IRepoScanService
{
    Task<RepoScanResult> ScanAsync(string repoUrl);
}

public sealed record RepoScanResult(
    string RepoUrl,
    string Owner,
    string RepoName,
    DateTime ScannedAt,
    bool IsPublic,
    IReadOnlyList<RepoFinding> Findings
);

public sealed record RepoFinding(
    string FilePath,
    string RuleId,
    string Title,
    string Description,
    RepoFindingSeverity Severity,
    int? LineNumber,
    string? Evidence
);

public enum RepoFindingSeverity
{
    Info,
    Warning,
    Danger
}
