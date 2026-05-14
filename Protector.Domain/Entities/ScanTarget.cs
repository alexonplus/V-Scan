namespace Protector.Domain.Entities;

public sealed class ScanTarget
{
    public required Uri BaseUrl { get; init; }
    public string? SourceCodePath { get; init; }
    public int MaxDepth { get; init; } = 3;
    public int TimeoutSeconds { get; init; } = 10;
    public bool FollowRedirects { get; init; } = true;
    public IReadOnlyList<string> ExcludedPaths { get; init; } = [];
}
