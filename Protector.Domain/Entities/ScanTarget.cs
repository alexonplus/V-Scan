namespace Protector.Domain.Entities;

public sealed class ScanTarget
{
    public required Uri BaseUrl { get; init; }
    public string? SourceCodePath { get; init; }
    public int MaxDepth { get; init; } = 1;
    public int TimeoutSeconds { get; init; } = 8;
    public bool FollowRedirects { get; init; } = true;
    public IReadOnlyList<string> ExcludedPaths { get; init; } = [];

    // Nuclei-specific settings derived from scan mode
    public bool UseNuclei { get; init; } = true;
    public string? NucleiTags { get; init; }
}
