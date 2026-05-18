namespace Protector.Application.DTOs;

public enum ScanMode
{
    /// <summary>Our HTTP analyzers only. ~30s</summary>
    Quick,
    /// <summary>Our HTTP analyzers only, faster and reliable. ~1min</summary>
    Standard,
    /// <summary>Everything + full Nuclei (9000+ templates). ~10-20min</summary>
    Deep
}

public sealed class ScanRequest
{
    public required string Url { get; init; }
    public string? SourceCodePath { get; init; }
    public ScanMode Mode { get; init; } = ScanMode.Standard;
    public int TimeoutSeconds { get; init; } = 8;
    public string ReportFormat { get; init; } = "html";
    public string OutputPath { get; init; } = "./reports";

    public int MaxDepth => Mode == ScanMode.Deep ? 2 : 1;
    // Nuclei only in Deep mode — too slow for Quick/Standard
    public bool UseNuclei => Mode == ScanMode.Deep;
    public string? NucleiTags => null; // null = all templates in Deep mode
}
