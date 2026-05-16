namespace Protector.Application.DTOs;

public enum ScanMode
{
    /// <summary>Only our HTTP analyzers. Fast (~30s)</summary>
    Quick,
    /// <summary>HTTP analyzers + Nuclei top tags. Balanced (~2min)</summary>
    Standard,
    /// <summary>Everything including full Nuclei templates. Thorough (~10min)</summary>
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

    // Derived from Mode — not set by user directly
    public int MaxDepth => Mode == ScanMode.Deep ? 2 : 1;
    public bool UseNuclei => Mode != ScanMode.Quick;
    public string? NucleiTags => Mode == ScanMode.Standard ? "cve,misconfig,exposure,headers" : null;
}
