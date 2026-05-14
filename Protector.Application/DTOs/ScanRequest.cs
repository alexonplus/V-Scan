namespace Protector.Application.DTOs;

/// <summary>
/// Input parameters supplied by the user via CLI.
/// Validated before being converted into a ScanTarget.
/// </summary>
public sealed class ScanRequest
{
    public required string Url { get; init; }
    public string? SourceCodePath { get; init; }
    public int MaxDepth { get; init; } = 3;
    public int TimeoutSeconds { get; init; } = 10;
    public string ReportFormat { get; init; } = "html";
    public string OutputPath { get; init; } = "./reports";
}
