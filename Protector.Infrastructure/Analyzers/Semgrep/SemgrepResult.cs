using System.Text.Json.Serialization;

namespace Protector.Infrastructure.Analyzers.Semgrep;

// Maps to semgrep JSON output (--json flag)
internal sealed class SemgrepOutput
{
    [JsonPropertyName("results")]
    public List<SemgrepFinding> Results { get; init; } = [];

    [JsonPropertyName("errors")]
    public List<SemgrepError> Errors { get; init; } = [];
}

internal sealed class SemgrepFinding
{
    [JsonPropertyName("check_id")]
    public string CheckId { get; init; } = "";

    [JsonPropertyName("path")]
    public string Path { get; init; } = "";

    [JsonPropertyName("start")]
    public SemgrepLocation Start { get; init; } = new();

    [JsonPropertyName("extra")]
    public SemgrepExtra Extra { get; init; } = new();
}

internal sealed class SemgrepExtra
{
    [JsonPropertyName("message")]
    public string Message { get; init; } = "";

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = "WARNING";

    [JsonPropertyName("lines")]
    public string Lines { get; init; } = "";

    [JsonPropertyName("metadata")]
    public SemgrepMetadata Metadata { get; init; } = new();
}

internal sealed class SemgrepMetadata
{
    [JsonPropertyName("cwe")]
    public List<string>? Cwe { get; init; }

    [JsonPropertyName("owasp")]
    public List<string>? Owasp { get; init; }

    [JsonPropertyName("references")]
    public List<string>? References { get; init; }
}

internal sealed class SemgrepLocation
{
    [JsonPropertyName("line")]
    public int Line { get; init; }
}

internal sealed class SemgrepError
{
    [JsonPropertyName("message")]
    public string Message { get; init; } = "";
}
