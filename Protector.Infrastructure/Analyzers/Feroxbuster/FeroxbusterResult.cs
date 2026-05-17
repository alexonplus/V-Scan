using System.Text.Json.Serialization;

namespace Protector.Infrastructure.Analyzers.Feroxbuster;

// Maps to feroxbuster JSON output (--json flag)
internal sealed class FeroxbusterResult
{
    [JsonPropertyName("url")]
    public string Url { get; init; } = "";

    [JsonPropertyName("status")]
    public int Status { get; init; }

    [JsonPropertyName("content_length")]
    public long ContentLength { get; init; }

    [JsonPropertyName("type")]
    public string Type { get; init; } = "";
}
