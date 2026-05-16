using System.Text.Json.Serialization;

namespace Protector.Infrastructure.Analyzers.Nuclei;

// Maps directly to Nuclei's JSON output format (nuclei -j flag)
internal sealed class NucleiResult
{
    [JsonPropertyName("template-id")]
    public string TemplateId { get; init; } = "";

    [JsonPropertyName("info")]
    public NucleiInfo Info { get; init; } = new();

    [JsonPropertyName("matched-at")]
    public string MatchedAt { get; init; } = "";

    [JsonPropertyName("extracted-results")]
    public List<string>? ExtractedResults { get; init; }

    [JsonPropertyName("matcher-name")]
    public string? MatcherName { get; init; }

    [JsonPropertyName("type")]
    public string Type { get; init; } = "";
}

internal sealed class NucleiInfo
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("description")]
    public string? Description { get; init; }

    [JsonPropertyName("severity")]
    public string Severity { get; init; } = "info";

    [JsonPropertyName("tags")]
    public List<string>? Tags { get; init; }

    [JsonPropertyName("classification")]
    public NucleiClassification? Classification { get; init; }

    [JsonPropertyName("remediation")]
    public string? Remediation { get; init; }
}

internal sealed class NucleiClassification
{
    [JsonPropertyName("cve-id")]
    public List<string>? CveId { get; init; }

    [JsonPropertyName("cwe-id")]
    public List<string>? CweId { get; init; }

    [JsonPropertyName("owasp-top-10")]
    public List<string>? OwaspTop10 { get; init; }
}
