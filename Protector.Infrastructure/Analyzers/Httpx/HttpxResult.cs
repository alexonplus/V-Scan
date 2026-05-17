using System.Text.Json.Serialization;

namespace Protector.Infrastructure.Analyzers.Httpx;

// Maps to httpx JSON output: httpx -u <url> -j -tech-detect -server -sc -title -response-time
internal sealed class HttpxResult
{
    [JsonPropertyName("url")]
    public string Url { get; init; } = "";

    [JsonPropertyName("status_code")]
    public int StatusCode { get; init; }

    [JsonPropertyName("title")]
    public string? Title { get; init; }

    [JsonPropertyName("webserver")]
    public string? WebServer { get; init; }

    [JsonPropertyName("tech")]
    public List<string>? Technologies { get; init; }

    [JsonPropertyName("response_time")]
    public string? ResponseTime { get; init; }

    [JsonPropertyName("failed")]
    public bool Failed { get; init; }
}
