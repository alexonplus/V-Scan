using System.Text.Json.Serialization;

namespace Protector.Infrastructure.Enrichers;

internal sealed class OllamaRequest
{
    [JsonPropertyName("model")]
    public string Model { get; init; } = "codellama";

    [JsonPropertyName("prompt")]
    public string Prompt { get; init; } = "";

    [JsonPropertyName("stream")]
    public bool Stream { get; init; } = false;

    [JsonPropertyName("options")]
    public OllamaOptions Options { get; init; } = new();
}

internal sealed class OllamaOptions
{
    // Keep responses focused and short
    [JsonPropertyName("num_predict")]
    public int NumPredict { get; init; } = 300;

    [JsonPropertyName("temperature")]
    public double Temperature { get; init; } = 0.2;
}

internal sealed class OllamaResponse
{
    [JsonPropertyName("response")]
    public string Response { get; init; } = "";

    [JsonPropertyName("done")]
    public bool Done { get; init; }
}
