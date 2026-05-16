using System.Net.Http.Json;
using Protector.Domain.Entities;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Enrichers;

/// <summary>
/// Sends vulnerability findings to a locally-running Ollama instance
/// and returns AI-generated explanations and specific remediation advice.
/// Ollama must be installed and running: https://ollama.ai
/// </summary>
public sealed class OllamaEnricher : IVulnerabilityEnricher
{
    private const string OllamaUrl = "http://localhost:11434/api/generate";
    private readonly HttpClient _http;
    private readonly string _model;

    public OllamaEnricher(IHttpClientFactory factory, string model = "codellama")
    {
        _http = factory.CreateClient("scanner");
        _model = model;
    }

    public static async Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            var response = await http.GetAsync("http://localhost:11434/api/tags", ct);
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    /// <summary>
    /// Enriches a single vulnerability with AI-generated insight.
    /// Returns null if Ollama is unavailable or times out.
    /// </summary>
    public async Task<string?> EnrichAsync(Vulnerability vuln, CancellationToken ct = default)
    {
        var prompt = BuildPrompt(vuln);

        try
        {
            var request = new OllamaRequest
            {
                Model = _model,
                Prompt = prompt,
                Stream = false,
                Options = new OllamaOptions { NumPredict = 300, Temperature = 0.2 }
            };

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(30));

            var httpResponse = await _http.PostAsJsonAsync(OllamaUrl, request, cts.Token);
            if (!httpResponse.IsSuccessStatusCode) return null;

            var result = await httpResponse.Content
                .ReadFromJsonAsync<OllamaResponse>(cancellationToken: cts.Token);

            return result?.Response?.Trim();
        }
        catch { return null; }
    }

    /// <summary>
    /// Enriches all vulnerabilities in parallel (max 3 at a time to not overwhelm Ollama).
    /// Returns a dictionary of vuln.Id → AI insight.
    /// </summary>
    public async Task<Dictionary<string, string>> EnrichAllAsync(
        IEnumerable<Vulnerability> vulnerabilities,
        Action<string>? progress = null,
        CancellationToken ct = default)
    {
        var results = new Dictionary<string, string>();

        // Only enrich High and Critical — saves time, focuses on what matters
        var targets = vulnerabilities
            .Where(v => v.Severity is Domain.Enums.Severity.Critical or Domain.Enums.Severity.High)
            .ToList();

        if (targets.Count == 0) return results;

        progress?.Invoke($"Enriching {targets.Count} critical/high findings with AI...");

        var semaphore = new SemaphoreSlim(3);

        var tasks = targets.Select(async vuln =>
        {
            await semaphore.WaitAsync(ct);
            try
            {
                progress?.Invoke($"  [Ollama] Analyzing: {vuln.Title}");
                var insight = await EnrichAsync(vuln, ct);
                if (insight is not null)
                    lock (results) results[vuln.Id] = insight;
            }
            finally { semaphore.Release(); }
        });

        await Task.WhenAll(tasks);
        return results;
    }

    private static string BuildPrompt(Vulnerability vuln)
    {
        var location = vuln.FilePath is not null
            ? $"File: {vuln.FilePath}" + (vuln.LineNumber.HasValue ? $" line {vuln.LineNumber}" : "")
            : $"URL: {vuln.Url}";

        var evidence = vuln.Evidence is not null
            ? $"\nEvidence: {vuln.Evidence}"
            : "";

        return $"""
            You are a security expert. Analyze this vulnerability briefly.

            Vulnerability: {vuln.Title}
            Severity: {vuln.Severity}
            Category: {vuln.Category}
            {location}{evidence}
            Description: {vuln.Description}

            Provide a short response (3-5 sentences max):
            1. Why this is dangerous in this specific context
            2. Exact code fix or configuration change needed

            Be concise and technical. No markdown headers.
            """;
    }
}
