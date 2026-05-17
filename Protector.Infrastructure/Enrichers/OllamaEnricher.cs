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

    public OllamaEnricher(IHttpClientFactory factory, string model = "llama3.2:3b")
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

        // Only enrich High and Critical, deduplicated by title
        // Same vuln type on multiple URLs → analyze once, apply to all
        var targets = vulnerabilities
            .Where(v => v.Severity is Domain.Enums.Severity.Critical or Domain.Enums.Severity.High)
            .GroupBy(v => v.Title.ToLowerInvariant())
            .Select(g => g.First())
            .ToList();

        if (targets.Count == 0) return results;

        var total = targets.Count;
        var done = 0;

        // Cache: title → insight (so all duplicates of same vuln get same AI text)
        var cache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        progress?.Invoke($"AI_PROGRESS:0:{total}:Starting AI analysis...");

        foreach (var vuln in targets)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Invoke($"AI_PROGRESS:{done}:{total}:Analyzing: {vuln.Title}");

            var insight = await EnrichAsync(vuln, ct);
            if (insight is not null)
                cache[vuln.Title] = insight;

            done++;
            progress?.Invoke($"AI_PROGRESS:{done}:{total}:{(done == total ? "AI analysis complete!" : $"Analyzed {done}/{total}")}");
        }

        // Apply cached insight to ALL vulns with same title (including duplicates)
        foreach (var vuln in vulnerabilities
            .Where(v => v.Severity is Domain.Enums.Severity.Critical or Domain.Enums.Severity.High))
        {
            if (cache.TryGetValue(vuln.Title, out var cached))
                results[vuln.Id] = cached;
        }

        return results;
    }

    public async Task<AiScanReport?> GenerateReportAsync(
        IEnumerable<Vulnerability> vulnerabilities,
        string targetUrl,
        CancellationToken ct = default)
    {
        var vulnList = vulnerabilities.ToList();
        if (vulnList.Count == 0) return null;

        var prompt = BuildReportPrompt(vulnList, targetUrl);

        try
        {
            var request = new OllamaRequest
            {
                Model = _model,
                Prompt = prompt,
                Stream = false,
                Options = new OllamaOptions { NumPredict = 500, Temperature = 0.3 }
            };

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(45));

            var httpResponse = await _http.PostAsJsonAsync(OllamaUrl, request, cts.Token);
            if (!httpResponse.IsSuccessStatusCode) return null;

            var result = await httpResponse.Content
                .ReadFromJsonAsync<OllamaResponse>(cancellationToken: cts.Token);

            return ParseReport(result?.Response?.Trim() ?? "");
        }
        catch { return null; }
    }

    private static string BuildReportPrompt(List<Vulnerability> vulns, string targetUrl)
    {
        var groups = vulns
            .GroupBy(v => v.Severity)
            .OrderByDescending(g => g.Key)
            .Select(g => $"{g.Key} ({g.Count()}): {string.Join(", ", g.Select(v => v.Title).Take(3))}");

        return $"""
            You are a security expert. Analyze these scan results for {targetUrl}.

            Vulnerabilities found:
            {string.Join("\n", groups)}
            Total: {vulns.Count}

            Respond in EXACTLY this format (no extra text):
            SUMMARY: [2-3 sentences about overall security posture]
            PRIORITY1: [most critical fix]
            PRIORITY2: [second most important fix]
            PRIORITY3: [third fix]
            RISK: [Low/Medium/High/Critical]
            """;
    }

    private static AiScanReport ParseReport(string response)
    {
        var lines = response.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        string summary = "AI analysis complete.";
        var priorities = new List<string>();
        string risk = "Medium";

        foreach (var line in lines)
        {
            if (line.StartsWith("SUMMARY:"))
                summary = line.Substring("SUMMARY:".Length).Trim();
            else if (line.StartsWith("PRIORITY1:") || line.StartsWith("PRIORITY2:") || line.StartsWith("PRIORITY3:"))
                priorities.Add(line.Substring(line.IndexOf(':') + 1).Trim());
            else if (line.StartsWith("RISK:"))
                risk = line.Substring("RISK:".Length).Trim();
        }

        // Fallback if parsing fails
        if (priorities.Count == 0 && response.Length > 10)
        {
            summary = response.Length > 300 ? response[..300] + "..." : response;
            priorities = ["Review and fix Critical/High findings first"];
            risk = "High";
        }

        return new AiScanReport
        {
            Summary = summary,
            TopPriorities = priorities,
            OverallRisk = risk
        };
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
