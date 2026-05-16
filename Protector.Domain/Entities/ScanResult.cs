using Protector.Domain.Enums;

namespace Protector.Domain.Entities;

public sealed class ScanResult
{
    private readonly List<Vulnerability> _vulnerabilities = [];
    private readonly List<string> _scannedUrls = [];

    public Guid Id { get; } = Guid.NewGuid();
    public required ScanTarget Target { get; init; }
    public DateTime StartedAt { get; } = DateTime.UtcNow;
    public DateTime? CompletedAt { get; private set; }
    public IReadOnlyList<Vulnerability> Vulnerabilities => _vulnerabilities;
    public IReadOnlyList<string> ScannedUrls => _scannedUrls;
    public ScanSummary Summary => new(this);

    // vulnId → AI-generated insight (populated by OllamaEnricher if available)
    public IReadOnlyDictionary<string, string> AiInsights { get; private set; } =
        new Dictionary<string, string>();

    public void AddVulnerability(Vulnerability vulnerability) =>
        _vulnerabilities.Add(vulnerability);

    public void AddScannedUrl(string url) =>
        _scannedUrls.Add(url);

    public void SetAiInsights(Dictionary<string, string> insights) =>
        AiInsights = insights;

    public void Complete() =>
        CompletedAt = DateTime.UtcNow;
}

public sealed class ScanSummary
{
    public int Total { get; }
    public int Critical { get; }
    public int High { get; }
    public int Medium { get; }
    public int Low { get; }
    public int Info { get; }

    // Weighted risk score: Critical=10, High=5, Medium=2, Low=1
    public int RiskScore { get; }

    public ScanSummary(ScanResult result)
    {
        Total    = result.Vulnerabilities.Count;
        Critical = result.Vulnerabilities.Count(v => v.Severity == Severity.Critical);
        High     = result.Vulnerabilities.Count(v => v.Severity == Severity.High);
        Medium   = result.Vulnerabilities.Count(v => v.Severity == Severity.Medium);
        Low      = result.Vulnerabilities.Count(v => v.Severity == Severity.Low);
        Info     = result.Vulnerabilities.Count(v => v.Severity == Severity.Info);
        RiskScore = Critical * 10 + High * 5 + Medium * 2 + Low;
    }
}
