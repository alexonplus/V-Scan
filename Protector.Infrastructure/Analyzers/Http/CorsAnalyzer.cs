using Protector.Domain.Entities;
using Protector.Domain.Enums;

namespace Protector.Infrastructure.Analyzers.Http;

public sealed class CorsAnalyzer : HttpAnalyzerBase
{
    public override string Name => "CORS Misconfiguration Analyzer";

    public CorsAnalyzer(IHttpClientFactory factory) : base(factory) { }

    public override async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        var url = target.BaseUrl.ToString();

        // Test 1: wildcard origin — server reflects back any origin
        var wildcardResult = await TestOriginAsync(url, "https://evil-attacker.com", ct);
        if (wildcardResult.IsVulnerable)
        {
            vulnerabilities.Add(new Vulnerability
            {
                Title = "CORS allows arbitrary origins",
                Description = "The server reflects any Origin header in Access-Control-Allow-Origin, " +
                              "allowing any website to make credentialed cross-origin requests.",
                Severity = Severity.High,
                Category = VulnerabilityCategory.CrossOriginResourceSharing,
                Url = url,
                Evidence = $"Request Origin: https://evil-attacker.com → " +
                           $"Response Access-Control-Allow-Origin: {wildcardResult.AllowOriginValue}",
                Remediation = "Maintain an explicit allowlist of trusted origins. " +
                              "Never reflect the Origin header directly without validation.",
                CweId = "CWE-942",
                OwaspCategory = "A05:2021 Security Misconfiguration"
            });
        }

        // Test 2: null origin — some servers allow null (used in sandboxed iframes)
        var nullResult = await TestOriginAsync(url, "null", ct);
        if (nullResult.IsVulnerable)
        {
            vulnerabilities.Add(new Vulnerability
            {
                Title = "CORS allows null origin",
                Description = "The server accepts 'null' as a valid origin, " +
                              "which can be exploited via sandboxed iframes.",
                Severity = Severity.Medium,
                Category = VulnerabilityCategory.CrossOriginResourceSharing,
                Url = url,
                Evidence = "Response contains Access-Control-Allow-Origin: null",
                Remediation = "Do not allow 'null' as a valid CORS origin.",
                CweId = "CWE-942",
                OwaspCategory = "A05:2021 Security Misconfiguration"
            });
        }

        return vulnerabilities;
    }

    private async Task<(bool IsVulnerable, string? AllowOriginValue)> TestOriginAsync(
        string url, string origin, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("Origin", origin);

            var response = await HttpClient.SendAsync(request, ct);

            if (response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values))
            {
                var allowOrigin = values.FirstOrDefault();
                var isVulnerable = allowOrigin == origin || allowOrigin == "*";
                return (isVulnerable, allowOrigin);
            }
        }
        catch { /* unreachable host — skip */ }

        return (false, null);
    }
}
