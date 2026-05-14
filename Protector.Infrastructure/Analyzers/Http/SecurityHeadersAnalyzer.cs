using Protector.Domain.Entities;
using Protector.Domain.Enums;

namespace Protector.Infrastructure.Analyzers.Http;

public sealed class SecurityHeadersAnalyzer : HttpAnalyzerBase
{
    public override string Name => "Security Headers Analyzer";

    public SecurityHeadersAnalyzer(IHttpClientFactory factory) : base(factory) { }

    // Each entry: (header name, severity, CWE, description, remediation)
    private static readonly (string Header, Severity Severity, string Cwe, string Description, string Remediation)[] RequiredHeaders =
    [
        (
            "Content-Security-Policy",
            Severity.High,
            "CWE-693",
            "Missing Content-Security-Policy header allows XSS and data injection attacks.",
            "Add a strict CSP header: Content-Security-Policy: default-src 'self'"
        ),
        (
            "Strict-Transport-Security",
            Severity.High,
            "CWE-319",
            "Missing HSTS header allows protocol downgrade and man-in-the-middle attacks.",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        ),
        (
            "X-Frame-Options",
            Severity.Medium,
            "CWE-1021",
            "Missing X-Frame-Options allows clickjacking attacks.",
            "Add: X-Frame-Options: DENY"
        ),
        (
            "X-Content-Type-Options",
            Severity.Medium,
            "CWE-693",
            "Missing X-Content-Type-Options allows MIME-type sniffing attacks.",
            "Add: X-Content-Type-Options: nosniff"
        ),
        (
            "Referrer-Policy",
            Severity.Low,
            "CWE-200",
            "Missing Referrer-Policy may leak sensitive URL data to third parties.",
            "Add: Referrer-Policy: strict-origin-when-cross-origin"
        ),
        (
            "Permissions-Policy",
            Severity.Low,
            "CWE-693",
            "Missing Permissions-Policy allows unrestricted access to browser features.",
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
        ),
    ];

    public override async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        var vulnerabilities = new List<Vulnerability>();

        var response = await TryGetAsync(target.BaseUrl.ToString(), ct);
        if (response is null)
            return vulnerabilities;

        foreach (var (header, severity, cwe, description, remediation) in RequiredHeaders)
        {
            if (!response.Headers.Contains(header) &&
                !response.Content.Headers.Contains(header))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Title = $"Missing {header} header",
                    Description = description,
                    Severity = severity,
                    Category = VulnerabilityCategory.SecurityHeaders,
                    Url = target.BaseUrl.ToString(),
                    Evidence = $"Header '{header}' not present in response",
                    Remediation = remediation,
                    CweId = cwe,
                    OwaspCategory = "A05:2021 Security Misconfiguration"
                });
            }
        }

        // Check for information-leaking headers
        if (response.Headers.TryGetValues("Server", out var serverValues))
        {
            var server = serverValues.FirstOrDefault();
            if (!string.IsNullOrEmpty(server))
            {
                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Server version disclosed in response header",
                    Description = $"The Server header reveals technology details: '{server}'",
                    Severity = Severity.Info,
                    Category = VulnerabilityCategory.SensitiveDataExposure,
                    Url = target.BaseUrl.ToString(),
                    Evidence = $"Server: {server}",
                    Remediation = "Remove or obscure the Server header in your web server configuration.",
                    CweId = "CWE-200",
                    OwaspCategory = "A05:2021 Security Misconfiguration"
                });
            }
        }

        return vulnerabilities;
    }
}
