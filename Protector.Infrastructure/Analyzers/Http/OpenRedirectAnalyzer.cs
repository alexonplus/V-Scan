using Protector.Domain.Entities;
using Protector.Domain.Enums;

namespace Protector.Infrastructure.Analyzers.Http;

public sealed class OpenRedirectAnalyzer : HttpAnalyzerBase
{
    public override string Name => "Open Redirect Analyzer";

    public OpenRedirectAnalyzer(IHttpClientFactory factory) : base(factory) { }

    private static readonly HashSet<string> SuspiciousParams =
    [
        "redirect", "url", "next", "return", "to", "goto",
        "returnurl", "redirecturl", "return_url", "redirect_url",
        "next_url", "target", "destination", "dest", "redir"
    ];

    private const string Payload = "https://evil-vscan-test.com";

    // Public for unit testing
    public bool IsSuspiciousParam(string name) =>
        SuspiciousParams.Contains(name.ToLowerInvariant());

    public override async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        var query = System.Web.HttpUtility.ParseQueryString(target.BaseUrl.Query);

        if (query.Count == 0)
            return vulnerabilities;

        var suspiciousKeys = query.AllKeys
            .Where(k => k is not null && IsSuspiciousParam(k))
            .ToList();

        if (suspiciousKeys.Count == 0)
            return vulnerabilities;

        foreach (var key in suspiciousKeys)
        {
            // Build URL with our payload as the redirect param value
            var builder = new UriBuilder(target.BaseUrl);
            var qs = System.Web.HttpUtility.ParseQueryString(target.BaseUrl.Query);
            qs[key] = Payload;
            builder.Query = qs.ToString();

            try
            {
                var response = await HttpClient.GetAsync(builder.Uri, ct);

                // Check if server redirected to our external payload
                if (response.StatusCode is System.Net.HttpStatusCode.Redirect
                    or System.Net.HttpStatusCode.MovedPermanently
                    or System.Net.HttpStatusCode.Found
                    or System.Net.HttpStatusCode.SeeOther
                    or System.Net.HttpStatusCode.TemporaryRedirect
                    or System.Net.HttpStatusCode.PermanentRedirect)
                {
                    var location = response.Headers.Location?.ToString();
                    if (location is not null && IsExternalRedirect(location, target.BaseUrl))
                    {
                        vulnerabilities.Add(new Vulnerability
                        {
                            Title = "Open Redirect",
                            Description = $"Parameter '{key}' allows redirecting users to external URLs. " +
                                          "Attackers can use this for phishing by crafting links that appear legitimate.",
                            Severity = Severity.High,
                            Category = VulnerabilityCategory.OpenRedirect,
                            Url = builder.Uri.ToString(),
                            Evidence = $"Server redirected to: {location}",
                            Remediation = "Validate redirect URLs against a whitelist of allowed domains. " +
                                          "Never redirect to user-supplied URLs without validation.",
                            CweId = "CWE-601",
                            OwaspCategory = "A01:2021"
                        });
                    }
                }
            }
            catch (Exception)
            {
                // Timeout or connection error — skip this param
            }
        }

        return vulnerabilities;
    }

    private static bool IsExternalRedirect(string location, Uri baseUrl)
    {
        if (!Uri.TryCreate(location, UriKind.Absolute, out var redirectUri))
            return false;

        // Safe if redirecting to same host
        if (redirectUri.Host.Equals(baseUrl.Host, StringComparison.OrdinalIgnoreCase))
            return false;

        return true;
    }
}
