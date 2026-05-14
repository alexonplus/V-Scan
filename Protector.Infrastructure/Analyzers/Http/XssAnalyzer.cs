using Protector.Domain.Entities;
using Protector.Domain.Enums;

namespace Protector.Infrastructure.Analyzers.Http;

public sealed class XssAnalyzer : HttpAnalyzerBase
{
    public override string Name => "Cross-Site Scripting (XSS) Analyzer";

    public XssAnalyzer(IHttpClientFactory factory) : base(factory) { }

    // Each payload has a unique marker so we can confirm reflection
    private static readonly (string Payload, string Marker)[] Payloads =
    [
        ("<script>alert('xss')</script>",        "<script>alert('xss')</script>"),
        ("<img src=x onerror=alert(1)>",          "onerror=alert(1)"),
        ("'\"><script>alert(1)</script>",          "\"><script>alert(1)</script>"),
        ("<svg/onload=alert(1)>",                 "onload=alert(1)"),
        ("javascript:alert(document.cookie)",     "javascript:alert(document.cookie)"),
    ];

    public override async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        var query = System.Web.HttpUtility.ParseQueryString(target.BaseUrl.Query);

        if (query.Count == 0)
            return vulnerabilities;

        foreach (string? paramName in query)
        {
            if (paramName is null) continue;

            foreach (var (payload, marker) in Payloads)
            {
                ct.ThrowIfCancellationRequested();

                var testUrl = InjectPayload(target.BaseUrl.ToString(), paramName, payload);
                var response = await TryGetAsync(testUrl, ct);
                if (response is null) continue;

                var body = await response.Content.ReadAsStringAsync(ct);

                // If the raw payload is reflected back unencoded — vulnerable
                if (body.Contains(marker, StringComparison.OrdinalIgnoreCase))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Title = $"Reflected XSS in parameter '{paramName}'",
                        Description = $"Parameter '{paramName}' reflects user input without encoding. " +
                                      $"An attacker can inject scripts that execute in victim's browser.",
                        Severity = Severity.High,
                        Category = VulnerabilityCategory.CrossSiteScripting,
                        Url = target.BaseUrl.ToString(),
                        Parameter = paramName,
                        Payload = payload,
                        Evidence = $"Payload marker '{marker}' found unencoded in response body",
                        Remediation = "HTML-encode all user-supplied data before rendering it. " +
                                      "In React use JSX expressions (not dangerouslySetInnerHTML). " +
                                      "In C# use HtmlEncoder.Default.Encode().",
                        CweId = "CWE-79",
                        OwaspCategory = "A03:2021 Injection"
                    });

                    break;
                }
            }
        }

        return vulnerabilities;
    }
}
