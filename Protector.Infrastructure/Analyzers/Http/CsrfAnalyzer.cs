using HtmlAgilityPack;
using Protector.Domain.Entities;
using Protector.Domain.Enums;

namespace Protector.Infrastructure.Analyzers.Http;

public sealed class CsrfAnalyzer : HttpAnalyzerBase
{
    public override string Name => "CSRF Protection Analyzer";

    public CsrfAnalyzer(IHttpClientFactory factory) : base(factory) { }

    // Common names for anti-forgery token fields
    private static readonly string[] TokenFieldNames =
    [
        "__requestverificationtoken", "_token", "csrf_token", "csrftoken",
        "xsrf_token", "_csrf", "authenticity_token", "antiforgerytoken"
    ];

    public override async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        var response = await TryGetAsync(target.BaseUrl.ToString(), ct);
        if (response is null) return vulnerabilities;

        var html = await response.Content.ReadAsStringAsync(ct);
        var doc = new HtmlDocument();
        doc.LoadHtml(html);

        // Find all POST forms
        var postForms = doc.DocumentNode
            .SelectNodes("//form[@method]")?
            .Where(f => f.GetAttributeValue("method", "").Equals("post", StringComparison.OrdinalIgnoreCase))
            .ToList() ?? [];

        foreach (var form in postForms)
        {
            var hasToken = form
                .SelectNodes(".//input[@type='hidden']")?
                .Any(input =>
                {
                    var name = input.GetAttributeValue("name", "").ToLowerInvariant();
                    return TokenFieldNames.Any(t => name.Contains(t));
                }) ?? false;

            if (!hasToken)
            {
                var action = form.GetAttributeValue("action", target.BaseUrl.ToString());

                vulnerabilities.Add(new Vulnerability
                {
                    Title = "Missing CSRF protection on form",
                    Description = "A POST form was found without an anti-forgery token. " +
                                  "An attacker can trick authenticated users into submitting this form.",
                    Severity = Severity.High,
                    Category = VulnerabilityCategory.CrossSiteRequestForgery,
                    Url = target.BaseUrl.ToString(),
                    Evidence = $"Form action='{action}' has no hidden CSRF token field",
                    Remediation = "In ASP.NET Core add [ValidateAntiForgeryToken] attribute and " +
                                  "@Html.AntiForgeryToken() in the form. " +
                                  "For APIs use SameSite=Strict cookies or custom request headers.",
                    CweId = "CWE-352",
                    OwaspCategory = "A01:2021 Broken Access Control"
                });
            }
        }

        return vulnerabilities;
    }
}
