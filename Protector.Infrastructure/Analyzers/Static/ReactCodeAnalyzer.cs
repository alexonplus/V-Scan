using System.Text.RegularExpressions;
using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Analyzers.Static;

public sealed class ReactCodeAnalyzer : IStaticCodeAnalyzer
{
    public string Name => "React/JavaScript Static Code Analyzer";
    public IEnumerable<string> SupportedExtensions => [".tsx", ".jsx", ".js", ".ts"];

    // Each rule: (regex pattern, title, description, severity, remediation, CWE)
    private static readonly AnalysisRule[] Rules =
    [
        new(
            Pattern: @"dangerouslySetInnerHTML\s*=\s*\{\s*\{",
            Title: "dangerouslySetInnerHTML usage detected",
            Description: "dangerouslySetInnerHTML bypasses React's XSS protection and injects raw HTML. " +
                         "If the content comes from user input or an API, it can execute malicious scripts.",
            Severity: Severity.High,
            Remediation: "Avoid dangerouslySetInnerHTML. Use React's JSX rendering instead. " +
                         "If HTML rendering is required, sanitize with DOMPurify first.",
            CweId: "CWE-79",
            Owasp: "A03:2021 Injection"
        ),
        new(
            Pattern: @"\beval\s*\(",
            Title: "eval() usage detected",
            Description: "eval() executes arbitrary JavaScript code from a string. " +
                         "If any part of the string comes from user input or external data, " +
                         "it can execute attacker-controlled code.",
            Severity: Severity.Critical,
            Remediation: "Remove eval() entirely. Use JSON.parse() for data, " +
                         "or refactor to avoid dynamic code execution.",
            CweId: "CWE-95",
            Owasp: "A03:2021 Injection"
        ),
        new(
            Pattern: @"new\s+Function\s*\(",
            Title: "new Function() usage detected",
            Description: "new Function() is equivalent to eval() and executes dynamic code. " +
                         "It can be exploited to run arbitrary JavaScript.",
            Severity: Severity.Critical,
            Remediation: "Replace with a static function definition.",
            CweId: "CWE-95",
            Owasp: "A03:2021 Injection"
        ),
        new(
            Pattern: @"localStorage\.setItem\s*\(\s*['""].*[Tt]oken",
            Title: "Authentication token stored in localStorage",
            Description: "Storing tokens in localStorage makes them accessible to any JavaScript on the page. " +
                         "An XSS attack can steal the token and impersonate the user.",
            Severity: Severity.High,
            Remediation: "Store authentication tokens in HttpOnly cookies instead of localStorage. " +
                         "HttpOnly cookies are not accessible via JavaScript.",
            CweId: "CWE-922",
            Owasp: "A02:2021 Cryptographic Failures"
        ),
        new(
            Pattern: @"(fetch|axios)\s*\(\s*['""]http://",
            Title: "HTTP (non-HTTPS) API call detected",
            Description: "API requests over plain HTTP are unencrypted. " +
                         "An attacker on the same network can intercept credentials and data.",
            Severity: Severity.Medium,
            Remediation: "Use HTTPS for all API calls. Update the URL to start with https://",
            CweId: "CWE-319",
            Owasp: "A02:2021 Cryptographic Failures"
        ),
        new(
            Pattern: @"(password|secret|apiKey|api_key|token)\s*[:=]\s*['""][^'""]{4,}['""]",
            Title: "Hardcoded secret in JavaScript/TypeScript code",
            Description: "A secret value is hardcoded in the frontend source code. " +
                         "Frontend code is always visible to users — this secret is fully exposed.",
            Severity: Severity.Critical,
            Remediation: "Never hardcode secrets in frontend code. " +
                         "Use environment variables (REACT_APP_*) for non-sensitive config only. " +
                         "Real secrets must stay on the server side.",
            CweId: "CWE-798",
            Owasp: "A02:2021 Cryptographic Failures"
        ),
        new(
            Pattern: @"window\.location\s*=\s*.*\+",
            Title: "Potential open redirect via window.location",
            Description: "Redirecting to a URL built from concatenated user input can allow " +
                         "an attacker to redirect users to a malicious site.",
            Severity: Severity.Medium,
            Remediation: "Validate redirect URLs against an allowlist of trusted domains before redirecting.",
            CweId: "CWE-601",
            Owasp: "A01:2021 Broken Access Control"
        ),
        new(
            Pattern: @"document\.write\s*\(",
            Title: "document.write() usage detected",
            Description: "document.write() can inject arbitrary HTML into the page. " +
                         "If the argument includes user-controlled data, it leads to XSS.",
            Severity: Severity.High,
            Remediation: "Replace document.write() with DOM manipulation methods like " +
                         "createElement() and appendChild().",
            CweId: "CWE-79",
            Owasp: "A03:2021 Injection"
        ),
    ];

    public async Task<IEnumerable<Vulnerability>> AnalyzeFileAsync(
        string filePath,
        CancellationToken ct = default)
    {
        var vulnerabilities = new List<Vulnerability>();
        var lines = await File.ReadAllLinesAsync(filePath, ct);

        for (var lineIndex = 0; lineIndex < lines.Length; lineIndex++)
        {
            var line = lines[lineIndex];

            // Skip commented-out lines
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("//") || trimmed.StartsWith("*") || trimmed.StartsWith("/*"))
                continue;

            foreach (var rule in Rules)
            {
                if (!Regex.IsMatch(line, rule.Pattern, RegexOptions.IgnoreCase))
                    continue;

                vulnerabilities.Add(new Vulnerability
                {
                    Title = rule.Title,
                    Description = rule.Description,
                    Severity = rule.Severity,
                    Category = VulnerabilityCategory.StaticAnalysisReact,
                    FilePath = filePath,
                    LineNumber = lineIndex + 1,
                    Evidence = line.Trim(),
                    Remediation = rule.Remediation,
                    CweId = rule.CweId,
                    OwaspCategory = rule.Owasp
                });
            }
        }

        return vulnerabilities;
    }
}

// Value record to hold rule metadata — keeps the Rules array readable
internal sealed record AnalysisRule(
    string Pattern,
    string Title,
    string Description,
    Severity Severity,
    string Remediation,
    string CweId,
    string Owasp);
