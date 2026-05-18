using System.Diagnostics;
using System.Text.Json;
using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Analyzers.Httpx;

/// <summary>
/// Runs httpx for fast technology fingerprinting.
/// Detects: server version, tech stack, status codes.
/// Much faster than Nuclei for standard scans.
/// </summary>
public sealed class HttpxAnalyzer : IVulnerabilityAnalyzer
{
    public string Name => "httpx Technology Scanner";

    // Technologies known to have active CVEs or EOL versions
    private static readonly Dictionary<string, (Severity Severity, string Warning)> RiskyTech = new(StringComparer.OrdinalIgnoreCase)
    {
        ["WordPress"]      = (Severity.Medium, "WordPress requires frequent security updates. Ensure it is up to date."),
        ["Drupal"]         = (Severity.Medium, "Drupal has had critical RCE vulnerabilities. Keep it updated."),
        ["Joomla"]         = (Severity.Medium, "Joomla has known vulnerabilities. Keep it updated."),
        ["PHP"]            = (Severity.Low,    "PHP version exposed. Old PHP versions have many known vulnerabilities."),
        ["Laravel"]        = (Severity.Info,   "Laravel framework detected. Check for debug mode in production."),
        ["jQuery"]         = (Severity.Low,    "jQuery version may be outdated. Old versions have known XSS vulnerabilities."),
        ["Bootstrap"]      = (Severity.Info,   "Bootstrap detected."),
        ["Apache Tomcat"]  = (Severity.Medium, "Apache Tomcat has had critical RCE vulnerabilities. Ensure it is patched."),
        ["Microsoft ASP.NET"] = (Severity.Info, "ASP.NET stack detected. Ensure debug mode is disabled in production."),
    };

    public async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        if (!HttpxDownloader.IsInstalled)
            return [];

        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var args = $"-u {target.BaseUrl} -j -tech-detect -server -sc -title -silent";
            var output = await RunHttpxAsync(args, ct);

            foreach (var line in output)
            {
                var result = TryParse(line);
                if (result is null || result.Failed) continue;

                // Check for exposed server version
                if (!string.IsNullOrEmpty(result.WebServer))
                {
                    vulnerabilities.Add(new Vulnerability
                    {
                        Title = $"Web server version disclosed: {result.WebServer}",
                        Description = $"The server is exposing its version string '{result.WebServer}' in the response. " +
                                      "This helps attackers find known vulnerabilities for that specific version.",
                        Severity = Severity.Info,
                        Category = VulnerabilityCategory.SensitiveDataExposure,
                        Url = result.Url,
                        Evidence = $"Server: {result.WebServer}",
                        Remediation = "Configure the web server to suppress or obscure the Server header.",
                        CweId = "CWE-200",
                        OwaspCategory = "A05:2021 Security Misconfiguration"
                    });
                }

                // Check detected technologies against known risky ones
                if (result.Technologies is not null)
                {
                    foreach (var tech in result.Technologies)
                    {
                        var matched = RiskyTech
                            .FirstOrDefault(k => tech.Contains(k.Key, StringComparison.OrdinalIgnoreCase));

                        if (!matched.Equals(default(KeyValuePair<string, (Severity, string)>)))
                        {
                            vulnerabilities.Add(new Vulnerability
                            {
                                Title = $"Technology detected: {tech}",
                                Description = $"httpx detected {tech} on this site. {matched.Value.Warning}",
                                Severity = matched.Value.Severity,
                                Category = VulnerabilityCategory.SensitiveDataExposure,
                                Url = result.Url,
                                Evidence = $"Detected technologies: {string.Join(", ", result.Technologies)}",
                                Remediation = matched.Value.Warning,
                                CweId = "CWE-200",
                                OwaspCategory = "A05:2021 Security Misconfiguration"
                            });
                        }
                    }
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* httpx unavailable — return empty */ }

        return vulnerabilities;
    }

    private static async Task<IEnumerable<string>> RunHttpxAsync(string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = HttpxDownloader.BinaryPath,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Could not start httpx");

        var lines = new List<string>();
        while (!process.StandardOutput.EndOfStream)
        {
            ct.ThrowIfCancellationRequested();
            var line = await process.StandardOutput.ReadLineAsync(ct);
            if (!string.IsNullOrWhiteSpace(line))
                lines.Add(line);
        }

        await process.WaitForExitAsync(ct);
        return lines;
    }

    private static HttpxResult? TryParse(string json)
    {
        try { return JsonSerializer.Deserialize<HttpxResult>(json); }
        catch { return null; }
    }
}
