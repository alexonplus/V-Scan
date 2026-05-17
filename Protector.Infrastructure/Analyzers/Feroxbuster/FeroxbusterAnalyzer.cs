using System.Diagnostics;
using System.Text.Json;
using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Analyzers.Feroxbuster;

/// <summary>
/// Runs feroxbuster to discover hidden paths: /admin, /.env, /backup.zip, /api/v1 etc.
/// These endpoints are often forgotten by developers and left unprotected.
/// </summary>
public sealed class FeroxbusterAnalyzer : IVulnerabilityAnalyzer
{
    public string Name => "feroxbuster Directory Scanner";

    // Paths that are dangerous if publicly accessible
    private static readonly Dictionary<string, (Severity Severity, string Description)> DangerousPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        ["/admin"]           = (Severity.High,     "Admin panel exposed publicly"),
        ["/administrator"]   = (Severity.High,     "Admin panel exposed publicly"),
        ["/.env"]            = (Severity.Critical, "Environment file with secrets exposed"),
        ["/.git"]            = (Severity.Critical, "Git repository exposed — source code leak"),
        ["/backup"]          = (Severity.High,     "Backup directory accessible"),
        ["/backup.zip"]      = (Severity.Critical, "Backup archive exposed — may contain credentials"),
        ["/wp-admin"]        = (Severity.High,     "WordPress admin panel exposed"),
        ["/phpmyadmin"]      = (Severity.Critical, "phpMyAdmin exposed — database admin panel"),
        ["/api/v1"]          = (Severity.Medium,   "API endpoint discovered — verify authentication"),
        ["/api/v2"]          = (Severity.Medium,   "API endpoint discovered — verify authentication"),
        ["/swagger"]         = (Severity.Medium,   "Swagger UI exposed — API documentation public"),
        ["/swagger-ui"]      = (Severity.Medium,   "Swagger UI exposed — API documentation public"),
        ["/actuator"]        = (Severity.High,     "Spring Boot Actuator exposed — system info leak"),
        ["/console"]         = (Severity.High,     "Console endpoint exposed"),
        ["/debug"]           = (Severity.High,     "Debug endpoint exposed in production"),
        ["/server-status"]   = (Severity.Medium,   "Apache server-status exposed"),
        ["/robots.txt"]      = (Severity.Info,     "robots.txt found — check for hidden paths"),
        ["/sitemap.xml"]     = (Severity.Info,     "sitemap.xml found"),
    };

    public async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        if (!FeroxbusterDownloader.IsInstalled)
            return [];

        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // --json: machine-readable output
            // --depth 1: only top-level paths
            // --rate-limit 50: polite scanning
            // --quiet: no banner
            // --no-recursion: don't recurse into found dirs
            var args = $"-u {target.BaseUrl} --json --depth 1 --rate-limit 50 --quiet --no-recursion --timeout {target.TimeoutSeconds}";
            var lines = await RunAsync(args, ct);

            foreach (var line in lines)
            {
                var result = TryParse(line);
                if (result is null || result.Status == 0) continue;

                // Only report 200 (found) and 403 (forbidden but exists)
                if (result.Status is not (200 or 403 or 401)) continue;

                var path = ExtractPath(result.Url, target.BaseUrl.ToString());
                var matched = DangerousPaths
                    .FirstOrDefault(kv => path.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase));

                if (!matched.Equals(default(KeyValuePair<string, (Severity, string)>)))
                {
                    var (severity, description) = matched.Value;
                    // 403/401 = exists but protected → lower severity
                    if (result.Status is 403 or 401)
                        severity = severity > Severity.Low ? severity - 1 : severity;

                    vulnerabilities.Add(new Vulnerability
                    {
                        Title = $"Exposed path: {path}",
                        Description = $"{description}. Status: {result.Status}.",
                        Severity = severity,
                        Category = VulnerabilityCategory.SensitiveDataExposure,
                        Url = result.Url,
                        Evidence = $"HTTP {result.Status} · {result.ContentLength} bytes",
                        Remediation = GetRemediation(path, result.Status),
                        CweId = "CWE-538",
                        OwaspCategory = "A05:2021 Security Misconfiguration"
                    });
                }
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* feroxbuster unavailable */ }

        return vulnerabilities;
    }

    private static async Task<IEnumerable<string>> RunAsync(string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = FeroxbusterDownloader.BinaryPath,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Could not start feroxbuster");

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

    private static FeroxbusterResult? TryParse(string json)
    {
        try { return JsonSerializer.Deserialize<FeroxbusterResult>(json); }
        catch { return null; }
    }

    private static string ExtractPath(string url, string baseUrl)
    {
        if (Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return uri.AbsolutePath;
        return url.Replace(baseUrl.TrimEnd('/'), "");
    }

    private static string GetRemediation(string path, int status) => path switch
    {
        "/.env"        => "Delete or move .env file outside the web root. Never commit secrets to git.",
        "/.git"        => "Block .git access in web server config or remove it from the web root.",
        "/phpmyadmin"  => "Restrict phpMyAdmin access by IP whitelist or move behind VPN.",
        "/backup.zip" or "/backup" => "Remove backup files from the web root.",
        "/swagger" or "/swagger-ui" => "Disable Swagger UI in production or restrict by IP.",
        "/actuator"    => "Restrict Spring Actuator endpoints behind authentication.",
        _              => status == 200
            ? "Restrict access to this path or remove it if not needed."
            : "Verify this endpoint requires proper authentication."
    };
}
