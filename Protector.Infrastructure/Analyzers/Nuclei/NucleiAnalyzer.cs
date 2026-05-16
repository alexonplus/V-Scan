using System.Diagnostics;
using System.Text.Json;
using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Analyzers.Nuclei;

public sealed class NucleiAnalyzer : IVulnerabilityAnalyzer
{
    public string Name => "Nuclei Scanner";

    public async Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default)
    {
        if (!NucleiDownloader.IsInstalled)
            return [];

        var vulnerabilities = new List<Vulnerability>();

        try
        {
            // Run nuclei: JSON output, silent, max 2 min total, rate limit 30 req/s
            var args = $"-u {target.BaseUrl} -j -silent -timeout 5 -rl 30 -duc -stats-json";
            var output = await RunNucleiAsync(args, ct);

            foreach (var line in output)
            {
                var result = TryParseResult(line);
                if (result is null) continue;

                vulnerabilities.Add(MapToVulnerability(result, target.BaseUrl.ToString()));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* nuclei unavailable — return empty */ }

        return vulnerabilities;
    }

    private static async Task<IEnumerable<string>> RunNucleiAsync(
        string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = NucleiDownloader.BinaryPath,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Could not start Nuclei process");

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

    private static NucleiResult? TryParseResult(string json)
    {
        try { return JsonSerializer.Deserialize<NucleiResult>(json); }
        catch { return null; }
    }

    private static Vulnerability MapToVulnerability(NucleiResult result, string targetUrl)
    {
        var severity = result.Info.Severity.ToLowerInvariant() switch
        {
            "critical" => Severity.Critical,
            "high"     => Severity.High,
            "medium"   => Severity.Medium,
            "low"      => Severity.Low,
            _          => Severity.Info
        };

        var cweId = result.Info.Classification?.CweId?.FirstOrDefault();
        var owasp = result.Info.Classification?.OwaspTop10?.FirstOrDefault();
        var tags  = result.Info.Tags is { Count: > 0 }
            ? string.Join(", ", result.Info.Tags)
            : null;

        return new Vulnerability
        {
            Title       = result.Info.Name,
            Description = result.Info.Description ?? $"Detected by Nuclei template: {result.TemplateId}",
            Severity    = severity,
            Category    = VulnerabilityCategory.SecurityHeaders, // best general category
            Url         = result.MatchedAt.Length > 0 ? result.MatchedAt : targetUrl,
            Evidence    = tags is not null ? $"Tags: {tags}" : null,
            Remediation = result.Info.Remediation ?? "Review the finding and apply vendor-recommended fixes.",
            CweId       = cweId,
            OwaspCategory = owasp
        };
    }
}
