using System.Diagnostics;
using System.Text.Json;
using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Analyzers.Semgrep;

/// <summary>
/// Runs semgrep with OWASP Top 10 and security-specific rule packs.
/// Replaces and greatly enhances our basic regex/Roslyn static analysis.
/// Supports: C#, TypeScript, JavaScript, React JSX/TSX.
/// </summary>
public sealed class SemgrepAnalyzer : IStaticCodeAnalyzer
{
    public string Name => "Semgrep Static Analyzer";

    public IEnumerable<string> SupportedExtensions =>
        [".cs", ".ts", ".tsx", ".js", ".jsx"];

    // Rule packs to use — auto-config picks the right rules per language
    private const string RulePacks = "p/owasp-top-ten p/secrets p/cwe-top-25";

    public async Task<IEnumerable<Vulnerability>> AnalyzeFileAsync(
        string filePath,
        CancellationToken ct = default)
    {
        // semgrep works better on directories — single file mode is limited
        // Delegate to AnalyzeDirectoryAsync for better results
        return await AnalyzePathAsync(filePath, ct);
    }

    public async Task<IEnumerable<Vulnerability>> AnalyzeDirectoryAsync(
        string directoryPath,
        CancellationToken ct = default)
    {
        return await AnalyzePathAsync(directoryPath, ct);
    }

    private static async Task<IEnumerable<Vulnerability>> AnalyzePathAsync(
        string path,
        CancellationToken ct)
    {
        if (!SemgrepDownloader.IsInstalled)
            return [];

        var vulnerabilities = new List<Vulnerability>();

        try
        {
            var args = $"--config {RulePacks} --json --quiet \"{path}\"";
            var output = await RunSemgrepAsync(args, ct);

            if (string.IsNullOrWhiteSpace(output)) return vulnerabilities;

            var result = JsonSerializer.Deserialize<SemgrepOutput>(output);
            if (result is null) return vulnerabilities;

            foreach (var finding in result.Results)
            {
                vulnerabilities.Add(MapToVulnerability(finding));
            }
        }
        catch (OperationCanceledException) { throw; }
        catch { /* semgrep unavailable */ }

        return vulnerabilities;
    }

    private static async Task<string> RunSemgrepAsync(string args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = SemgrepDownloader.BinaryPath,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Could not start semgrep");

        var output = await process.StandardOutput.ReadToEndAsync(ct);
        await process.WaitForExitAsync(ct);
        return output;
    }

    private static Vulnerability MapToVulnerability(SemgrepFinding finding)
    {
        var severity = finding.Extra.Severity.ToUpperInvariant() switch
        {
            "ERROR"   => Severity.High,
            "WARNING" => Severity.Medium,
            "INFO"    => Severity.Low,
            _         => Severity.Info
        };

        var cwe = finding.Extra.Metadata.Cwe?.FirstOrDefault();
        var owasp = finding.Extra.Metadata.Owasp?.FirstOrDefault();

        // Determine category from check_id
        var category = finding.CheckId.ToLowerInvariant() switch
        {
            var id when id.Contains("sql")         => VulnerabilityCategory.SqlInjection,
            var id when id.Contains("xss")         => VulnerabilityCategory.CrossSiteScripting,
            var id when id.Contains("secret")
                     || id.Contains("hardcoded")   => VulnerabilityCategory.SensitiveDataExposure,
            var id when id.Contains("deserializ")  => VulnerabilityCategory.InsecureDeserialization,
            var id when id.Contains("auth")        => VulnerabilityCategory.Authentication,
            _                                      => VulnerabilityCategory.StaticAnalysisCSharp
        };

        return new Vulnerability
        {
            Title = $"[semgrep] {finding.CheckId.Split('.').Last().Replace("-", " ")}",
            Description = finding.Extra.Message,
            Severity = severity,
            Category = category,
            FilePath = finding.Path,
            LineNumber = finding.Start.Line,
            Evidence = finding.Extra.Lines.Trim(),
            Remediation = $"See semgrep rule: {finding.CheckId}",
            CweId = cwe,
            OwaspCategory = owasp
        };
    }
}
