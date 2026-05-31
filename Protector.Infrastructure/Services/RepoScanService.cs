using System.Net.Http.Json;
using System.Text.Json;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Services;

public sealed class RepoScanService(IHttpClientFactory httpClientFactory) : IRepoScanService
{
    // Suspicious patterns to detect in files
    private static readonly IReadOnlyList<RepoRule> Rules =
    [
        new("POSTINSTALL_SCRIPT",   "Malicious postinstall script",
            "postinstall script can execute arbitrary code on npm install",
            RepoFindingSeverity.Danger,
            ["package.json"],
            ["\"postinstall\"", "'postinstall'"]),

        new("CURL_WGET",            "Network download in script",
            "Script downloads content from the internet — could pull malware",
            RepoFindingSeverity.Danger,
            ["*.sh", "*.ps1", "*.bat", "*.cmd", "Makefile", "setup.py", "setup.sh"],
            ["curl ", "wget ", "Invoke-WebRequest", "curl.exe"]),

        new("HARDCODED_TOKEN",      "Hardcoded secret or token",
            "Real API keys or tokens committed to the repository",
            RepoFindingSeverity.Danger,
            ["*.env", "*.json", "*.yaml", "*.yml", "*.py", "*.js", "*.ts", "*.cs"],
            ["AKIA", "ghp_", "sk-", "xox", "eyJhbGciOiJIUzI1NiJ9"]),

        new("CURSOR_RULES",         "Suspicious Cursor/IDE config",
            ".cursor/rules or IDE config that may exfiltrate data or run commands",
            RepoFindingSeverity.Danger,
            [".cursor/rules", ".cursorrules", ".vscode/settings.json", ".idea/workspace.xml"],
            ["curl", "wget", "ssh", "exec(", "eval(", "os.system", "subprocess"]),

        new("REVERSE_SHELL",        "Possible reverse shell",
            "Code pattern associated with reverse shell connections",
            RepoFindingSeverity.Danger,
            ["*.sh", "*.py", "*.js", "*.ps1"],
            ["/dev/tcp/", "nc -e", "ncat -e", "bash -i", "python -c 'import socket"]),

        new("EXTERNAL_IP",          "Hardcoded external IP address",
            "Script connects to a specific IP — possible C2 server",
            RepoFindingSeverity.Warning,
            ["*.sh", "*.py", "*.js", "*.ps1", "*.json"],
            ["192.168.", "10.0.", "172.16."]),

        new("ENV_EXFIL",            "Reads environment variables and sends them out",
            "Code reads .env or environment variables and makes network calls nearby",
            RepoFindingSeverity.Danger,
            ["*.js", "*.ts", "*.py", "*.sh"],
            ["process.env", "os.environ", "dotenv", "$env:"]),
    ];

    public async Task<RepoScanResult> ScanAsync(string repoUrl)
    {
        var (owner, repo) = ParseRepoUrl(repoUrl);
        var client = httpClientFactory.CreateClient("github");

        // Get repo tree (all files recursively)
        var tree = await GetRepoTree(client, owner, repo);
        var findings = new List<RepoFinding>();

        foreach (var file in tree)
        {
            var matchingRules = Rules.Where(r => MatchesGlob(file, r.FilePatterns)).ToList();
            if (matchingRules.Count == 0) continue;

            // Fetch file content
            var content = await GetFileContent(client, owner, repo, file);
            if (content is null) continue;

            foreach (var rule in matchingRules)
            {
                foreach (var pattern in rule.Patterns)
                {
                    var lines = content.Split('\n');
                    for (int i = 0; i < lines.Length; i++)
                    {
                        if (lines[i].Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            findings.Add(new RepoFinding(
                                FilePath: file,
                                RuleId: rule.Id,
                                Title: rule.Title,
                                Description: rule.Description,
                                Severity: rule.Severity,
                                LineNumber: i + 1,
                                Evidence: lines[i].Trim()
                            ));
                            break; // one finding per rule per file
                        }
                    }
                }
            }
        }

        return new RepoScanResult(repoUrl, owner, repo, DateTime.UtcNow, true, findings);
    }

    private static (string owner, string repo) ParseRepoUrl(string url)
    {
        // Handles: https://github.com/owner/repo or github.com/owner/repo or owner/repo
        var cleaned = url
            .Replace("https://", "")
            .Replace("http://", "")
            .Replace("github.com/", "")
            .TrimEnd('/');

        var parts = cleaned.Split('/');
        if (parts.Length < 2)
            throw new ArgumentException("Invalid GitHub repository URL");

        return (parts[0], parts[1]);
    }

    private static async Task<List<string>> GetRepoTree(HttpClient client, string owner, string repo)
    {
        try
        {
            var response = await client.GetFromJsonAsync<JsonElement>(
                $"repos/{owner}/{repo}/git/trees/HEAD?recursive=1");

            return response.GetProperty("tree")
                .EnumerateArray()
                .Where(n => n.GetProperty("type").GetString() == "blob")
                .Select(n => n.GetProperty("path").GetString() ?? "")
                .Where(p => !string.IsNullOrEmpty(p))
                .Take(200) // limit to avoid rate limiting
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    private static async Task<string?> GetFileContent(HttpClient client, string owner, string repo, string path)
    {
        try
        {
            var response = await client.GetFromJsonAsync<JsonElement>(
                $"repos/{owner}/{repo}/contents/{path}");

            var encoding = response.GetProperty("encoding").GetString();
            if (encoding != "base64") return null;

            var base64 = response.GetProperty("content").GetString()
                ?.Replace("\n", "").Replace("\r", "");

            if (base64 is null) return null;

            return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        }
        catch
        {
            return null;
        }
    }

    private static bool MatchesGlob(string filePath, IEnumerable<string> patterns)
    {
        var fileName = Path.GetFileName(filePath);
        var fullLower = filePath.ToLowerInvariant();

        return patterns.Any(pattern =>
        {
            if (pattern.StartsWith("*."))
                return fileName.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase);
            if (pattern.Contains('/'))
                return fullLower.Contains(pattern.ToLowerInvariant());
            return fileName.Equals(pattern, StringComparison.OrdinalIgnoreCase);
        });
    }

    private sealed record RepoRule(
        string Id,
        string Title,
        string Description,
        RepoFindingSeverity Severity,
        IReadOnlyList<string> FilePatterns,
        IReadOnlyList<string> Patterns
    );
}
