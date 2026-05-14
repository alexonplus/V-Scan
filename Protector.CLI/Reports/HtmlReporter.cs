using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Domain.Interfaces;

namespace Protector.CLI.Reports;

public sealed class HtmlReporter : IReportGenerator
{
    public string Format => "html";

    public async Task GenerateAsync(ScanResult result, string outputPath, CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputPath);
        var fileName = $"vscan-report-{DateTime.Now:yyyyMMdd-HHmmss}.html";
        var fullPath = Path.Combine(outputPath, fileName);

        var html = BuildHtml(result);
        await File.WriteAllTextAsync(fullPath, html, ct);

        Console.WriteLine($"\nHTML report saved: {fullPath}");
    }

    private static string BuildHtml(ScanResult result)
    {
        var s = result.Summary;
        var duration = result.CompletedAt.HasValue
            ? (result.CompletedAt.Value - result.StartedAt).TotalSeconds
            : 0;

        var vulnRows = string.Join("\n", result.Vulnerabilities
            .OrderByDescending(v => v.Severity)
            .Select(v =>
            {
                var sev = v.Severity.ToString().ToLower();
                var location = Escape(v.Url ?? v.FilePath ?? "-") +
                               (v.LineNumber.HasValue ? $":{v.LineNumber}" : "");
                return $"<tr><td><span class=\"badge {sev}\">{v.Severity}</span></td>" +
                       $"<td>{Escape(v.Title)}</td>" +
                       $"<td>{Escape(v.Category.ToString())}</td>" +
                       $"<td>{location}</td>" +
                       $"<td><code>{Escape(v.Evidence ?? "-")}</code></td>" +
                       $"<td>{Escape(v.CweId ?? "-")}</td>" +
                       $"<td>{Escape(v.Remediation)}</td></tr>";
            }));

        var css = """
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                   background: #0d1117; color: #e6edf3; padding: 2rem; }
            h1 { font-size: 2rem; color: #ff4444; margin-bottom: .5rem; }
            h2 { font-size: 1.2rem; color: #8b949e; margin: 2rem 0 1rem; }
            .meta { color: #8b949e; margin-bottom: 2rem; font-size: .9rem; }
            .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
            .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                    padding: 1rem 1.5rem; min-width: 120px; text-align: center; }
            .card .num { font-size: 2rem; font-weight: bold; }
            .card .lbl { font-size: .8rem; color: #8b949e; }
            .critical .num { color: #ff4444; } .high .num { color: #ff8c00; }
            .medium .num { color: #ffd700; } .low .num { color: #4493f8; }
            .info .num { color: #8b949e; } .risk .num { color: #ff4444; }
            table { width: 100%; border-collapse: collapse; font-size: .85rem; }
            th { background: #161b22; padding: .75rem 1rem; text-align: left;
                 border-bottom: 2px solid #30363d; color: #8b949e; }
            td { padding: .6rem 1rem; border-bottom: 1px solid #21262d; vertical-align: top; }
            tr:hover td { background: #161b22; }
            code { background: #161b22; padding: .2rem .4rem; border-radius: 4px;
                   font-size: .8rem; word-break: break-all; }
            .badge { padding: .2rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: bold; }
            .badge.critical { background: #ff4444; color: white; }
            .badge.high { background: #ff8c00; color: white; }
            .badge.medium { background: #ffd700; color: black; }
            .badge.low { background: #4493f8; color: white; }
            .badge.info { background: #30363d; color: #e6edf3; }
            """;

        return $"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>V-Scan Report</title>
                <style>{css}</style>
            </head>
            <body>
                <h1>V-Scan Security Report</h1>
                <div class="meta">
                    Target: <strong>{Escape(result.Target.BaseUrl.ToString())}</strong> &nbsp;|&nbsp;
                    Scanned: {result.StartedAt:yyyy-MM-dd HH:mm} UTC &nbsp;|&nbsp;
                    Duration: {duration:F1}s &nbsp;|&nbsp;
                    URLs crawled: {result.ScannedUrls.Count}
                </div>
                <h2>Summary</h2>
                <div class="cards">
                    <div class="card critical"><div class="num">{s.Critical}</div><div class="lbl">Critical</div></div>
                    <div class="card high"><div class="num">{s.High}</div><div class="lbl">High</div></div>
                    <div class="card medium"><div class="num">{s.Medium}</div><div class="lbl">Medium</div></div>
                    <div class="card low"><div class="num">{s.Low}</div><div class="lbl">Low</div></div>
                    <div class="card info"><div class="num">{s.Info}</div><div class="lbl">Info</div></div>
                    <div class="card risk"><div class="num">{s.RiskScore}</div><div class="lbl">Risk Score</div></div>
                </div>
                <h2>Vulnerabilities ({s.Total})</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th><th>Title</th><th>Category</th>
                            <th>Location</th><th>Evidence</th><th>CWE</th><th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>{vulnRows}</tbody>
                </table>
            </body>
            </html>
            """;
    }

    private static string Escape(string s) =>
        s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
}
