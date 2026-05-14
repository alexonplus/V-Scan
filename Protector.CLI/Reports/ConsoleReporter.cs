using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Spectre.Console;

namespace Protector.CLI.Reports;

/// <summary>
/// Renders scan results as rich colored tables in the terminal using Spectre.Console.
/// </summary>
public static class ConsoleReporter
{
    public static void PrintBanner()
    {
        AnsiConsole.Write(new FigletText("V-Scan").Color(Color.Red));
        AnsiConsole.MarkupLine("[grey]Web Vulnerability Scanner — github.com/alexonplus/V-Scan[/]");
        AnsiConsole.WriteLine();
    }

    public static void PrintScanStart(string url, string? sourcePath)
    {
        var panel = new Panel(
            $"[bold]Target URL:[/] {url}\n" +
            $"[bold]Source Code:[/] {sourcePath ?? "not provided"}")
        {
            Header = new PanelHeader(" Scan Configuration ", Justify.Center),
            Border = BoxBorder.Rounded
        };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    public static void PrintProgress(string message)
    {
        AnsiConsole.MarkupLine($"[grey]  » {Markup.Escape(message)}[/]");
    }

    public static void PrintSummary(ScanResult result)
    {
        AnsiConsole.WriteLine();

        var summary = result.Summary;
        var duration = result.CompletedAt.HasValue
            ? (result.CompletedAt.Value - result.StartedAt).TotalSeconds
            : 0;

        // Risk score panel
        var riskColor = summary.RiskScore switch
        {
            0 => "green",
            <= 10 => "yellow",
            <= 30 => "orange3",
            _ => "red"
        };

        AnsiConsole.Write(new Rule("[bold]Scan Summary[/]").RuleStyle("grey"));

        // Summary table
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Metric")
            .AddColumn("Value");

        table.AddRow("URLs scanned", result.ScannedUrls.Count.ToString());
        table.AddRow("Duration", $"{duration:F1}s");
        table.AddRow("Total vulnerabilities", $"[bold]{summary.Total}[/]");
        table.AddRow("[red]Critical[/]", summary.Critical.ToString());
        table.AddRow("[orange3]High[/]", summary.High.ToString());
        table.AddRow("[yellow]Medium[/]", summary.Medium.ToString());
        table.AddRow("[blue]Low[/]", summary.Low.ToString());
        table.AddRow("[grey]Info[/]", summary.Info.ToString());
        table.AddRow($"[{riskColor}]Risk Score[/]", $"[{riskColor}]{summary.RiskScore}[/]");

        AnsiConsole.Write(table);
    }

    public static void PrintVulnerabilities(ScanResult result)
    {
        if (result.Summary.Total == 0)
        {
            AnsiConsole.MarkupLine("[green]No vulnerabilities found.[/]");
            return;
        }

        AnsiConsole.Write(new Rule("[bold]Vulnerabilities Found[/]").RuleStyle("grey"));

        // Group by severity (Critical first)
        var grouped = result.Vulnerabilities
            .OrderByDescending(v => v.Severity)
            .GroupBy(v => v.Severity);

        foreach (var group in grouped)
        {
            var (color, icon) = group.Key switch
            {
                Severity.Critical => ("red",     "✖"),
                Severity.High     => ("orange3",  "●"),
                Severity.Medium   => ("yellow",   "◆"),
                Severity.Low      => ("blue",     "◇"),
                _                 => ("grey",     "○")
            };

            AnsiConsole.MarkupLine(
                $"\n[{color} bold]{icon} {group.Key} ({group.Count()})[/]");

            foreach (var vuln in group)
            {
                var table = new Table()
                    .Border(TableBorder.Simple)
                    .AddColumn(new TableColumn("Field").Width(16))
                    .AddColumn("Details");

                table.AddRow("[bold]ID[/]", vuln.Id);
                table.AddRow("[bold]Title[/]", Markup.Escape(vuln.Title));
                table.AddRow("[bold]Description[/]", Markup.Escape(vuln.Description));

                if (vuln.Url is not null)
                    table.AddRow("[bold]URL[/]", Markup.Escape(vuln.Url));
                if (vuln.FilePath is not null)
                    table.AddRow("[bold]File[/]",
                        $"{Markup.Escape(vuln.FilePath)}:{vuln.LineNumber}");
                if (vuln.Evidence is not null)
                    table.AddRow("[bold]Evidence[/]",
                        $"[italic]{Markup.Escape(vuln.Evidence)}[/]");

                table.AddRow("[bold]CWE[/]", vuln.CweId ?? "-");
                table.AddRow("[bold]OWASP[/]", vuln.OwaspCategory ?? "-");
                table.AddRow("[bold]Fix[/]", Markup.Escape(vuln.Remediation));

                AnsiConsole.Write(table);
            }
        }
    }
}
