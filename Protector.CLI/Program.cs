using Microsoft.Extensions.DependencyInjection;
using Protector.Application.DTOs;
using Protector.Application.UseCases;
using Protector.Infrastructure;
using Protector.Infrastructure.Analyzers.Feroxbuster;
using Protector.Infrastructure.Analyzers.Semgrep;
using Protector.Infrastructure.Analyzers.Httpx;
using Protector.Infrastructure.Analyzers.Nuclei;
using Protector.CLI.Reports;
using Spectre.Console;

ConsoleReporter.PrintBanner();

// Handle --install-nuclei before anything else
if (args.Contains("--install-semgrep"))
{
    await SemgrepDownloader.EnsureInstalledAsync(
        progress: msg => AnsiConsole.MarkupLine($"[grey]  » {Markup.Escape(msg)}[/]"));
    AnsiConsole.MarkupLine("[green]semgrep ready.[/] Run a scan with --source to use it.");
    return 0;
}

if (args.Contains("--install-feroxbuster"))
{
    await FeroxbusterDownloader.EnsureInstalledAsync(
        progress: msg => AnsiConsole.MarkupLine($"[grey]  » {Markup.Escape(msg)}[/]"));
    AnsiConsole.MarkupLine("[green]feroxbuster ready.[/] Run a scan to use it.");
    return 0;
}

if (args.Contains("--install-httpx"))
{
    await HttpxDownloader.EnsureInstalledAsync(
        progress: msg => AnsiConsole.MarkupLine($"[grey]  » {Markup.Escape(msg)}[/]"));
    AnsiConsole.MarkupLine("[green]httpx ready.[/] Run a scan to use it.");
    return 0;
}

if (args.Contains("--install-nuclei"))
{
    await NucleiDownloader.EnsureInstalledAsync(
        progress: msg => AnsiConsole.MarkupLine($"[grey]  » {Markup.Escape(msg)}[/]"));
    AnsiConsole.MarkupLine("[green]Nuclei ready.[/] Run a scan to use it.");
    return 0;
}

// Parse arguments: --url, --source, --report, --output, --depth, --timeout
var url = GetArg(args, "--url");
var source = GetArg(args, "--source");
var report = GetArg(args, "--report") ?? "html";
var output = GetArg(args, "--output") ?? "./reports";
var depth = int.TryParse(GetArg(args, "--depth"), out var d) ? d : 3;
var timeout = int.TryParse(GetArg(args, "--timeout"), out var t) ? t : 10;

if (url is null)
{
    AnsiConsole.MarkupLine("[red]Error:[/] --url is required.");
    AnsiConsole.MarkupLine("");
    AnsiConsole.MarkupLine("[bold]Usage:[/]");
    AnsiConsole.MarkupLine("  dotnet run --project Protector.CLI -- --url https://example.com");
    AnsiConsole.MarkupLine("  dotnet run --project Protector.CLI -- --url https://example.com --source ./src");
    AnsiConsole.MarkupLine("  dotnet run --project Protector.CLI -- --url https://example.com --report html --output ./reports");
    AnsiConsole.MarkupLine("");
    AnsiConsole.MarkupLine("[bold]Nuclei:[/]");
    AnsiConsole.MarkupLine("  dotnet run --project Protector.CLI -- --install-nuclei");
    return 1;
}

if (!Uri.TryCreate(url, UriKind.Absolute, out _))
{
    AnsiConsole.MarkupLine($"[red]Error:[/] Invalid URL: {url}");
    return 1;
}

ConsoleReporter.PrintScanStart(url, source);

// Setup DI container
var services = new ServiceCollection();
services.AddProtector();
services.AddSingleton<HtmlReporter>();

var provider = services.BuildServiceProvider();
var useCase = provider.GetRequiredService<RunScanUseCase>();

useCase.OnProgress += ConsoleReporter.PrintProgress;

var request = new ScanRequest
{
    Url = url,
    SourceCodePath = source,
    TimeoutSeconds = timeout,
    ReportFormat = report,
    OutputPath = output
};

try
{
    using var cts = new CancellationTokenSource();

    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        AnsiConsole.MarkupLine("\n[yellow]Scan cancelled by user.[/]");
        cts.Cancel();
    };

    var result = await useCase.ExecuteAsync(request, cts.Token);

    ConsoleReporter.PrintSummary(result);
    ConsoleReporter.PrintVulnerabilities(result);

    if (report.Equals("html", StringComparison.OrdinalIgnoreCase))
    {
        var htmlReporter = provider.GetRequiredService<HtmlReporter>();
        await htmlReporter.GenerateAsync(result, output, cts.Token);
    }

    return result.Summary.Total > 0 ? 1 : 0;
}
catch (OperationCanceledException)
{
    return 130;
}
catch (Exception ex)
{
    AnsiConsole.MarkupLine($"[red]Fatal error:[/] {Markup.Escape(ex.Message)}");
    return 1;
}

static string? GetArg(string[] args, string name)
{
    var idx = Array.IndexOf(args, name);
    return idx >= 0 && idx + 1 < args.Length ? args[idx + 1] : null;
}
