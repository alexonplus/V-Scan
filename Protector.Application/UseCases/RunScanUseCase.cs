using Protector.Domain.Entities;
using Protector.Domain.Interfaces;
using Protector.Application.DTOs;

namespace Protector.Application.UseCases;

/// <summary>
/// Orchestrates the full scan: crawls URLs, runs all HTTP analyzers,
/// optionally runs static code analyzers, and returns a complete ScanResult.
/// </summary>
public sealed class RunScanUseCase
{
    private readonly IEnumerable<IVulnerabilityAnalyzer> _httpAnalyzers;
    private readonly IEnumerable<IStaticCodeAnalyzer> _staticAnalyzers;
    private readonly IWebCrawler _crawler;

    // All dependencies come from DI — this class never creates analyzers itself
    public RunScanUseCase(
        IEnumerable<IVulnerabilityAnalyzer> httpAnalyzers,
        IEnumerable<IStaticCodeAnalyzer> staticAnalyzers,
        IWebCrawler crawler)
    {
        _httpAnalyzers = httpAnalyzers;
        _staticAnalyzers = staticAnalyzers;
        _crawler = crawler;
    }

    public event Action<string>? OnProgress;

    public async Task<ScanResult> ExecuteAsync(ScanRequest request, CancellationToken ct = default)
    {
        var target = new ScanTarget
        {
            BaseUrl = new Uri(request.Url),
            SourceCodePath = request.SourceCodePath,
            MaxDepth = request.MaxDepth,
            TimeoutSeconds = request.TimeoutSeconds
        };

        var result = new ScanResult { Target = target };

        // Step 1: Crawl the site to discover all URLs
        OnProgress?.Invoke("Crawling site to discover URLs...");
        var urls = new List<string>();
        await foreach (var url in _crawler.CrawlAsync(target, ct))
        {
            urls.Add(url);
            result.AddScannedUrl(url);
        }
        OnProgress?.Invoke($"Discovered {urls.Count} URLs.");

        // Step 2: Run all HTTP analyzers against each discovered URL
        // Each analyzer is independent — run them in parallel per URL for speed
        OnProgress?.Invoke("Running HTTP vulnerability analyzers...");
        foreach (var url in urls)
        {
            var urlTarget = new ScanTarget
            {
                BaseUrl = new Uri(url),
                MaxDepth = 1,
                TimeoutSeconds = target.TimeoutSeconds
            };

            var httpTasks = _httpAnalyzers.Select(async analyzer =>
            {
                OnProgress?.Invoke($"  [{analyzer.Name}] {url}");
                try
                {
                    return await analyzer.AnalyzeAsync(urlTarget, ct);
                }
                catch
                {
                    return Enumerable.Empty<Vulnerability>();
                }
            });

            var httpResults = await Task.WhenAll(httpTasks);
            foreach (var vuln in httpResults.SelectMany(v => v))
                result.AddVulnerability(vuln);
        }

        // Step 3: Run static code analyzers if source code path was provided
        if (!string.IsNullOrEmpty(request.SourceCodePath) &&
            Directory.Exists(request.SourceCodePath))
        {
            OnProgress?.Invoke("Running static code analyzers...");
            await RunStaticAnalysisAsync(result, request.SourceCodePath, ct);
        }

        result.Complete();
        OnProgress?.Invoke($"Scan complete. Found {result.Summary.Total} vulnerabilities.");

        return result;
    }

    private async Task RunStaticAnalysisAsync(
        ScanResult result, string sourcePath, CancellationToken ct)
    {
        // Collect all supported file extensions across all analyzers
        var extensionMap = _staticAnalyzers
            .SelectMany(a => a.SupportedExtensions.Select(ext => (Ext: ext, Analyzer: a)))
            .GroupBy(x => x.Ext)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Analyzer).ToList());

        // Walk the directory tree and analyze each matching file
        var files = Directory.EnumerateFiles(sourcePath, "*.*", SearchOption.AllDirectories)
            .Where(f => extensionMap.ContainsKey(Path.GetExtension(f).ToLowerInvariant()))
            .Where(f => !f.Contains("node_modules") && !f.Contains("bin") && !f.Contains("obj"));

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(file).ToLowerInvariant();

            foreach (var analyzer in extensionMap[ext])
            {
                OnProgress?.Invoke($"  [{analyzer.Name}] {Path.GetFileName(file)}");
                try
                {
                    var vulns = await analyzer.AnalyzeFileAsync(file, ct);
                    foreach (var vuln in vulns)
                        result.AddVulnerability(vuln);
                }
                catch { /* skip unreadable files */ }
            }
        }
    }
}
