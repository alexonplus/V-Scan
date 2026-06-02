using Protector.Domain.Entities;
using Protector.Domain.Interfaces;
using Protector.Application.DTOs;

namespace Protector.Application.UseCases;

public sealed class RunScanUseCase
{
    private readonly IEnumerable<IVulnerabilityAnalyzer> _httpAnalyzers;
    private readonly IEnumerable<IStaticCodeAnalyzer> _staticAnalyzers;
    private readonly IWebCrawler _crawler;
    private readonly IVulnerabilityEnricher? _enricher;

    public RunScanUseCase(
        IEnumerable<IVulnerabilityAnalyzer> httpAnalyzers,
        IEnumerable<IStaticCodeAnalyzer> staticAnalyzers,
        IWebCrawler crawler,
        IVulnerabilityEnricher? enricher = null)
    {
        _httpAnalyzers = httpAnalyzers;
        _staticAnalyzers = staticAnalyzers;
        _crawler = crawler;
        _enricher = enricher;
    }

    public event Action<string>? OnProgress;

    // Sends stage progress: "STAGE:name:done:total:message"
    private void StageProgress(string stage, int done, int total, string message)
    {
        OnProgress?.Invoke($"STAGE:{stage}:{done}:{total}:{message}");
        OnProgress?.Invoke(message);
    }

    public async Task<ScanResult> ExecuteAsync(ScanRequest request, CancellationToken ct = default)
    {
        var hasStatic = !string.IsNullOrEmpty(request.SourceCodePath) && Directory.Exists(request.SourceCodePath);
        var hasNuclei = request.UseNuclei;
        var hasAi = _enricher is not null;

        var target = new ScanTarget
        {
            BaseUrl = new Uri(request.Url),
            SourceCodePath = request.SourceCodePath,
            MaxDepth = request.MaxDepth,
            TimeoutSeconds = request.TimeoutSeconds,
            UseNuclei = request.UseNuclei,
            NucleiTags = request.NucleiTags
        };

        var result = new ScanResult { Target = target };

        // Stage 1: Crawl
        StageProgress("crawl", 0, 1, "Crawling site to discover URLs...");
        var urls = new List<string>();
        await foreach (var url in _crawler.CrawlAsync(target, ct))
        {
            urls.Add(url);
            result.AddScannedUrl(url);
        }
        StageProgress("crawl", 1, 1, $"Discovered {urls.Count} URLs.");

        // Stage 2: HTTP Analyzers
        var analyzerList = _httpAnalyzers
            .Where(a => hasNuclei || a.Name != "Nuclei Scanner")
            .ToList();
        StageProgress("http", 0, urls.Count, "Running HTTP vulnerability analyzers...");

        for (var i = 0; i < urls.Count; i++)
        {
            var url = urls[i];
            var urlTarget = new ScanTarget
            {
                BaseUrl = new Uri(url),
                MaxDepth = 1,
                TimeoutSeconds = target.TimeoutSeconds,
                UseNuclei = target.UseNuclei,
                NucleiTags = target.NucleiTags
            };

            var httpTasks = analyzerList
                .Where(a => a.Name != "Nuclei Scanner")
                .Select(async analyzer =>
                {
                    try
                    {
                        var found = await analyzer.AnalyzeAsync(urlTarget, ct);
                        return found.Select(v => TagWith(v, analyzer.Name));
                    }
                    catch { return Enumerable.Empty<Vulnerability>(); }
                });

            var httpResults = await Task.WhenAll(httpTasks);
            foreach (var vuln in httpResults.SelectMany(v => v))
                result.AddVulnerability(vuln);

            StageProgress("http", i + 1, urls.Count, $"Analyzed {i + 1}/{urls.Count}: {url}");
        }

        // Stage 3: Nuclei
        if (hasNuclei)
        {
            var nucleiAnalyzer = analyzerList.FirstOrDefault(a => a.Name == "Nuclei Scanner");
            if (nucleiAnalyzer is not null)
            {
                StageProgress("nuclei", 0, urls.Count, "Running Nuclei scanner...");
                for (var i = 0; i < urls.Count; i++)
                {
                    var urlTarget = new ScanTarget
                    {
                        BaseUrl = new Uri(urls[i]),
                        MaxDepth = 1,
                        TimeoutSeconds = target.TimeoutSeconds,
                        UseNuclei = true,
                        NucleiTags = target.NucleiTags
                    };
                    try
                    {
                        var vulns = await nucleiAnalyzer.AnalyzeAsync(urlTarget, ct);
                        foreach (var v in vulns) result.AddVulnerability(TagWith(v, "Nuclei Scanner"));
                    }
                    catch { }
                    StageProgress("nuclei", i + 1, urls.Count, $"Nuclei {i + 1}/{urls.Count}: {urls[i]}");
                }
            }
        }

        // Stage 4: Static analysis
        if (hasStatic)
        {
            StageProgress("static", 0, 1, "Running static code analyzers...");
            await RunStaticAnalysisAsync(result, request.SourceCodePath!, ct);
            StageProgress("static", 1, 1, "Static analysis complete.");
        }

        // Stage 5: AI Enrichment — skipped here, triggered manually via POST /api/scan/{id}/analyze
        result.Complete();
        StageProgress("done", 1, 1, $"Scan complete. Found {result.Summary.Total} vulnerabilities.");

        return result;
    }

    private static Vulnerability TagWith(Vulnerability v, string analyzerName) =>
        v.FoundBy is not null ? v : new Vulnerability
        {
            Title = v.Title, Description = v.Description, Severity = v.Severity,
            Category = v.Category, Remediation = v.Remediation, Url = v.Url,
            Parameter = v.Parameter, Payload = v.Payload, Evidence = v.Evidence,
            FilePath = v.FilePath, LineNumber = v.LineNumber, CweId = v.CweId,
            OwaspCategory = v.OwaspCategory, FoundBy = analyzerName
        };

    private async Task RunStaticAnalysisAsync(ScanResult result, string sourcePath, CancellationToken ct)
    {
        var extensionMap = _staticAnalyzers
            .SelectMany(a => a.SupportedExtensions.Select(ext => (Ext: ext, Analyzer: a)))
            .GroupBy(x => x.Ext)
            .ToDictionary(g => g.Key, g => g.Select(x => x.Analyzer).ToList());

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
                        result.AddVulnerability(TagWith(vuln, analyzer.Name));
                }
                catch { }
            }
        }
    }
}
