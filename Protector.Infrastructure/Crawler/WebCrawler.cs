using System.Runtime.CompilerServices;
using HtmlAgilityPack;
using Protector.Domain.Entities;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Crawler;

/// <summary>
/// Crawls a website by following links up to the configured MaxDepth.
/// Uses BFS (breadth-first search) to discover URLs level by level.
/// </summary>
public sealed class WebCrawler : IWebCrawler
{
    private readonly IHttpClientFactory _httpClientFactory;

    public WebCrawler(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async IAsyncEnumerable<string> CrawlAsync(
        ScanTarget target,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var client = _httpClientFactory.CreateClient("scanner");
        var baseHost = target.BaseUrl.Host;

        // visited: tracks URLs we already processed to avoid infinite loops
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // queue holds (url, depth) pairs for BFS traversal
        var queue = new Queue<(string Url, int Depth)>();

        var startUrl = target.BaseUrl.ToString().TrimEnd('/');
        queue.Enqueue((startUrl, 0));
        visited.Add(startUrl);

        while (queue.Count > 0 && !ct.IsCancellationRequested)
        {
            var (url, depth) = queue.Dequeue();

            yield return url;

            // Don't go deeper than configured MaxDepth
            if (depth >= target.MaxDepth)
                continue;

            // Download the page and extract all <a href="..."> links
            var links = await ExtractLinksAsync(client, url, baseHost, ct);

            foreach (var link in links)
            {
                if (!visited.Contains(link) &&
                    !target.ExcludedPaths.Any(p => link.Contains(p)))
                {
                    visited.Add(link);
                    queue.Enqueue((link, depth + 1));
                }
            }
        }
    }

    private static async Task<IEnumerable<string>> ExtractLinksAsync(
        HttpClient client, string url, string baseHost, CancellationToken ct)
    {
        try
        {
            var html = await client.GetStringAsync(url, ct);
            var doc = new HtmlDocument();
            doc.LoadHtml(html);

            var links = doc.DocumentNode
                .SelectNodes("//a[@href]")?
                .Select(node => node.GetAttributeValue("href", ""))
                .Where(href => !string.IsNullOrWhiteSpace(href))
                .Select(href => NormalizeUrl(href, url, baseHost))
                .Where(href => href is not null)
                .Select(href => href!)
                .Distinct()
                .ToList() ?? [];

            return links;
        }
        catch
        {
            return [];
        }
    }

    private static string? NormalizeUrl(string href, string pageUrl, string baseHost)
    {
        // Skip anchors, javascript:, mailto:, tel:
        if (href.StartsWith('#') ||
            href.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
            href.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ||
            href.StartsWith("tel:", StringComparison.OrdinalIgnoreCase))
            return null;

        // Absolute URL — only keep same-host links
        if (Uri.TryCreate(href, UriKind.Absolute, out var absoluteUri))
            return absoluteUri.Host.Equals(baseHost, StringComparison.OrdinalIgnoreCase)
                ? absoluteUri.ToString().TrimEnd('/')
                : null;

        // Relative URL — resolve against current page
        if (Uri.TryCreate(new Uri(pageUrl), href, out var relativeUri))
            return relativeUri.Host.Equals(baseHost, StringComparison.OrdinalIgnoreCase)
                ? relativeUri.ToString().TrimEnd('/')
                : null;

        return null;
    }
}
