using Protector.Domain.Entities;

namespace Protector.Domain.Interfaces;

/// <summary>
/// Discovers all reachable URLs within the target site up to the configured depth.
/// </summary>
public interface IWebCrawler
{
    IAsyncEnumerable<string> CrawlAsync(ScanTarget target, CancellationToken ct = default);
}
