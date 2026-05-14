using Protector.Domain.Entities;
using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Analyzers.Http;

public abstract class HttpAnalyzerBase : IVulnerabilityAnalyzer
{
    protected readonly HttpClient HttpClient;

    protected HttpAnalyzerBase(IHttpClientFactory httpClientFactory)
    {
        HttpClient = httpClientFactory.CreateClient("scanner");
    }

    public abstract string Name { get; }

    public abstract Task<IEnumerable<Vulnerability>> AnalyzeAsync(
        ScanTarget target,
        CancellationToken ct = default);

    protected static string BuildUrl(string baseUrl, string path) =>
        $"{baseUrl.TrimEnd('/')}/{path.TrimStart('/')}";

    protected static string InjectPayload(string url, string paramName, string payload)
    {
        var uri = new UriBuilder(url);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        query[paramName] = payload;
        uri.Query = query.ToString();
        return uri.ToString();
    }

    protected async Task<HttpResponseMessage?> TryGetAsync(string url, CancellationToken ct)
    {
        try
        {
            return await HttpClient.GetAsync(url, ct);
        }
        catch
        {
            return null;
        }
    }
}
