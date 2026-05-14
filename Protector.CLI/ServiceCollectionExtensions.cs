using Microsoft.Extensions.DependencyInjection;
using Protector.Application.UseCases;
using Protector.Domain.Interfaces;
using Protector.Infrastructure.Analyzers.Http;
using Protector.Infrastructure.Analyzers.Static;
using Protector.Infrastructure.Crawler;

namespace Protector.CLI;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all Protector services into the DI container.
    /// Call this once from CLI's Program.cs.
    /// </summary>
    public static IServiceCollection AddProtector(this IServiceCollection services)
    {
        // HttpClient factory — shared, thread-safe, handles connection pooling
        // Configured to skip SSL validation so we can scan sites with bad certs
        services.AddHttpClient("scanner", client =>
        {
            client.Timeout = TimeSpan.FromSeconds(15);
            client.DefaultRequestHeaders.Add("User-Agent", "V-Scan/1.0 Security Scanner");
        }).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true,
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5
        });

        // HTTP analyzers — each registered as IVulnerabilityAnalyzer
        // IEnumerable<IVulnerabilityAnalyzer> in RunScanUseCase gets ALL of them
        services.AddScoped<IVulnerabilityAnalyzer, SecurityHeadersAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, SqlInjectionAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, XssAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, CorsAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, CsrfAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, SslAnalyzer>();

        // Static code analyzers
        services.AddScoped<IStaticCodeAnalyzer, CSharpCodeAnalyzer>();
        services.AddScoped<IStaticCodeAnalyzer, ReactCodeAnalyzer>();

        // Web crawler
        services.AddScoped<IWebCrawler, WebCrawler>();

        // Use case
        services.AddScoped<RunScanUseCase>();

        return services;
    }
}
