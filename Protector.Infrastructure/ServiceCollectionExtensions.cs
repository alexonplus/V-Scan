using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Protector.Application.UseCases;
using Protector.Domain.Interfaces;
using Protector.Infrastructure.Analyzers.Http;
using Protector.Infrastructure.Analyzers.Feroxbuster;
using Protector.Infrastructure.Analyzers.Semgrep;
using Protector.Infrastructure.Analyzers.Httpx;
using Protector.Infrastructure.Analyzers.Nuclei;
using Protector.Infrastructure.Analyzers.Static;
using Protector.Infrastructure.Crawler;
using Protector.Infrastructure.Enrichers;
using Protector.Infrastructure.Persistence;
using Protector.Infrastructure.Persistence.Repositories;
using Protector.Infrastructure.Services;

namespace Protector.Infrastructure;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all Protector services into the DI container.
    /// Call this once from CLI's Program.cs.
    /// </summary>
    public static IServiceCollection AddProtector(this IServiceCollection services, string? connectionString = null)
    {
        // EF Core — scan history database (SQL Server if connection string provided, otherwise in-memory for CLI/tests)
        if (!string.IsNullOrEmpty(connectionString))
            services.AddDbContext<AppDbContext>(o => o.UseSqlServer(connectionString));
        else
            services.AddDbContext<AppDbContext>(o => o.UseInMemoryDatabase("VScanDev"));

        services.AddScoped<IScanSessionRepository, ScanSessionRepository>();
        services.AddScoped<IScanHistoryService, ScanHistoryService>();

        // Scanner client — for HTTP vulnerability checks, 15s timeout
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

        // Ollama client — for local LLM inference, needs longer timeout
        services.AddHttpClient("ollama", client =>
        {
            client.Timeout = TimeSpan.FromMinutes(3);
            client.BaseAddress = new Uri("http://localhost:11434");
        });

        // HTTP analyzers — each registered as IVulnerabilityAnalyzer
        // IEnumerable<IVulnerabilityAnalyzer> in RunScanUseCase gets ALL of them
        services.AddScoped<IVulnerabilityAnalyzer, SecurityHeadersAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, SqlInjectionAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, XssAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, CorsAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, CsrfAnalyzer>();
        services.AddScoped<IVulnerabilityAnalyzer, SslAnalyzer>();

        // httpx — fast tech fingerprinting, active in Standard + Deep
        if (HttpxDownloader.IsInstalled)
            services.AddScoped<IVulnerabilityAnalyzer, HttpxAnalyzer>();

        // feroxbuster — hidden path discovery, active in Standard + Deep
        if (FeroxbusterDownloader.IsInstalled)
            services.AddScoped<IVulnerabilityAnalyzer, FeroxbusterAnalyzer>();

        // Nuclei — deep CVE scanning, active in Deep mode only
        if (NucleiDownloader.IsInstalled)
            services.AddScoped<IVulnerabilityAnalyzer, NucleiAnalyzer>();

        // Static code analyzers
        services.AddScoped<IStaticCodeAnalyzer, CSharpCodeAnalyzer>();
        services.AddScoped<IStaticCodeAnalyzer, ReactCodeAnalyzer>();

        // Semgrep — professional static analysis (replaces basic regex when available)
        if (SemgrepDownloader.IsInstalled)
            services.AddScoped<IStaticCodeAnalyzer, SemgrepAnalyzer>();

        // Web crawler
        services.AddScoped<IWebCrawler, WebCrawler>();

        // Ollama enricher — registered only if Ollama is running locally
        // Checked synchronously via a quick ping at startup
        services.AddScoped<IVulnerabilityEnricher, OllamaEnricher>();

        // Use case
        services.AddScoped<RunScanUseCase>();

        return services;
    }
}
