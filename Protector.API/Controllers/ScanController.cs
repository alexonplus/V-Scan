using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Protector.API.Hubs;
using Protector.API.Models;
using Protector.Application.DTOs;
using Protector.Application.UseCases;
using Protector.Domain.Entities;
using Protector.Domain.Interfaces;
using ScanMode = Protector.Application.DTOs.ScanMode;

namespace Protector.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class ScanController : ControllerBase
{
    // In-memory store — entries expire after 30 minutes to prevent memory leak
    private static readonly Dictionary<string, (ScanResult result, DateTime addedAt)> _results = new();
    private static readonly Dictionary<string, (string status, DateTime addedAt)> _status = new();
    private static readonly TimeSpan _ttl = TimeSpan.FromMinutes(30);

    private static void CleanupExpired()
    {
        var cutoff = DateTime.UtcNow - _ttl;
        foreach (var key in _status.Keys.ToList())
            if (_status[key].addedAt < cutoff)
            {
                _status.Remove(key);
                _results.Remove(key);
            }
    }

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IHubContext<ScanHub> _hubContext;

    public ScanController(IServiceScopeFactory scopeFactory, IHubContext<ScanHub> hubContext)
    {
        _scopeFactory = scopeFactory;
        _hubContext = hubContext;
    }

    // POST /api/scan — starts a new scan, returns scanId immediately
    // React polls progress via SignalR using this scanId
    [HttpPost]
    public IActionResult StartScan([FromBody] StartScanRequest request)
    {
        if (!Uri.TryCreate(request.Url, UriKind.Absolute, out var uri))
            return BadRequest(new { error = "Invalid URL format" });

        // SSRF protection — block scans targeting internal network
        if (IsInternalAddress(uri))
            return BadRequest(new { error = "Scanning internal/private addresses is not allowed" });

        CleanupExpired();
        var scanId = Guid.NewGuid().ToString("N")[..12];
        _status[scanId] = ("running", DateTime.UtcNow);

        // Run the scan in background — don't block the HTTP response
        _ = Task.Run(async () => await RunScanAsync(scanId, request));

        return Accepted(new ScanStatusResponse
        {
            ScanId = scanId,
            Status = "running",
            Message = "Scan started"
        });
    }

    // POST /api/scan/{scanId}/analyze — trigger AI enrichment on demand
    [HttpPost("{scanId}/analyze")]
    public IActionResult StartAiAnalysis(string scanId)
    {
        if (!_results.TryGetValue(scanId, out var resultEntry))
            return NotFound(new { error = "Scan not found or not completed yet" });

        var result = resultEntry.result;

        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var enricher = scope.ServiceProvider.GetService<Protector.Domain.Interfaces.IVulnerabilityEnricher>();
                if (enricher is null)
                {
                    await _hubContext.Clients.Group(scanId).SendAsync("AiError", "Ollama is not running");
                    return;
                }

                var aiTotal = result.Vulnerabilities.Count(v =>
                    v.Severity is Domain.Enums.Severity.Critical or Domain.Enums.Severity.High);

                if (aiTotal > 0)
                {
                    var insights = await enricher.EnrichAllAsync(
                        result.Vulnerabilities,
                        progress: msg => _hubContext.Clients.Group(scanId).SendAsync("Progress", msg),
                        default);
                    result.SetAiInsights(insights);
                }

                var report = await enricher.GenerateReportAsync(result.Vulnerabilities, result.Target.BaseUrl.ToString(), default);
                if (report is not null)
                    result.SetAiReport(report);

                await _hubContext.Clients.Group(scanId).SendAsync("AiCompleted", MapToResponse(scanId, result));
            }
            catch (Exception ex)
            {
                await _hubContext.Clients.Group(scanId).SendAsync("AiError", ex.Message);
            }
        });

        return Accepted(new { message = "AI analysis started" });
    }

    // GET /api/scan/{scanId} — returns full results when scan is complete
    [HttpGet("{scanId}")]
    public IActionResult GetResult(string scanId)
    {
        if (!_status.TryGetValue(scanId, out var statusEntry))
            return NotFound(new { error = "Scan not found" });

        var status = statusEntry.status;

        if (status == "running")
            return Ok(new ScanStatusResponse { ScanId = scanId, Status = "running" });

        if (!_results.TryGetValue(scanId, out var resultEntry))
            return StatusCode(500, new { error = "Scan failed" });

        var result = resultEntry.result;

        return Ok(MapToResponse(scanId, result));
    }

    private async Task RunScanAsync(string scanId, StartScanRequest request)
    {
        try
        {
            // Create a new DI scope for each scan — scoped services need this
            using var scope = _scopeFactory.CreateScope();
            var useCase = scope.ServiceProvider.GetRequiredService<RunScanUseCase>();

            // Wire up progress → send to all SignalR clients in the scan group
            useCase.OnProgress += async msg =>
                await _hubContext.Clients.Group(scanId).SendAsync("Progress", msg);

            var mode = Enum.TryParse<ScanMode>(request.Mode, true, out var m) ? m : ScanMode.Standard;
            var scanRequest = new ScanRequest
            {
                Url = request.Url,
                SourceCodePath = request.SourceCodePath,
                Mode = mode,
                TimeoutSeconds = request.TimeoutSeconds
            };

            var result = await useCase.ExecuteAsync(scanRequest);

            _results[scanId] = (result, DateTime.UtcNow);
            _status[scanId] = ("completed", DateTime.UtcNow);

            // Persist scan to database via service layer
            var historyService = scope.ServiceProvider.GetRequiredService<IScanHistoryService>();
            await historyService.SaveAsync(new ScanHistoryItem(
                result.Id,
                result.Target.BaseUrl.ToString(),
                request.Mode,
                result.StartedAt,
                result.CompletedAt,
                result.Summary.Total,
                result.Summary.Critical,
                result.Summary.High,
                result.Summary.Medium,
                result.Summary.Low,
                result.Summary.Info,
                result.Summary.RiskScore,
                result.Vulnerabilities.Select(v => new ScanHistoryFinding(
                    Guid.NewGuid(),
                    v.Title,
                    v.Description,
                    v.Severity.ToString(),
                    v.Category.ToString(),
                    v.Remediation,
                    v.Url,
                    v.Evidence,
                    v.CweId,
                    v.OwaspCategory,
                    v.FoundBy,
                    v.LineNumber,
                    v.FilePath,
                    v.DiscoveredAt
                )).ToList()
            ));

            // Notify React that scan is done — send full results
            await _hubContext.Clients.Group(scanId)
                .SendAsync("Completed", MapToResponse(scanId, result));
        }
        catch (Exception ex)
        {
            _status[scanId] = ("failed", DateTime.UtcNow);
            await _hubContext.Clients.Group(scanId)
                .SendAsync("Error", ex.Message);
        }
    }

    private static bool IsInternalAddress(Uri uri)
    {
        var host = uri.Host.ToLowerInvariant();

        // Block localhost variants
        if (host is "localhost" or "127.0.0.1" or "::1" or "0.0.0.0")
            return true;

        // Block internal IP ranges (RFC 1918 + link-local)
        if (System.Net.IPAddress.TryParse(host, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                if (bytes[0] == 10) return true;                          // 10.x.x.x
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true; // 172.16-31.x.x
                if (bytes[0] == 192 && bytes[1] == 168) return true;     // 192.168.x.x
                if (bytes[0] == 169 && bytes[1] == 254) return true;     // 169.254.x.x link-local
            }
        }

        // Block metadata endpoints (AWS, Azure, GCP)
        if (host is "169.254.169.254" or "metadata.google.internal") return true;

        return false;
    }

    private static ScanResultResponse MapToResponse(string scanId, ScanResult result) =>
        new()
        {
            ScanId = scanId,
            TargetUrl = result.Target.BaseUrl.ToString(),
            StartedAt = result.StartedAt,
            CompletedAt = result.CompletedAt,
            TotalVulnerabilities = result.Summary.Total,
            Critical = result.Summary.Critical,
            High = result.Summary.High,
            Medium = result.Summary.Medium,
            Low = result.Summary.Low,
            Info = result.Summary.Info,
            RiskScore = result.Summary.RiskScore,
            ScannedUrls = result.ScannedUrls,
            AiInsights = result.AiInsights,
            AiReport = result.AiReport is null ? null : new AiReportDto
            {
                Summary = result.AiReport.Summary,
                TopPriorities = result.AiReport.TopPriorities,
                OverallRisk = result.AiReport.OverallRisk
            },
            Vulnerabilities = result.Vulnerabilities.Select(v => new VulnerabilityDto
            {
                Id = v.Id,
                Title = v.Title,
                Description = v.Description,
                Severity = v.Severity.ToString(),
                Category = v.Category.ToString(),
                Url = v.Url,
                FilePath = v.FilePath,
                LineNumber = v.LineNumber,
                Evidence = v.Evidence,
                CweId = v.CweId,
                OwaspCategory = v.OwaspCategory,
                Remediation = v.Remediation,
                FoundBy = v.FoundBy
            })
        };
}
