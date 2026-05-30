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
    // In-memory store for scan results (keyed by scanId)
    // In a real app this would be a database or distributed cache
    private static readonly Dictionary<string, ScanResult> _results = new();
    private static readonly Dictionary<string, string> _status = new();

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
        if (!Uri.TryCreate(request.Url, UriKind.Absolute, out _))
            return BadRequest(new { error = "Invalid URL format" });

        var scanId = Guid.NewGuid().ToString("N")[..12];
        _status[scanId] = "running";

        // Run the scan in background — don't block the HTTP response
        _ = Task.Run(async () => await RunScanAsync(scanId, request));

        return Accepted(new ScanStatusResponse
        {
            ScanId = scanId,
            Status = "running",
            Message = "Scan started"
        });
    }

    // GET /api/scan/{scanId} — returns full results when scan is complete
    [HttpGet("{scanId}")]
    public IActionResult GetResult(string scanId)
    {
        if (!_status.TryGetValue(scanId, out var status))
            return NotFound(new { error = "Scan not found" });

        if (status == "running")
            return Ok(new ScanStatusResponse { ScanId = scanId, Status = "running" });

        if (!_results.TryGetValue(scanId, out var result))
            return StatusCode(500, new { error = "Scan failed" });

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

            _results[scanId] = result;
            _status[scanId] = "completed";

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
            _status[scanId] = "failed";
            await _hubContext.Clients.Group(scanId)
                .SendAsync("Error", ex.Message);
        }
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
