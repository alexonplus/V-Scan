using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.SignalR;
using Protector.API.Hubs;
using Protector.API.Models;
using Protector.API.Services;
using Protector.Application.DTOs;
using Protector.Application.UseCases;
using Protector.Domain.Entities;
using Protector.Domain.Interfaces;
using ScanMode = Protector.Application.DTOs.ScanMode;

namespace Protector.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class ScanController(
    IServiceScopeFactory scopeFactory,
    IHubContext<ScanHub> hubContext,
    IScanStateStore store) : ControllerBase
{
    // POST /api/scan — starts a new scan, returns scanId immediately
    // IServiceScopeFactory is used (not IScanHistoryService directly) because scans run in
    // Task.Run() — a background thread that outlives the HTTP request scope.
    // Scoped services (DbContext) cannot be safely captured from a singleton context.
    [HttpPost]
    public IActionResult StartScan([FromBody] StartScanRequest request)
    {
        if (!Uri.TryCreate(request.Url, UriKind.Absolute, out var uri))
            return BadRequest(new { error = "Invalid URL format" });

        if (IsInternalAddress(uri))
            return BadRequest(new { error = "Scanning internal/private addresses is not allowed" });

        var scanId = Guid.NewGuid().ToString("N")[..12];
        store.SetRunning(scanId);

        _ = Task.Run(() => RunScanAsync(scanId, request));

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
        var state = store.Get(scanId);
        if (state?.Result is null)
            return NotFound(new { error = "Scan not found or not completed yet" });

        var result = state.Result;

        _ = Task.Run(async () =>
        {
            try
            {
                using var scope = scopeFactory.CreateScope();
                var enricher = scope.ServiceProvider.GetService<IVulnerabilityEnricher>();
                if (enricher is null)
                {
                    await hubContext.Clients.Group(scanId).SendAsync("AiError", "Ollama is not running");
                    return;
                }

                var aiTotal = result.Vulnerabilities.Count(v =>
                    v.Severity is Domain.Enums.Severity.Critical or Domain.Enums.Severity.High);

                if (aiTotal > 0)
                {
                    var insights = await enricher.EnrichAllAsync(
                        result.Vulnerabilities,
                        progress: msg => hubContext.Clients.Group(scanId).SendAsync("Progress", msg),
                        default);
                    result.SetAiInsights(insights);
                }

                var report = await enricher.GenerateReportAsync(result.Vulnerabilities, result.Target.BaseUrl.ToString(), default);
                if (report is not null)
                    result.SetAiReport(report);

                await hubContext.Clients.Group(scanId).SendAsync("AiCompleted", MapToResponse(scanId, result));
            }
            catch (Exception ex)
            {
                await hubContext.Clients.Group(scanId).SendAsync("AiError", ex.Message);
            }
        });

        return Accepted(new { message = "AI analysis started" });
    }

    // GET /api/scan/{scanId} — returns full results when scan is complete
    [HttpGet("{scanId}")]
    public IActionResult GetResult(string scanId)
    {
        var state = store.Get(scanId);
        if (state is null)
            return NotFound(new { error = "Scan not found" });

        if (state.Status == "running")
            return Ok(new ScanStatusResponse { ScanId = scanId, Status = "running" });

        if (state.Status == "failed" || state.Result is null)
            return StatusCode(500, new { error = "Scan failed" });

        return Ok(MapToResponse(scanId, state.Result));
    }

    private async Task RunScanAsync(string scanId, StartScanRequest request)
    {
        try
        {
            using var scope = scopeFactory.CreateScope();
            var useCase = scope.ServiceProvider.GetRequiredService<RunScanUseCase>();

            useCase.OnProgress += async msg =>
                await hubContext.Clients.Group(scanId).SendAsync("Progress", msg);

            var mode = Enum.TryParse<ScanMode>(request.Mode, true, out var m) ? m : ScanMode.Standard;
            var scanRequest = new ScanRequest
            {
                Url = request.Url,
                SourceCodePath = request.SourceCodePath,
                Mode = mode,
                TimeoutSeconds = request.TimeoutSeconds
            };

            var result = await useCase.ExecuteAsync(scanRequest);
            store.SetCompleted(scanId, result);

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

            await hubContext.Clients.Group(scanId)
                .SendAsync("Completed", MapToResponse(scanId, result));
        }
        catch (Exception ex)
        {
            store.SetFailed(scanId);
            await hubContext.Clients.Group(scanId).SendAsync("Error", ex.Message);
        }
    }

    private static bool IsInternalAddress(Uri uri)
    {
        var host = uri.Host.ToLowerInvariant();
        if (host is "localhost" or "127.0.0.1" or "::1" or "0.0.0.0") return true;
        if (System.Net.IPAddress.TryParse(host, out var ip))
        {
            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                if (bytes[0] == 10) return true;
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;
                if (bytes[0] == 192 && bytes[1] == 168) return true;
                if (bytes[0] == 169 && bytes[1] == 254) return true;
            }
        }
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
