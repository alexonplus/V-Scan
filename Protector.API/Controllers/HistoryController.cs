using Microsoft.AspNetCore.Mvc;
using Protector.API.Models;
using Protector.Domain.Interfaces;

namespace Protector.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class HistoryController(IScanHistoryService historyService) : ControllerBase
{
    // GET /api/history — last 20 scans as ScanSessionSummaryDto
    [HttpGet]
    public async Task<ActionResult<IEnumerable<ScanSessionSummaryDto>>> GetAll()
    {
        var sessions = await historyService.GetRecentAsync(20);
        var result = sessions.Select(s => new ScanSessionSummaryDto(
            s.Id, s.TargetUrl, s.Mode, s.StartedAt, s.CompletedAt,
            s.TotalVulnerabilities, s.Critical, s.High, s.Medium, s.Low, s.Info,
            s.RiskScore, s.Notes));
        return Ok(result);
    }

    // GET /api/history/{id} — single scan with all vulnerabilities
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var session = await historyService.GetByIdAsync(id);
        if (session is null)
            return NotFound(new { error = "Scan not found" });
        return Ok(session);
    }

    // POST /api/history — manually create a scan session record (explicit Create for CRUD)
    [HttpPost]
    public async Task<ActionResult<ScanSessionSummaryDto>> Create([FromBody] CreateScanSessionRequest request)
    {
        var session = new ScanHistoryItem(
            Id: Guid.NewGuid(),
            TargetUrl: request.TargetUrl,
            Mode: request.Mode,
            StartedAt: DateTime.UtcNow,
            CompletedAt: DateTime.UtcNow,
            TotalVulnerabilities: request.TotalVulnerabilities,
            Critical: request.Critical,
            High: request.High,
            Medium: request.Medium,
            Low: request.Low,
            Info: request.Info,
            RiskScore: request.RiskScore,
            Findings: [],
            Notes: request.Notes
        );

        await historyService.SaveAsync(session);

        var dto = new ScanSessionSummaryDto(
            session.Id, session.TargetUrl, session.Mode, session.StartedAt,
            session.CompletedAt, session.TotalVulnerabilities, session.Critical,
            session.High, session.Medium, session.Low, session.Info,
            session.RiskScore, session.Notes);

        return CreatedAtAction(nameof(GetById), new { id = session.Id }, dto);
    }

    // PUT /api/history/{id} — update scan notes
    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateScanNotesRequest request)
    {
        var session = await historyService.GetByIdAsync(id);
        if (session is null)
            return NotFound(new { error = "Scan not found" });

        await historyService.UpdateNotesAsync(id, request.Notes ?? string.Empty);
        return NoContent();
    }

    // DELETE /api/history/{id} — remove scan from history
    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var session = await historyService.GetByIdAsync(id);
        if (session is null)
            return NotFound(new { error = "Scan not found" });
        await historyService.DeleteAsync(id);
        return NoContent();
    }
}

public sealed record UpdateScanNotesRequest(string? Notes);
