using Microsoft.AspNetCore.Mvc;
using Protector.Domain.Interfaces;

namespace Protector.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class HistoryController(IScanHistoryService historyService) : ControllerBase
{
    // GET /api/history — last 20 scans, summary only
    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var sessions = await historyService.GetRecentAsync(20);
        var result = sessions.Select(s => new
        {
            s.Id,
            s.TargetUrl,
            s.Mode,
            s.StartedAt,
            s.CompletedAt,
            s.TotalVulnerabilities,
            s.Critical,
            s.High,
            s.Medium,
            s.Low,
            s.Info,
            s.RiskScore
        });
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
