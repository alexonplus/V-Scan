using Microsoft.AspNetCore.Mvc;
using Protector.Domain.Interfaces;

namespace Protector.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public sealed class RepoScanController(IRepoScanService repoScanService) : ControllerBase
{
    // POST /api/reposcan — analyze a GitHub repository for malicious patterns
    [HttpPost]
    public async Task<IActionResult> Scan([FromBody] RepoScanRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.RepoUrl))
            return BadRequest(new { error = "Repository URL is required" });

        try
        {
            var result = await repoScanService.ScanAsync(request.RepoUrl);
            return Ok(result);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = ex.Message });
        }
    }
}

public sealed record RepoScanRequest(string RepoUrl);
