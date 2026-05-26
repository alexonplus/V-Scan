using System.ComponentModel.DataAnnotations;

namespace Protector.Infrastructure.Persistence.Entities;

public sealed class ScanSessionEntity
{
    public Guid Id { get; set; }

    [Required, MaxLength(2048)]
    public string TargetUrl { get; set; } = string.Empty;

    [Required, MaxLength(20)]
    public string Mode { get; set; } = string.Empty;

    public DateTime StartedAt { get; set; }
    public DateTime? CompletedAt { get; set; }

    public int TotalVulnerabilities { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Info { get; set; }
    public int RiskScore { get; set; }

    public ICollection<VulnerabilityRecordEntity> Vulnerabilities { get; set; } = [];
}
