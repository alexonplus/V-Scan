using FluentAssertions;
using Protector.Domain.Entities;
using Protector.Domain.Enums;

namespace Protector.Tests.Domain;

public class ScanSummaryTests
{
    private static ScanResult CreateResult(params (Severity severity, string title)[] vulns)
    {
        var target = new ScanTarget { BaseUrl = new Uri("https://example.com") };
        var result = new ScanResult { Target = target };
        foreach (var (severity, title) in vulns)
        {
            result.AddVulnerability(new Vulnerability
            {
                Title = title,
                Description = "Test",
                Severity = severity,
                Category = VulnerabilityCategory.SecurityHeaders,
                Remediation = "Fix it"
            });
        }
        return result;
    }

    [Fact]
    public void RiskScore_WithNoCritical_IsZero_WhenEmpty()
    {
        // Arrange
        var result = CreateResult();

        // Act
        var summary = result.Summary;

        // Assert
        summary.RiskScore.Should().Be(0);
        summary.Total.Should().Be(0);
    }

    [Fact]
    public void RiskScore_OneCritical_ReturnsTen()
    {
        // Arrange
        var result = CreateResult((Severity.Critical, "SQL Injection"));

        // Act & Assert
        result.Summary.RiskScore.Should().Be(10);
        result.Summary.Critical.Should().Be(1);
    }

    [Fact]
    public void RiskScore_Mixed_CalculatesCorrectly()
    {
        // Arrange: 1 Critical(10) + 2 High(10) + 1 Medium(2) + 1 Low(1) = 23
        var result = CreateResult(
            (Severity.Critical, "Critical vuln"),
            (Severity.High,     "High vuln 1"),
            (Severity.High,     "High vuln 2"),
            (Severity.Medium,   "Medium vuln"),
            (Severity.Low,      "Low vuln")
        );

        // Act & Assert
        result.Summary.RiskScore.Should().Be(23);
        result.Summary.Total.Should().Be(5);
    }

    [Fact]
    public void Summary_CountsEachSeverityCorrectly()
    {
        // Arrange
        var result = CreateResult(
            (Severity.Critical, "C1"),
            (Severity.High,     "H1"),
            (Severity.High,     "H2"),
            (Severity.Medium,   "M1"),
            (Severity.Low,      "L1"),
            (Severity.Info,     "I1")
        );

        // Act
        var s = result.Summary;

        // Assert
        s.Critical.Should().Be(1);
        s.High.Should().Be(2);
        s.Medium.Should().Be(1);
        s.Low.Should().Be(1);
        s.Info.Should().Be(1);
        s.Total.Should().Be(6);
    }

    [Fact]
    public void Complete_SetsCompletedAt()
    {
        // Arrange
        var result = CreateResult();
        result.CompletedAt.Should().BeNull();

        // Act
        result.Complete();

        // Assert
        result.CompletedAt.Should().NotBeNull();
        result.CompletedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(2));
    }
}
