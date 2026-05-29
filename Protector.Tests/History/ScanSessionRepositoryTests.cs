using FluentAssertions;
using NSubstitute;
using Protector.Domain.Interfaces;

namespace Protector.Tests.History;

public class ScanSessionRepositoryTests
{
    // Helper — creates a sample scan session for tests
    private static ScanHistoryItem CreateSession(Guid? id = null, int riskScore = 10) => new(
        Id: id ?? Guid.NewGuid(),
        TargetUrl: "https://example.com",
        Mode: "Standard",
        StartedAt: DateTime.UtcNow.AddMinutes(-5),
        CompletedAt: DateTime.UtcNow,
        TotalVulnerabilities: 2,
        Critical: 1,
        High: 1,
        Medium: 0,
        Low: 0,
        Info: 0,
        RiskScore: riskScore,
        Findings: []
    );

    [Fact]
    public async Task GetRecentAsync_ReturnsSessions_WhenSessionsExist()
    {
        // Arrange
        var repository = Substitute.For<IScanSessionRepository>();
        var sessions = new List<ScanHistoryItem> { CreateSession(), CreateSession() };
        repository.GetRecentAsync(20).Returns(sessions);

        // Act
        var result = await repository.GetRecentAsync(20);

        // Assert
        result.Should().HaveCount(2);
    }

    [Fact]
    public async Task GetRecentAsync_ReturnsEmpty_WhenNoSessionsExist()
    {
        // Arrange
        var repository = Substitute.For<IScanSessionRepository>();
        repository.GetRecentAsync(20).Returns(new List<ScanHistoryItem>());

        // Act
        var result = await repository.GetRecentAsync(20);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsSession_WhenSessionExists()
    {
        // Arrange
        var repository = Substitute.For<IScanSessionRepository>();
        var id = Guid.NewGuid();
        var session = CreateSession(id);
        repository.GetByIdAsync(id).Returns(session);

        // Act
        var result = await repository.GetByIdAsync(id);

        // Assert
        result.Should().NotBeNull();
        result!.Id.Should().Be(id);
        result.TargetUrl.Should().Be("https://example.com");
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenSessionNotFound()
    {
        // Arrange
        var repository = Substitute.For<IScanSessionRepository>();
        repository.GetByIdAsync(Arg.Any<Guid>()).Returns((ScanHistoryItem?)null);

        // Act
        var result = await repository.GetByIdAsync(Guid.NewGuid());

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task AddAsync_CallsRepository_WithCorrectSession()
    {
        // Arrange
        var repository = Substitute.For<IScanSessionRepository>();
        var session = CreateSession();

        // Act
        await repository.AddAsync(session);

        // Assert — verify AddAsync was called exactly once with our session
        await repository.Received(1).AddAsync(session);
    }

    [Fact]
    public async Task DeleteAsync_CallsRepository_WithCorrectId()
    {
        // Arrange
        var repository = Substitute.For<IScanSessionRepository>();
        var id = Guid.NewGuid();

        // Act
        await repository.DeleteAsync(id);

        // Assert — verify DeleteAsync was called with the correct id
        await repository.Received(1).DeleteAsync(id);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsCorrectRiskScore_ForHighRiskSession()
    {
        // Arrange
        var repository = Substitute.For<IScanSessionRepository>();
        var id = Guid.NewGuid();
        var highRiskSession = CreateSession(id, riskScore: 55);
        repository.GetByIdAsync(id).Returns(highRiskSession);

        // Act
        var result = await repository.GetByIdAsync(id);

        // Assert
        result!.RiskScore.Should().Be(55);
        result.Critical.Should().Be(1);
    }
}
