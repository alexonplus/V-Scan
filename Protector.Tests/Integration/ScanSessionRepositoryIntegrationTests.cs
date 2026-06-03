using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Protector.Domain.Interfaces;
using Protector.Infrastructure.Persistence;
using Protector.Infrastructure.Persistence.Repositories;

namespace Protector.Tests.Integration;

/// <summary>
/// Integration tests — use a REAL InMemory database, not mocks.
/// Tests the full Service → Repository → DbContext chain together.
/// Run manually: dotnet test --filter "Category=Integration"
/// </summary>
[Trait("Category", "Integration")]
public class ScanSessionRepositoryIntegrationTests
{
    // Creates a fresh InMemory database for each test — no leftover data
    private static AppDbContext CreateDb(string name) =>
        new(new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(databaseName: name)
            .Options);

    private static ScanHistoryItem CreateSession(Guid? id = null) => new(
        Id: id ?? Guid.NewGuid(),
        TargetUrl: "https://testphp.vulnweb.com",
        Mode: "Standard",
        StartedAt: DateTime.UtcNow.AddMinutes(-2),
        CompletedAt: DateTime.UtcNow,
        TotalVulnerabilities: 3,
        Critical: 1,
        High: 1,
        Medium: 1,
        Low: 0,
        Info: 0,
        RiskScore: 17,
        Findings:
        [
            new ScanHistoryFinding(
                Guid.NewGuid(), "SQL Injection", "User input not sanitized",
                "High", "SqlInjection", "Use parameterized queries",
                "https://testphp.vulnweb.com/artists.php?artist=1", null, "CWE-89", "A03:2021", "SQL Analyzer", null, null, DateTime.UtcNow)
        ]
    );

    [Fact]
    public async Task AddAsync_AndGetById_ReturnsCorrectSession_WithFindings()
    {
        // Arrange — real database, real repository, no mocks
        using var db = CreateDb(nameof(AddAsync_AndGetById_ReturnsCorrectSession_WithFindings));
        var repository = new ScanSessionRepository(db);
        var session = CreateSession();

        // Act — write to real InMemory database
        await repository.AddAsync(session);
        var retrieved = await repository.GetByIdAsync(session.Id);

        // Assert — verify full round-trip through database
        retrieved.Should().NotBeNull();
        retrieved!.Id.Should().Be(session.Id);
        retrieved.TargetUrl.Should().Be("https://testphp.vulnweb.com");
        retrieved.RiskScore.Should().Be(17);
        retrieved.Findings.Should().HaveCount(1);
        retrieved.Findings[0].Title.Should().Be("SQL Injection");
        retrieved.Findings[0].CweId.Should().Be("CWE-89");
    }

    [Fact]
    public async Task DeleteAsync_RemovesSession_AndCascadesFindings()
    {
        // Arrange — save a session with findings
        using var db = CreateDb(nameof(DeleteAsync_RemovesSession_AndCascadesFindings));
        var repository = new ScanSessionRepository(db);
        var session = CreateSession();
        await repository.AddAsync(session);

        // Act — delete the session
        await repository.DeleteAsync(session.Id);
        var retrieved = await repository.GetByIdAsync(session.Id);

        // Assert — session gone, and cascade delete removed its findings too
        retrieved.Should().BeNull();
        db.VulnerabilityRecords.Count().Should().Be(0);
    }

    [Fact]
    public async Task GetRecentAsync_ReturnsSessions_OrderedByDate_NewestFirst()
    {
        // Arrange — save 3 sessions at different times
        using var db = CreateDb(nameof(GetRecentAsync_ReturnsSessions_OrderedByDate_NewestFirst));
        var repository = new ScanSessionRepository(db);

        var old = CreateSession() with { StartedAt = DateTime.UtcNow.AddHours(-3) };
        var mid = CreateSession() with { StartedAt = DateTime.UtcNow.AddHours(-1) };
        var newest = CreateSession() with { StartedAt = DateTime.UtcNow };

        await repository.AddAsync(old);
        await repository.AddAsync(mid);
        await repository.AddAsync(newest);

        // Act
        var results = await repository.GetRecentAsync(10);

        // Assert — newest first
        results.Should().HaveCount(3);
        results[0].StartedAt.Should().BeCloseTo(newest.StartedAt, TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenIdDoesNotExist()
    {
        // Arrange — empty database
        using var db = CreateDb(nameof(GetByIdAsync_ReturnsNull_WhenIdDoesNotExist));
        var repository = new ScanSessionRepository(db);

        // Act
        var result = await repository.GetByIdAsync(Guid.NewGuid());

        // Assert
        result.Should().BeNull();
    }

    [Fact]
    public async Task ScanHistoryService_SaveAndRetrieve_WorksEndToEnd()
    {
        // Arrange — test the full Service → Repository → DbContext chain
        using var db = CreateDb(nameof(ScanHistoryService_SaveAndRetrieve_WorksEndToEnd));
        var repository = new ScanSessionRepository(db);
        var service = new Protector.Infrastructure.Services.ScanHistoryService(repository);
        var session = CreateSession();

        // Act — save via service, retrieve via service
        await service.SaveAsync(session);
        var retrieved = await service.GetByIdAsync(session.Id);

        // Assert — full chain works correctly
        retrieved.Should().NotBeNull();
        retrieved!.TotalVulnerabilities.Should().Be(3);
        retrieved.Critical.Should().Be(1);
    }
}
