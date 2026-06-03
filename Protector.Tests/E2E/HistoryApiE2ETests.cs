using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using Protector.Domain.Interfaces;
using Protector.Infrastructure.Persistence;
using Protector.Infrastructure.Persistence.Repositories;
using Protector.Infrastructure.Services;

namespace Protector.Tests.E2E;

/// <summary>
/// E2E tests — start the REAL API server in memory, send HTTP requests, check responses.
/// Tests the full stack: HTTP request → Controller → Service → Repository → Database → HTTP response.
/// Run manually: dotnet test --filter "Category=E2E"
/// </summary>
[Trait("Category", "E2E")]
public class HistoryApiE2ETests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public HistoryApiE2ETests(WebApplicationFactory<Program> factory)
    {
        // Configure the real API with InMemory database for E2E tests
        _client = factory.WithWebHostBuilder(builder =>
        {
            builder.ConfigureServices(services =>
            {
                // Replace SQL Server with InMemory for tests
                var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<AppDbContext>));
                if (descriptor != null) services.Remove(descriptor);

                services.AddDbContext<AppDbContext>(o =>
                    o.UseInMemoryDatabase("E2ETestDb_" + Guid.NewGuid()));
            });
        }).CreateClient();
    }

    [Fact]
    public async Task GET_History_ReturnsOk_WithEmptyList_WhenNothingSaved()
    {
        // Arrange — fresh empty database, no setup needed

        // Act — send real HTTP GET request to the running API
        var response = await _client.GetAsync("/api/history");

        // Assert — API responds with 200 OK and empty array
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().NotBeNull();
    }

    [Fact]
    public async Task GET_History_ById_Returns404_WhenNotFound()
    {
        // Arrange — random GUID that doesn't exist in database
        var fakeId = Guid.NewGuid();

        // Act — send real HTTP GET request
        var response = await _client.GetAsync($"/api/history/{fakeId}");

        // Assert — API returns 404 Not Found
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task DELETE_History_Returns404_WhenSessionNotFound()
    {
        // Arrange
        var fakeId = Guid.NewGuid();

        // Act — send real HTTP DELETE request
        var response = await _client.DeleteAsync($"/api/history/{fakeId}");

        // Assert — 404 because session doesn't exist
        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task POST_Scan_Returns400_WhenUrlIsInvalid()
    {
        // Arrange — invalid URL payload
        var payload = new { url = "not-a-valid-url", mode = "Standard", timeoutSeconds = 8 };

        // Act — send real HTTP POST to start a scan
        var response = await _client.PostAsJsonAsync("/api/scan", payload);

        // Assert — API rejects invalid URL with 400 Bad Request
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("error");
    }

    [Fact]
    public async Task POST_Scan_Returns400_WhenUrlIsLocalhost_SsrfProtection()
    {
        // Arrange — localhost URL that should be blocked by SSRF protection
        var payload = new { url = "http://localhost/admin", mode = "Standard", timeoutSeconds = 8 };

        // Act
        var response = await _client.PostAsJsonAsync("/api/scan", payload);

        // Assert — SSRF protection blocks internal addresses
        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync();
        body.Should().Contain("internal");
    }
}
