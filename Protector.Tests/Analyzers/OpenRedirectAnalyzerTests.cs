using FluentAssertions;
using NSubstitute;
using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Infrastructure.Analyzers.Http;

namespace Protector.Tests.Analyzers;

/// <summary>
/// TDD — tests written FIRST before OpenRedirectAnalyzer exists.
/// RED phase: all tests fail until we implement the analyzer.
///
/// Spec: analyzer checks URL parameters for open redirect by injecting
/// an external URL and verifying the server does NOT redirect to it.
/// </summary>
public class OpenRedirectAnalyzerTests
{
    private static ScanTarget CreateTarget(string url) => new()
    {
        BaseUrl = new Uri(url),
        TimeoutSeconds = 5
    };

    // ── Happy path ────────────────────────────────────────────────────────────

    [Fact]
    public async Task NoQueryParams_ReturnsEmpty()
    {
        // Arrange
        var factory = Substitute.For<IHttpClientFactory>();
        var analyzer = new OpenRedirectAnalyzer(factory);
        var target = CreateTarget("https://example.com/page");

        // Act
        var result = await analyzer.AnalyzeAsync(target);

        // Assert — no params → nothing to test
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task QueryParams_WithoutRedirectNames_ReturnsEmpty()
    {
        // Arrange
        var factory = Substitute.For<IHttpClientFactory>();
        var analyzer = new OpenRedirectAnalyzer(factory);
        var target = CreateTarget("https://example.com/search?q=hello&page=1");

        // Act — params named 'q' and 'page' are not redirect params
        var result = await analyzer.AnalyzeAsync(target);

        // Assert
        result.Should().BeEmpty();
    }

    [Fact]
    public void AnalyzerName_IsCorrect()
    {
        // Arrange
        var factory = Substitute.For<IHttpClientFactory>();
        var analyzer = new OpenRedirectAnalyzer(factory);

        // Act & Assert
        analyzer.Name.Should().Be("Open Redirect Analyzer");
    }

    // ── Suspicious parameter detection ───────────────────────────────────────

    [Theory]
    [InlineData("redirect")]
    [InlineData("url")]
    [InlineData("next")]
    [InlineData("return")]
    [InlineData("to")]
    [InlineData("goto")]
    [InlineData("returnUrl")]
    [InlineData("redirectUrl")]
    public void IsSuspiciousParam_ReturnsTrue_ForKnownRedirectNames(string paramName)
    {
        // Arrange
        var factory = Substitute.For<IHttpClientFactory>();
        var analyzer = new OpenRedirectAnalyzer(factory);

        // Act — test internal detection logic via reflection or public method
        var result = analyzer.IsSuspiciousParam(paramName);

        // Assert
        result.Should().BeTrue($"'{paramName}' is a known redirect parameter name");
    }

    [Theory]
    [InlineData("q")]
    [InlineData("page")]
    [InlineData("id")]
    [InlineData("search")]
    public void IsSuspiciousParam_ReturnsFalse_ForNonRedirectNames(string paramName)
    {
        // Arrange
        var factory = Substitute.For<IHttpClientFactory>();
        var analyzer = new OpenRedirectAnalyzer(factory);

        // Act
        var result = analyzer.IsSuspiciousParam(paramName);

        // Assert
        result.Should().BeFalse();
    }

    // ── Vulnerability detection ───────────────────────────────────────────────

    [Fact]
    public async Task DetectsOpenRedirect_WhenServerRedirectsToExternalUrl()
    {
        // Arrange — mock HTTP client that returns 302 to evil.com
        var mockHandler = new RedirectMockHandler(
            statusCode: 302,
            locationHeader: "https://evil.com");

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("scanner").Returns(new HttpClient(mockHandler));

        var analyzer = new OpenRedirectAnalyzer(factory);
        var target = CreateTarget("https://example.com/login?redirect=https://evil.com");

        // Act
        var result = await analyzer.AnalyzeAsync(target);

        // Assert — vulnerability found
        result.Should().ContainSingle();
        var vuln = result.First();
        vuln.Category.Should().Be(VulnerabilityCategory.OpenRedirect);
        vuln.Severity.Should().Be(Severity.High);
        vuln.Title.Should().Contain("Open Redirect");
        vuln.Evidence.Should().Contain("evil.com");
    }

    [Fact]
    public async Task NoVulnerability_WhenServerReturns200()
    {
        // Arrange — server ignores redirect param and returns 200
        var mockHandler = new RedirectMockHandler(statusCode: 200, locationHeader: null);
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("scanner").Returns(new HttpClient(mockHandler));

        var analyzer = new OpenRedirectAnalyzer(factory);
        var target = CreateTarget("https://example.com/login?redirect=https://evil.com");

        // Act
        var result = await analyzer.AnalyzeAsync(target);

        // Assert — no vulnerability
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task NoVulnerability_WhenServerRedirectsToInternalUrl()
    {
        // Arrange — server redirects to own domain (safe)
        var mockHandler = new RedirectMockHandler(
            statusCode: 302,
            locationHeader: "https://example.com/dashboard");

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("scanner").Returns(new HttpClient(mockHandler));

        var analyzer = new OpenRedirectAnalyzer(factory);
        var target = CreateTarget("https://example.com/login?redirect=https://evil.com");

        // Act
        var result = await analyzer.AnalyzeAsync(target);

        // Assert — redirect to own domain is safe
        result.Should().BeEmpty();
    }
}

/// <summary>
/// Test helper — HTTP handler that returns a fixed status code and Location header.
/// Simulates server redirect behavior without real HTTP calls.
/// </summary>
internal sealed class RedirectMockHandler(int statusCode, string? locationHeader) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var response = new HttpResponseMessage((System.Net.HttpStatusCode)statusCode);
        if (locationHeader is not null)
            response.Headers.Location = new Uri(locationHeader);
        return Task.FromResult(response);
    }
}
