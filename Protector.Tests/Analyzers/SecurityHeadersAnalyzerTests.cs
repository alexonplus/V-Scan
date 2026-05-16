using System.Net;
using FluentAssertions;
using NSubstitute;
using Protector.Domain.Entities;
using Protector.Domain.Enums;
using Protector.Infrastructure.Analyzers.Http;

namespace Protector.Tests.Analyzers;

public class SecurityHeadersAnalyzerTests
{
    // Creates a fake HttpClientFactory that returns preset responses
    private static IHttpClientFactory CreateFactory(
        HttpStatusCode status = HttpStatusCode.OK,
        Dictionary<string, string>? headers = null)
    {
        var response = new HttpResponseMessage(status);
        if (headers != null)
            foreach (var (k, v) in headers)
                response.Headers.TryAddWithoutValidation(k, v);

        var handler = new FakeHttpMessageHandler(response);
        var client = new HttpClient(handler);

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("scanner").Returns(client);
        return factory;
    }

    private static ScanTarget Target => new()
    {
        BaseUrl = new Uri("https://example.com")
    };

    [Fact]
    public async Task Detects_MissingCsp_Header()
    {
        // Arrange — response has NO security headers
        var factory = CreateFactory();
        var analyzer = new SecurityHeadersAnalyzer(factory);

        // Act
        var vulns = (await analyzer.AnalyzeAsync(Target)).ToList();

        // Assert
        vulns.Should().Contain(v =>
            v.Title.Contains("Content-Security-Policy") &&
            v.Severity == Severity.High);
    }

    [Fact]
    public async Task Detects_MissingHsts_Header()
    {
        var factory = CreateFactory();
        var analyzer = new SecurityHeadersAnalyzer(factory);

        var vulns = await analyzer.AnalyzeAsync(Target);

        vulns.Should().Contain(v =>
            v.Title.Contains("Strict-Transport-Security") &&
            v.Severity == Severity.High);
    }

    [Fact]
    public async Task Detects_ServerVersionDisclosure()
    {
        // Arrange — response reveals server version
        var factory = CreateFactory(headers: new() { ["Server"] = "nginx/1.18.0" });
        var analyzer = new SecurityHeadersAnalyzer(factory);

        // Act
        var vulns = await analyzer.AnalyzeAsync(Target);

        // Assert
        vulns.Should().Contain(v =>
            v.Category == VulnerabilityCategory.SensitiveDataExposure &&
            v.Evidence!.Contains("nginx"));
    }

    [Fact]
    public async Task ReturnsVulnerabilities_WithCorrectUrl()
    {
        var factory = CreateFactory();
        var analyzer = new SecurityHeadersAnalyzer(factory);

        var vulns = await analyzer.AnalyzeAsync(Target);

        vulns.Should().OnlyContain(v => v.Url == "https://example.com/");
    }

    [Fact]
    public async Task ReturnsEmpty_WhenHostUnreachable()
    {
        // Arrange — factory returns null (simulates connection failure)
        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("scanner").Returns(new HttpClient(new ThrowingHandler()));
        var analyzer = new SecurityHeadersAnalyzer(factory);

        // Act
        var vulns = await analyzer.AnalyzeAsync(Target);

        // Assert — should not throw, should return empty
        vulns.Should().BeEmpty();
    }
}

// Test helpers — fake HTTP handlers for controlled responses
internal sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly HttpResponseMessage _response;
    public FakeHttpMessageHandler(HttpResponseMessage response) => _response = response;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        => Task.FromResult(_response);
}

internal sealed class ThrowingHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        => throw new HttpRequestException("Connection refused");
}
