using FluentAssertions;
using Protector.Domain.Enums;
using Protector.Infrastructure.Analyzers.Static;

namespace Protector.Tests.Analyzers;

public class ReactCodeAnalyzerTests : IDisposable
{
    private readonly ReactCodeAnalyzer _analyzer = new();
    private readonly string _tempFile = Path.GetTempFileName() + ".tsx";

    private async Task<IEnumerable<Protector.Domain.Entities.Vulnerability>> AnalyzeCode(string code)
    {
        await File.WriteAllTextAsync(_tempFile, code);
        return await _analyzer.AnalyzeFileAsync(_tempFile);
    }

    [Fact]
    public async Task Detects_DangerouslySetInnerHTML()
    {
        // Arrange
        var code = """
            const MyComponent = ({ html }) => (
              <div dangerouslySetInnerHTML={{ __html: html }} />
            );
            """;

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().ContainSingle(v =>
            v.Category == VulnerabilityCategory.StaticAnalysisReact &&
            v.Title.Contains("dangerouslySetInnerHTML"));
    }

    [Fact]
    public async Task Detects_EvalUsage()
    {
        // Arrange
        var code = "const result = eval(userInput);";

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().ContainSingle(v => v.Title.Contains("eval()"));
        vulns.First().Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task Detects_TokenInLocalStorage()
    {
        // Arrange
        var code = """localStorage.setItem("authToken", token);""";

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().ContainSingle(v => v.Title.Contains("localStorage"));
    }

    [Fact]
    public async Task Detects_HttpApiCall()
    {
        // Arrange
        var code = """const data = await fetch("http://api.example.com/users");""";

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().ContainSingle(v => v.Title.Contains("HTTP"));
    }

    [Fact]
    public async Task Skips_CommentedOutCode()
    {
        // Arrange — commented eval should NOT be flagged
        var code = """
            // const result = eval(userInput);
            const value = 42;
            """;

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().BeEmpty();
    }

    [Fact]
    public async Task CleanCode_ReturnsNoVulnerabilities()
    {
        // Arrange
        var code = """
            const MyComponent = () => {
              const [data, setData] = React.useState(null);
              return <div>{data}</div>;
            };
            """;

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().BeEmpty();
    }

    public void Dispose()
    {
        if (File.Exists(_tempFile))
            File.Delete(_tempFile);
    }
}
