using FluentAssertions;
using Protector.Domain.Enums;
using Protector.Infrastructure.Analyzers.Static;

namespace Protector.Tests.Analyzers;

public class CSharpCodeAnalyzerTests : IDisposable
{
    private readonly CSharpCodeAnalyzer _analyzer = new();
    private readonly string _tempFile = Path.GetTempFileName() + ".cs";

    // Writes C# code to a temp file and runs the analyzer
    private async Task<IEnumerable<Protector.Domain.Entities.Vulnerability>> AnalyzeCode(string code)
    {
        await File.WriteAllTextAsync(_tempFile, code);
        return await _analyzer.AnalyzeFileAsync(_tempFile);
    }

    [Fact]
    public async Task Detects_SqlInjection_ViaStringConcatenation()
    {
        // Arrange
        var code = """
            var id = Request.Query["id"];
            var sql = "SELECT * FROM users WHERE id = " + id;
            """;

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().ContainSingle(v => v.Category == VulnerabilityCategory.SqlInjection);
    }

    [Fact]
    public async Task Detects_HardcodedPassword()
    {
        // Arrange
        var code = """
            string password = "SuperSecret123";
            """;

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().ContainSingle(v => v.Category == VulnerabilityCategory.SensitiveDataExposure);
        vulns.First().Severity.Should().Be(Severity.High);
    }

    [Fact]
    public async Task Detects_BinaryFormatter()
    {
        // Arrange
        var code = """
            using System.Runtime.Serialization.Formatters.Binary;
            var formatter = new BinaryFormatter();
            """;

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().ContainSingle(v => v.Category == VulnerabilityCategory.InsecureDeserialization);
        vulns.First().Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public async Task Detects_WeakCryptography_MD5()
    {
        // Arrange
        var code = """
            var hash = MD5.Create().ComputeHash(data);
            """;

        // Act
        var vulns = await AnalyzeCode(code);

        // Assert
        vulns.Should().Contain(v => v.Title.Contains("MD5"));
    }

    [Fact]
    public async Task CleanCode_ReturnsNoVulnerabilities()
    {
        // Arrange
        var code = """
            public class SafeService
            {
                public string GetName() => "hello";
            }
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
