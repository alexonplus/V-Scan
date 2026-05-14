using Protector.Domain.Entities;

namespace Protector.Domain.Interfaces;

/// <summary>
/// Analyzes source code files on disk rather than a live HTTP endpoint.
/// </summary>
public interface IStaticCodeAnalyzer
{
    string Name { get; }
    IEnumerable<string> SupportedExtensions { get; }
    Task<IEnumerable<Vulnerability>> AnalyzeFileAsync(string filePath, CancellationToken ct = default);
}
