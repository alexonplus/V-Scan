using Protector.Domain.Entities;

namespace Protector.Domain.Interfaces;

public interface IReportGenerator
{
    string Format { get; }
    Task GenerateAsync(ScanResult result, string outputPath, CancellationToken ct = default);
}
