using Protector.Domain.Interfaces;

namespace Protector.Infrastructure.Services;

public sealed class ScanHistoryService(IScanSessionRepository repository) : IScanHistoryService
{
    public Task<IReadOnlyList<ScanHistoryItem>> GetRecentAsync(int count = 20) =>
        repository.GetRecentAsync(count);

    public Task<ScanHistoryItem?> GetByIdAsync(Guid id) =>
        repository.GetByIdAsync(id);

    public Task SaveAsync(ScanHistoryItem session) =>
        repository.AddAsync(session);

    public Task DeleteAsync(Guid id) =>
        repository.DeleteAsync(id);
}
