namespace Protector.Domain.Interfaces;

public interface IScanHistoryService
{
    Task<IReadOnlyList<ScanHistoryItem>> GetRecentAsync(int count = 20);
    Task<ScanHistoryItem?> GetByIdAsync(Guid id);
    Task SaveAsync(ScanHistoryItem session);
    Task UpdateNotesAsync(Guid id, string notes);
    Task DeleteAsync(Guid id);
}
