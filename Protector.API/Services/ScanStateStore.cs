using Microsoft.Extensions.Caching.Memory;
using Protector.Domain.Entities;

namespace Protector.API.Services;

public sealed record ScanState(string Status, ScanResult? Result);

public interface IScanStateStore
{
    void SetRunning(string scanId);
    void SetCompleted(string scanId, ScanResult result);
    void SetFailed(string scanId);
    ScanState? Get(string scanId);
}

// IMemoryCache is thread-safe — no manual locking needed.
// TTL is set on each write so cleanup is automatic — no CleanupExpired() needed.
// Registered as singleton so state survives across HTTP requests.
public sealed class ScanStateStore(IMemoryCache cache) : IScanStateStore
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(30);

    public void SetRunning(string scanId) =>
        cache.Set(scanId, new ScanState("running", null), Ttl);

    public void SetCompleted(string scanId, ScanResult result) =>
        cache.Set(scanId, new ScanState("completed", result), Ttl);

    public void SetFailed(string scanId) =>
        cache.Set(scanId, new ScanState("failed", null), Ttl);

    public ScanState? Get(string scanId) =>
        cache.TryGetValue(scanId, out ScanState? state) ? state : null;
}
