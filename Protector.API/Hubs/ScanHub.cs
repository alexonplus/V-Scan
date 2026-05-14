using Microsoft.AspNetCore.SignalR;

namespace Protector.API.Hubs;

/// <summary>
/// SignalR hub that pushes real-time scan progress to connected React clients.
/// React client connects to /hubs/scan and listens for these events:
/// - "Progress" (string message)
/// - "Completed" (ScanResultResponse)
/// - "Error" (string message)
/// </summary>
public sealed class ScanHub : Hub
{
    // Called automatically when a client disconnects
    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        await base.OnDisconnectedAsync(exception);
    }
}
