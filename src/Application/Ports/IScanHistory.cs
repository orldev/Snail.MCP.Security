namespace Snail.MCP.Security.Application.Ports;

/// <summary>Each task's last scan, so the next one says what got fixed and the findings can be read page by page.</summary>
public interface IScanHistory
{
    /// <summary>The task's last scan; null before its first.</summary>
    Task<ScanReport?> LastAsync(string task, CancellationToken cancellationToken);

    /// <summary>Keeps the scan as the task's last.</summary>
    Task SaveAsync(string task, ScanReport report, CancellationToken cancellationToken);
}
