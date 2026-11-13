using System.ComponentModel;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Snail.MCP.Security.Application;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Hosting.Jobs;

namespace Snail.MCP.Security.Tools;

/// <summary>Scans of the task's working copy, and their findings page by page.</summary>
/// <remarks>
/// A scan takes from seconds to the whole scan time, so it runs as a job: the tool answers within the wait the client
/// allows with the scan, or with the running job at <c>job://security/scan/&lt;id&gt;</c>, whose resource carries the scan
/// once it ends. A client that went away no longer takes the scan down with it: the scan ends and is kept, and
/// security_findings reads it. Asked for again while it runs, the same scan is joined rather than started twice.
/// </remarks>
[McpServerToolType]
public sealed class SecurityTools(Scans scans, ScanJobs running, Compliance compliance)
{
    /// <summary>Scans the working copy as a job.</summary>
    [McpServerTool(Name = "security_scan", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description(ToolDescriptions.Scan)]
    public async Task<CallToolResult> ScanAsync(
        [Description(ToolDescriptions.ScanChecks)] string[]? checks = null,
        [Description(ToolDescriptions.ScanWait)] int wait = 60,
        CancellationToken cancellationToken = default)
    {
        if (wait < 0)
            return ToolAnswer.Failed(Messages.WaitBelowZero(wait), type: ToolFailures.Arguments);

        var request = scans.Plan(checks);
        if (!request.TryGet(out var planned))
            return ToolAnswer.Failed(request);

        var job = running.Start(planned);
        var report = await job.ForAsync(TimeSpan.FromSeconds(wait), cancellationToken);

        return JobAnswer.Envelope(report);
    }

    /// <summary>Reads a page of the last scan's findings.</summary>
    [McpServerTool(Name = "security_findings", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description(ToolDescriptions.Findings)]
    public async Task<CallToolResult> FindingsAsync(
        [Description(ToolDescriptions.FindingsSeverity)] string? severity = null,
        [Description(ToolDescriptions.FindingsCheck)] string? check = null,
        [Description(ToolDescriptions.FindingsOffset)] int offset = 0,
        [Description(ToolDescriptions.FindingsLimit)] int? limit = null,
        CancellationToken cancellationToken = default) =>
        ToolAnswer.From(await scans.FindingsAsync(severity, check, offset, limit, cancellationToken), page => AnswerFields.Of(page, compliance));
}
