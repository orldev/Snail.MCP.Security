using System.ComponentModel;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Snail.MCP.Security.Application;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Hosting.Jobs;

namespace Snail.MCP.Security.Tools;

/// <summary>A customer's site: proving it is theirs, and checking it.</summary>
/// <remarks>
/// Open world: the proof asks the public DNS, and the scan reaches the site itself. A scan takes minutes, so it runs as a
/// job: the tool answers within the wait with the scan, or with the running job at <c>job://security/site/&lt;id&gt;</c>, and
/// asked for again it answers with the same scan rather than scanning the site twice.
/// </remarks>
[McpServerToolType]
public sealed class SiteTools(Sites sites, SiteJobs running, SessionCopy session)
{
    /// <summary>Proves a site is the customer's, or says which record proves it.</summary>
    [McpServerTool(Name = "security_site_prove", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = true)]
    [Description(ToolDescriptions.SiteProve)]
    public async Task<CallToolResult> ProveAsync(
        [Description(ToolDescriptions.SiteName)] string site,
        CancellationToken cancellationToken = default) =>
        ToolAnswer.From(await sites.ProveAsync(site, cancellationToken), AnswerFields.Of);

    /// <summary>Scans a proven site as a job.</summary>
    [McpServerTool(Name = "security_site_scan", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = true)]
    [Description(ToolDescriptions.SiteScan)]
    public async Task<CallToolResult> ScanAsync(
        [Description(ToolDescriptions.SiteName)] string site,
        [Description(ToolDescriptions.SiteScanChecks)] string[]? checks = null,
        [Description(ToolDescriptions.ScanWait)] int wait = 60,
        CancellationToken cancellationToken = default)
    {
        if (wait < 0)
            return ToolAnswer.Failed(Messages.WaitBelowZero(wait), type: ToolFailures.Arguments);

        var plan = await sites.PlanAsync(site, checks, cancellationToken);
        if (!plan.TryGet(out var planned))
            return ToolAnswer.Failed(plan);

        string? task = session.Current().TryGet(out var copy) ? copy.Task : null;
        var job = running.Start(planned, task);
        var report = await job.ForAsync(TimeSpan.FromSeconds(wait), cancellationToken);

        return JobAnswer.Envelope(report);
    }
}
