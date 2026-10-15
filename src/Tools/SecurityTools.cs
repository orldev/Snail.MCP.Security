using System.ComponentModel;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Tools;

/// <summary>Scans of the task's working copy, and their findings page by page.</summary>
[McpServerToolType]
public sealed class SecurityTools(Scans scans, IOptions<SecurityOptions> options)
{
    /// <summary>Scans the working copy.</summary>
    [McpServerTool(Name = "security_scan", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description(ToolDescriptions.Scan)]
    public async Task<CallToolResult> ScanAsync(
        [Description(ToolDescriptions.ScanChecks)] string[]? checks = null,
        CancellationToken cancellationToken = default) =>
        ToolResponse.From(await scans.ScanAsync(checks, cancellationToken), options.Value.ShownFindings);

    /// <summary>Reads a page of the last scan's findings.</summary>
    [McpServerTool(Name = "security_findings", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description(ToolDescriptions.Findings)]
    public async Task<CallToolResult> FindingsAsync(
        [Description(ToolDescriptions.FindingsSeverity)] string? severity = null,
        [Description(ToolDescriptions.FindingsCheck)] string? check = null,
        [Description(ToolDescriptions.FindingsOffset)] int offset = 0,
        [Description(ToolDescriptions.FindingsLimit)] int? limit = null,
        CancellationToken cancellationToken = default) =>
        ToolResponse.From(await scans.FindingsAsync(severity, check, offset, limit, cancellationToken));
}
