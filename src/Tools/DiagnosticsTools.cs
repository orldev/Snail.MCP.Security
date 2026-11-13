using System.ComponentModel;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Tools;

/// <summary>Whether the server can scan: the scheduler, the images, the network and the proxy.</summary>
[McpServerToolType]
public sealed class DiagnosticsTools(IScanner scanner, IOptions<SecurityOptions> options, Compliance compliance)
{
    /// <summary>Says whether scans can run.</summary>
    [McpServerTool(Name = "security_diagnose", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description(ToolDescriptions.Diagnose)]
    public async Task<CallToolResult> DiagnoseAsync(CancellationToken cancellationToken = default)
    {
        var reached = await scanner.ReachAsync(cancellationToken);
        if (!reached.TryGet(out var nomad))
            return ToolAnswer.Failed(reached);

        return ToolAnswer.Ok(AnswerFields.Of(nomad, options.Value, compliance));
    }
}
