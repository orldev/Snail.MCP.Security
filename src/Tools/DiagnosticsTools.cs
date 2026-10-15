using System.ComponentModel;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Tools;

/// <summary>Whether the server can scan: the scheduler, the images, the network and the proxy.</summary>
[McpServerToolType]
public sealed class DiagnosticsTools(IScanner scanner, IOptions<SecurityOptions> options)
{
    /// <summary>Says whether scans can run.</summary>
    [McpServerTool(Name = "security_diagnose", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description(ToolDescriptions.Diagnose)]
    public async Task<CallToolResult> DiagnoseAsync(CancellationToken cancellationToken = default)
    {
        var reached = await scanner.ReachAsync(cancellationToken);
        if (reached.Value is not { } version)
            return ToolResponse.Failure(reached.Error!, reached.Hint);

        var settings = options.Value;
        var state = new JsonObject
        {
            ["server"] = typeof(DiagnosticsTools).Assembly.GetName().Version?.ToString(3),
            ["nomad"] = version,
            ["trivy"] = settings.TrivyImage,
            ["semgrep"] = settings.SemgrepImage,
            ["sdk"] = settings.SdkImage,
            ["semgrepRules"] = new JsonArray([.. settings.SemgrepConfigs.Select(rules => JsonValue.Create(rules))]),
            ["network"] = settings.Network,
            ["proxy"] = settings.Proxy,
            ["proxyHosts"] = new JsonArray([.. settings.ProxyHosts.Select(host => JsonValue.Create(host))])
        };

        return ToolResponse.Success(state);
    }
}
