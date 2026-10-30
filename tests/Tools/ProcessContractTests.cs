using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using ModelContextProtocol.Client;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Hosting.Jobs;
using Snail.Sdk.Mcp.JobClient;
using Snail.Sdk.Mcp.Testing;

namespace Snail.MCP.Security.Tests.Tools;

/// <summary>
/// The program as the platform starts it — the build beside the tests, or the publication <c>SNAIL_SECURITY_SERVER</c>
/// names — asked over HTTP.
/// </summary>
/// <remarks>Nomad's address names a port nothing listens on: no scan runs, and the tools that need the scheduler have to say so in an answer of their own.</remarks>
public sealed class ProcessContractTests : IAsyncLifetime
{
    public const string ServerVariable = "SNAIL_SECURITY_SERVER";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private readonly Uri _address = new($"http://127.0.0.1:{FreePort()}");
    private Process _server = default!;

    public async Task InitializeAsync()
    {
        var (command, arguments) = ServerProgram.Command("Snail.MCP.Security", ServerVariable);
        var start = new ProcessStartInfo(command, arguments)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };

        start.Environment["HOME"] = ServerProgram.Home;
        start.Environment["SNAIL_MCP_SECURITY_URL"] = _address.ToString();
        start.Environment["SNAIL_MCP_SECURITY_NOMAD_ADDRESS"] = $"http://127.0.0.1:{FreePort()}";
        start.Environment[ServerSettings.FileVariableOf("security")] = ServerProgram.NoSettingsFile;

        _server = Process.Start(start)!;
        _server.OutputDataReceived += (_, _) => { };
        _server.ErrorDataReceived += (_, _) => { };
        _server.BeginOutputReadLine();
        _server.BeginErrorReadLine();

        using var waiting = new CancellationTokenSource(Timeout);
        using var http = new HttpClient { BaseAddress = _address };

        while (true)
        {
            try
            {
                using var answer = await http.GetAsync(new Uri("/healthz", UriKind.Relative), waiting.Token);

                if (answer.IsSuccessStatusCode)
                    return;
            }
            catch (HttpRequestException) when (!_server.HasExited)
            {
            }

            await Task.Delay(100, waiting.Token);
        }
    }

    public Task DisposeAsync()
    {
        _server.Kill(entireProcessTree: true);
        _server.WaitForExit();
        _server.Dispose();

        return Task.CompletedTask;
    }

    [Fact]
    public async Task ListTools_StartedProgram_OffersEveryTool()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync(null, cancellation.Token);

        var tools = await session.ListToolsAsync(cancellationToken: cancellation.Token);

        Assert.Equal(["security_diagnose", "security_findings", "security_scan"], tools.Select(tool => tool.Name).Order(StringComparer.Ordinal));
    }

    /// <summary>The guard rules of every Snail server, on the list a model receives.</summary>
    [Fact]
    public async Task Tools_AsListed_KeepTheGuardRules()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync(null, cancellation.Token);

        var tools = await session.ListToolsAsync(cancellationToken: cancellation.Token);

        Assert.Empty(ToolGuards.Problems(tools.Select(tool => tool.ProtocolTool)));
    }

    [Fact]
    public async Task CallTool_DiagnoseWithoutNomad_NamesTheAddressThatDidNotAnswer()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync(null, cancellation.Token);

        var result = await session.CallToolAsync("security_diagnose", cancellationToken: cancellation.Token);

        Assert.True(result.IsError);
        Assert.Contains("did not answer", result.Text(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallTool_ScanWithoutACopyInTheAddress_IsAToolErrorThatSaysWhereTheCopyComesFrom()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync(null, cancellation.Token);

        var result = await session.CallToolAsync("security_scan", cancellationToken: cancellation.Token);

        Assert.True(result.IsError);
        Assert.Contains("?root=", result.Text(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task CallTool_ToolNotGrantedToTheSession_IsRefusedByName()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync("tool=security_findings", cancellation.Token);

        var result = await session.CallToolAsync("security_scan", cancellationToken: cancellation.Token);

        Assert.True(result.IsError);
        Assert.Contains("'security_scan' was not granted", result.Text(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The scan as a job end to end: called with no wait, awaited by subscription, ended with every check not run, since
    /// Nomad's address names a port nothing listens on — a scan that could not be made is a result, not a lost call.
    /// </summary>
    [Fact]
    public async Task CallJob_ScanWithNomadDown_EndsWithEveryCheckNotRun()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync("root=/workspaces/0c2b9e1f/step-2", cancellation.Token);

        var report = await session.CallJobAsync("security_scan", cancellationToken: cancellation.Token);

        Assert.Equal(JobState.Succeeded, report.State);
        var runs = report.Result!.Value.GetProperty("runs").EnumerateArray().ToList();
        Assert.Equal(4, runs.Count);
        Assert.All(runs, run => Assert.False(run.GetProperty("ran").GetBoolean()));
    }

    /// <summary>A page in a browser always sends Origin and an agent's client never does: no web page may reach the scans.</summary>
    [Fact]
    public async Task Request_FromABrowser_IsRefused()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        using var http = new HttpClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_address, "/mcp"));

        request.Headers.Add("Origin", "https://example.com");

        using var answer = await http.SendAsync(request, cancellation.Token);

        Assert.Equal(HttpStatusCode.Forbidden, answer.StatusCode);
    }

    private Task<McpClient> SessionAsync(string? query, CancellationToken cancellationToken) =>
        McpClient.CreateAsync(new HttpClientTransport(new HttpClientTransportOptions { Endpoint = new Uri(_address, query is null ? "/mcp" : $"/mcp?{query}") }), cancellationToken: cancellationToken);

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
