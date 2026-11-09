using ModelContextProtocol;
using ModelContextProtocol.Client;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Hosting.Jobs;
using Snail.Sdk.Mcp.Hosting.Sessions;
using Snail.Sdk.Mcp.JobClient;
using Snail.Sdk.Mcp.Testing;

namespace Snail.MCP.Security.Tests.Tools;

/// <summary>
/// The program as the platform starts it — the build beside the tests, or the publication <c>SNAIL_SECURITY_SERVER</c>
/// names — asked over HTTP, at the address <c>SNAIL_MCP_SECURITY_URL</c> gives it, ready once <c>/healthz</c> answers.
/// </summary>
/// <remarks>Nomad's address names a port nothing listens on: no scan runs, and the tools that need the scheduler have to say so in an answer of their own.</remarks>
public sealed class ProcessContractTests : IAsyncLifetime
{
    public const string ServerVariable = "SNAIL_SECURITY_SERVER";

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private HttpServerProgram _server = null!;

    public async Task InitializeAsync() =>
        _server = await HttpServerProgram.StartAsync(
            "Snail.MCP.Security",
            ServerVariable,
            new Dictionary<string, string?> { ["SNAIL_MCP_SECURITY_NOMAD_ADDRESS"] = $"http://127.0.0.1:{Ports.Free()}" });

    public async Task DisposeAsync() => await _server.DisposeAsync();

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
        Assert.Contains("did not answer", result.Error(), StringComparison.Ordinal);
        Assert.Equal("unreachable", result.Type());
    }

    [Fact]
    public async Task CallTool_ScanWithoutACopyInTheAddress_IsAToolErrorThatSaysWhereTheCopyComesFrom()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync(null, cancellation.Token);

        var result = await session.CallToolAsync("security_scan", cancellationToken: cancellation.Token);

        Assert.True(result.IsError);
        Assert.Equal(Reached.NoRoot, result.Type());
        Assert.Contains("?root=", result.Hint(), StringComparison.Ordinal);
    }

    /// <summary>A role given some of the tools sees those alone, and a call to another is refused by name in the envelope.</summary>
    [Fact]
    public async Task CallTool_ToolNotGrantedToTheSession_IsHiddenAndRefusedByName()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync("tool=security_findings", cancellation.Token);

        var tools = await session.ListToolsAsync(cancellationToken: cancellation.Token);
        var result = await session.CallToolAsync("security_scan", cancellationToken: cancellation.Token);

        Assert.Equal(["security_findings"], tools.Select(tool => tool.Name));
        Assert.True(result.IsError);
        Assert.Equal(GrantOptions.NotGranted, result.Type());
        Assert.Contains("'security_scan' was not granted", result.Error(), StringComparison.Ordinal);
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

    /// <summary>
    /// A scan is its task's: another step of the task reads its job, a client of another task or of no copy is told the
    /// job does not exist, as for a URI nobody made — the server is one for every task of the platform.
    /// </summary>
    [Fact]
    public async Task ReadResource_ScanJobOfAnotherTask_IsUnknown()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var scanning = await SessionAsync("root=/workspaces/0c2b9e1f/step-2", cancellation.Token);
        await using var nextStep = await SessionAsync("root=/workspaces/0c2b9e1f/step-3", cancellation.Token);
        await using var otherTask = await SessionAsync("root=/workspaces/7d4a0b33/step-1", cancellation.Token);
        await using var noCopy = await SessionAsync(null, cancellation.Token);

        var started = await scanning.CallToolAsync("security_scan", new Dictionary<string, object?> { ["wait"] = 0 }, cancellationToken: cancellation.Token);
        var job = new Uri(started.Report()!.Uri);

        var read = await nextStep.ReadResourceAsync(job, cancellationToken: cancellation.Token);

        Assert.Single(read.Contents);
        await Assert.ThrowsAnyAsync<McpException>(async () => await otherTask.ReadResourceAsync(job, cancellationToken: cancellation.Token));
        await Assert.ThrowsAnyAsync<McpException>(async () => await noCopy.ReadResourceAsync(job, cancellationToken: cancellation.Token));
    }

    /// <summary>
    /// Every argument a tool takes, as the program binds it: an array of checks, then a page narrowed by severity, check,
    /// offset and limit. A native build binds what it was told about and fails on anything else, so the arguments are
    /// asked of the process, not of the code.
    /// </summary>
    [Fact]
    public async Task CallTool_EveryArgumentKind_IsBoundByTheProgram()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync("root=/workspaces/0c2b9e1f/step-2", cancellation.Token);

        var report = await session.CallJobAsync("security_scan", new Dictionary<string, object?> { ["checks"] = new[] { "code" } }, cancellationToken: cancellation.Token);
        var page = await session.CallToolAsync("security_findings", new Dictionary<string, object?> { ["severity"] = "high", ["check"] = "code", ["offset"] = 0, ["limit"] = 5 }, cancellationToken: cancellation.Token);

        var run = Assert.Single(report.Result!.Value.GetProperty("runs").EnumerateArray());
        Assert.Equal("code", run.GetProperty("check").GetString());
        Assert.True(page.IsOk(), page.Text());
        Assert.Equal(0, page.Data()!["total"]!.GetValue<int>());
    }

    /// <summary>A parameter the tool does not take is refused before the scan starts, naming the one it probably meant.</summary>
    [Fact]
    public async Task CallTool_ParameterTheToolDoesNotTake_IsRefusedAsArguments()
    {
        using var cancellation = new CancellationTokenSource(Timeout);
        await using var session = await SessionAsync("root=/workspaces/0c2b9e1f/step-2", cancellation.Token);

        var result = await session.CallToolAsync("security_scan", new Dictionary<string, object?> { ["check"] = new[] { "code" } }, cancellationToken: cancellation.Token);

        Assert.True(result.IsError);
        Assert.Equal(ToolFailures.Arguments, result.Type());
        Assert.Contains("checks", result.Text(), StringComparison.Ordinal);
    }

    /// <summary>A page in a browser always sends Origin and an agent's client never does: no web page may reach the scans.</summary>
    [Fact]
    public async Task Request_FromABrowser_IsRefused()
    {
        using var cancellation = new CancellationTokenSource(Timeout);

        var problems = await HttpGuards.ProblemsAsync(_server.Endpoint, cancellation.Token);

        Assert.Empty(problems);
    }

    private Task<McpClient> SessionAsync(string? query, CancellationToken cancellationToken) =>
        _server.SessionAsync(query, cancellationToken: cancellationToken);
}
