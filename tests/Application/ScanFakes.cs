using Snail.MCP.Security.Application.Ports;
using Snail.Sdk.Mcp.Hosting.Sessions;

namespace Snail.MCP.Security.Tests.Application;

/// <summary>A scanner that answers at once with what the test sets, every check asked for run.</summary>
internal sealed class FakeScanner : IScanner
{
    public List<IReadOnlyCollection<Check>> Asked { get; } = [];

    public ScanOutcome Next { get; set; } = new([], []);

    /// <summary>What the scan waits for before it answers; done already unless a test holds it.</summary>
    public Task Held { get; set; } = Task.CompletedTask;

    public async Task<ScanOutcome> ScanAsync(WorkspacePlace<string> copy, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
    {
        Asked.Add(checks);
        await Held.WaitAsync(cancellationToken);

        return Next with { Runs = [.. checks.Select(check => new CheckRun(check, true))] };
    }

    public Task<Answer<string>> ReachAsync(CancellationToken cancellationToken) => Task.FromResult(Answer.Ok("1.10"));
}

/// <summary>Each task's last scan, kept in memory.</summary>
internal sealed class MemoryHistory : IScanHistory
{
    private readonly Dictionary<string, ScanReport> _kept = [];

    public Task<ScanReport?> LastAsync(string task, CancellationToken cancellationToken) => Task.FromResult(_kept.GetValueOrDefault(task));

    public Task SaveAsync(string task, ScanReport report, CancellationToken cancellationToken)
    {
        _kept[task] = report;

        return Task.CompletedTask;
    }
}
