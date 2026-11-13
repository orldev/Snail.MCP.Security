using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting.Sessions;
using Snail.Toolkit.Nomad;
using Snail.Toolkit.Nomad.Models;

namespace Snail.MCP.Security.Adapters;

/// <summary>Scans as Nomad batch jobs, one at a time, read back from the report files the scanners leave in the shared cache volume.</summary>
/// <remarks>
/// One scan at a time across the server: Trivy keeps its database in BoltDB, which one process holds at a time, and the
/// cache volume is shared. A scanner that failed, or printed something other than its JSON, makes its checks
/// «did not run», with the end of what it said — a scan that skipped a check proves nothing about it.
/// </remarks>
public sealed class NomadScanner(INomadClient nomad, NomadBatch batch, IFixes fixes, IOptions<SecurityOptions> options) : IScanner, IDisposable
{
    /// <summary>Bytes of a scanner's standard error kept for a check that did not run.</summary>
    private const int ReasonBytes = 2048;

    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <inheritdoc />
    public async Task<ScanOutcome> ScanAsync(WorkspacePlace<string> copy, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await RunAsync(copy, checks, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<Answer<string>> ReachAsync(CancellationToken cancellationToken)
    {
        try
        {
            return Answer.Ok((await nomad.GetAgentAsync(cancellationToken)).Version);
        }
        catch (Exception exception) when (exception is HttpRequestException or NomadException or TaskCanceledException)
        {
            return Answer.Failed(Messages.SchedulerDown(options.Value.NomadAddress, exception.Message), Messages.SchedulerDownHint, FailureTypes.Unreachable);
        }
    }

    /// <summary>Releases the gate.</summary>
    public void Dispose() => _gate.Dispose();

    /// <summary>Runs the scan's job and reads what it left; a job the scan gives up on is stopped, whatever made it give up (<see cref="NomadBatch"/>).</summary>
    private async Task<ScanOutcome> RunAsync(WorkspacePlace<string> copy, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
    {
        string run = Guid.NewGuid().ToString("N");
        var ended = await batch.RunAsync(ScanJob.Of(copy.Task), ScannerJob.Of(copy, checks, run, options.Value), TimeSpan.FromSeconds(options.Value.ScanSeconds), cancellationToken);

        if (ended.Ended is { } allocation)
            return await ReadAsync(copy, checks, run, allocation, cancellationToken);

        if (ended.Refused is { } refused)
            return NotRun(checks, Messages.SchedulerFailed(options.Value.NomadAddress, refused));

        return NotRun(checks, $"the scan did not finish in {options.Value.ScanSeconds} s");
    }

    private static ScanOutcome NotRun(IReadOnlyCollection<Check> checks, string reason) =>
        new([], [.. checks.Select(check => new CheckRun(check, false, Messages.CheckFailed(ToolAnswer.Word(check), reason)))]);

    /// <summary>What the scanners left in the cache, each check run or not with the scanner's own words.</summary>
    /// <remarks>A stage that failed started no scanner at all, so its words are the reason of every check.</remarks>
    private async Task<ScanOutcome> ReadAsync(WorkspacePlace<string> copy, IReadOnlyCollection<Check> checks, string run, Allocation allocation, CancellationToken cancellationToken)
    {
        if (allocation.TaskStates?.GetValueOrDefault(ScannerJob.Stage)?.Failed == true)
        {
            string said = (await batch.LogsAsync(allocation.Id, ScannerJob.Stage, LogType.Stderr, ReasonBytes, cancellationToken)).Trim();

            return NotRun(checks, said.Length > 0 ? $"the copy could not be staged: {said}" : "the copy could not be staged");
        }

        List<Finding> findings = [];
        List<CheckRun> runs = [];

        foreach (string task in ScannerJob.TasksFor(checks))
        {
            var covered = Covered(task, checks);
            string file = ScannerJob.ReportOf(copy, run, task);
            string report = File.Exists(file) ? await File.ReadAllTextAsync(file, cancellationToken) : string.Empty;
            var read = Read(task, report);
            bool hasFailed = allocation.TaskStates?.GetValueOrDefault(task)?.Failed == true;

            if (read is null || hasFailed)
            {
                string said = (await batch.LogsAsync(allocation.Id, task, LogType.Stderr, ReasonBytes, cancellationToken)).Trim();
                string reason = said.Length > 0 ? said : "it printed no report";
                runs.AddRange(covered.Select(check => new CheckRun(check, false, Messages.CheckFailed(ToolAnswer.Word(check), reason))));
                continue;
            }

            findings.AddRange(read.Where(finding => checks.Contains(finding.Check)));

            IReadOnlyList<string> unread = task == ScannerJob.Dotnet ? ScannerReports.DotnetFailures(report) : [];
            if (unread.Count > 0)
                runs.AddRange(covered.Select(check => new CheckRun(check, false, Messages.CheckFailed(ToolAnswer.Word(check), unread[0]))));
        }

        var failed = runs.Select(run => run.Check).ToHashSet();
        runs.AddRange(checks.Where(check => !failed.Contains(check)).Select(check => new CheckRun(check, true)));

        IReadOnlyList<CheckRun> each = [.. runs.GroupBy(run => run.Check).Select(same => same.First()).OrderBy(run => run.Check)];
        List<Finding> merged = [];

        foreach (var finding in ScannerReports.Merged(findings))
            merged.Add(finding is { Check: Check.Packages, FixedIn: null, Package: { } package } ? finding with { FixedIn = await fixes.FixedInAsync(package, finding.Rule, cancellationToken) } : finding);

        return new ScanOutcome(merged, each);
    }

    /// <summary>
    /// The checks a scanner answers for, when it fails: the .NET scanner and Trivy both answer for packages, and either failing
    /// leaves packages unproven. What a scanner finds is kept for any check asked for: Semgrep's Dockerfile rules are settings.
    /// </summary>
    private static IReadOnlyCollection<Check> Covered(string task, IReadOnlyCollection<Check> checks) => task switch
    {
        ScannerJob.Trivy => [.. checks.Where(check => check is Check.Packages or Check.Secrets or Check.Config)],
        ScannerJob.Semgrep => [Check.Code],
        _ => [Check.Packages]
    };

    /// <summary>A scanner's findings, or null when what it printed is not its report.</summary>
    private static IReadOnlyList<Finding>? Read(string task, string report)
    {
        string trimmed = report.Trim();

        if (task == ScannerJob.Dotnet)
            return trimmed.Length == 0 || trimmed.StartsWith('{') || trimmed.StartsWith(ScannerReports.Separator, StringComparison.Ordinal) ? ScannerReports.Dotnet(trimmed) : null;

        if (!trimmed.StartsWith('{'))
            return null;

        return task == ScannerJob.Trivy ? ScannerReports.Trivy(trimmed) : ScannerReports.Semgrep(trimmed);
    }
}
