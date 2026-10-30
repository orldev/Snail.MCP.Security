using System.Net;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Toolkit.Nomad;
using Snail.Toolkit.Nomad.Models;

namespace Snail.MCP.Security.Adapters;

/// <summary>Scans as Nomad batch jobs, one at a time, read back from the report files the scanners leave in the shared cache volume.</summary>
/// <remarks>
/// One scan at a time across the server: Trivy keeps its database in BoltDB, which one process holds at a time, and the
/// cache volume is shared. A scanner that failed, or printed something other than its JSON, makes its checks
/// «did not run», with the end of what it said — a scan that skipped a check proves nothing about it.
/// </remarks>
public sealed class NomadScanner(INomadClient nomad, IFixes fixes, IOptions<SecurityOptions> options, TimeProvider clock) : IScanner, IDisposable
{
    /// <summary>How often a running scan is looked at.</summary>
    private static readonly TimeSpan Poll = TimeSpan.FromSeconds(2);

    /// <summary>Bytes of a scanner's standard error kept for a check that did not run.</summary>
    private const int ReasonBytes = 2048;

    private static readonly string[] Ended = ["complete", "failed", "lost"];

    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <inheritdoc />
    public async Task<ScanOutcome> ScanAsync(CopyPlace copy, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
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
            return Answer.Failed<string>(Messages.SchedulerDown(options.Value.NomadAddress, exception.Message), Messages.SchedulerDownHint);
        }
    }

    /// <summary>Releases the gate.</summary>
    public void Dispose() => _gate.Dispose();

    private async Task<ScanOutcome> RunAsync(CopyPlace copy, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
    {
        string run = Guid.NewGuid().ToString("N");
        await nomad.StopJobAsync(copy.Job, purge: true, cancellationToken);
        await nomad.RegisterJobAsync(ScannerJob.Of(copy, checks, run, options.Value), cancellationToken);

        var allocation = await EndedAsync(copy.Job, cancellationToken);
        if (allocation is null)
        {
            await nomad.StopJobAsync(copy.Job, purge: false, cancellationToken);
            string reason = $"the scan did not finish in {options.Value.ScanSeconds} s";

            return new ScanOutcome([], [.. checks.Select(check => new CheckRun(check, false, Messages.CheckFailed(Scans.Word(check), reason)))]);
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
                string said = (await LogsAsync(allocation.Id, task, LogType.Stderr, ReasonBytes, cancellationToken)).Trim();
                string reason = said.Length > 0 ? said : "it printed no report";
                runs.AddRange(covered.Select(check => new CheckRun(check, false, Messages.CheckFailed(Scans.Word(check), reason))));
                continue;
            }

            findings.AddRange(read.Where(finding => checks.Contains(finding.Check)));
        }

        var failed = runs.Select(run => run.Check).ToHashSet();
        runs.AddRange(checks.Where(check => !failed.Contains(check)).Select(check => new CheckRun(check, true)));

        IReadOnlyList<CheckRun> each = [.. runs.GroupBy(run => run.Check).Select(same => same.First()).OrderBy(run => run.Check)];
        List<Finding> merged = [];

        foreach (var finding in ScannerReports.Merged(findings))
            merged.Add(finding is { Check: Check.Packages, FixedIn: null, Package: { } package } ? finding with { FixedIn = await fixes.FixedInAsync(package, finding.Rule, cancellationToken) } : finding);

        return new ScanOutcome(merged, each);
    }

    private async Task<Allocation?> EndedAsync(string job, CancellationToken cancellationToken)
    {
        long started = clock.GetTimestamp();
        var timeout = TimeSpan.FromSeconds(options.Value.ScanSeconds);

        while (clock.GetElapsedTime(started) < timeout)
        {
            await Task.Delay(Poll, clock, cancellationToken);
            var allocations = await nomad.ListAllocationsAsync(job, cancellationToken: cancellationToken);
            var allocation = allocations.Items.Count > 0 ? allocations.Items[0] : null;

            if (allocation is not null && Ended.Contains(allocation.ClientStatus, StringComparer.Ordinal))
                return allocation;
        }

        return null;
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

    private async Task<string> LogsAsync(string allocation, string task, LogType type, int bytes, CancellationToken cancellationToken)
    {
        try
        {
            return await nomad.ReadLogsAsync(allocation, task, type, bytes, cancellationToken);
        }
        catch (NomadException exception) when (exception.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.BadRequest or HttpStatusCode.InternalServerError)
        {
            return string.Empty;
        }
    }
}
