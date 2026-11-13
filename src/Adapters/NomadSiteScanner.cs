using System.Net;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Toolkit.Nomad.Models;

namespace Snail.MCP.Security.Adapters;

/// <summary>Site scans as Nomad batch jobs, one at a time, read back from the report files the scanners leave in the cache volume.</summary>
/// <remarks>
/// One at a time across the server: a site scan is the one thing this server sends to the internet, and two at once would
/// double what a customer's site receives. A scanner that failed, or left something other than its report, makes the
/// checks it answers for «did not run», with the end of what it said.
/// </remarks>
public sealed class NomadSiteScanner(NomadBatch batch, IOptions<SecurityOptions> options) : ISiteScanner, IDisposable
{
    /// <summary>Bytes of a scanner's standard error kept for a check that did not run.</summary>
    private const int ReasonBytes = 2048;

    private readonly SemaphoreSlim _gate = new(1, 1);

    /// <inheritdoc />
    public async Task<ScanOutcome> ScanAsync(Site site, IReadOnlyList<IPAddress> addresses, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return await RunAsync(site, addresses, checks, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Releases the gate.</summary>
    public void Dispose() => _gate.Dispose();

    /// <summary>The checks a scanner answers for when it fails: Nuclei for TLS, headers and exposure, nmap for services.</summary>
    /// <remarks>nmap's TLS findings come beside Nuclei's; TLS is Nuclei's to prove, so nmap failing leaves it run.</remarks>
    public static IReadOnlyCollection<Check> Covered(string task, IReadOnlyCollection<Check> checks) => task == SiteJob.Nuclei
        ? [.. checks.Where(check => check is Check.Tls or Check.Headers or Check.Exposure)]
        : [.. checks.Where(check => check is Check.Services)];

    private async Task<ScanOutcome> RunAsync(Site site, IReadOnlyList<IPAddress> addresses, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
    {
        string run = Guid.NewGuid().ToString("N");
        var spec = SiteJob.Of(site, addresses, checks, run, options.Value);
        var ended = await batch.RunAsync(SiteJob.NameOf(site), spec, TimeSpan.FromSeconds(options.Value.ScanSeconds), cancellationToken);

        if (ended.Ended is { } allocation)
            return await ReadAsync(site, checks, run, allocation, cancellationToken);

        if (ended.Refused is { } refused)
            return NotRun(checks, Messages.SchedulerFailed(options.Value.NomadAddress, refused));

        return NotRun(checks, $"the scan did not finish in {options.Value.ScanSeconds} s");
    }

    private async Task<ScanOutcome> ReadAsync(Site site, IReadOnlyCollection<Check> checks, string run, Allocation allocation, CancellationToken cancellationToken)
    {
        List<Finding> findings = [];
        List<CheckRun> runs = [];

        foreach (string task in SiteJob.TasksFor(checks))
        {
            var covered = Covered(task, checks);
            string file = SiteJob.ReportOf(site, run, task);
            string report = File.Exists(file) ? await File.ReadAllTextAsync(file, cancellationToken) : string.Empty;
            bool hasFailed = allocation.TaskStates?.GetValueOrDefault(task)?.Failed == true;
            var read = hasFailed || !File.Exists(file) ? null : Read(task, report);

            if (read is null)
            {
                string said = (await batch.LogsAsync(allocation.Id, task, LogType.Stderr, ReasonBytes, cancellationToken)).Trim();
                string reason = said.Length > 0 ? said : "it left no report";
                runs.AddRange(covered.Select(check => new CheckRun(check, false, Messages.CheckFailed(ToolAnswer.Word(check), reason))));
                continue;
            }

            findings.AddRange(read.Where(finding => checks.Contains(finding.Check)));
        }

        var failed = runs.Select(each => each.Check).ToHashSet();
        runs.AddRange(checks.Where(check => !failed.Contains(check)).Select(check => new CheckRun(check, true)));

        IReadOnlyList<CheckRun> ordered = [.. runs.OrderBy(each => each.Check)];
        IReadOnlyList<Finding> distinct = [.. findings.DistinctBy(finding => finding.Identity, StringComparer.Ordinal)];

        return new ScanOutcome(distinct, ordered);
    }

    private static IReadOnlyList<Finding>? Read(string task, string report) =>
        task == SiteJob.Nuclei ? SiteReports.Nuclei(report) : SiteReports.Nmap(report);

    private static ScanOutcome NotRun(IReadOnlyCollection<Check> checks, string reason) =>
        new([], [.. checks.Select(check => new CheckRun(check, false, Messages.CheckFailed(ToolAnswer.Word(check), reason)))]);
}
