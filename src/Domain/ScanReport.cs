namespace Snail.MCP.Security.Domain;

/// <summary>One check as it ran: whether it ran at all, and why not.</summary>
public sealed record CheckRun(Check Check, bool HasRun, string? Note = null);

/// <summary>How a scan differs from the one before it: the problems it no longer finds, the ones it finds first, the ones it still finds.</summary>
public sealed record Comparison(int Fixed, int New, int Remaining);

/// <summary>A scan of a working copy: every finding, each check's run, and how it compares with the scan before.</summary>
public sealed record ScanReport(DateTimeOffset At, IReadOnlyList<Finding> Findings, IReadOnlyList<CheckRun> Runs, Comparison? Since)
{
    /// <summary>Whether nothing blocks the work: no critical or high finding, and every check that was asked for ran.</summary>
    public bool IsClean => Runs.All(run => run.HasRun) && !Findings.Any(finding => finding.IsBlocking);

    /// <summary>The findings by severity, worst first, then by where they are.</summary>
    public IReadOnlyList<Finding> Ordered =>
        [.. Findings.OrderBy(finding => finding.Severity).ThenBy(finding => finding.Check).ThenBy(finding => finding.Location, StringComparer.Ordinal)];

    /// <summary>How this scan compares with <paramref name="before"/>, over the checks both of them ran: a check left out now fixed nothing.</summary>
    public Comparison Against(ScanReport before)
    {
        var ran = Runs.Where(run => run.HasRun).Select(run => run.Check).Intersect(before.Runs.Where(run => run.HasRun).Select(run => run.Check)).ToHashSet();
        var now = Findings.Where(finding => ran.Contains(finding.Check)).Select(finding => finding.Key).ToHashSet(StringComparer.Ordinal);
        var then = before.Findings.Where(finding => ran.Contains(finding.Check)).Select(finding => finding.Key).ToHashSet(StringComparer.Ordinal);

        return new Comparison(then.Count(key => !now.Contains(key)), now.Count(key => !then.Contains(key)), now.Count(then.Contains));
    }
}

/// <summary>What the scanners left: every finding they made, and each check's run.</summary>
public sealed record ScanOutcome(IReadOnlyList<Finding> Findings, IReadOnlyList<CheckRun> Runs);

/// <summary>One page of a scan's findings, and how many there are in all.</summary>
public sealed record FindingPage(int Total, int Offset, IReadOnlyList<Finding> Findings, DateTimeOffset ScannedAt);
