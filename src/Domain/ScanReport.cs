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
    /// <remarks>
    /// Counted per problem, not per kind of problem: two secrets of one rule in one file share a key, and fixing one of
    /// them is one fixed and one remaining, not nothing at all.
    /// </remarks>
    public Comparison Against(ScanReport before)
    {
        var ran = Runs.Where(run => run.HasRun).Select(run => run.Check).Intersect(before.Runs.Where(run => run.HasRun).Select(run => run.Check)).ToHashSet();
        var now = CountsOf(Findings, ran);
        var then = CountsOf(before.Findings, ran);

        int fixedCount = then.Sum(pair => Math.Max(0, pair.Value - now.GetValueOrDefault(pair.Key)));
        int newCount = now.Sum(pair => Math.Max(0, pair.Value - then.GetValueOrDefault(pair.Key)));
        int remaining = now.Sum(pair => Math.Min(pair.Value, then.GetValueOrDefault(pair.Key)));

        return new Comparison(fixedCount, newCount, remaining);
    }

    private static Dictionary<string, int> CountsOf(IEnumerable<Finding> findings, HashSet<Check> ran) =>
        findings
            .Where(finding => ran.Contains(finding.Check))
            .GroupBy(finding => finding.Key, StringComparer.Ordinal)
            .ToDictionary(same => same.Key, same => same.Count(), StringComparer.Ordinal);
}

/// <summary>What the scanners left: every finding they made, and each check's run.</summary>
public sealed record ScanOutcome(IReadOnlyList<Finding> Findings, IReadOnlyList<CheckRun> Runs);

/// <summary>One page of a scan's findings, and how many there are in all.</summary>
public sealed record FindingPage(int Total, int Offset, IReadOnlyList<Finding> Findings, DateTimeOffset ScannedAt);
