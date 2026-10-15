using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Application;

/// <summary>Scans of the session's working copy: run, compared with the task's scan before, kept, and read page by page.</summary>
public sealed class Scans(SessionCopy session, IScanner scanner, IScanHistory history, IOptions<SecurityOptions> options, TimeProvider clock)
{
    /// <summary>The checks a caller may name, as the tools spell them.</summary>
    public static readonly IReadOnlyDictionary<string, Check> Words = Enum.GetValues<Check>().ToDictionary(Word, check => check, StringComparer.OrdinalIgnoreCase);

    /// <summary>Scans the copy with the checks named, every one when none is, and says how the result compares with the task's scan before.</summary>
    public async Task<Answer<ScanReport>> ScanAsync(IReadOnlyList<string>? checks, CancellationToken cancellationToken)
    {
        var place = session.Current();
        if (place.Value is not { } copy)
            return Answer.Failed<ScanReport>(place.Error!, place.Hint);

        var unknown = (checks ?? []).Where(word => !Words.ContainsKey(word)).ToList();
        if (unknown.Count > 0)
            return Answer.Failed<ScanReport>(Messages.UnknownChecks(unknown, Words.Keys));

        IReadOnlyCollection<Check> wanted = checks is { Count: > 0 } ? [.. checks.Select(word => Words[word]).Distinct()] : Enum.GetValues<Check>();
        var outcome = await scanner.ScanAsync(copy, wanted, cancellationToken);
        var before = await history.LastAsync(copy.Task, cancellationToken);
        var report = new ScanReport(clock.GetUtcNow(), outcome.Findings, outcome.Runs, null);
        var compared = before is null ? report : report with { Since = report.Against(before) };

        await history.SaveAsync(copy.Task, compared, cancellationToken);

        return Answer.Ok(compared);
    }

    /// <summary>One page of the task's last scan, narrowed to a severity and up and to one check when the caller names them.</summary>
    public async Task<Answer<FindingPage>> FindingsAsync(string? severity, string? check, int offset, int? limit, CancellationToken cancellationToken)
    {
        var place = session.Current();
        if (place.Value is not { } copy)
            return Answer.Failed<FindingPage>(place.Error!, place.Hint);

        Severity? floor = null;
        if (severity is { Length: > 0 })
        {
            if (!Enum.TryParse<Severity>(severity, ignoreCase: true, out var parsed))
                return Answer.Failed<FindingPage>(Messages.UnknownSeverity(severity));

            floor = parsed;
        }

        Check? only = null;
        if (check is { Length: > 0 })
        {
            if (!Words.TryGetValue(check, out var named))
                return Answer.Failed<FindingPage>(Messages.UnknownChecks([check], Words.Keys));

            only = named;
        }

        if (await history.LastAsync(copy.Task, cancellationToken) is not { } report)
            return Answer.Failed<FindingPage>(Messages.NotScanned, Messages.NotScannedHint);

        var matching = report.Ordered.Where(finding => (floor is null || finding.Severity <= floor) && (only is null || finding.Check == only)).ToList();
        int size = Math.Clamp(limit ?? options.Value.ShownFindings, 1, options.Value.MaxPage);
        int start = Math.Max(0, offset);

        return Answer.Ok(new FindingPage(matching.Count, start, [.. matching.Skip(start).Take(size)], report.At));
    }

    /// <summary>A check as the tools spell it.</summary>
    public static string Word(Check check) => check.ToString().ToLowerInvariant();
}
