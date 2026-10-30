using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Application;

/// <summary>Scans of the session's working copy: run, compared with the task's scan before, kept, and read page by page.</summary>
public sealed class Scans(SessionCopy session, IScanner scanner, IScanHistory history, IOptions<SecurityOptions> options, TimeProvider clock)
{
    /// <summary>The checks a caller may name, as the tools spell them.</summary>
    public static readonly IReadOnlyDictionary<string, Check> Words = Checks.Copy.ToDictionary(Word, check => check, StringComparer.OrdinalIgnoreCase);

    /// <summary>The scan this session asks for: its copy, and the checks named, every one when none is.</summary>
    /// <remarks>Read while the request is still the session's: the scan itself runs as a job, after the call that started it may have ended.</remarks>
    public Answer<ScanRequest> Plan(IReadOnlyList<string>? checks)
    {
        var place = session.Current();
        if (place.Value is not { } copy)
            return Answer.Failed<ScanRequest>(place.Error!, place.Hint);

        var unknown = (checks ?? []).Where(word => !Words.ContainsKey(word)).ToList();
        if (unknown.Count > 0)
            return Answer.Failed<ScanRequest>(Messages.UnknownChecks(unknown, Words.Keys));

        IReadOnlyCollection<Check> wanted = checks is { Count: > 0 } ? [.. checks.Select(word => Words[word]).Distinct()] : Checks.Copy;

        return Answer.Ok(new ScanRequest(copy, wanted));
    }

    /// <summary>Scans the copy with the checks asked for, says how the result compares with the task's scan before, and keeps it.</summary>
    public async Task<ScanReport> RunAsync(ScanRequest request, CancellationToken cancellationToken)
    {
        var outcome = await scanner.ScanAsync(request.Copy, request.Checks, cancellationToken);
        var before = await history.LastAsync(request.Copy.Task, cancellationToken);
        var report = new ScanReport(clock.GetUtcNow(), outcome.Findings, outcome.Runs, null);
        var compared = before is null ? report : report with { Since = report.Against(before) };

        await history.SaveAsync(request.Copy.Task, compared, cancellationToken);

        return compared;
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

/// <summary>A scan asked for: the copy and the checks to run on it.</summary>
public sealed record ScanRequest(CopyPlace Copy, IReadOnlyCollection<Check> Checks);
