using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Hosting.Sessions;

namespace Snail.MCP.Security.Application;

/// <summary>Scans of the session's working copy: run, compared with the task's scan before, kept, and read page by page.</summary>
public sealed class Scans(SessionCopy session, IScanner scanner, IScanHistory history, IOptions<SecurityOptions> options, TimeProvider clock)
{
    /// <summary>The checks a caller may name, as the tools spell them.</summary>
    public static readonly IReadOnlyDictionary<string, Check> Words = Checks.Copy.ToDictionary(check => ToolAnswer.Word(check), check => check, StringComparer.OrdinalIgnoreCase);

    /// <summary>The scan this session asks for: its copy, and the checks named, every one when none is.</summary>
    /// <remarks>Read while the request is still the session's: the scan itself runs as a job, after the call that started it may have ended.</remarks>
    public Answer<ScanRequest> Plan(IReadOnlyList<string>? checks)
    {
        var place = session.Current();
        if (!place.TryGet(out var copy))
            return place.As<ScanRequest>();

        var unknown = (checks ?? []).Where(word => !Words.ContainsKey(word)).ToList();
        if (unknown.Count > 0)
            return Answer.Failed(Messages.UnknownChecks(unknown, Words.Keys), type: ToolFailures.Arguments);

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
    /// <remarks>
    /// An offset below zero or a page outside 1 to <see cref="SecurityOptions.MaxPage"/> is refused as the SDK's
    /// <c>arguments</c>: it used to be clamped in silence, so a caller asking for 500 findings read 100 and took them for all.
    /// </remarks>
    public async Task<Answer<FindingPage>> FindingsAsync(string? severity, string? check, int offset, int? limit, CancellationToken cancellationToken)
    {
        var place = session.Current();
        if (!place.TryGet(out var copy))
            return place.As<FindingPage>();

        Severity? floor = null;
        if (severity is { Length: > 0 })
        {
            if (!Enum.TryParse<Severity>(severity, ignoreCase: true, out var parsed))
                return Answer.Failed(Messages.UnknownSeverity(severity), type: ToolFailures.Arguments);

            floor = parsed;
        }

        Check? only = null;
        if (check is { Length: > 0 })
        {
            if (!Words.TryGetValue(check, out var named))
                return Answer.Failed(Messages.UnknownChecks([check], Words.Keys), type: ToolFailures.Arguments);

            only = named;
        }

        if (offset < 0)
            return Answer.Failed(Messages.OffsetBelowZero(offset), type: ToolFailures.Arguments);

        int most = options.Value.MaxPage;
        if (limit is { } asked && (asked < 1 || asked > most))
            return Answer.Failed(Messages.LimitOutOfRange(asked, most), type: ToolFailures.Arguments);

        if (await history.LastAsync(copy.Task, cancellationToken) is not { } report)
            return Answer.Failed(Messages.NotScanned, Messages.NotScannedHint, FailureTypes.NotScanned);

        var matching = report.Ordered.Where(finding => (floor is null || finding.Severity <= floor) && (only is null || finding.Check == only)).ToList();
        int size = limit ?? options.Value.ShownFindings;

        return Answer.Ok(new FindingPage(matching.Count, offset, [.. matching.Skip(offset).Take(size)], report.At));
    }
}

/// <summary>A scan asked for: the copy and the checks to run on it.</summary>
public sealed record ScanRequest(WorkspacePlace<string> Copy, IReadOnlyCollection<Check> Checks);
