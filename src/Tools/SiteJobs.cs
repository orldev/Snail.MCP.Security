using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting.Jobs;

namespace Snail.MCP.Security.Tools;

/// <summary>The site scans running as jobs, one per owner, site and set of checks: asked for again, a scan is joined, not started twice.</summary>
/// <remarks>
/// A client that waits by asking again — the platform's worker sees tools, not resources — gets the scan already running,
/// and, for a while after it ended, the scan that ended: a site scan is the one thing this server sends to the internet,
/// and asking again a minute late must not send it again. A scan belongs to the task of the session's copy when it has
/// one, and to the site otherwise: no other task's client reads it by its address, nor is answered with it when it asks
/// for the same site.
/// </remarks>
public sealed class SiteJobs(Jobs jobs, Sites sites, IOptions<SecurityOptions> options, TimeProvider clock)
{
    /// <summary>The kind of job a site scan is, the second part of its resource's address.</summary>
    public const string Kind = "site";

    /// <summary>How long an ended scan answers a repeated ask instead of a new scan.</summary>
    public static readonly TimeSpan Kept = TimeSpan.FromMinutes(10);

    private readonly ConcurrentDictionary<string, Job> _known = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <summary>The job of the scan asked for: the one running or just ended for the same site and checks, or a new one.</summary>
    public Job Start(SitePlan plan, string? task)
    {
        string owner = task ?? $"site:{plan.Proof.Site.Host}";
        string key = $"{owner}|{plan.Proof.Site.Host}|{string.Join(',', plan.Checks.Order())}";

        lock (_gate)
        {
            if (_known.TryGetValue(key, out var known) && IsFresh(known))
                return known;

            int shown = options.Value.ShownFindings;
            var job = jobs.Start(Kind, owner, async (_, token) => AnswerFields.Of(await sites.RunAsync(plan, token), shown), ToolAnswer.ObjectInfo);

            _known[key] = job;

            return job;
        }
    }

    /// <summary>Whether a job still answers a repeated ask: running, or succeeded no longer ago than <see cref="Kept"/>; a scan that failed is asked for again.</summary>
    private bool IsFresh(Job job)
    {
        var report = job.Report;
        if (report.IsRunning)
            return true;

        return report.State == JobState.Succeeded && report.EndedAt is { } ended && clock.GetUtcNow() - ended < Kept;
    }
}
