using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting.Jobs;

namespace Snail.MCP.Security.Tools;

/// <summary>The scans running as jobs, one per copy and set of checks: asked for again while it runs, a scan is joined, not started twice.</summary>
/// <remarks>
/// A client that cannot read a job's resource — the platform's worker sees tools, not resources — waits by asking for
/// the same scan again within its own HTTP timeout. Each ask used to start another scan behind the first; now it is
/// answered by the scan already running, and a new one starts only once that one ended.
/// </remarks>
public sealed class ScanJobs(Jobs jobs, Scans scans, IOptions<SecurityOptions> options)
{
    /// <summary>The kind of job a scan is, the second part of its resource's address.</summary>
    public const string Kind = "scan";

    private readonly ConcurrentDictionary<string, Job> _running = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <summary>The job of the scan asked for: the one running for the same copy and checks, or a new one.</summary>
    public Job Start(ScanRequest request)
    {
        string key = KeyOf(request);

        lock (_gate)
        {
            if (_running.TryGetValue(key, out var running) && running.Report.IsRunning)
                return running;

            int shown = options.Value.ShownFindings;
            var job = jobs.Start(Kind, async (_, token) => ToolResponse.Scan(await scans.RunAsync(request, token), shown), AnswerJson.Default.JsonObject);

            _running[key] = job;
            _ = ForgetAsync(key, job);

            return job;
        }
    }

    private async Task ForgetAsync(string key, Job job)
    {
        await job.Completion;

        _running.TryRemove(KeyValuePair.Create(key, job));
    }

    private static string KeyOf(ScanRequest request) => $"{request.Copy.Path}|{string.Join(',', request.Checks.Order())}";
}
