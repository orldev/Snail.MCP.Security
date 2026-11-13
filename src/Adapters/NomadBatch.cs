using System.Net;
using System.Text.Json.Nodes;
using Snail.Toolkit.Nomad;
using Snail.Toolkit.Nomad.Models;

namespace Snail.MCP.Security.Adapters;

/// <summary>How a scan's batch job ended: its allocation once it ended, or Nomad's words when Nomad would not run it; neither when the time ran out.</summary>
public sealed record BatchRun(Allocation? Ended, string? Refused)
{
    /// <summary>Whether the job outlasted the time it was given, and was stopped.</summary>
    public bool HasTimedOut => Ended is null && Refused is null;
}

/// <summary>A scan's batch job run to its end: registered over the last run of the same name, waited for, and stopped whenever the scan gives up on it.</summary>
/// <remarks>
/// The copy scans and the site scans run their jobs alike, so the one way of doing it lives here. A client that went away
/// cancels the wait and the job is stopped before it ends, rather than left reading a copy or a site for the rest of the
/// scan time; Nomad refusing the job is its words, never an exception a client sees as a bare "an error occurred".
/// </remarks>
public sealed class NomadBatch(INomadClient nomad, TimeProvider clock)
{
    /// <summary>How often a running job is looked at.</summary>
    private static readonly TimeSpan Poll = TimeSpan.FromSeconds(2);

    private static readonly string[] Ended = ["complete", "failed", "lost"];

    /// <summary>Registers the job and waits for its end, at most <paramref name="timeout"/>; a job the wait gives up on is stopped.</summary>
    public async Task<BatchRun> RunAsync(string job, JsonObject spec, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            await nomad.StopJobAsync(job, purge: true, cancellationToken);
            await nomad.RegisterJobAsync(spec, cancellationToken);

            var allocation = await EndedAsync(job, timeout, cancellationToken);
            if (allocation is not null)
                return new BatchRun(allocation, null);

            await StopAsync(job);

            return new BatchRun(null, null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await StopAsync(job);
            throw;
        }
        catch (Exception exception) when (exception is HttpRequestException or NomadException or TaskCanceledException)
        {
            await StopAsync(job);

            return new BatchRun(null, exception.Message);
        }
    }

    /// <summary>The end of what a task printed, empty when Nomad no longer has it.</summary>
    public async Task<string> LogsAsync(string allocation, string task, LogType type, int bytes, CancellationToken cancellationToken)
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

    /// <summary>Stops a job the scan no longer waits for, with a token of its own: the caller's may be the one that was cancelled.</summary>
    private async Task StopAsync(string job)
    {
        try
        {
            await nomad.StopJobAsync(job, purge: false, CancellationToken.None);
        }
        catch (Exception exception) when (exception is HttpRequestException or NomadException or TaskCanceledException)
        {
            return;
        }
    }

    private async Task<Allocation?> EndedAsync(string job, TimeSpan timeout, CancellationToken cancellationToken)
    {
        long started = clock.GetTimestamp();

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
}
