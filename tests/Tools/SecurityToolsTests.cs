using Microsoft.Extensions.Options;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;
using Snail.MCP.Security.Tests.Application;
using Snail.MCP.Security.Tools;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Hosting.Jobs;
using Snail.Sdk.Mcp.Testing;

namespace Snail.MCP.Security.Tests.Tools;

/// <summary>security_scan as a job: the scan within the wait, the running job past it, and a refusal before any job.</summary>
public sealed class SecurityToolsTests
{
    private static SecurityTools Of(FakeScanner scanner, Jobs? jobs = null, string? root = "/workspaces/0c2b9e1f/step-2")
    {
        var address = root is null ? new FixedAddress() : new FixedAddress((SessionCopy.Parameter, root));
        var options = Options.Create(new SecurityOptions());
        var scans = new Scans(new SessionCopy(address, options), scanner, new MemoryHistory(), options, TimeProvider.System);

        var compliance = CatalogFiles.Read(null);

        return new SecurityTools(scans, new ScanJobs(jobs ?? new Jobs(SecuritySettings.Name), scans, options, compliance), compliance);
    }

    [Fact]
    public async Task ScanAsync_ScanEndsWithinTheWait_AnswersWithTheScanAsTheJobsResult()
    {
        var answer = await Of(new FakeScanner()).ScanAsync(wait: 30);

        var report = answer.Report()!;
        Assert.True(answer.IsOk(), answer.Text());
        Assert.Equal(JobState.Succeeded, report.State);
        Assert.True(report.Result!.Value.GetProperty("clean").GetBoolean());
    }

    /// <summary>A scan that outlasts the wait is not lost: the answer names its job, and the job ends with the scan.</summary>
    [Fact]
    public async Task ScanAsync_ScanOutlastsTheWait_AnswersWithTheRunningJobThatEndsWithTheScan()
    {
        var held = new TaskCompletionSource();
        var jobs = new Jobs(SecuritySettings.Name);
        var tools = Of(new FakeScanner { Held = held.Task }, jobs);

        var answer = await tools.ScanAsync(wait: 0);

        var running = answer.Report()!;
        Assert.True(answer.IsOk());
        Assert.Equal(JobState.Running, running.State);
        Assert.StartsWith("job://security/scan/", running.Uri, StringComparison.Ordinal);

        held.SetResult();
        var ended = await jobs.Find(running.Uri)!.Completion;

        Assert.Equal(JobState.Succeeded, ended.State);
        Assert.True(ended.Result!.Value.GetProperty("clean").GetBoolean());
    }

    /// <summary>A scan belongs to the task of its copy: a client of another task finds no job at its URI.</summary>
    [Fact]
    public async Task ScanAsync_JobOfTheScan_BelongsToTheTaskOfTheCopy()
    {
        var jobs = new Jobs(SecuritySettings.Name);

        var running = (await Of(new FakeScanner(), jobs).ScanAsync(wait: 0)).Report()!;

        Assert.Equal("0c2b9e1f", jobs.Find(running.Uri)!.Owner);
        Assert.NotNull(jobs.Find(running.Uri, "0c2b9e1f"));
        Assert.Null(jobs.Find(running.Uri, "7d4a0b33"));
        Assert.Null(jobs.Find(running.Uri, null));
    }

    /// <summary>A client that waits by asking again joins the scan it started, rather than queueing another behind it.</summary>
    [Fact]
    public async Task ScanAsync_SameScanAskedWhileItRuns_IsJoinedNotStartedAgain()
    {
        var held = new TaskCompletionSource();
        var scanner = new FakeScanner { Held = held.Task };
        var tools = Of(scanner);

        var first = (await tools.ScanAsync(wait: 0)).Report()!;
        var second = (await tools.ScanAsync(wait: 0)).Report()!;
        held.SetResult();

        Assert.Equal(first.Uri, second.Uri);
        Assert.Single(scanner.Asked);
    }

    /// <summary>A wait below zero used to start the scan and answer as if it were 0; it is the caller's mistake, refused before any scan.</summary>
    [Fact]
    public async Task ScanAsync_WaitBelowZero_IsRefusedAsArgumentsBeforeAnyJob()
    {
        var scanner = new FakeScanner();

        var answer = await Of(scanner).ScanAsync(wait: -1);

        Assert.True(answer.IsError);
        Assert.Equal(ToolFailures.Arguments, answer.Type());
        Assert.Empty(scanner.Asked);
    }

    [Fact]
    public async Task ScanAsync_SessionWithoutACopy_IsRefusedBeforeAnyJob()
    {
        var scanner = new FakeScanner();

        var answer = await Of(scanner, root: null).ScanAsync();

        Assert.True(answer.IsError);
        Assert.Equal(Messages.NoCopy, answer.Error());
        Assert.Empty(scanner.Asked);
    }
}
