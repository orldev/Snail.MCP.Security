using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;
using Snail.MCP.Security.Tests.Application;
using Snail.MCP.Security.Tools;
using Snail.Sdk.Mcp.Hosting.Jobs;

namespace Snail.MCP.Security.Tests.Tools;

/// <summary>security_scan as a job: the scan within the wait, the running job past it, and a refusal before any job.</summary>
public sealed class SecurityToolsTests
{
    private static SecurityTools Of(FakeScanner scanner, Jobs? jobs = null, string? root = "/workspaces/0c2b9e1f/step-2")
    {
        var context = new DefaultHttpContext();
        if (root is not null)
            context.Request.QueryString = QueryString.Create(SessionCopy.Parameter, root);

        var options = Options.Create(new SecurityOptions());
        var scans = new Scans(new SessionCopy(new HttpContextAccessor { HttpContext = context }, options), scanner, new MemoryHistory(), options, TimeProvider.System);

        return new SecurityTools(scans, new ScanJobs(jobs ?? new Jobs(SecuritySettings.Name), scans, options));
    }

    private static JobReport ReportOf(CallToolResult answer) => JobReport.FromJson(answer.StructuredContent!.Value.GetRawText())!;

    [Fact]
    public async Task ScanAsync_ScanEndsWithinTheWait_AnswersWithTheScanAsTheJobsResult()
    {
        var answer = await Of(new FakeScanner()).ScanAsync(wait: 30);

        var report = ReportOf(answer);
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

        var running = ReportOf(answer);
        Assert.NotEqual(true, answer.IsError);
        Assert.Equal(JobState.Running, running.State);
        Assert.StartsWith("job://security/scan/", running.Uri, StringComparison.Ordinal);

        held.SetResult();
        var ended = await jobs.Find(running.Uri)!.Completion;

        Assert.Equal(JobState.Succeeded, ended.State);
        Assert.True(ended.Result!.Value.GetProperty("clean").GetBoolean());
    }

    /// <summary>A client that waits by asking again joins the scan it started, rather than queueing another behind it.</summary>
    [Fact]
    public async Task ScanAsync_SameScanAskedWhileItRuns_IsJoinedNotStartedAgain()
    {
        var held = new TaskCompletionSource();
        var scanner = new FakeScanner { Held = held.Task };
        var tools = Of(scanner);

        var first = ReportOf(await tools.ScanAsync(wait: 0));
        var second = ReportOf(await tools.ScanAsync(wait: 0));
        held.SetResult();

        Assert.Equal(first.Uri, second.Uri);
        Assert.Single(scanner.Asked);
    }

    [Fact]
    public async Task ScanAsync_SessionWithoutACopy_IsRefusedBeforeAnyJob()
    {
        var scanner = new FakeScanner();

        var answer = await Of(scanner, root: null).ScanAsync();

        Assert.True(answer.IsError);
        Assert.Empty(scanner.Asked);
    }
}
