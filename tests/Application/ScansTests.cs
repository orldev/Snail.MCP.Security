using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Hosting.Sessions;
using Snail.Sdk.Mcp.Testing;

namespace Snail.MCP.Security.Tests.Application;

public sealed class ScansTests
{
    private const string Copy = "/workspaces/0c2b9e1f/step-2";

    private static Scans Of(FakeScanner scanner, IScanHistory history, string? root = Copy)
    {
        var address = root is null ? new FixedAddress() : new FixedAddress((SessionCopy.Parameter, root));
        var options = Options.Create(new SecurityOptions());

        return new Scans(new SessionCopy(address, options), scanner, history, options, TimeProvider.System);
    }

    private static async Task<Answer<ScanReport>> ScanAsync(Scans scans, IReadOnlyList<string>? checks)
    {
        var request = scans.Plan(checks);
        if (!request.TryGet(out var planned))
            return request.As<ScanReport>();

        return Answer.Ok(await scans.RunAsync(planned, CancellationToken.None));
    }

    private static readonly Finding Secret = new(Check.Secrets, Severity.Critical, "github-pat", "token", "appsettings.json:5");

    private static readonly Finding Package = new(Check.Packages, Severity.High, "GHSA-5crp-9r3c-p9vr", "Newtonsoft", "Shop.Api.csproj", "Newtonsoft.Json", "12.0.3", "13.0.1");

    [Fact]
    public async Task ScanAsync_NoChecksNamed_RunsEveryCheckOfTheCopy()
    {
        var scanner = new FakeScanner();

        await ScanAsync(Of(scanner, new MemoryHistory()), null);

        Assert.Equal(Checks.Copy, Assert.Single(scanner.Asked).Order());
    }

    [Fact]
    public async Task ScanAsync_AfterAFix_SaysWhatGotFixedAgainstTheScanBefore()
    {
        var scanner = new FakeScanner { Next = new([Secret, Package], []) };
        var history = new MemoryHistory();
        await ScanAsync(Of(scanner, history), null);
        scanner.Next = new([Secret], []);

        var answer = await ScanAsync(Of(scanner, history), null);

        Assert.Equal(new Comparison(1, 0, 1), answer.Value!.Since);
        Assert.False(answer.Value.IsClean);
    }

    [Fact]
    public async Task ScanAsync_CheckThatDoesNotExist_IsRefusedByNameAndNothingRuns()
    {
        var scanner = new FakeScanner();

        var answer = await ScanAsync(Of(scanner, new MemoryHistory()), ["packages", "licences"]);

        Assert.Equal(Messages.UnknownChecks(["licences"], Scans.Words.Keys), answer.Error);
        Assert.Equal(ToolFailures.Arguments, answer.Type);
        Assert.Empty(scanner.Asked);
    }

    [Fact]
    public async Task ScanAsync_SessionWithoutACopy_SaysWhereTheCopyComesFrom()
    {
        var answer = await ScanAsync(Of(new FakeScanner(), new MemoryHistory(), root: null), null);

        Assert.Equal(Messages.NoCopyHint, answer.Hint);
    }

    [Fact]
    public async Task FindingsAsync_SeverityFloorAndCheck_NarrowTheWorstFirstList()
    {
        var scanner = new FakeScanner { Next = new([Package, Secret, new Finding(Check.Code, Severity.Low, "r", "t", "a.cs:1")], []) };
        var history = new MemoryHistory();
        await ScanAsync(Of(scanner, history), null);

        var high = await Of(scanner, history).FindingsAsync("high", null, 0, null, CancellationToken.None);
        var code = await Of(scanner, history).FindingsAsync(null, "code", 0, null, CancellationToken.None);

        Assert.Equal([Severity.Critical, Severity.High], high.Value!.Findings.Select(finding => finding.Severity));
        Assert.Equal(1, code.Value!.Total);
    }

    [Fact]
    public async Task FindingsAsync_BeforeAnyScan_SaysToScanFirst()
    {
        var answer = await Of(new FakeScanner(), new MemoryHistory()).FindingsAsync(null, null, 0, null, CancellationToken.None);

        Assert.Equal(Messages.NotScanned, answer.Error);
        Assert.Equal("notScanned", answer.Type);
    }

    /// <summary>A severity or a check the server does not know is the SDK's <c>arguments</c>, told apart from a task with no scan yet.</summary>
    [Theory]
    [InlineData("urgent", null)]
    [InlineData(null, "licences")]
    public async Task FindingsAsync_UnknownSeverityOrCheck_IsTypedArguments(string? severity, string? check)
    {
        var answer = await Of(new FakeScanner(), new MemoryHistory()).FindingsAsync(severity, check, 0, null, CancellationToken.None);

        Assert.Equal(ToolFailures.Arguments, answer.Type);
    }

    /// <summary>A page before the first finding, of none, or past a page used to be clamped in silence; it is refused as the caller's mistake.</summary>
    [Theory]
    [InlineData(-1, null)]
    [InlineData(0, 0)]
    [InlineData(0, 101)]
    public async Task FindingsAsync_OffsetBelowZeroOrLimitOutsideAPage_IsTypedArguments(int offset, int? limit)
    {
        var scanner = new FakeScanner { Next = new([Package, Secret], []) };
        var history = new MemoryHistory();
        await ScanAsync(Of(scanner, history), null);

        var answer = await Of(scanner, history).FindingsAsync(null, null, offset, limit, CancellationToken.None);

        Assert.Equal(ToolFailures.Arguments, answer.Type);
    }

    [Fact]
    public async Task FindingsAsync_LimitOfAWholePage_IsThatPage()
    {
        var scanner = new FakeScanner { Next = new([Package, Secret], []) };
        var history = new MemoryHistory();
        await ScanAsync(Of(scanner, history), null);

        var answer = await Of(scanner, history).FindingsAsync(null, null, 1, 100, CancellationToken.None);

        Assert.Equal((2, 1, 1), (answer.Value!.Total, answer.Value.Offset, answer.Value.Findings.Count));
    }

    /// <summary>One sentence for every root that is no task's copy, typed by the reason so a program can tell them apart.</summary>
    [Theory]
    [InlineData("/etc", Reached.Outside)]
    [InlineData("/workspaces/../etc", "malformed")]
    [InlineData("/workspaces/Task_1/step-1", "notATask")]
    [InlineData("/workspaces", Reached.Outside)]
    public void SessionCopy_RootOutsideTheWorkspaces_IsRefused(string root, string type)
    {
        var answer = SessionCopy.Of(root, "/workspaces");

        Assert.Equal(Messages.CopyOutside(root, "/workspaces"), answer.Error);
        Assert.Equal(type, answer.Type);
    }

    /// <summary>No copy and a copy outside the root are different facts, and the caller is told which.</summary>
    [Theory]
    [InlineData(null)]
    [InlineData(" ")]
    public void SessionCopy_NoRoot_SaysWhereTheCopyComesFrom(string? root)
    {
        var answer = SessionCopy.Of(root, "/workspaces");

        Assert.Equal(Messages.NoCopy, answer.Error);
        Assert.Equal(Messages.NoCopyHint, answer.Hint);
        Assert.Equal(Reached.NoRoot, answer.Type);
    }

    [Fact]
    public void SessionCopy_RootUnderATask_IsTheCopyOfThatTask()
    {
        var answer = SessionCopy.Of("/workspaces/0c2b9e1f/step-2/", "/workspaces/");

        Assert.Equal(new WorkspacePlace<string>("0c2b9e1f", "/workspaces/0c2b9e1f/step-2"), answer.Value);
    }
}
