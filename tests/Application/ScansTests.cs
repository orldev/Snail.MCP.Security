using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Tests.Application;

public sealed class ScansTests
{
    private const string Copy = "/workspaces/0c2b9e1f/step-2";

    private sealed class FakeScanner : IScanner
    {
        public List<IReadOnlyCollection<Check>> Asked { get; } = [];

        public ScanOutcome Next { get; set; } = new([], []);

        public Task<ScanOutcome> ScanAsync(CopyPlace copy, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
        {
            Asked.Add(checks);

            return Task.FromResult(Next with { Runs = [.. checks.Select(check => new CheckRun(check, true))] });
        }

        public Task<Answer<string>> ReachAsync(CancellationToken cancellationToken) => Task.FromResult(Answer.Ok("1.10"));
    }

    private sealed class MemoryHistory : IScanHistory
    {
        private readonly Dictionary<string, ScanReport> _kept = [];

        public Task<ScanReport?> LastAsync(string task, CancellationToken cancellationToken) => Task.FromResult(_kept.GetValueOrDefault(task));

        public Task SaveAsync(string task, ScanReport report, CancellationToken cancellationToken)
        {
            _kept[task] = report;

            return Task.CompletedTask;
        }
    }

    private static Scans Of(FakeScanner scanner, IScanHistory history, string? root = Copy)
    {
        var context = new DefaultHttpContext();
        if (root is not null)
            context.Request.QueryString = QueryString.Create(SessionCopy.Parameter, root);

        var options = Options.Create(new SecurityOptions());

        return new Scans(new SessionCopy(new HttpContextAccessor { HttpContext = context }, options), scanner, history, options, TimeProvider.System);
    }

    private static readonly Finding Secret = new(Check.Secrets, Severity.Critical, "github-pat", "token", "appsettings.json:5");

    private static readonly Finding Package = new(Check.Packages, Severity.High, "GHSA-5crp-9r3c-p9vr", "Newtonsoft", "Shop.Api.csproj", "Newtonsoft.Json", "12.0.3", "13.0.1");

    [Fact]
    public async Task ScanAsync_NoChecksNamed_RunsEveryCheck()
    {
        var scanner = new FakeScanner();

        await Of(scanner, new MemoryHistory()).ScanAsync(null, CancellationToken.None);

        Assert.Equal(Enum.GetValues<Check>(), Assert.Single(scanner.Asked).Order());
    }

    [Fact]
    public async Task ScanAsync_AfterAFix_SaysWhatGotFixedAgainstTheScanBefore()
    {
        var scanner = new FakeScanner { Next = new([Secret, Package], []) };
        var history = new MemoryHistory();
        await Of(scanner, history).ScanAsync(null, CancellationToken.None);
        scanner.Next = new([Secret], []);

        var answer = await Of(scanner, history).ScanAsync(null, CancellationToken.None);

        Assert.Equal(new Comparison(1, 0, 1), answer.Value!.Since);
        Assert.False(answer.Value.IsClean);
    }

    [Fact]
    public async Task ScanAsync_CheckThatDoesNotExist_IsRefusedByNameAndNothingRuns()
    {
        var scanner = new FakeScanner();

        var answer = await Of(scanner, new MemoryHistory()).ScanAsync(["packages", "licences"], CancellationToken.None);

        Assert.Equal(Messages.UnknownChecks(["licences"], Scans.Words.Keys), answer.Error);
        Assert.Empty(scanner.Asked);
    }

    [Fact]
    public async Task ScanAsync_SessionWithoutACopy_SaysWhereTheCopyComesFrom()
    {
        var answer = await Of(new FakeScanner(), new MemoryHistory(), root: null).ScanAsync(null, CancellationToken.None);

        Assert.Equal(Messages.NoCopyHint, answer.Hint);
    }

    [Fact]
    public async Task FindingsAsync_SeverityFloorAndCheck_NarrowTheWorstFirstList()
    {
        var scanner = new FakeScanner { Next = new([Package, Secret, new Finding(Check.Code, Severity.Low, "r", "t", "a.cs:1")], []) };
        var history = new MemoryHistory();
        await Of(scanner, history).ScanAsync(null, CancellationToken.None);

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
    }

    [Theory]
    [InlineData("/etc")]
    [InlineData("/workspaces/../etc")]
    [InlineData("/workspaces/Task_1/step-1")]
    public void SessionCopy_RootOutsideTheWorkspaces_IsRefused(string root)
    {
        Assert.NotNull(SessionCopy.Of(root, "/workspaces").Error);
    }
}
