using Snail.MCP.Security.Adapters;

namespace Snail.MCP.Security.Tests.Adapters;

public sealed class FileScanHistoryTests : IDisposable
{
    private readonly string _folder = Directory.CreateTempSubdirectory("security-history-").FullName;

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    [Fact]
    public async Task SaveThenLast_Report_ComesBackWhole()
    {
        var history = new FileScanHistory(_folder);
        var report = new ScanReport(
            DateTimeOffset.Parse("2026-10-15T01:00:00Z", System.Globalization.CultureInfo.InvariantCulture),
            [new Finding(Check.Packages, Severity.High, "GHSA-1", "t", "a.csproj", "P", "1.0", "1.1", "https://x")],
            [new CheckRun(Check.Packages, true), new CheckRun(Check.Code, false, "no rules")],
            new Comparison(1, 0, 2));

        await history.SaveAsync("task-1", report, CancellationToken.None);
        var back = await new FileScanHistory(_folder).LastAsync("task-1", CancellationToken.None);

        Assert.Equal(report.Findings, back!.Findings);
        Assert.Equal(report.Runs, back.Runs);
        Assert.Equal(report.Since, back.Since);
    }

    [Fact]
    public async Task Last_TaskNeverScanned_IsNull()
    {
        Assert.Null(await new FileScanHistory(_folder).LastAsync("none", CancellationToken.None));
    }
}
