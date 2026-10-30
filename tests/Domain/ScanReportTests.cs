namespace Snail.MCP.Security.Tests.Domain;

public sealed class ScanReportTests
{
    private static readonly DateTimeOffset At = DateTimeOffset.UnixEpoch;

    private static CheckRun[] All => [.. Enum.GetValues<Check>().Select(check => new CheckRun(check, true))];

    [Fact]
    public void IsClean_OnlyMediumFindings_IsClean()
    {
        var report = new ScanReport(At, [new Finding(Check.Code, Severity.Medium, "r", "t", "a.cs:1")], All, null);

        Assert.True(report.IsClean);
    }

    [Fact]
    public void IsClean_HighFindingOrACheckThatDidNotRun_IsNotClean()
    {
        Assert.False(new ScanReport(At, [new Finding(Check.Packages, Severity.High, "GHSA-1", "t", "a.csproj", "P", "1.0")], All, null).IsClean);
        Assert.False(new ScanReport(At, [], [new CheckRun(Check.Code, false, "no rules")], null).IsClean);
    }

    /// <summary>A line that moved because code above it changed is the same problem, not one fixed and one new.</summary>
    [Fact]
    public void Against_SameProblemOnAnotherLineAndOneFixed_CountsRemainingAndFixed()
    {
        var before = new ScanReport(At, [new Finding(Check.Code, Severity.High, "sqli", "t", "a.cs:6"), new Finding(Check.Secrets, Severity.Critical, "github-pat", "t", "s.json:5")], All, null);
        var now = new ScanReport(At, [new Finding(Check.Code, Severity.High, "sqli", "t", "a.cs:9"), new Finding(Check.Config, Severity.Low, "DS-0026", "t", "Dockerfile")], All, null);

        Assert.Equal(new Comparison(1, 1, 1), now.Against(before));
    }

    [Fact]
    public void Against_CheckLeftOutNow_FixedNothing()
    {
        var before = new ScanReport(At, [new Finding(Check.Code, Severity.High, "sqli", "t", "a.cs:6")], All, null);
        var now = new ScanReport(At, [], [new CheckRun(Check.Packages, true)], null);

        Assert.Equal(new Comparison(0, 0, 0), now.Against(before));
    }

    /// <summary>Two secrets of one rule in one file share a key: taking one out is one fixed and one remaining.</summary>
    [Fact]
    public void Against_TwoProblemsOfOneKeyAndOneFixed_CountsOneFixedOneRemaining()
    {
        var before = new ScanReport(At, [new Finding(Check.Secrets, Severity.Critical, "aws-access-key-id", "t", "s.json:3"), new Finding(Check.Secrets, Severity.Critical, "aws-access-key-id", "t", "s.json:40")], All, null);
        var now = new ScanReport(At, [new Finding(Check.Secrets, Severity.Critical, "aws-access-key-id", "t", "s.json:3")], All, null);

        Assert.Equal(new Comparison(1, 0, 1), now.Against(before));
    }

    [Fact]
    public void Ordered_Findings_AreWorstFirst()
    {
        var report = new ScanReport(At, [new Finding(Check.Code, Severity.Low, "a", "t", "x"), new Finding(Check.Secrets, Severity.Critical, "b", "t", "y")], All, null);

        Assert.Equal([Severity.Critical, Severity.Low], report.Ordered.Select(finding => finding.Severity));
    }
}
