using Snail.MCP.Security.Adapters;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>The readers over what the scanners printed in real runs, kept as fixtures.</summary>
public sealed class ScannerReportsTests
{
    private static string Fixture(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Trivy_PackagesFromALockFile_AreNamedByTheirGhsaWithTheFixingVersion()
    {
        var findings = ScannerReports.Trivy(Fixture("trivy-packages.json"));

        var newtonsoft = Assert.Single(findings, finding => finding.Package == "Newtonsoft.Json");
        Assert.Equal((Check.Packages, Severity.High, "GHSA-5crp-9r3c-p9vr"), (newtonsoft.Check, newtonsoft.Severity, newtonsoft.Rule));
        Assert.Equal(("12.0.3", "13.0.1"), (newtonsoft.Version, newtonsoft.FixedIn));
        Assert.Equal("https://github.com/advisories/GHSA-5crp-9r3c-p9vr", newtonsoft.Link);
        Assert.Equal(3, findings.Count);
    }

    [Fact]
    public void Trivy_SecretsAndDockerfileSettings_AreFoundWithTheirLines()
    {
        var findings = ScannerReports.Trivy(Fixture("trivy-secrets-config.json"));

        Assert.Contains(findings, finding => finding is { Check: Check.Secrets, Rule: "aws-access-key-id", Severity: Severity.Critical, Location: "src/Shop.Api/appsettings.json:3" });
        Assert.Contains(findings, finding => finding is { Check: Check.Secrets, Rule: "github-pat", Location: "src/Shop.Api/appsettings.json:5" });
        Assert.Contains(findings, finding => finding is { Check: Check.Config, Rule: "DS-0002", Severity: Severity.High, Location: "infra/Dockerfile" });
    }

    [Fact]
    public void Semgrep_CsharpSqlInjection_IsHighWithItsWeaknessAndRelativeLine()
    {
        var finding = Assert.Single(ScannerReports.Semgrep(Fixture("semgrep-csharp.json")));

        Assert.Equal((Check.Code, Severity.High, "csharp-sqli"), (finding.Check, finding.Severity, finding.Rule));
        Assert.Equal("src/Shop.Api/Program.cs:6", finding.Location);
        Assert.StartsWith("CWE-89:", finding.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void Dotnet_DirectAndTransitivePackages_AreAllFound()
    {
        var findings = ScannerReports.Dotnet(Fixture("dotnet-vulnerable.json"));

        Assert.Equal(["Newtonsoft.Json", "System.Net.Http", "System.Text.RegularExpressions"], findings.Select(finding => finding.Package).Order(StringComparer.Ordinal));
        Assert.All(findings, finding => Assert.StartsWith("GHSA-", finding.Rule, StringComparison.Ordinal));
    }

    [Fact]
    public void Dotnet_SeveralProjects_AreReadOneAfterTheOther()
    {
        string one = Fixture("dotnet-vulnerable.json");

        var findings = ScannerReports.Dotnet($"{one}\n{ScannerReports.Separator}\n{one}\n{ScannerReports.Separator}\n");

        Assert.Equal(6, findings.Count);
    }

    /// <summary>The same advisory from Trivy's lock file and from NuGet is one finding, and Trivy's, which knows the fixing version, is kept.</summary>
    [Fact]
    public void Merged_SameAdvisoryFromTwoScanners_IsOneFindingWithTheFixingVersion()
    {
        var merged = ScannerReports.Merged([.. ScannerReports.Dotnet(Fixture("dotnet-vulnerable.json")), .. ScannerReports.Trivy(Fixture("trivy-packages.json"))]);

        Assert.Equal(3, merged.Count);
        Assert.All(merged, finding => Assert.NotNull(finding.FixedIn));
    }

    [Fact]
    public void Dotnet_ProjectPathInTheScannersCopy_IsRelativeToTheWorkingCopy()
    {
        string report = Fixture("dotnet-vulnerable.json").Replace("\"/src/T.csproj\"", "\"/tmp/src/src/Shop.Api/Shop.Api.csproj\"", StringComparison.Ordinal);

        Assert.All(ScannerReports.Dotnet(report), finding => Assert.Equal("src/Shop.Api/Shop.Api.csproj", finding.Location));
    }

    [Fact]
    public void Semgrep_DockerfileRule_IsASettingNotCode()
    {
        const string report = """{"results":[{"check_id":"dockerfile.security.last-user-is-root.last-user-is-root","path":"Dockerfile","start":{"line":4},"extra":{"severity":"ERROR","message":"root","metadata":{}}}]}""";

        Assert.Equal(Check.Config, Assert.Single(ScannerReports.Semgrep(report)).Check);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Unable to find image")]
    [InlineData("{ \"Results\": ")]
    public void Readers_OutputThatIsNotAReport_FindNothing(string output)
    {
        Assert.Empty(ScannerReports.Trivy(output));
        Assert.Empty(ScannerReports.Semgrep(output));
    }
}
