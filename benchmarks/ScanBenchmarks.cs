using BenchmarkDotNet.Attributes;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Domain;

namespace Snail.MCP.Security.Benchmarks;

/// <summary>The work a scan does on the server itself, measured: reading a large Trivy report and merging it with NuGet's.</summary>
[MemoryDiagnoser]
public class ScanBenchmarks
{
    private static readonly string Report = Large();

    private static readonly IReadOnlyList<Finding> Findings = ScannerReports.Trivy(Report);

    /// <summary>A Trivy report of five hundred vulnerable packages.</summary>
    [Benchmark]
    public IReadOnlyList<Finding> ReadTrivy() => ScannerReports.Trivy(Report);

    /// <summary>The same findings twice, merged into one each.</summary>
    [Benchmark]
    public IReadOnlyList<Finding> Merge() => ScannerReports.Merged([.. Findings, .. Findings]);

    private static string Large()
    {
        var vulnerabilities = Enumerable.Range(0, 500).Select(index =>
            $$"""{"VulnerabilityID":"CVE-2024-{{index}}","VendorIDs":["GHSA-{{index}}"],"PkgName":"Package{{index}}","InstalledVersion":"1.0.{{index}}","FixedVersion":"1.1.0","Severity":"HIGH","Title":"Title {{index}}"}""");

        return $$"""{"Results":[{"Target":"packages.lock.json","Class":"lang-pkgs","Type":"nuget","Vulnerabilities":[{{string.Join(',', vulnerabilities)}}]}]}""";
    }
}
