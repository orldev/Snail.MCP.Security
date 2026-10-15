using System.Text.Json.Nodes;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Tests.Adapters;

public sealed class ScannerJobTests
{
    private static readonly CopyPlace Copy = new("0c2b9e1f", "/workspaces/0c2b9e1f/step-2");

    private static readonly SecurityOptions Options = new() { Proxy = "http://mcp-security:3128" };

    private static IEnumerable<JsonObject> Tasks(JsonObject job) => job["TaskGroups"]![0]!["Tasks"]!.AsArray().Select(task => task!.AsObject());

    [Fact]
    public void Of_EveryCheck_RunsTheThreeScannersReadOnlyOnTheScannersNetwork()
    {
        var job = ScannerJob.Of(Copy, Enum.GetValues<Check>(), "r1", Options);

        Assert.Equal(("sec-0c2b9e1f", "batch", "r1"), ((string?)job["ID"], (string?)job["Type"], (string?)job["Meta"]!["s3l.security.run"]));
        Assert.Equal(["trivy", "semgrep", "dotnet"], Tasks(job).Select(task => (string?)task["Name"]));
        Assert.All(Tasks(job), task => Assert.Equal("s3l-security", (string?)task["Config"]!["network_mode"]));
        Assert.All(Tasks(job), task => Assert.True((bool?)task["VolumeMounts"]![0]!["ReadOnly"]));
        Assert.All(Tasks(job), task => Assert.Equal("http://mcp-security:3128", (string?)task["Env"]!["HTTPS_PROXY"]));
    }

    [Fact]
    public void Of_SecretsAlone_RunsTrivyWithTheSecretScannerOnly()
    {
        var job = ScannerJob.Of(Copy, [Check.Secrets], "r1", Options);

        var trivy = Assert.Single(Tasks(job));
        string script = (string?)trivy["Config"]!["args"]![1] ?? string.Empty;
        Assert.Contains("--scanners secret ", script, StringComparison.Ordinal);
        Assert.Contains("--output \"$S3L_REPORTS/trivy.json\" \"$S3L_COPY\"", script, StringComparison.Ordinal);
        Assert.Equal(ScannerJob.ReportsOf(Copy, "r1"), (string?)trivy["Env"]!["S3L_REPORTS"]);
    }

    /// <summary>A scanner reads all of a task's code: its image is pinned by digest, never by a tag that can be moved.</summary>
    [Fact]
    public void Defaults_ScannerImages_ArePinnedByDigest()
    {
        var defaults = new SecurityOptions();

        Assert.Contains("@sha256:", defaults.TrivyImage, StringComparison.Ordinal);
        Assert.Contains("@sha256:", defaults.SemgrepImage, StringComparison.Ordinal);
    }

    /// <summary>Nomad interpolates every <c>${…}</c> of a config string: the scripts never use the form.</summary>
    [Fact]
    public void Scripts_ShellExpansions_StayOutOfNomadsWay()
    {
        var job = ScannerJob.Of(Copy, Enum.GetValues<Check>(), "r1", Options);

        var strings = Tasks(job).SelectMany(task => task["Config"]!["args"]!.AsArray()).Select(argument => (string?)argument ?? string.Empty);

        Assert.All(strings, text => Assert.DoesNotMatch(@"(?<!\$)\$\{", text));
    }

    /// <summary>A run's reports go to a folder of its own: a scanner that failed before writing leaves nothing to mistake for its report.</summary>
    [Fact]
    public void ReportOf_TwoRuns_AreDifferentFilesUnderTheTasksFolder()
    {
        Assert.NotEqual(ScannerJob.ReportOf(Copy, "r1", "trivy"), ScannerJob.ReportOf(Copy, "r2", "trivy"));
        Assert.StartsWith($"{ScannerJob.RunsOf(Copy)}/", ScannerJob.ReportOf(Copy, "r1", "trivy"), StringComparison.Ordinal);
    }

    [Fact]
    public void Of_Code_RunsSemgrepWithoutMetricsOverEveryRuleSet()
    {
        var job = ScannerJob.Of(Copy, [Check.Code], "r1", Options);

        string script = (string?)Assert.Single(Tasks(job))["Config"]!["args"]![1] ?? string.Empty;
        Assert.Contains("--metrics=off", script, StringComparison.Ordinal);
        Assert.Contains("--config p/csharp --config p/default", script, StringComparison.Ordinal);
    }
}
