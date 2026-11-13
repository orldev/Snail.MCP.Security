using System.Net;
using System.Text.Json.Nodes;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>The site scan's Nomad job: where the scanners run, what they are given, and every limit that keeps them from attacking.</summary>
public sealed class SiteJobTests
{
    private static readonly Site Shop = new("shop.example.com");

    private static readonly SecurityOptions Defaults = new();

    private static readonly IReadOnlyList<IPAddress> Addresses = [IPAddress.Parse("93.184.215.14"), IPAddress.Parse("2606:2800:21f:cb07:6820:80da:af6b:8b2c")];

    private static JsonObject Job(IReadOnlyCollection<Check>? checks = null) => SiteJob.Of(Shop, Addresses, checks ?? [Check.Tls, Check.Headers, Check.Exposure, Check.Services], "run1", Defaults);

    private static IEnumerable<JsonNode> Tasks(JsonObject job) => job["TaskGroups"]![0]!["Tasks"]!.AsArray().Select(task => task!);

    private static string Script(JsonNode task) => (string)task["Config"]!["args"]![1]!;

    [Fact]
    public void Of_EveryActiveCheck_RunsNucleiAndNmapOnTheSiteNetworkWithNoWorkspace()
    {
        var job = Job();

        Assert.Equal(["nuclei", "nmap"], Tasks(job).Select(task => (string)task["Name"]!));
        Assert.All(Tasks(job), task => Assert.Equal(Defaults.SiteNetwork, (string)task["Config"]!["network_mode"]!));
        Assert.Null(job["TaskGroups"]![0]!["Volumes"]);
        Assert.Equal("sec-site-shop.example.com", (string)job["ID"]!);
    }

    [Theory]
    [InlineData(Check.Services, "nmap")]
    [InlineData(Check.Headers, "nuclei")]
    [InlineData(Check.Exposure, "nuclei")]
    public void TasksFor_OneCheck_RunsOnlyTheScannerItNeeds(Check check, string task)
    {
        Assert.Equal([task], SiteJob.TasksFor([check]));
    }

    /// <summary>Nuclei never goes to a private address, never runs a template that attacks, and asks slowly.</summary>
    [Fact]
    public void Nuclei_Script_KeepsEveryLimit()
    {
        string script = Script(Tasks(Job()).Single(task => (string)task["Name"]! == "nuclei"));

        Assert.Contains(" -lna ", script, StringComparison.Ordinal);
        Assert.Contains($" -etags {SiteJob.ExcludedTags} ", script, StringComparison.Ordinal);
        Assert.Contains(" -rl 30 ", script, StringComparison.Ordinal);
        Assert.Contains(" -duc ", script, StringComparison.Ordinal);
        Assert.Contains(" -ni ", script, StringComparison.Ordinal);
        Assert.DoesNotContain(" -code", script, StringComparison.Ordinal);
        Assert.DoesNotContain(" -dast", script, StringComparison.Ordinal);
        Assert.DoesNotContain(" -headless", script, StringComparison.Ordinal);
    }

    /// <summary>The templates are the checked archive, unpacked only when its SHA-256 matches.</summary>
    [Fact]
    public void Nuclei_Templates_AreCheckedAgainstTheirDigestBeforeTheyAreUnpacked()
    {
        var nuclei = Tasks(Job()).Single(task => (string)task["Name"]! == "nuclei");
        string script = Script(nuclei);

        Assert.True(script.IndexOf("sha256sum -c", StringComparison.Ordinal) < script.IndexOf("tar -xzf", StringComparison.Ordinal));
        Assert.Equal(Defaults.NucleiTemplatesSha256, (string)nuclei["Env"]!["S3L_TEMPLATES_SHA256"]!);
        Assert.EndsWith(Defaults.NucleiTemplatesSha256, (string)nuclei["Env"]!["S3L_TEMPLATES"]!, StringComparison.Ordinal);
        Assert.Contains("set -e", script, StringComparison.Ordinal);
    }

    /// <summary>nmap is handed the checked addresses, one family at a time, and never the name it would resolve again.</summary>
    [Fact]
    public void Nmap_Arguments_AreTheCheckedAddressesNeverTheName()
    {
        var words = SiteJob.NmapArguments(Shop, Addresses, Defaults);

        Assert.Equal("93.184.215.14", words[^1]);
        Assert.DoesNotContain("2606:2800:21f:cb07:6820:80da:af6b:8b2c", words);
        Assert.DoesNotContain(Shop.Host, words);
        Assert.Contains("-n", words);
        Assert.Contains($"tls.servername={Shop.Host}", words);
    }

    [Fact]
    public void Nmap_Arguments_ConnectOnlyToTheListedPortsSlowly()
    {
        var words = SiteJob.NmapArguments(Shop, Addresses, Defaults);

        Assert.Contains("-sT", words);
        Assert.Contains("--unprivileged", words);
        Assert.Equal(Defaults.SitePorts, words[words.ToList().IndexOf("-p") + 1]);
        Assert.Equal("50", words[words.ToList().IndexOf("--max-rate") + 1]);
        Assert.Equal(SiteJob.NmapScripts, words[words.ToList().IndexOf("--script") + 1]);
    }

    [Fact]
    public void Nmap_OnlyIpv6_ScansIpv6()
    {
        var words = SiteJob.NmapArguments(Shop, [IPAddress.Parse("2606:2800:21f:cb07:6820:80da:af6b:8b2c")], Defaults);

        Assert.Contains("-6", words);
        Assert.Equal("2606:2800:21f:cb07:6820:80da:af6b:8b2c", words[^1]);
    }

    /// <summary>Nomad interpolates ${…} in a task's config; a script that used it would run with Nomad's values instead of its own.</summary>
    [Fact]
    public void Scripts_UseNoNomadInterpolation()
    {
        Assert.All(Tasks(Job()), task => Assert.DoesNotContain("${", Script(task), StringComparison.Ordinal));
    }
}
