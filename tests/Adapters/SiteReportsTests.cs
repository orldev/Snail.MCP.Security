using Snail.MCP.Security.Adapters;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>
/// The readers over what the site scanners printed in a real run on 13.11.2026: nginx 1.27 with a self-signed certificate,
/// no security headers and its .git/config served, and Redis 7.4 beside it.
/// </summary>
public sealed class SiteReportsTests
{
    private static string Fixture(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Nuclei_ServedGitConfig_IsAnExposureAtItsAddress()
    {
        var findings = SiteReports.Nuclei(Fixture("nuclei-site.jsonl"));

        var git = Assert.Single(findings, finding => finding.Rule == "git-config");
        Assert.Equal((Check.Exposure, Severity.Medium, "https://shop.test/.git/config"), (git.Check, git.Severity, git.Location));
    }

    [Fact]
    public void Nuclei_SelfSignedCertificate_IsATlsFinding()
    {
        var findings = SiteReports.Nuclei(Fixture("nuclei-site.jsonl"));

        var tls = Assert.Single(findings, finding => finding.Check == Check.Tls);
        Assert.Equal(("self-signed-ssl", Severity.Low, "shop.test:443"), (tls.Rule, tls.Severity, tls.Location));
    }

    /// <summary>Of the ten headers Nuclei reported missing, the five every site should send are findings; the rest, and the TLS versions it lists, are inventory.</summary>
    [Fact]
    public void Nuclei_MissingHeaders_OnlyTheRequiredOnesAreFindings()
    {
        var findings = SiteReports.Nuclei(Fixture("nuclei-site.jsonl"));

        var headers = findings.Where(finding => finding.Check == Check.Headers).Select(finding => finding.Rule.Split(':')[1]).Order(StringComparer.Ordinal);
        Assert.Equal(SiteReports.RequiredHeaders.Order(StringComparer.Ordinal), headers);
        Assert.DoesNotContain(findings, finding => finding.Rule == "tls-version");
        Assert.Equal(7, findings.Count);
    }

    [Fact]
    public void Nuclei_LinesThatAreNotJson_AreSkipped()
    {
        Assert.Empty(SiteReports.Nuclei("[INF] Templates loaded\n\n{not json"));
    }

    [Fact]
    public void Nmap_RedisBesideTheWebServer_IsTheOneServiceThatShouldNotFaceTheInternet()
    {
        var findings = SiteReports.Nmap(Fixture("nmap-site.xml"))!;

        var redis = Assert.Single(findings);
        Assert.Equal((Check.Services, Severity.High, "exposed-6379", "192.168.107.2:6379"), (redis.Check, redis.Severity, redis.Rule, redis.Location));
        Assert.Contains("Redis key-value store 7.4.12", redis.Title, StringComparison.Ordinal);
    }

    /// <summary>A site that still offers TLS 1.0 and ciphers graded C: both are findings of the port that offers them.</summary>
    [Fact]
    public void Nmap_OldProtocolAndWeakGrade_AreTlsFindings()
    {
        const string xml = """
            <?xml version="1.0"?>
            <nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports>
            <port protocol="tcp" portid="443"><state state="open"/><service name="http" product="Apache httpd" version="2.4.29" tunnel="ssl"/>
            <script id="ssl-enum-ciphers" output="..."><table key="TLSv1.0"><table key="ciphers"/></table><table key="TLSv1.2"><table key="ciphers"/></table><elem key="least strength">C</elem></script>
            </port></ports></host></nmaprun>
            """;

        var findings = SiteReports.Nmap(xml)!;

        Assert.Equal(["old-protocol-TLSv1.0", "weak-ciphers"], findings.Select(finding => finding.Rule).Order(StringComparer.Ordinal));
        Assert.All(findings, finding => Assert.Equal((Check.Tls, Severity.Medium, "203.0.113.10:443"), (finding.Check, finding.Severity, finding.Location)));
    }

    [Fact]
    public void Nmap_OpenPortThatIsNeitherWebNorExposed_IsLow()
    {
        const string xml = """<nmaprun><host><address addr="203.0.113.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port><port protocol="tcp" portid="25"><state state="closed"/></port></ports></host></nmaprun>""";

        var finding = Assert.Single(SiteReports.Nmap(xml)!);

        Assert.Equal((Check.Services, Severity.Low, "open-22"), (finding.Check, finding.Severity, finding.Rule));
    }

    [Theory]
    [InlineData("")]
    [InlineData("Starting Nmap 7.98")]
    [InlineData("<html/>")]
    public void Nmap_TextThatIsNotItsXml_IsNull(string text)
    {
        Assert.Null(SiteReports.Nmap(text));
    }
}
