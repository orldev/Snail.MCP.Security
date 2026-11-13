using System.Net;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.Sdk.Mcp.Hosting;

namespace Snail.MCP.Security.Tests.Application;

/// <summary>A customer's site: proven first, then planned only towards public addresses, then checked.</summary>
public sealed class SitesTests
{
    private static readonly Key OwnershipKey = new();

    private static readonly IPAddress Public = IPAddress.Parse("93.184.215.14");

    private static Sites Of(Dns dns, FakeSiteScanner? scanner = null) => new(new Ownership(dns, OwnershipKey), dns, scanner ?? new FakeSiteScanner(), TimeProvider.System);

    private static string CodeOf(string domain) => new Ownership(new Dns(), OwnershipKey).CodeOf(domain);

    private static Dns Proven(string domain = "example.com") => new() { [$"_snail-challenge.{domain}"] = [CodeOf(domain)], Addresses = [Public] };

    [Theory]
    [InlineData("")]
    [InlineData("localhost")]
    [InlineData("10.0.0.1")]
    [InlineData("https://[::1]/")]
    public async Task ProveAsync_NotAPublicDomainName_IsTypedArguments(string named)
    {
        var dns = new Dns();

        var answer = await Of(dns).ProveAsync(named, CancellationToken.None);

        Assert.Equal(ToolFailures.Arguments, answer.Type);
        Assert.Empty(dns.Asked);
    }

    /// <summary>The refusal is also the way in: its hint names the record and the value the customer publishes.</summary>
    [Fact]
    public async Task ProveAsync_NoRecord_HintNamesTheRecordAndTheCodeToPublish()
    {
        var answer = await Of(new Dns()).ProveAsync("https://Shop.Example.com/cart", CancellationToken.None);

        Assert.Equal("notProven", answer.Type);
        Assert.Contains("_snail-challenge.shop.example.com", answer.Hint, StringComparison.Ordinal);
        Assert.Contains(CodeOf("shop.example.com"), answer.Hint, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ProveAsync_RecordOfAParent_IsProvenByThatParent()
    {
        var answer = await Of(Proven()).ProveAsync("shop.example.com", CancellationToken.None);

        Assert.Equal(("shop.example.com", "example.com"), (answer.Value?.Site.Host, answer.Value?.ProvenBy));
    }

    /// <summary>Nothing is resolved, let alone scanned, about a site that is not proven.</summary>
    [Fact]
    public async Task PlanAsync_NotProven_ResolvesNothing()
    {
        var dns = new Dns { Addresses = [Public] };

        var answer = await Of(dns).PlanAsync("shop.example.com", null, CancellationToken.None);

        Assert.Equal("notProven", answer.Type);
        Assert.All(dns.Asked, name => Assert.StartsWith("_snail-challenge.", name, StringComparison.Ordinal));
    }

    /// <summary>A customer controls where its name points: one private address among public ones refuses the site whole, before any scanner.</summary>
    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("fd00::1")]
    public async Task PlanAsync_AnAddressThatIsNotPublic_IsTypedNotPublic(string address)
    {
        var dns = Proven();
        dns.Addresses = [Public, IPAddress.Parse(address)];

        var answer = await Of(dns).PlanAsync("example.com", null, CancellationToken.None);

        Assert.Equal("notPublic", answer.Type);
        Assert.Contains(address, answer.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PlanAsync_NoAddress_IsTypedUnresolved()
    {
        var dns = Proven();
        dns.Addresses = [];

        var answer = await Of(dns).PlanAsync("example.com", ["tls"], CancellationToken.None);

        Assert.Equal("unresolved", answer.Type);
    }

    /// <summary>Mail reads the DNS alone: a domain with no address of its own may still have its mail checked.</summary>
    [Fact]
    public async Task PlanAsync_MailAlone_NeedsNoAddress()
    {
        var dns = Proven();
        dns.Addresses = [];

        var answer = await Of(dns).PlanAsync("example.com", ["mail"], CancellationToken.None);

        Assert.Equal([Check.Mail], answer.Value!.Checks);
    }

    [Fact]
    public async Task PlanAsync_UnknownCheck_IsTypedArgumentsBeforeTheDnsIsAsked()
    {
        var dns = Proven();

        var answer = await Of(dns).PlanAsync("example.com", ["tls", "ddos"], CancellationToken.None);

        Assert.Equal(ToolFailures.Arguments, answer.Type);
        Assert.Empty(dns.Asked);
    }

    /// <summary>The scanners are handed the addresses checked public and the checks that reach the site; mail stays with the DNS.</summary>
    [Fact]
    public async Task RunAsync_EveryCheck_ScannersGetThePublicAddressesAndMailComesFromTheDns()
    {
        var scanner = new FakeSiteScanner { Next = new([new Finding(Check.Services, Severity.High, "exposed-6379", "Redis faces the internet", "93.184.215.14:6379")], []) };
        var sites = Of(Proven(), scanner);
        var plan = (await sites.PlanAsync("example.com", null, CancellationToken.None)).Value!;

        var scan = await sites.RunAsync(plan, CancellationToken.None);

        var asked = Assert.Single(scanner.Asked);
        Assert.Equal([Public], asked.Addresses);
        Assert.DoesNotContain(Check.Mail, asked.Checks);
        Assert.Equal(Checks.Site, scan.Report.Runs.Select(run => run.Check));
        Assert.Contains(scan.Report.Findings, finding => finding.Rule == "exposed-6379");
        Assert.Contains(scan.Report.Findings, finding => finding.Rule == "spf-missing");
    }

    [Fact]
    public async Task RunAsync_EnforcedMailAlone_FindsNothingAndRunsNoScanner()
    {
        var dns = Proven();
        dns["example.com"] = ["v=spf1 include:_spf.example.net -all"];
        dns["_dmarc.example.com"] = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"];
        var scanner = new FakeSiteScanner();
        var sites = Of(dns, scanner);
        var plan = (await sites.PlanAsync("example.com", ["mail"], CancellationToken.None)).Value!;

        var scan = await sites.RunAsync(plan, CancellationToken.None);

        Assert.Empty(scan.Report.Findings);
        Assert.Empty(scanner.Asked);
        Assert.True(scan.Report.IsClean);
    }

    /// <summary>A DNS that does not answer the mail records is a check that did not run, not a domain without them.</summary>
    [Fact]
    public async Task RunAsync_DnsSilentOnTheMailRecords_TellsMailNotRun()
    {
        var dns = Proven();
        dns.Silent.Add("_dmarc.example.com");
        var sites = Of(dns);
        var plan = (await sites.PlanAsync("example.com", ["mail"], CancellationToken.None)).Value!;

        var scan = await sites.RunAsync(plan, CancellationToken.None);

        Assert.False(Assert.Single(scan.Report.Runs).HasRun);
        Assert.Empty(scan.Report.Findings);
    }

    private sealed class Key : IProofKey
    {
        public byte[] Bytes { get; } = [.. Enumerable.Range(0, 32).Select(index => (byte)(index * 7))];
    }

    /// <summary>A site scanner that answers at once with what the test sets, every check asked for run, and keeps what it was asked.</summary>
    private sealed class FakeSiteScanner : ISiteScanner
    {
        public List<(IReadOnlyList<IPAddress> Addresses, IReadOnlyCollection<Check> Checks)> Asked { get; } = [];

        public ScanOutcome Next { get; init; } = new([], []);

        public Task<ScanOutcome> ScanAsync(Site site, IReadOnlyList<IPAddress> addresses, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken)
        {
            Asked.Add((addresses, checks));

            return Task.FromResult(Next with { Runs = [.. checks.Select(check => new CheckRun(check, true))] });
        }
    }

    /// <summary>The public DNS as the test sets it: the TXT records of each name, the addresses, the names that do not answer, and every name asked.</summary>
    private sealed class Dns : Dictionary<string, IReadOnlyList<string>>, ISiteDns
    {
        public HashSet<string> Silent { get; } = [];

        public List<string> Asked { get; } = [];

        public IReadOnlyList<IPAddress> Addresses { get; set; } = [];

        public Task<IReadOnlyList<string>?> TextsAsync(string name, CancellationToken cancellationToken)
        {
            Asked.Add(name);

            if (Silent.Contains(name))
                return Task.FromResult<IReadOnlyList<string>?>(null);

            return Task.FromResult<IReadOnlyList<string>?>(TryGetValue(name, out var texts) ? texts : []);
        }

        public Task<IReadOnlyList<IPAddress>?> AddressesAsync(string name, CancellationToken cancellationToken)
        {
            Asked.Add(name);

            return Task.FromResult<IReadOnlyList<IPAddress>?>(Addresses);
        }
    }
}
