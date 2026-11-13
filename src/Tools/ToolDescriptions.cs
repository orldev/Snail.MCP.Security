namespace Snail.MCP.Security.Tools;

/// <summary>What the model reads before calling: the tool contract, guarded by the tests in <c>ToolCatalogTests</c>.</summary>
/// <remarks>Every number here is a default of <c>SecurityOptions</c>, and a guard test fails when the two drift apart.</remarks>
public static class ToolDescriptions
{
    /// <summary>The checks a scan runs, as the tools spell them; a guard test compares them with <c>Check</c>.</summary>
    public const string Checks = "packages, secrets, config and code";

    /// <summary>The severities a finding carries; a guard test compares them with <c>Severity</c>.</summary>
    public const string Severities = "critical, high, medium, low or unknown";

    /// <summary>The contract of security_scan.</summary>
    public const string Scan =
        $"""
        Scan the task's working copy for security problems and get back what blocks the work. The checks are
        {Checks}: packages with a published vulnerability (NuGet from NuGet's own advisories, every other ecosystem by
        Trivy), secrets written into files, insecure Dockerfile, compose and Kubernetes settings, and insecure code found
        by Semgrep. Each finding carries a severity — {Severities} — where it is, the version that fixes a package when
        one is known, and the ENS measures and NIS2 letters it falls under. The scan is clean when nothing is critical or
        high and every check ran. The answer names the 20 worst findings and how this scan compares with the task's scan
        before it: fixed, new, remaining. A scan takes up to 900 seconds; scans run one at a time. The scan runs as a job:
        the answer is the job's report, with the scan as its result when it ends within the wait, or the running job,
        whose resource job://security/scan/<id> carries the scan once it ends; the last scan is also read with
        security_findings. A scan that failed or was cancelled answers ok false with its job's report, which says why.
        Asking for the same scan while it runs answers with that scan's job, not a second scan.
        """;

    /// <summary>The wait parameter of security_scan.</summary>
    public const string ScanWait = "Seconds to wait for the scan before answering with the running job, 0 or more; 60 when not given, 0 answers with the job at once.";

    /// <summary>The checks parameter of security_scan.</summary>
    public const string ScanChecks = $"Which checks to run, any of {Checks}; every one when not given.";

    /// <summary>The contract of security_findings.</summary>
    public const string Findings =
        """
        Read the findings of the task's last scan page by page, worst first, with where each one is, what fixes it and
        the ENS measures and NIS2 letters it falls under. Narrow by severity and by check. A page holds 20 findings unless
        asked for more, at most 100.
        """;

    /// <summary>The severity parameter of security_findings.</summary>
    public const string FindingsSeverity = $"Only findings this severe or worse: {Severities}; all when not given.";

    /// <summary>The check parameter of security_findings.</summary>
    public const string FindingsCheck = $"Only findings of one check: {Checks}; all when not given.";

    /// <summary>The offset parameter of security_findings.</summary>
    public const string FindingsOffset = "How many findings to skip, for the next page, 0 or more; 0 when not given.";

    /// <summary>The limit parameter of security_findings.</summary>
    public const string FindingsLimit = "How many findings one page holds, from 1 to 100; 20 when not given.";

    /// <summary>The checks of a site, as the tools spell them; a guard test compares them with <c>Checks.Site</c>.</summary>
    public const string SiteChecks = "tls, headers, mail, exposure and services";

    /// <summary>The contract of security_site_prove.</summary>
    public const string SiteProve =
        """
        Prove that a customer's site is theirs before anything is checked on it, or learn how to. A site is proven by a
        TXT record under _snail-challenge on the site's domain or a parent of it, holding the code this server gives that
        domain; a parent's record covers its subdomains. Proven, the answer names the domain whose record proves it;
        not proven, it is refused with type notProven and its hint names the exact record and value to publish. Only
        someone who controls the domain's DNS can publish it, which is how the customer authorises the checks. The
        record is read again on every call, so removing it withdraws the authorisation. Reads the public DNS through
        two resolvers that have to agree; never reaches the site.
        """;

    /// <summary>The contract of security_site_scan.</summary>
    public const string SiteScan =
        $"""
        Scan a customer's proven site and get back what weakens it, each finding with the ENS measures and NIS2 letters
        it falls under. The checks are {SiteChecks}: TLS — old protocol versions, weak ciphers, a certificate that is
        self-signed, expired or for another name; the security headers every site should send; admin panels and files the
        site exposes, such as .git/config; open ports and the services behind them, databases and remote administration
        facing the internet first; and whether the domain's SPF and DMARC stop mail from being forged. Nothing attacks:
        no exploit, no password guessed, at most a few dozen requests a second. A site that is not proven is refused
        with type notProven — prove it with security_site_prove first — and one whose name points at an address that is
        not public with type notPublic, before anything reaches it. The answer names the 20 worst findings. A scan takes
        up to 900 seconds and runs as a job: the answer is the job's report, with the scan as its result when it ends
        within the wait, or the running job, whose resource job://security/site/<id> carries the scan once it ends.
        Asking for the same scan again within 10 minutes answers with that scan, not a second one.
        """;

    /// <summary>The checks parameter of security_site_scan.</summary>
    public const string SiteScanChecks = $"Which checks to run, any of {SiteChecks}; every one when not given.";

    /// <summary>The site parameter of the site tools.</summary>
    public const string SiteName = "The site: a public domain name, such as shop.example.com, or an address on it; never an IP address.";

    /// <summary>The contract of security_diagnose.</summary>
    public const string Diagnose =
        """
        Say whether this server can scan at all: Nomad's version, the scanner images, the network they run in and the
        hosts the egress proxy lets through, and for sites the nmap and Nuclei images, the templates' version, the
        network, the ports and how fast the site scanners go, and the compliance catalogs findings are placed in.
        Changes nothing.
        """;
}
