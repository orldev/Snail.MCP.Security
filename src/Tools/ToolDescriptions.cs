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
        before it: fixed, new, remaining. A scan takes up to 900 seconds; scans run one at a time.
        """;

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
    public const string FindingsOffset = "How many findings to skip, for the next page; 0 when not given.";

    /// <summary>The limit parameter of security_findings.</summary>
    public const string FindingsLimit = "How many findings one page holds; 20 when not given, at most 100.";

    /// <summary>The contract of security_diagnose.</summary>
    public const string Diagnose =
        """
        Say whether this server can scan at all: Nomad's version, the scanner images, the network they run in and the
        hosts the egress proxy lets through. Changes nothing.
        """;
}
