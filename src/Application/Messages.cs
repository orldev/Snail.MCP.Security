namespace Snail.MCP.Security.Application;

/// <summary>What a caller reads when something did not happen, with what to do about it.</summary>
public static class Messages
{
    /// <summary>The session names no working copy.</summary>
    public const string NoCopy = "This session names no working copy, so there is nothing to scan.";

    /// <summary>Where the copy comes from.</summary>
    public const string NoCopyHint = "The platform names the step's copy in the server's address as ?root=; connect the server to a role through the platform.";

    /// <summary>No scan was made for the task yet.</summary>
    public const string NotScanned = "This task has no scan yet.";

    /// <summary>What makes one.</summary>
    public const string NotScannedHint = "Call security_scan first.";

    /// <summary>A scan with nothing that blocks the work.</summary>
    public const string Clean = "Nothing critical or high: the work is not blocked by security findings.";

    /// <summary>A scan that found what blocks the work.</summary>
    public const string Blocked = "Critical or high findings block the work: fix them — update the package to the version named, remove the secret and rotate it, change the setting or the code — and scan again.";

    /// <summary>A scan where some check did not run.</summary>
    public const string Partial = "Not every check ran, so the scan proves nothing about what it skipped: see runs.";

    /// <summary>A copy outside the workspaces root.</summary>
    public static string CopyOutside(string root, string workspaces) =>
        $"The working copy \"{root}\" is not a task's copy under {workspaces}.";

    /// <summary>Checks the server does not know.</summary>
    public static string UnknownChecks(IEnumerable<string> unknown, IEnumerable<string> known) =>
        $"No check is called {string.Join(", ", unknown)}; the checks are {string.Join(", ", known)}.";

    /// <summary>A severity the server does not know.</summary>
    public static string UnknownSeverity(string severity) =>
        $"\"{severity}\" is not a severity: critical, high, medium, low or unknown.";

    /// <summary>An offset before the first finding.</summary>
    public static string OffsetBelowZero(int offset) => $"offset is {offset}; it is how many findings to skip, 0 or more.";

    /// <summary>A page of no findings, or of more than a page holds.</summary>
    public static string LimitOutOfRange(int limit, int most) => $"limit is {limit}; a page holds from 1 to {most} findings.";

    /// <summary>A wait before now.</summary>
    public static string WaitBelowZero(int wait) => $"wait is {wait}; it is a number of seconds, 0 or more — 0 answers with the job at once.";

    /// <summary>A check that did not run, and why.</summary>
    public static string CheckFailed(string check, string reason) => $"The {check} check did not run: {reason}";

    /// <summary>Nomad did not answer.</summary>
    public static string SchedulerDown(string address, string reason) => $"Nomad at {address} did not answer: {reason}";

    /// <summary>Nomad answered, but did not run the scan.</summary>
    public static string SchedulerFailed(string address, string reason) => $"Nomad at {address} did not run the scan: {reason}";

    /// <summary>Where Nomad comes from.</summary>
    public const string SchedulerDownHint = "Scans run through Nomad: start the stand with SWARM_NOMAD=1, or point SNAIL_MCP_SECURITY_NOMAD_ADDRESS at it.";

    /// <summary>A site that is not a public domain name.</summary>
    public static string NotASite(string named) =>
        $"\"{named}\" is not a site this server checks: name a public domain, such as shop.example.com — an address alone cannot be proven yours.";

    /// <summary>A site whose ownership is not proven.</summary>
    public static string NotProven(string host) =>
        $"{host} is not proven to be yours, so it is not checked: scanning a system without its owner's authorisation is an offence (Código Penal, art. 197 bis and 264 bis).";

    /// <summary>How to prove a site.</summary>
    public static string ProveHint(string record, string code) =>
        $"Publish a TXT record {record} with the value {code}, wait for DNS to spread, and ask again. A record on a parent domain covers its subdomains.";

    /// <summary>DNS that did not answer.</summary>
    public static string DnsUnanswered(string name) => $"The public DNS did not answer the same for {name}; try again in a minute.";

    /// <summary>A site that points at an address that is not public.</summary>
    public static string NotPublic(string host, string address) =>
        $"{host} points at {address}, which is not a public address: the site is not checked, so the scanners never reach a private network.";

    /// <summary>A site that does not resolve.</summary>
    public static string Unresolved(string host) => $"{host} has no address in the public DNS.";

    /// <summary>The ownership key's file refused, with what replacing it would cost the customers.</summary>
    public static string KeyRefused(string refusal) =>
        $"{refusal} A new key changes every site's ownership code: every customer who proved a domain would publish its TXT record again.";

    /// <summary>A site proven the customer's.</summary>
    public static string Proven(string host, string domain) =>
        host == domain ? $"{host} is proven yours by its own record." : $"{host} is proven yours by the record of {domain}, which covers its subdomains.";

    /// <summary>A site with no check yet.</summary>
    public const string SiteNotScanned = "This site has no check yet.";

    /// <summary>What makes one.</summary>
    public const string SiteNotScannedHint = "Call security_site_scan first.";
}
