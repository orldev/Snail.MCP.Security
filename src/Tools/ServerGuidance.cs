namespace Snail.MCP.Security.Tools;

/// <summary>What the model is told about this server when it connects.</summary>
public static class ServerGuidance
{
    /// <summary>The instructions a client shows the model before any tool.</summary>
    public const string Instructions =
        """
        This server checks the task's working copy for security problems: vulnerable packages, secrets in files, insecure
        container and infrastructure settings, and insecure code. Every finding names the ENS measures and NIS2 letters
        it falls under.

        Start with security_scan. It answers with the scan's job: the scan itself in result when it ended within the wait,
        or the running job, whose resource carries the scan once it ends. Fix what the scan says blocks the work — critical
        and high findings — then scan again: the answer says what got fixed since the scan before. Update a package to the version the finding names; take a
        secret out of the files and say it has to be rotated, since it was exposed; change the setting or the code the
        finding points at. Read the rest with security_findings.

        A customer's site is checked only once it is proven theirs: security_site_prove names the TXT record and value
        the customer publishes, and says when it is in place. security_site_scan then checks the site's TLS, security
        headers, what it exposes, the services facing the internet and its mail, as a job like security_scan. It never
        attacks the site; tell the customer what each finding means and how to fix it.

        Every answer is JSON with an ok flag, and a failed call is also flagged isError. When ok is false, read error and
        hint and fix the call instead of retrying it verbatim; type names the failure: arguments a check or severity
        that does not exist or a site that is not a public domain name, notScanned no scan of the task yet, unreachable
        Nomad or the public DNS not answering, notProven a site with no record that proves it, notPublic a site that
        points at an address that is not public, unresolved a site with no address, noRoot or outside a session with no
        task's copy. A scan that failed or was cancelled answers ok false too, with its job's report:
        the scan did start, so read why it ended before scanning again.
        """;
}
