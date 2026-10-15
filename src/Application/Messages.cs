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

    /// <summary>A check that did not run, and why.</summary>
    public static string CheckFailed(string check, string reason) => $"The {check} check did not run: {reason}";

    /// <summary>Nomad did not answer.</summary>
    public static string SchedulerDown(string address, string reason) => $"Nomad at {address} did not answer: {reason}";

    /// <summary>Where Nomad comes from.</summary>
    public const string SchedulerDownHint = "Scans run through Nomad: start the stand with SWARM_NOMAD=1, or point SNAIL_MCP_SECURITY_NOMAD_ADDRESS at it.";
}
