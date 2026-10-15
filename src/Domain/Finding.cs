namespace Snail.MCP.Security.Domain;

/// <summary>What a check looks at in the working copy.</summary>
public enum Check
{
    /// <summary>Third-party packages with a published vulnerability.</summary>
    Packages,

    /// <summary>Secrets written into the files: keys, tokens, passwords.</summary>
    Secrets,

    /// <summary>Insecure settings of containers and infrastructure files: Dockerfiles, compose files, Kubernetes manifests.</summary>
    Config,

    /// <summary>Insecure code found by static analysis.</summary>
    Code
}

/// <summary>How bad a finding is, worst first.</summary>
public enum Severity
{
    /// <summary>Exploitable and serious: fix before anything ships.</summary>
    Critical,

    /// <summary>Serious: fix before the work is called done.</summary>
    High,

    /// <summary>Worth fixing; does not block the work.</summary>
    Medium,

    /// <summary>Minor.</summary>
    Low,

    /// <summary>The scanner gave no severity.</summary>
    Unknown
}

/// <summary>One problem a check found: what, how bad, where, and what fixes it.</summary>
/// <param name="Check">The check that found it.</param>
/// <param name="Severity">How bad it is.</param>
/// <param name="Rule">The advisory or rule that names the problem: a CVE, a GHSA, a scanner's rule id.</param>
/// <param name="Title">What the problem is, in the scanner's words.</param>
/// <param name="Location">The file, with its line where the problem has one.</param>
/// <param name="Package">The vulnerable package, for a package finding.</param>
/// <param name="Version">The package's version in the copy.</param>
/// <param name="FixedIn">The first package version without the problem, when one is known.</param>
/// <param name="Link">The advisory's or the rule's page.</param>
public sealed record Finding(
    Check Check,
    Severity Severity,
    string Rule,
    string Title,
    string Location,
    string? Package = null,
    string? Version = null,
    string? FixedIn = null,
    string? Link = null)
{
    /// <summary>What makes two scans' findings the same problem: the line moves when code above it changes, so it is left out.</summary>
    public string Key => $"{Check}|{Rule}|{Package ?? FileOf(Location)}|{Version}";

    /// <summary>Whether the finding stops the work from being done: critical or high.</summary>
    public bool IsBlocking => Severity is Severity.Critical or Severity.High;

    private static string FileOf(string location)
    {
        int colon = location.LastIndexOf(':');

        return colon > 0 && int.TryParse(location[(colon + 1)..], out _) ? location[..colon] : location;
    }
}
