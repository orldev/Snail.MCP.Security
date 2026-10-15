using Microsoft.Extensions.Options;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Application;

/// <summary>The working copy this session checks, read from the address it opened, and the task it belongs to.</summary>
/// <remarks>
/// The platform names a step's copy in the address — <c>/mcp?root=/workspaces/&lt;task&gt;/step-3</c> — as it does for its
/// file and git servers. The task is the copy's first folder under the workspaces root, so a scan after a fix is compared
/// with the task's scan before it. A copy outside the root is refused, whatever the address says: the scanners mount it
/// from a volume that holds nothing else.
/// </remarks>
public sealed partial class SessionCopy(IHttpContextAccessor requests, IOptions<SecurityOptions> options)
{
    /// <summary>What the address calls the working copy.</summary>
    public const string Parameter = "root";

    /// <summary>The copy and its task, or why this session has none.</summary>
    public Answer<CopyPlace> Current() => Of(requests.HttpContext?.Request.Query[Parameter].FirstOrDefault(), options.Value.WorkspacesRoot);

    /// <summary>The copy a root names under the workspaces folder, or why it names none.</summary>
    public static Answer<CopyPlace> Of(string? root, string workspaces)
    {
        if (string.IsNullOrWhiteSpace(root))
            return Answer.Failed<CopyPlace>(Messages.NoCopy, Messages.NoCopyHint);

        string under = workspaces.TrimEnd('/');
        string relative = root.StartsWith($"{under}/", StringComparison.Ordinal) ? root[(under.Length + 1)..].Trim('/') : string.Empty;
        string[] segments = relative.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (segments.Length == 0 || segments.Any(segment => segment is "." or "..") || !TaskId().IsMatch(segments[0]))
            return Answer.Failed<CopyPlace>(Messages.CopyOutside(root, workspaces));

        return Answer.Ok(new CopyPlace(segments[0], $"{under}/{string.Join('/', segments)}"));
    }

    [System.Text.RegularExpressions.GeneratedRegex("^[a-z0-9][a-z0-9-]{0,62}$")]
    private static partial System.Text.RegularExpressions.Regex TaskId();
}

/// <summary>A working copy as a path under the workspaces root, and the task it belongs to.</summary>
public sealed record CopyPlace(string Task, string Path)
{
    /// <summary>The Nomad job a scan of this task runs as.</summary>
    public string Job => $"{ScanJob.Prefix}{Task}";
}

/// <summary>The names scan jobs carry.</summary>
public static class ScanJob
{
    /// <summary>What every scan job's name begins with, so the server finds its own among Nomad's jobs.</summary>
    public const string Prefix = "sec-";
}
