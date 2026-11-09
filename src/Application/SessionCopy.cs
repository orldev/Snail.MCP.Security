using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting.Sessions;

namespace Snail.MCP.Security.Application;

/// <summary>The working copy this session checks, read from the address it opened, and the task it belongs to.</summary>
/// <remarks>
/// The platform names a step's copy in the address — <c>/mcp?root=/workspaces/&lt;task&gt;/step-3</c> — as it does for its
/// file and git servers. The task is the copy's first folder under the workspaces root (<see cref="WorkspaceCopy"/>), so a
/// scan after a fix is compared with the task's scan before it. A copy outside the root is refused, whatever the address
/// says: the scanners mount it from a volume that holds nothing else. What stays here is this server's words for the
/// SDK's reason (<see cref="CopyRefusal"/>): a session that names no copy is told where the copy comes from, and one that
/// names anything but a task's copy — outside the root, climbing out of it, or under a folder that is no task — is told so.
/// </remarks>
public sealed partial class SessionCopy(ISessionAddress address, IOptions<SecurityOptions> options)
{
    /// <summary>What the address calls the working copy.</summary>
    public const string Parameter = SessionRoots.Parameter;

    /// <summary>The copy and its task, or why this session has none.</summary>
    public Answer<WorkspacePlace<string>> Current() => Of(address.Values(Parameter).FirstOrDefault(), options.Value.WorkspacesRoot);

    /// <summary>The copy a root names under the workspaces folder, or why it names none.</summary>
    /// <remarks>The refusal is typed by the SDK's reason — <c>noRoot</c>, <c>outside</c>, <c>malformed</c>, <c>notATask</c> — so a program tells a missing copy from a wrong one.</remarks>
    public static Answer<WorkspacePlace<string>> Of(string? root, string workspaces) =>
        WorkspaceCopy.Of(root, workspaces, IsTaskId).ToAnswer(refusal => refusal == CopyRefusal.NoRoot
            ? Answer.Failed(Messages.NoCopy, Messages.NoCopyHint)
            : Answer.Failed(Messages.CopyOutside(root!, workspaces)));

    /// <summary>Whether a folder under the workspaces root is named as the platform names a task.</summary>
    public static bool IsTaskId(string folder) => TaskId().IsMatch(folder);

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{0,62}$")]
    private static partial Regex TaskId();
}

/// <summary>The names scan jobs carry.</summary>
public static class ScanJob
{
    /// <summary>What every scan job's name begins with, so the server finds its own among Nomad's jobs.</summary>
    public const string Prefix = "sec-";

    /// <summary>The Nomad job a scan of a task runs as.</summary>
    public static string Of(string task) => $"{Prefix}{task}";
}
