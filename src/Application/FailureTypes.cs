namespace Snail.MCP.Security.Application;

/// <summary>The <c>type</c> of a refusal: the word a program branches on, where the error is prose for the model.</summary>
/// <remarks>
/// A contract like a check's name: the platform tells "scan first" from "the call named a check that does not exist" by
/// this word, never by the error's text, which stays free to reword. The SDK's words where one fits, camel case like
/// them where none does. A session's copy is typed by the SDK's reason (<c>noRoot</c>, <c>outside</c>, <c>malformed</c>,
/// <c>notATask</c>), a tool not granted is the SDK's <c>notGranted</c>, and a check or a severity the tool does not know
/// is the SDK's <c>ToolFailures.Arguments</c>, since to the caller it is the same mistake as an argument that did not bind.
/// </remarks>
public static class FailureTypes
{
    /// <summary>The task has no scan to read yet.</summary>
    public const string NotScanned = "notScanned";

    /// <summary>A service the server needs did not answer: Nomad, or the public DNS.</summary>
    public const string Unreachable = "unreachable";

    /// <summary>No record proves the site is the customer's.</summary>
    public const string NotProven = "notProven";
}
