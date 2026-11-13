using System.Globalization;
using Microsoft.Extensions.Options;
using Snail.Sdk.Mcp.Hosting;

namespace Snail.MCP.Security.Configuration;

/// <summary>Refuses settings a scan could not run with, at the start and naming the variable that set them.</summary>
/// <remarks>
/// <para>
/// Bound without a check, a zero or negative number went on to do something nobody asked for: <c>ScanSeconds=0</c> gave
/// every scan no time, <c>MaxPage=0</c> made security_findings clamp every page to one finding, a port past 65535 failed
/// only when the proxy started, and an image named by a tag ran a scanner that could be moved under it. Each of them is
/// now a refused start, in one line, with the variable an operator set (<see cref="ServerSettings.NameOfSetting"/>); the
/// SDK's host turns the failure into that line and exit code 1.
/// </para>
/// <para>
/// Written by hand rather than generated from attributes: the generated messages name the property, where the operator
/// set a variable, and a digest or an address is not a range.
/// </para>
/// </remarks>
public sealed class SecurityOptionsValidation : IValidateOptions<SecurityOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, SecurityOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        List<string> problems = [];

        Positive(problems, nameof(SecurityOptions.ScanSeconds), options.ScanSeconds, "a number of seconds above zero");
        Positive(problems, nameof(SecurityOptions.ShownFindings), options.ShownFindings, "a number of findings above zero");
        Positive(problems, nameof(SecurityOptions.MaxPage), options.MaxPage, "a number of findings above zero");
        Positive(problems, nameof(SecurityOptions.ScannerMemoryMegabytes), options.ScannerMemoryMegabytes, "a number of megabytes above zero");
        Positive(problems, nameof(SecurityOptions.ScannerCpu), options.ScannerCpu, "a number of MHz above zero");

        if (options.ShownFindings > options.MaxPage)
            problems.Add($"{Setting(nameof(SecurityOptions.ShownFindings))} is {options.ShownFindings}; it is a page of security_findings, so it is at most {Setting(nameof(SecurityOptions.MaxPage))}, {options.MaxPage}.");

        if (options.ProxyPort is < 0 or > 65535)
            problems.Add($"{Setting(nameof(SecurityOptions.ProxyPort))} is {options.ProxyPort}; it is a port from 1 to 65535, or 0 to keep the proxy off.");

        if (!IsWebAddress(options.NomadAddress, Uri.UriSchemeHttp, Uri.UriSchemeHttps))
            problems.Add($"{Setting(nameof(SecurityOptions.NomadAddress))} is '{options.NomadAddress}'; it is Nomad's absolute http or https address, such as http://nomad:4646.");

        if (options.Proxy is { Length: > 0 } proxy && !IsWebAddress(proxy, Uri.UriSchemeHttp))
            problems.Add($"{Setting(nameof(SecurityOptions.Proxy))} is '{proxy}'; it is the egress proxy's absolute http address as a scanner reaches it, such as http://mcp-security:3128, or empty.");

        if (string.IsNullOrWhiteSpace(options.WorkspacesRoot) || !Path.IsPathRooted(options.WorkspacesRoot))
            problems.Add($"{Setting(nameof(SecurityOptions.WorkspacesRoot))} is '{options.WorkspacesRoot}'; it is an absolute folder, such as /workspaces.");

        Positive(problems, nameof(SecurityOptions.SiteRequestsPerSecond), options.SiteRequestsPerSecond, "a number of requests a second above zero");
        Positive(problems, nameof(SecurityOptions.SitePacketsPerSecond), options.SitePacketsPerSecond, "a number of packets a second above zero");

        if (string.IsNullOrWhiteSpace(options.SiteNetwork) || string.Equals(options.SiteNetwork, options.Network, StringComparison.Ordinal))
            problems.Add($"{Setting(nameof(SecurityOptions.SiteNetwork))} is '{options.SiteNetwork}'; it is a network of its own that reaches the internet, never {Setting(nameof(SecurityOptions.Network))}, the internal one the copy scanners are held in.");

        if (!IsPortList(options.SitePorts))
            problems.Add($"{Setting(nameof(SecurityOptions.SitePorts))} is '{options.SitePorts}'; it is a list of ports from 1 to 65535 separated by commas, such as 22,80,443.");

        if (!IsWebAddress(options.NucleiTemplates, Uri.UriSchemeHttps))
            problems.Add($"{Setting(nameof(SecurityOptions.NucleiTemplates))} is '{options.NucleiTemplates}'; it is the https address of a release archive of the Nuclei templates.");

        if (!IsSha256(options.NucleiTemplatesSha256))
            problems.Add($"{Setting(nameof(SecurityOptions.NucleiTemplatesSha256))} is '{options.NucleiTemplatesSha256}'; it is the archive's SHA-256, 64 hexadecimal digits.");

        Pinned(problems, nameof(SecurityOptions.NmapImage), options.NmapImage);
        Pinned(problems, nameof(SecurityOptions.NucleiImage), options.NucleiImage);
        Pinned(problems, nameof(SecurityOptions.TrivyImage), options.TrivyImage);
        Pinned(problems, nameof(SecurityOptions.SemgrepImage), options.SemgrepImage);
        Pinned(problems, nameof(SecurityOptions.SdkImage), options.SdkImage);

        return problems.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(problems);
    }

    private static void Positive(List<string> problems, string key, int value, string meaning)
    {
        if (value <= 0)
            problems.Add($"{Setting(key)} is {value}; it is {meaning}.");
    }

    /// <summary>A scanner reads all of a task's code, so its image is named by a digest nobody can move (see <see cref="SecurityOptions"/>).</summary>
    private static void Pinned(List<string> problems, string key, string image)
    {
        if (!image.Contains("@sha256:", StringComparison.Ordinal))
            problems.Add($"{Setting(key)} is '{image}'; it is an image pinned by its digest, such as name:tag@sha256:…, since a tag can be moved to other code.");
    }

    private static bool IsWebAddress(string value, params string[] schemes)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var address))
            return false;

        return schemes.Contains(address.Scheme, StringComparer.Ordinal);
    }

    private static bool IsPortList(string ports)
    {
        if (string.IsNullOrWhiteSpace(ports))
            return false;

        foreach (string port in ports.Split(','))
        {
            if (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out int number) || number is < 1 or > 65535)
                return false;
        }

        return true;
    }

    private static bool IsSha256(string digest) => digest.Length == 64 && digest.All(char.IsAsciiHexDigitLower);

    private static string Setting(string key) => ServerSettings.NameOfSetting(SecuritySettings.Name, key);
}
