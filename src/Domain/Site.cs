using System.Net;
using System.Net.Sockets;

namespace Snail.MCP.Security.Domain;

/// <summary>A site to check: a domain name, lower case, with at least one dot, never an address.</summary>
/// <remarks>
/// Only a name can be proven to belong to the customer — a DNS record under it is the proof — so an address alone is
/// refused. The proof of a domain covers its subdomains, as a verified domain does at Google: whoever controls the zone
/// controls every name in it. A name is held to the proof of itself or of any parent of two labels or more.
/// </remarks>
public readonly record struct Site(string Host)
{
    /// <summary>The label the proof's TXT record sits under, prefixed to the domain it proves.</summary>
    public const string ChallengeLabel = "_snail-challenge";

    /// <summary>The site a caller named — a bare domain or an address with scheme, port and path — or null for one that is not a public domain name.</summary>
    public static Site? Of(string? named)
    {
        if (string.IsNullOrWhiteSpace(named))
            return null;

        string text = named.Trim().ToLowerInvariant();
        string host = Uri.TryCreate(text.Contains("://", StringComparison.Ordinal) ? text : $"https://{text}", UriKind.Absolute, out var uri) ? uri.IdnHost : string.Empty;

        if (host.Length is 0 or > 253 || !host.Contains('.', StringComparison.Ordinal) || IPAddress.TryParse(host, out _))
            return null;

        return host.Split('.').All(IsLabel) ? new Site(host.TrimEnd('.')) : null;
    }

    /// <summary>The names whose proof covers this one: itself, then each parent down to two labels.</summary>
    public IReadOnlyList<string> Provers
    {
        get
        {
            string[] labels = Host.Split('.');

            return [.. Enumerable.Range(0, labels.Length - 1).Select(skip => string.Join('.', labels.Skip(skip)))];
        }
    }

    /// <summary>The name of the TXT record that proves <paramref name="domain"/>.</summary>
    public static string RecordOf(string domain) => $"{ChallengeLabel}.{domain}";

    /// <inheritdoc />
    public override string ToString() => Host;

    private static bool IsLabel(string label) =>
        label.Length is > 0 and <= 63 && !label.StartsWith('-') && !label.EndsWith('-') && label.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
}

/// <summary>Which addresses a check may go to: public ones only.</summary>
/// <remarks>
/// A customer controls where its name points. A name pointed at a private, loopback or link-local address would turn the
/// scanners against the stand's own network, so a site any of whose addresses is not public is refused whole.
/// </remarks>
public static class Addresses
{
    /// <summary>Whether the address is one the public internet routes.</summary>
    public static bool IsPublic(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            return false;

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return !(address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || address.IsIPv6UniqueLocal || address.IsIPv6Multicast);

        byte[] bytes = address.GetAddressBytes();

        return bytes switch
        {
            [10, ..] => false,
            [172, >= 16 and <= 31, ..] => false,
            [192, 168, ..] => false,
            [169, 254, ..] => false,
            [100, >= 64 and <= 127, ..] => false,
            [0, ..] => false,
            [>= 224, ..] => false,
            [192, 0, 0, ..] or [192, 0, 2, ..] or [198, 51, 100, ..] or [203, 0, 113, ..] => false,
            [198, 18 or 19, ..] => false,
            _ => true
        };
    }
}
