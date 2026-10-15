using System.Net;

namespace Snail.MCP.Security.Application.Ports;

/// <summary>The public DNS as the internet sees a customer's domain.</summary>
public interface ISiteDns
{
    /// <summary>The TXT strings of the name, each record joined whole, as every resolver asked agrees on; null when they could not be asked or disagree.</summary>
    Task<IReadOnlyList<string>?> TextsAsync(string name, CancellationToken cancellationToken);

    /// <summary>The name's IPv4 and IPv6 addresses; null when they could not be resolved.</summary>
    Task<IReadOnlyList<IPAddress>?> AddressesAsync(string name, CancellationToken cancellationToken);
}
