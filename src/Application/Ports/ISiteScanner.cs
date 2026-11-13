using System.Net;

namespace Snail.MCP.Security.Application.Ports;

/// <summary>Where the scanners run over a customer's site.</summary>
public interface ISiteScanner
{
    /// <summary>Runs the checks asked for over the site at the addresses given, already checked public, and reads back what they found; a check that could not run says why.</summary>
    Task<ScanOutcome> ScanAsync(Site site, IReadOnlyList<IPAddress> addresses, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken);
}
