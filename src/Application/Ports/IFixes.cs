namespace Snail.MCP.Security.Application.Ports;

/// <summary>The versions that fix a package's advisories, from the package registry's own data.</summary>
public interface IFixes
{
    /// <summary>The first version without the advisory; null when the registry does not say or cannot be reached.</summary>
    Task<string?> FixedInAsync(string package, string advisory, CancellationToken cancellationToken);
}
