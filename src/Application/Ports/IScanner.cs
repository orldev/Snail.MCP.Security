namespace Snail.MCP.Security.Application.Ports;

/// <summary>Where the scanners run over a working copy.</summary>
public interface IScanner
{
    /// <summary>Runs the checks asked for over the copy and reads back what they found; a check that could not run says why.</summary>
    Task<ScanOutcome> ScanAsync(CopyPlace copy, IReadOnlyCollection<Check> checks, CancellationToken cancellationToken);

    /// <summary>The version of the scheduler that answered, or why none did.</summary>
    Task<Answer<string>> ReachAsync(CancellationToken cancellationToken);
}
