namespace Snail.MCP.Security.Application.Ports;

/// <summary>The server's own secret the ownership codes are made with.</summary>
public interface IProofKey
{
    /// <summary>The secret's bytes; made once and kept, so a domain's code stays the same across restarts.</summary>
    byte[] Bytes { get; }
}
