using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting;

namespace Snail.MCP.Security.Adapters;

/// <summary>The ownership secret in the server's data folder: 32 random bytes made on first use and kept, readable by the server alone.</summary>
/// <remarks>
/// A new secret changes every domain's code, and every customer would have to publish theirs again; so it is made once and
/// never rotated by the server. <see cref="ServerSecret"/> keeps it: readable by the server alone from its first byte,
/// moved into place whole by one instance at a time, and a file of another length refused rather than used or replaced.
/// The refusal names this server's consequence beside the SDK's words: the codes it would invalidate are TXT records
/// customers published, and each of them would have to publish a new one.
/// It stays a <see cref="StartRefusedException"/>, as the SDK's is, so a program that reads the key at its start says
/// the sentence on stderr and exits with 1 instead of crashing with a trace.
/// </remarks>
public sealed class FileProofKey(string file) : IProofKey
{
    /// <summary>How many bytes a key is.</summary>
    public const int Length = 32;

    private readonly Lazy<byte[]> _bytes = new(() => Read(file));

    /// <summary>The key in the server's own data folder.</summary>
    public static FileProofKey InDataFolder() => new(Path.Combine(ServerFolders.DataDirectory(SecuritySettings.Name), "proof.key"));

    /// <inheritdoc />
    public byte[] Bytes => _bytes.Value;

    private static byte[] Read(string file)
    {
        try
        {
            return ServerSecret.ReadOrCreate(file, Length);
        }
        catch (ServerSecretRefusedException refused)
        {
            throw new StartRefusedException(Messages.KeyRefused(refused.Message), refused);
        }
    }
}
