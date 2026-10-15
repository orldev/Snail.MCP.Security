using System.Security.Cryptography;
using Snail.MCP.Security.Application.Ports;
using Snail.Sdk.Mcp.Hosting;

namespace Snail.MCP.Security.Adapters;

/// <summary>The ownership secret in the server's data folder: 32 random bytes made on first use and kept, readable by the server alone.</summary>
/// <remarks>A new secret changes every domain's code, and every customer would have to publish theirs again; so it is made once and never rotated by the server.</remarks>
public sealed class FileProofKey(string file) : IProofKey
{
    private readonly Lazy<byte[]> _bytes = new(() => Load(file));

    /// <summary>The key in the server's own data folder.</summary>
    public static FileProofKey InDataFolder() => new(Path.Combine(ServerFolders.DataDirectory("security"), "proof.key"));

    /// <inheritdoc />
    public byte[] Bytes => _bytes.Value;

    private static byte[] Load(string file)
    {
        if (File.Exists(file))
            return File.ReadAllBytes(file);

        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        byte[] made = RandomNumberGenerator.GetBytes(32);
        File.WriteAllBytes(file, made);

        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        return made;
    }
}
