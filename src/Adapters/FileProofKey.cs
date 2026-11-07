using System.Security.Cryptography;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;
using Snail.Sdk.Mcp.Hosting;

namespace Snail.MCP.Security.Adapters;

/// <summary>The ownership secret in the server's data folder: 32 random bytes made on first use and kept, readable by the server alone.</summary>
/// <remarks>
/// <para>A new secret changes every domain's code, and every customer would have to publish theirs again; so it is made once and never rotated by the server.</para>
/// <para>
/// The key is written to a file of its own, created readable by the server alone, and moved into place only whole and
/// only when no key is there yet. It was written in place and closed to others afterwards: for a moment the key lay
/// readable under the process's umask, a second instance starting beside the first could overwrite a key already handed
/// out, and a file cut short was taken as the key. A file of any other length than a key's is now refused, not used.
/// </para>
/// </remarks>
public sealed class FileProofKey(string file) : IProofKey
{
    /// <summary>How many bytes a key is.</summary>
    public const int Length = 32;

    private readonly Lazy<byte[]> _bytes = new(() => Load(file));

    /// <summary>The key in the server's own data folder.</summary>
    public static FileProofKey InDataFolder() => new(Path.Combine(ServerFolders.DataDirectory("security"), "proof.key"));

    /// <inheritdoc />
    public byte[] Bytes => _bytes.Value;

    private static byte[] Load(string file)
    {
        if (!File.Exists(file))
            Make(file);

        byte[] kept = File.ReadAllBytes(file);

        if (kept.Length != Length)
            throw new InvalidOperationException(Messages.ProofKeyBroken(file, kept.Length, Length));

        return kept;
    }

    /// <summary>Puts a new key in place, unless another instance put one there first, in which case that one stands.</summary>
    private static void Make(string file)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        string draft = $"{file}.{Guid.NewGuid():N}.new";

        try
        {
            Write(draft, RandomNumberGenerator.GetBytes(Length));
            File.Move(draft, file, overwrite: false);
        }
        catch (IOException) when (File.Exists(file))
        {
            return;
        }
        finally
        {
            File.Delete(draft);
        }
    }

    /// <summary>Writes the key to a new file that only the server may read, from the moment it exists.</summary>
    private static void Write(string path, byte[] key)
    {
        var creating = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };

        if (!OperatingSystem.IsWindows())
            creating.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        using var stream = new FileStream(path, creating);
        stream.Write(key);
        stream.Flush(flushToDisk: true);
    }
}
