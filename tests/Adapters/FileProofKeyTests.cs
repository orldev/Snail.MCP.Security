using Snail.MCP.Security.Adapters;
using Snail.Sdk.Mcp.Hosting;
using Snail.Sdk.Mcp.Testing;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>The ownership key: made once, readable by the server alone, the same for every instance, and never replaced by a broken file.</summary>
/// <remarks>Many instances starting at once agree on one key: <c>ServerSecret</c> of Snail.Sdk.Mcp.Hosting holds that, and its own tests prove it.</remarks>
public sealed class FileProofKeyTests : IDisposable
{
    private readonly string _folder = TestFolder.Create();

    private string KeyFile => Path.Combine(_folder, "data", "proof.key");

    public void Dispose() => Directory.Delete(_folder, recursive: true);

    [Fact]
    public void Bytes_FirstUse_MakesAKeyOnlyTheServerReads()
    {
        byte[] key = new FileProofKey(KeyFile).Bytes;

        Assert.Equal(FileProofKey.Length, key.Length);
        Assert.Equal(key, File.ReadAllBytes(KeyFile));

        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(KeyFile));
    }

    [Fact]
    public void Bytes_KeyAlreadyKept_IsTheSameForANewInstance()
    {
        byte[] first = new FileProofKey(KeyFile).Bytes;

        byte[] second = new FileProofKey(KeyFile).Bytes;

        Assert.Equal(first, second);
    }

    /// <summary>A file cut short used to be taken as the key; a new key would change every domain's code, so it is refused instead, saying so.</summary>
    [Fact]
    public void Bytes_FileOfAnotherLength_IsRefusedAndKept()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(KeyFile)!);
        File.WriteAllBytes(KeyFile, [1, 2, 3]);

        var refusal = Assert.Throws<StartRefusedException>(() => new FileProofKey(KeyFile).Bytes);

        Assert.Contains("3 bytes instead of 32", refusal.Message, StringComparison.Ordinal);
        Assert.Contains("publish its TXT record again", refusal.Message, StringComparison.Ordinal);
        Assert.IsType<ServerSecretRefusedException>(refusal.InnerException);
        Assert.Equal([1, 2, 3], File.ReadAllBytes(KeyFile));
    }
}
