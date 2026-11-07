using Snail.MCP.Security.Adapters;
using Snail.Sdk.Mcp.Testing;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>The ownership key: made once, readable by the server alone, the same for every instance, and never replaced by a broken file.</summary>
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

    /// <summary>Two instances starting together used to write a key each, the second over the first.</summary>
    [Fact]
    public async Task Bytes_ManyInstancesAtOnce_AgreeOnOneKey()
    {
        var reads = Enumerable.Range(0, 16).Select(_ => Task.Run(() => new FileProofKey(KeyFile).Bytes));

        byte[][] keys = await Task.WhenAll(reads);

        Assert.All(keys, key => Assert.Equal(keys[0], key));
        Assert.Equal(keys[0], File.ReadAllBytes(KeyFile));
        Assert.Single(Directory.GetFiles(Path.GetDirectoryName(KeyFile)!));
    }

    /// <summary>A file cut short used to be taken as the key; a new key would change every domain's code, so it is refused instead.</summary>
    [Fact]
    public void Bytes_FileOfAnotherLength_IsRefusedAndKept()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(KeyFile)!);
        File.WriteAllBytes(KeyFile, [1, 2, 3]);

        var refusal = Assert.Throws<InvalidOperationException>(() => new FileProofKey(KeyFile).Bytes);

        Assert.Contains("3 bytes instead of 32", refusal.Message, StringComparison.Ordinal);
        Assert.Equal([1, 2, 3], File.ReadAllBytes(KeyFile));
    }
}
