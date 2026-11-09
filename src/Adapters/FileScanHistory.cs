using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using Snail.MCP.Security.Application.Ports;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Hosting;

namespace Snail.MCP.Security.Adapters;

/// <summary>Each task's last scan as a JSON file in the server's data folder, so a restart does not forget what was found.</summary>
public sealed class FileScanHistory(string folder) : IScanHistory
{
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _gates = new(StringComparer.Ordinal);

    /// <summary>The history in the server's own data folder.</summary>
    public static FileScanHistory InDataFolder() => new(Path.Combine(ServerFolders.DataDirectory(SecuritySettings.Name), "scans"));

    /// <inheritdoc />
    public async Task<ScanReport?> LastAsync(string task, CancellationToken cancellationToken)
    {
        string file = FileOf(task);
        if (!File.Exists(file))
            return null;

        await using var stream = File.OpenRead(file);

        return await JsonSerializer.DeserializeAsync(stream, ScanJson.Default.ScanReport, cancellationToken);
    }

    /// <inheritdoc />
    public async Task SaveAsync(string task, ScanReport report, CancellationToken cancellationToken)
    {
        var gate = _gates.GetOrAdd(task, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(folder);
            string written = $"{FileOf(task)}.{Guid.NewGuid():N}";
            await File.WriteAllTextAsync(written, JsonSerializer.Serialize(report, ScanJson.Default.ScanReport), cancellationToken);
            File.Move(written, FileOf(task), overwrite: true);
        }
        finally
        {
            gate.Release();
        }
    }

    private string FileOf(string task) => Path.Combine(folder, $"{task}.json");
}

/// <summary>A scan as it is kept, read and written without reflection.</summary>
[JsonSourceGenerationOptions(UseStringEnumConverter = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(ScanReport))]
public sealed partial class ScanJson : JsonSerializerContext;
