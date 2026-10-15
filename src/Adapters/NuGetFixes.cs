using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Snail.MCP.Security.Application.Ports;

namespace Snail.MCP.Security.Adapters;

/// <summary>The fixing versions of NuGet advisories, from NuGet's own vulnerability data, read once every few hours.</summary>
/// <remarks>
/// <c>dotnet list package --vulnerable</c> names an advisory but not the version that fixes it, and Trivy, which would,
/// does not read a project file without a lock file. NuGet publishes every advisory with the range of versions it
/// affects — <c>(, 13.0.1)</c> for Newtonsoft.Json's GHSA-5crp-9r3c-p9vr — and an excluded upper bound is the first
/// version without it. The data is about six hundred packages in two files, read by the server, not by a scanner.
/// </remarks>
public sealed class NuGetFixes(IHttpClientFactory clients, TimeProvider clock) : IFixes, IDisposable
{
    /// <summary>Name of the HTTP client this adapter is given.</summary>
    public const string Client = "nuget";

    /// <summary>NuGet's vulnerability resource.</summary>
    public static readonly Uri Index = new("https://api.nuget.org/v3/vulnerabilities/index.json");

    /// <summary>How long the data is kept before it is read again.</summary>
    public static readonly TimeSpan Kept = TimeSpan.FromHours(6);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private IReadOnlyDictionary<string, string>? _ranges;
    private DateTimeOffset _readAt;

    /// <inheritdoc />
    public async Task<string?> FixedInAsync(string package, string advisory, CancellationToken cancellationToken)
    {
        var ranges = await RangesAsync(cancellationToken);

        return ranges.TryGetValue(KeyOf(package, advisory), out var range) ? FixedIn(range) : null;
    }

    /// <summary>The first version outside a NuGet range, when its upper bound is excluded: <c>(, 13.0.1)</c> is fixed in 13.0.1.</summary>
    public static string? FixedIn(string range)
    {
        string trimmed = range.Trim();
        if (!trimmed.EndsWith(')'))
            return null;

        string upper = trimmed.TrimEnd(')').Split(',').Last().Trim();

        return upper.Length > 0 ? upper : null;
    }

    /// <summary>Every package's advisories in one NuGet vulnerability file, by package and GHSA.</summary>
    public static IEnumerable<KeyValuePair<string, string>> RangesIn(JsonNode? file)
    {
        if (file is not JsonObject packages)
            yield break;

        foreach (var (package, advisories) in packages)
        {
            foreach (var advisory in advisories as JsonArray ?? [])
            {
                string? url = (string?)advisory?["url"];
                string? range = (string?)advisory?["versions"];
                string? ghsa = url?.Split('/').LastOrDefault(part => part.StartsWith("GHSA-", StringComparison.Ordinal));

                if (ghsa is not null && range is not null)
                    yield return KeyValuePair.Create(KeyOf(package, ghsa), range);
            }
        }
    }

    /// <summary>Releases the gate.</summary>
    public void Dispose() => _gate.Dispose();

    private async Task<IReadOnlyDictionary<string, string>> RangesAsync(CancellationToken cancellationToken)
    {
        if (_ranges is { } fresh && clock.GetUtcNow() - _readAt < Kept)
            return fresh;

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (_ranges is { } read && clock.GetUtcNow() - _readAt < Kept)
                return read;

            _ranges = await ReadAsync(cancellationToken) ?? _ranges ?? new Dictionary<string, string>();
            _readAt = clock.GetUtcNow();

            return _ranges;
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<IReadOnlyDictionary<string, string>?> ReadAsync(CancellationToken cancellationToken)
    {
        try
        {
            using var client = clients.CreateClient(Client);
            var index = JsonNode.Parse(await client.GetStringAsync(Index, cancellationToken)) as JsonArray ?? [];
            Dictionary<string, string> ranges = new(StringComparer.Ordinal);

            foreach (string? file in index.Select(entry => (string?)entry?["@id"]))
            {
                if (file is null)
                    continue;

                foreach (var (key, range) in RangesIn(JsonNode.Parse(await client.GetStringAsync(file, cancellationToken))))
                    ranges[key] = range;
            }

            return ranges;
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    private static string KeyOf(string package, string advisory) => $"{package.ToLowerInvariant()}|{advisory}";

    /// <summary>The handler NuGet's files need: they come gzipped.</summary>
    public static HttpMessageHandler Handler() => new SocketsHttpHandler { AutomaticDecompression = DecompressionMethods.All };
}
