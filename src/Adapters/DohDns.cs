using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Snail.MCP.Security.Application.Ports;

namespace Snail.MCP.Security.Adapters;

/// <summary>The public DNS through two DNS-over-HTTPS resolvers, Cloudflare's and Google's, which have to agree.</summary>
/// <remarks>
/// Two vantage points, as the IETF draft on domain verification advises: one poisoned or stale answer does not prove a
/// domain. .NET's own resolver reads no TXT before .NET 11, and the DoH JSON API needs no package. The two write TXT
/// differently — Cloudflare in presentation form, each string quoted, a long record as «"…" "…"»; Google unquoted and
/// joined — so each value is brought to one string per record before they are compared.
/// </remarks>
public sealed partial class DohDns(IHttpClientFactory clients) : ISiteDns
{
    /// <summary>Name of the HTTP client this adapter is given.</summary>
    public const string Client = "doh";

    /// <summary>The resolvers asked, each a DoH JSON endpoint.</summary>
    public static readonly Uri[] Resolvers = [new("https://cloudflare-dns.com/dns-query"), new("https://dns.google/resolve")];

    private const int Txt = 16;
    private const int A = 1;
    private const int Aaaa = 28;

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>?> TextsAsync(string name, CancellationToken cancellationToken)
    {
        List<IReadOnlyList<string>> answers = [];

        foreach (var resolver in Resolvers)
        {
            if (await AskAsync(resolver, name, Txt, cancellationToken) is not { } records)
                return null;

            answers.Add([.. records.Select(Text).Order(StringComparer.Ordinal)]);
        }

        return answers.All(answer => answer.SequenceEqual(answers[0], StringComparer.Ordinal)) ? answers[0] : null;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<IPAddress>?> AddressesAsync(string name, CancellationToken cancellationToken)
    {
        HashSet<IPAddress> found = [];

        foreach (var resolver in Resolvers)
        {
            foreach (int type in (int[])[A, Aaaa])
            {
                if (await AskAsync(resolver, name, type, cancellationToken) is not { } records)
                    return null;

                found.UnionWith(records.Select(record => IPAddress.TryParse(record, out var address) ? address : null).OfType<IPAddress>());
            }
        }

        return [.. found];
    }

    /// <summary>One TXT record as one string: a presentation-form value has its quoted strings joined; a plain one stands as it is.</summary>
    public static string Text(string data)
    {
        string trimmed = data.Trim();
        if (!trimmed.StartsWith('"'))
            return trimmed;

        return string.Concat(Quoted().Matches(trimmed).Select(match => match.Groups[1].Value.Replace("\\\"", "\"", StringComparison.Ordinal)));
    }

    /// <summary>The records of one type a resolver answers for the name: empty for a name without them, null when it did not answer.</summary>
    public static IReadOnlyList<string>? Records(string json, int type)
    {
        JsonNode? answer;
        try
        {
            answer = JsonNode.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }

        int? status = (int?)answer?["Status"];
        if (status is not (0 or 3))
            return null;

        return [.. (answer?["Answer"] as JsonArray ?? []).Where(record => (int?)record?["type"] == type).Select(record => (string?)record?["data"] ?? string.Empty)];
    }

    private async Task<IReadOnlyList<string>?> AskAsync(Uri resolver, string name, int type, CancellationToken cancellationToken)
    {
        try
        {
            using var client = clients.CreateClient(Client);
            using var request = new HttpRequestMessage(HttpMethod.Get, new Uri($"{resolver}?name={Uri.EscapeDataString(name)}&type={type}"));
            request.Headers.Accept.ParseAdd("application/dns-json");
            using var response = await client.SendAsync(request, cancellationToken);

            return response.IsSuccessStatusCode ? Records(await response.Content.ReadAsStringAsync(cancellationToken), type) : null;
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException && !cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }

    [GeneratedRegex("\"((?:[^\"\\\\]|\\\\.)*)\"")]
    private static partial Regex Quoted();
}
