using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Adapters;

/// <summary>The one door out of the scanners' network: an HTTP proxy that lets through only the hosts it names.</summary>
/// <remarks>
/// The scanners run on an internal network, so the only way out is this proxy, and it opens only the hosts their
/// databases and rules come from, and NuGet's, on ports 80 and 443. A scanner reads the task's code: nothing in that code
/// may reach anywhere else, and neither may a scanner that was told to.
/// </remarks>
public sealed class EgressProxy(IOptions<SecurityOptions> options, ILogger<EgressProxy> logger) : BackgroundService
{
    /// <summary>The longest request head read before the request is refused.</summary>
    internal const int MaxHeadBytes = 16 * 1024;

    /// <summary>How long a connection may take to say where it goes before it is dropped.</summary>
    internal static readonly TimeSpan HeadTimeout = TimeSpan.FromSeconds(30);

    private TcpListener? _listener;

    /// <summary>The port the proxy listens on, once it does; zero before it starts or when it is off.</summary>
    public int Port { get; private set; }

    /// <summary>Whether a request for this host and port may go through.</summary>
    public static bool Allows(IReadOnlyCollection<string> hosts, string host, int port) =>
        port is 80 or 443 && hosts.Contains(host, StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.Value.ProxyPort <= 0)
            return;

        _listener = new TcpListener(IPAddress.Any, options.Value.ProxyPort);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Log.ProxyListening(logger, Port);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(stoppingToken);
                _ = ServeAsync(client, stoppingToken);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            _listener.Stop();
        }
    }

    /// <summary>Releases the listener with the service; it was stopped already when the service stopped.</summary>
    public override void Dispose()
    {
        _listener?.Dispose();
        base.Dispose();
    }

    private async Task ServeAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            try
            {
                NetworkStream stream = client.GetStream();
                using var heading = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                heading.CancelAfter(HeadTimeout);

                if (await HeadAsync(stream, heading.Token) is not { } head)
                    return;

                if (Request.Of(head) is not { } request)
                {
                    await RefuseAsync(stream, "400 Bad Request", cancellationToken);
                    return;
                }

                if (!Allows(options.Value.ProxyHosts, request.Host, request.Port))
                {
                    Log.ProxyRefused(logger, request.Host, request.Port);
                    await RefuseAsync(stream, "403 Forbidden", cancellationToken);
                    return;
                }

                await ForwardAsync(stream, request, head, cancellationToken);
            }
            catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException)
            {
                Log.ProxyConnectionEnded(logger, exception);
            }
        }
    }

    /// <summary>Joins the connection to the host it asked for, both ways, until either side ends.</summary>
    /// <remarks>
    /// Once one direction ends, the other is cancelled and awaited before the upstream socket is disposed: it used to be
    /// left copying on a socket already disposed, its exception unobserved (CA2025).
    /// </remarks>
    private static async Task ForwardAsync(NetworkStream stream, Request request, byte[] head, CancellationToken cancellationToken)
    {
        using var upstream = new TcpClient();
        await upstream.ConnectAsync(request.Host, request.Port, cancellationToken);
        NetworkStream far = upstream.GetStream();

        if (request.IsTunnel)
            await stream.WriteAsync("HTTP/1.1 200 Connection established\r\n\r\n"u8.ToArray(), cancellationToken);
        else
            await far.WriteAsync(request.Forwarded(head), cancellationToken);

        using var both = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task outbound = stream.CopyToAsync(far, both.Token);
        Task inbound = far.CopyToAsync(stream, both.Token);

        await Task.WhenAny(outbound, inbound);
        await both.CancelAsync();

        await EndedAsync(outbound);
        await EndedAsync(inbound);
    }

    /// <summary>Waits for a copy that was told to stop; how it stopped is the connection's end, not a failure.</summary>
    private static async Task EndedAsync(Task copy)
    {
        try
        {
            await copy;
        }
        catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            return;
        }
    }

    private static async Task<byte[]?> HeadAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        List<byte> read = [];
        var one = new byte[1];

        while (read.Count < MaxHeadBytes)
        {
            if (await stream.ReadAsync(one, cancellationToken) == 0)
                return null;

            read.Add(one[0]);
            if (read.Count >= 4 && read[^4] == '\r' && read[^3] == '\n' && read[^2] == '\r' && read[^1] == '\n')
                return [.. read];
        }

        return null;
    }

    private static Task RefuseAsync(NetworkStream stream, string status, CancellationToken cancellationToken) =>
        stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), cancellationToken).AsTask();

    /// <summary>One request as the proxy reads it: where it goes, and whether it is a tunnel.</summary>
    internal sealed record Request(string Host, int Port, bool IsTunnel, string Target)
    {
        /// <summary>The request read from its head; null when it is neither a tunnel nor a request for an absolute address.</summary>
        public static Request? Of(byte[] head)
        {
            string[] lines = Encoding.ASCII.GetString(head).Split("\r\n");
            string[] first = lines[0].Split(' ');
            if (first.Length != 3)
                return null;

            if (string.Equals(first[0], "CONNECT", StringComparison.OrdinalIgnoreCase))
            {
                int colon = first[1].LastIndexOf(':');

                return colon > 0 && int.TryParse(first[1][(colon + 1)..], out var port)
                    ? new Request(first[1][..colon].Trim('[', ']'), port, true, first[1])
                    : null;
            }

            return Uri.TryCreate(first[1], UriKind.Absolute, out var target) && target.Scheme == Uri.UriSchemeHttp
                ? new Request(target.Host, target.Port, false, first[1])
                : null;
        }

        /// <summary>The head as the host expects it: the path instead of the whole address, and nothing meant for the proxy.</summary>
        public byte[] Forwarded(byte[] head)
        {
            string[] lines = Encoding.ASCII.GetString(head).Split("\r\n");
            string[] first = lines[0].Split(' ');
            var target = new Uri(Target);
            IEnumerable<string> kept = lines.Skip(1).Where(line => !line.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase));

            return Encoding.ASCII.GetBytes(string.Join("\r\n", [$"{first[0]} {target.PathAndQuery} {first[2]}", .. kept]));
        }
    }
}
