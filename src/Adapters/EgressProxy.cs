using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Adapters;

/// <summary>The one door out of the scanners' network: an HTTP proxy that lets through only the hosts it names.</summary>
/// <remarks>
/// <para>
/// The scanners run on an internal network, so the only way out is this proxy, and it opens only the hosts their
/// databases and rules come from, and NuGet's, on ports 80 and 443. A scanner reads the task's code: nothing in that code
/// may reach anywhere else, and neither may a scanner that was told to.
/// </para>
/// <para>
/// It holds its own limits, as Snail.MCP.E2E's restore proxy does: a connection is refused once <see cref="MaxConnections"/>
/// are open, a request head must arrive within <see cref="HeadTimeout"/>, a host must answer within
/// <see cref="ConnectTimeout"/>, and a connection quiet both ways for <see cref="IdleTimeout"/> is closed. It held only the
/// head's limit before: a host that never answered, or a tunnel left open and silent, kept its socket for ever, and so
/// did any number of them at once. The head is read in blocks, and what came after it — a request's body — goes on to
/// the host instead of being dropped.
/// </para>
/// <para>
/// A tunnel is piped both ways; a plain request is not, since the next request on its connection may name another host:
/// it carries one request, its host told to close after it (see <c>ForwardAsync</c>).
/// </para>
/// </remarks>
public sealed class EgressProxy(IOptions<SecurityOptions> options, ILogger<EgressProxy> logger) : BackgroundService
{
    /// <summary>The longest request head read before the request is refused.</summary>
    internal const int MaxHeadBytes = 16 * 1024;

    private const int CopyBytes = 81920;

    private TcpListener? _listener;
    private SemaphoreSlim? _slots;

    /// <summary>The port the proxy listens on, once it does; zero before it starts or when it is off.</summary>
    public int Port { get; private set; }

    /// <summary>Most connections open at once; one more is answered 503 and closed.</summary>
    internal int MaxConnections { get; init; } = 256;

    /// <summary>How long a connection may take to say where it goes before it is dropped.</summary>
    internal TimeSpan HeadTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>How long a host has to accept the connection.</summary>
    internal TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>How long a connection may pass nothing either way before it is closed.</summary>
    internal TimeSpan IdleTimeout { get; init; } = TimeSpan.FromMinutes(2);

    /// <summary>The ports a host is reached at: the web's; a test names the port of a host of its own.</summary>
    internal IReadOnlyCollection<int> WebPorts { get; init; } = [80, 443];

    /// <summary>Whether a request for this host and port may go through.</summary>
    public static bool Allows(IReadOnlyCollection<string> hosts, string host, int port) =>
        Allows(hosts, [80, 443], host, port);

    /// <summary>Whether a request for this host and port may go through, the host reached at one of <paramref name="ports"/>.</summary>
    internal static bool Allows(IReadOnlyCollection<string> hosts, IReadOnlyCollection<int> ports, string host, int port) =>
        ports.Contains(port) && hosts.Contains(host, StringComparer.OrdinalIgnoreCase);

    /// <summary>The head of a request and whatever arrived after it, or null while the head has not ended.</summary>
    internal static Head? Split(ReadOnlySpan<byte> read)
    {
        int end = read.IndexOf("\r\n\r\n"u8);
        if (end < 0)
            return null;

        int headEnd = end + 4;

        return new Head(read[..headEnd].ToArray(), read[headEnd..].ToArray());
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (options.Value.ProxyPort <= 0)
            return;

        _slots = new SemaphoreSlim(MaxConnections, MaxConnections);
        _listener = new TcpListener(IPAddress.Any, options.Value.ProxyPort);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        Log.ProxyListening(logger, Port);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client = await _listener.AcceptTcpClientAsync(stoppingToken);
                bool hasSlot = await _slots.WaitAsync(0, stoppingToken);

                _ = hasSlot ? ServeAsync(client, _slots, stoppingToken) : RefuseBusyAsync(client, stoppingToken);
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
        _slots?.Dispose();
        base.Dispose();
    }

    private async Task ServeAsync(TcpClient client, SemaphoreSlim slots, CancellationToken cancellationToken)
    {
        using (client)
        {
            try
            {
                NetworkStream stream = client.GetStream();

                if (await HeadAsync(stream, cancellationToken) is not { } head)
                    return;

                if (Request.Of(head.Bytes) is not { } request)
                {
                    await RefuseAsync(stream, "400 Bad Request", cancellationToken);
                    return;
                }

                if (!Allows(options.Value.ProxyHosts, WebPorts, request.Host, request.Port))
                {
                    Log.ProxyRefused(logger, request.Host, request.Port);
                    await RefuseAsync(stream, "403 Forbidden", cancellationToken);
                    return;
                }

                long? bodyLength = request.IsTunnel ? 0 : Request.BodyLength(head.Bytes);
                if (bodyLength is not { } length)
                {
                    await RefuseAsync(stream, "411 Length Required", cancellationToken);
                    return;
                }

                await ForwardAsync(stream, request, head, length, cancellationToken);
            }
            catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException)
            {
                Log.ProxyConnectionEnded(logger, exception);
            }
            finally
            {
                slots.Release();
            }
        }
    }

    private static async Task RefuseBusyAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            try
            {
                await RefuseAsync(client.GetStream(), "503 Service Unavailable", cancellationToken);
            }
            catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task<Head?> HeadAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        using var reading = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        reading.CancelAfter(HeadTimeout);

        var buffer = new byte[MaxHeadBytes];
        int filled = 0;

        while (filled < buffer.Length)
        {
            int got = await stream.ReadAsync(buffer.AsMemory(filled), reading.Token);
            if (got == 0)
                return null;

            filled += got;

            if (Split(buffer.AsSpan(0, filled)) is { } head)
                return head;
        }

        return null;
    }

    /// <summary>Joins the connection to the host it asked for: a tunnel both ways, a plain request for its one answer.</summary>
    /// <remarks>
    /// A tunnel is TLS to the host it named, so whatever passes through it can only be for that host. A plain request is
    /// not: once the proxy piped the connection raw, the next request on it — kept alive or pipelined — went to the
    /// address of the first host whatever host it named, unchecked (Go's net/http, Trivy's, reuses one proxy connection
    /// for plain requests to different hosts). So a plain connection carries one request: the host is told to close after
    /// it (<c>Connection: close</c>), hears its body as long as <c>Content-Length</c> says and nothing after it, and the
    /// answer is copied back until the host closes. The client's next request finds the connection closed and opens
    /// another, whose head is checked like the first.
    /// </remarks>
    private async Task ForwardAsync(NetworkStream stream, Request request, Head head, long bodyLength, CancellationToken cancellationToken)
    {
        using var upstream = new TcpClient();

        using (var connecting = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            connecting.CancelAfter(ConnectTimeout);
            await upstream.ConnectAsync(request.Host, request.Port, connecting.Token);
        }

        NetworkStream far = upstream.GetStream();

        if (request.IsTunnel)
        {
            await stream.WriteAsync("HTTP/1.1 200 Connection established\r\n\r\n"u8.ToArray(), cancellationToken);

            if (head.Rest.Length > 0)
                await far.WriteAsync(head.Rest, cancellationToken);

            await PumpAsync(stream, far, bothWays: true, cancellationToken);
            return;
        }

        await far.WriteAsync(request.Forwarded(head.Bytes), cancellationToken);
        await BodyAsync(stream, far, head.Rest, bodyLength, cancellationToken);
        await PumpAsync(stream, far, bothWays: false, cancellationToken);
    }

    /// <summary>Sends the host the body of a plain request: what came with the head, then the rest of its length from the client.</summary>
    private async Task BodyAsync(NetworkStream near, NetworkStream far, byte[] rest, long length, CancellationToken cancellationToken)
    {
        int already = (int)Math.Min(rest.Length, length);
        if (already > 0)
            await far.WriteAsync(rest.AsMemory(0, already), cancellationToken);

        long left = length - already;
        var buffer = new byte[CopyBytes];
        using var reading = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        while (left > 0)
        {
            reading.CancelAfter(IdleTimeout);

            int got = await near.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, left)), reading.Token);
            if (got == 0)
                return;

            await far.WriteAsync(buffer.AsMemory(0, got), cancellationToken);
            left -= got;
        }
    }

    /// <summary>Copies until either side ends or nothing passes for the idle span: both ways for a tunnel, the host's answer alone for a plain request.</summary>
    /// <remarks>
    /// Once one direction ends, the others are cancelled and awaited before the upstream socket is disposed: a copy left
    /// running on a disposed socket threw unobserved (CA2025).
    /// </remarks>
    private async Task PumpAsync(NetworkStream near, NetworkStream far, bool bothWays, CancellationToken cancellationToken)
    {
        using var open = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var traffic = new Traffic();

        Task outbound = bothWays ? CopyAsync(near, far, traffic, open.Token) : Task.Delay(Timeout.Infinite, open.Token);
        Task inbound = CopyAsync(far, near, traffic, open.Token);
        Task quiet = QuietAsync(traffic, open.Token);

        await Task.WhenAny(outbound, inbound, quiet);
        await open.CancelAsync();

        await EndedAsync(outbound);
        await EndedAsync(inbound);
        await EndedAsync(quiet);
    }

    private static async Task CopyAsync(NetworkStream from, NetworkStream to, Traffic traffic, CancellationToken cancellationToken)
    {
        var buffer = new byte[CopyBytes];
        int got;

        while ((got = await from.ReadAsync(buffer, cancellationToken)) > 0)
        {
            await to.WriteAsync(buffer.AsMemory(0, got), cancellationToken);
            traffic.Passed();
        }
    }

    /// <summary>Ends once nothing has passed for the idle span.</summary>
    private async Task QuietAsync(Traffic traffic, CancellationToken cancellationToken)
    {
        var look = TimeSpan.FromTicks(Math.Max(IdleTimeout.Ticks / 4, TimeSpan.TicksPerMillisecond));

        while (traffic.QuietFor < IdleTimeout)
            await Task.Delay(look, cancellationToken);
    }

    /// <summary>Waits for a task that was told to stop; how it stopped is the connection's end, not a failure.</summary>
    private static async Task EndedAsync(Task stopped)
    {
        try
        {
            await stopped;
        }
        catch (Exception exception) when (exception is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
            return;
        }
    }

    private static Task RefuseAsync(NetworkStream stream, string status, CancellationToken cancellationToken) =>
        stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), cancellationToken).AsTask();

    /// <summary>A request's head as read, and the bytes that came after it in the same reads.</summary>
    internal sealed record Head(byte[] Bytes, byte[] Rest);

    /// <summary>When anything last passed through a connection, either way.</summary>
    private sealed class Traffic
    {
        private long _last = Environment.TickCount64;

        public TimeSpan QuietFor => TimeSpan.FromMilliseconds(Environment.TickCount64 - Interlocked.Read(ref _last));

        public void Passed() => Interlocked.Exchange(ref _last, Environment.TickCount64);
    }

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

        /// <summary>The length of a plain request's body: its Content-Length, none without one, and null when no length can be trusted.</summary>
        /// <remarks>
        /// A chunked body, or a Content-Length that is not one number, ends where the host decides, and the proxy could not
        /// tell where the next request begins: such a request is refused rather than piped.
        /// </remarks>
        public static long? BodyLength(byte[] head)
        {
            long? length = 0;
            bool seen = false;

            foreach (var (name, value) in Fields(head))
            {
                if (string.Equals(name, "Transfer-Encoding", StringComparison.OrdinalIgnoreCase))
                    return null;

                if (!string.Equals(name, "Content-Length", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (!long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var stated) || (seen && stated != length))
                    return null;

                length = stated;
                seen = true;
            }

            return length;
        }

        /// <summary>The head as the host expects it: the path instead of the whole address, nothing meant for the proxy, and the connection closed after it.</summary>
        public byte[] Forwarded(byte[] head)
        {
            string[] lines = Encoding.ASCII.GetString(head).Split("\r\n");
            string[] first = lines[0].Split(' ');
            var target = new Uri(Target);
            IEnumerable<string> kept = lines
                .Skip(1)
                .TakeWhile(line => line.Length > 0)
                .Where(line => !IsHopByHop(line));

            return Encoding.ASCII.GetBytes(string.Join("\r\n", [$"{first[0]} {target.PathAndQuery} {first[2]}", .. kept, "Connection: close", "", ""]));
        }

        private static bool IsHopByHop(string line) =>
            line.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Connection:", StringComparison.OrdinalIgnoreCase)
            || line.StartsWith("Keep-Alive:", StringComparison.OrdinalIgnoreCase);

        private static IEnumerable<(string Name, string Value)> Fields(byte[] head)
        {
            foreach (string line in Encoding.ASCII.GetString(head).Split("\r\n").Skip(1))
            {
                int colon = line.IndexOf(':', StringComparison.Ordinal);
                if (colon > 0)
                    yield return (line[..colon].Trim(), line[(colon + 1)..].Trim());
            }
        }
    }
}
