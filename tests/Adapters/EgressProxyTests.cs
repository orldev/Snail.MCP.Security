using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Configuration;
using Snail.Sdk.Mcp.Testing;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>The scanners' one door out: what it reads from a request, whom it lets through, and how it refuses the rest.</summary>
public sealed class EgressProxyTests
{
    private static readonly string[] Hosts = ["api.nuget.org", "mirror.gcr.io"];

    [Fact]
    public void RequestOf_Tunnel_IsTheHostAndPortItNames()
    {
        var request = EgressProxy.Request.Of(Encoding.ASCII.GetBytes("CONNECT api.nuget.org:443 HTTP/1.1\r\nHost: api.nuget.org:443\r\n\r\n"));

        Assert.Equal(("api.nuget.org", 443, true), (request?.Host, request?.Port, request?.IsTunnel));
    }

    [Fact]
    public void RequestOf_AbsoluteHttpAddress_IsItsHostAndPort()
    {
        var request = EgressProxy.Request.Of(Encoding.ASCII.GetBytes("GET http://mirror.gcr.io/v2/ HTTP/1.1\r\nHost: mirror.gcr.io\r\n\r\n"));

        Assert.Equal(("mirror.gcr.io", 80, false), (request?.Host, request?.Port, request?.IsTunnel));
    }

    [Theory]
    [InlineData("GET /v2/ HTTP/1.1\r\n\r\n")]
    [InlineData("GET https://mirror.gcr.io/ HTTP/1.1\r\n\r\n")]
    [InlineData("CONNECT api.nuget.org HTTP/1.1\r\n\r\n")]
    [InlineData("hello\r\n\r\n")]
    public void RequestOf_NeitherATunnelNorAnAbsoluteHttpAddress_IsNone(string head)
    {
        Assert.Null(EgressProxy.Request.Of(Encoding.ASCII.GetBytes(head)));
    }

    [Theory]
    [InlineData("api.nuget.org", 443, true)]
    [InlineData("API.NuGet.org", 80, true)]
    [InlineData("api.nuget.org", 22, false)]
    [InlineData("evil.example", 443, false)]
    [InlineData("nuget.org", 443, false)]
    public void Allows_HostAndPort_OnlyTheNamedHostsOnTheWebPorts(string host, int port, bool isAllowed)
    {
        Assert.Equal(isAllowed, EgressProxy.Allows(Hosts, host, port));
    }

    /// <summary>A host is asked for the path alone, and nothing meant for the proxy reaches it.</summary>
    [Fact]
    public void Forwarded_AbsoluteRequest_IsThePathWithoutTheProxysHeaders()
    {
        byte[] head = Encoding.ASCII.GetBytes("GET http://mirror.gcr.io/v2/?a=1 HTTP/1.1\r\nHost: mirror.gcr.io\r\nProxy-Authorization: Basic eA==\r\n\r\n");

        string forwarded = Encoding.ASCII.GetString(EgressProxy.Request.Of(head)!.Forwarded(head));

        Assert.StartsWith("GET /v2/?a=1 HTTP/1.1\r\nHost: mirror.gcr.io\r\n", forwarded, StringComparison.Ordinal);
        Assert.DoesNotContain("Proxy-", forwarded, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("CONNECT evil.example:443 HTTP/1.1\r\n\r\n", "HTTP/1.1 403 Forbidden")]
    [InlineData("CONNECT api.nuget.org:22 HTTP/1.1\r\n\r\n", "HTTP/1.1 403 Forbidden")]
    [InlineData("hello there\r\n\r\n", "HTTP/1.1 400 Bad Request")]
    public async Task Connection_ToAHostNotNamed_IsRefusedWithItsStatus(string head, string status)
    {
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var proxy = new EgressProxy(Options.Create(new SecurityOptions { ProxyPort = Ports.Free(), ProxyHosts = Hosts }), NullLogger<EgressProxy>.Instance);
        await proxy.StartAsync(stopping.Token);

        string answer = await AskAsync(proxy, head, stopping.Token);
        await proxy.StopAsync(CancellationToken.None);

        Assert.StartsWith(status, answer, StringComparison.Ordinal);
    }

    [Fact]
    public void Split_HeadWithABodyAfterIt_KeepsTheBodyToForward()
    {
        var head = EgressProxy.Split("POST http://api.nuget.org/x HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi"u8);

        Assert.EndsWith("\r\n\r\n", Encoding.ASCII.GetString(head!.Bytes), StringComparison.Ordinal);
        Assert.Equal("hi", Encoding.ASCII.GetString(head.Rest));
    }

    [Fact]
    public void Split_HeadNotEndedYet_IsNull()
    {
        Assert.Null(EgressProxy.Split("CONNECT api.nuget.org:443 HTTP/1.1\r\nHost: x\r\n"u8));
    }

    /// <summary>A client that connected and sent nothing used to hold its socket until the head's limit, and any number of them at once.</summary>
    [Fact]
    public async Task Connection_ThatSendsNoHead_IsClosedOnceTheHeadTimeoutPasses()
    {
        using var proxy = Limited(maxConnections: 4);
        await proxy.StartAsync(CancellationToken.None);
        using var client = await ConnectAsync(proxy);

        int got = await client.GetStream().ReadAsync(new byte[16]).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await proxy.StopAsync(CancellationToken.None);

        Assert.Equal(0, got);
    }

    [Fact]
    public async Task Connection_OnePastTheLimit_IsAnswered503()
    {
        using var proxy = Limited(maxConnections: 1);
        await proxy.StartAsync(CancellationToken.None);
        using var holding = await ConnectAsync(proxy);
        await Task.Delay(100);
        using var extra = await ConnectAsync(proxy);

        var buffer = new byte[256];
        int got = await extra.GetStream().ReadAsync(buffer).AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await proxy.StopAsync(CancellationToken.None);

        Assert.StartsWith("HTTP/1.1 503", Encoding.ASCII.GetString(buffer, 0, got), StringComparison.Ordinal);
    }

    /// <summary>
    /// A plain request used to open a raw pipe to its host: a second request on the same connection, kept alive or
    /// pipelined, went to that host's address unchecked, whatever host it named. The host now hears one request, told to
    /// close after it, and nothing that came after it.
    /// </summary>
    [Fact]
    public async Task PlainConnection_SecondRequestForAnotherHost_NeverReachesTheFirstHost()
    {
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var upstream = await Upstream.StartAsync(stopping.Token);
        using var proxy = Towards(upstream);
        await proxy.StartAsync(stopping.Token);

        string answer = await AskAsync(proxy,
            $"GET http://127.0.0.1:{upstream.Port}/a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n" +
            "GET http://evil.example/b HTTP/1.1\r\nHost: evil.example\r\n\r\n",
            stopping.Token);
        string heard = await upstream.HeardAsync();
        await proxy.StopAsync(CancellationToken.None);

        Assert.StartsWith("HTTP/1.1 200 OK", answer, StringComparison.Ordinal);
        Assert.StartsWith("GET /a HTTP/1.1\r\n", heard, StringComparison.Ordinal);
        Assert.Contains("\r\nConnection: close\r\n", heard, StringComparison.Ordinal);
        Assert.DoesNotContain("keep-alive", heard, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("evil.example", heard, StringComparison.Ordinal);
    }

    /// <summary>A plain request's body goes to the host as long as its Content-Length says, and no further.</summary>
    [Fact]
    public async Task PlainConnection_BodyOfItsLength_GoesToTheHostAndNothingAfterIt()
    {
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var upstream = await Upstream.StartAsync(stopping.Token);
        using var proxy = Towards(upstream);
        await proxy.StartAsync(stopping.Token);

        await AskAsync(proxy, $"POST http://127.0.0.1:{upstream.Port}/a HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\n\r\nhiGET /more HTTP/1.1\r\n\r\n", stopping.Token);
        string heard = await upstream.HeardAsync();
        await proxy.StopAsync(CancellationToken.None);

        Assert.EndsWith("\r\n\r\nhi", heard, StringComparison.Ordinal);
    }

    /// <summary>A body of no stated length cannot be told from the next request, so it is not taken.</summary>
    [Fact]
    public async Task PlainConnection_ChunkedBody_IsAnswered411()
    {
        using var stopping = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        await using var upstream = await Upstream.StartAsync(stopping.Token);
        using var proxy = Towards(upstream);
        await proxy.StartAsync(stopping.Token);

        string answer = await AskAsync(proxy, $"POST http://127.0.0.1:{upstream.Port}/a HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", stopping.Token);
        await proxy.StopAsync(CancellationToken.None);

        Assert.StartsWith("HTTP/1.1 411 Length Required", answer, StringComparison.Ordinal);
    }

    private static EgressProxy Towards(Upstream upstream) =>
        new(Options.Create(new SecurityOptions { ProxyPort = Ports.Free(), ProxyHosts = ["127.0.0.1"] }), NullLogger<EgressProxy>.Instance)
        {
            WebPorts = [upstream.Port]
        };

    private static EgressProxy Limited(int maxConnections) =>
        new(Options.Create(new SecurityOptions { ProxyPort = Ports.Free(), ProxyHosts = Hosts }), NullLogger<EgressProxy>.Instance)
        {
            MaxConnections = maxConnections,
            HeadTimeout = TimeSpan.FromMilliseconds(300)
        };

    private static async Task<TcpClient> ConnectAsync(EgressProxy proxy)
    {
        while (proxy.Port == 0)
            await Task.Delay(10);

        var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, proxy.Port);

        return client;
    }

    private static async Task<string> AskAsync(EgressProxy proxy, string head, CancellationToken cancellationToken)
    {
        while (proxy.Port == 0)
            await Task.Delay(10, cancellationToken);

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, proxy.Port, cancellationToken);
        NetworkStream stream = client.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(head), cancellationToken);

        using var reader = new StreamReader(stream, Encoding.ASCII);

        return await reader.ReadToEndAsync(cancellationToken);
    }

    /// <summary>
    /// A host on loopback that answers the first request it hears and, kept alive, goes on listening as a real one would:
    /// it closes after its answer only when the request asked it to. Everything it heard is kept.
    /// </summary>
    private sealed class Upstream : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly Task<string> _heard;

        private Upstream(TcpListener listener, CancellationToken cancellationToken)
        {
            _listener = listener;
            _heard = ServeAsync(cancellationToken);
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public static Task<Upstream> StartAsync(CancellationToken cancellationToken)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();

            return Task.FromResult(new Upstream(listener, cancellationToken));
        }

        /// <summary>What the host heard on its one connection, once that connection ended or a second went quiet.</summary>
        public Task<string> HeardAsync() => _heard.WaitAsync(TimeSpan.FromSeconds(10));

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            _listener.Dispose();

            try
            {
                await _heard;
            }
            catch (Exception exception) when (exception is SocketException or OperationCanceledException or ObjectDisposedException)
            {
                return;
            }
        }

        private async Task<string> ServeAsync(CancellationToken cancellationToken)
        {
            using TcpClient client = await _listener.AcceptTcpClientAsync(cancellationToken);
            NetworkStream stream = client.GetStream();
            var heard = new StringBuilder();
            var buffer = new byte[4096];
            bool answered = false;

            while (true)
            {
                using var quiet = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                quiet.CancelAfter(TimeSpan.FromSeconds(1));

                int got;
                try
                {
                    got = await stream.ReadAsync(buffer, quiet.Token);
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                if (got == 0)
                    break;

                heard.Append(Encoding.ASCII.GetString(buffer, 0, got));

                string text = heard.ToString();
                if (answered || !text.Contains("\r\n\r\n", StringComparison.Ordinal))
                    continue;

                await stream.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"u8.ToArray(), cancellationToken);
                answered = true;

                if (text.Contains("\r\nConnection: close\r\n", StringComparison.OrdinalIgnoreCase))
                {
                    await Task.Delay(200, cancellationToken);
                    heard.Append(DrainedText(stream));
                    break;
                }
            }

            return heard.ToString();
        }

        private static string DrainedText(NetworkStream stream)
        {
            var text = new StringBuilder();
            var buffer = new byte[4096];

            while (stream.DataAvailable)
            {
                int got = stream.Read(buffer);
                if (got == 0)
                    break;

                text.Append(Encoding.ASCII.GetString(buffer, 0, got));
            }

            return text.ToString();
        }
    }
}
