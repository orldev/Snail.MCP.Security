using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Configuration;

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
        using var proxy = new EgressProxy(Options.Create(new SecurityOptions { ProxyPort = FreePort(), ProxyHosts = Hosts }), NullLogger<EgressProxy>.Instance);
        await proxy.StartAsync(stopping.Token);

        string answer = await AskAsync(proxy, head, stopping.Token);
        await proxy.StopAsync(CancellationToken.None);

        Assert.StartsWith(status, answer, StringComparison.Ordinal);
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

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();

        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}
