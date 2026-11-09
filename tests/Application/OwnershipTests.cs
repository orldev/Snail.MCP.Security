using System.Net;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Application.Ports;

namespace Snail.MCP.Security.Tests.Application;

/// <summary>The proof that a site is the customer's, and the words a program reads when there is none.</summary>
public sealed class OwnershipTests
{
    private static readonly Site Shop = new("shop.example.com");

    [Fact]
    public async Task ProvenAsync_RecordOfAParent_ProvesTheSite()
    {
        var ownership = new Ownership(new Dns(), new Key());
        var dns = new Dns { [Site.RecordOf("example.com")] = [ownership.CodeOf("example.com")] };

        var answer = await new Ownership(dns, new Key()).ProvenAsync(Shop, CancellationToken.None);

        Assert.Equal("example.com", answer.Value);
    }

    /// <summary>No record is <c>notProven</c>, told apart from a DNS that did not answer, which is worth asking again.</summary>
    [Fact]
    public async Task ProvenAsync_NoRecord_IsTypedNotProven()
    {
        var answer = await new Ownership(new Dns(), new Key()).ProvenAsync(Shop, CancellationToken.None);

        Assert.Equal("notProven", answer.Type);
    }

    [Fact]
    public async Task ProvenAsync_DnsDoesNotAnswer_IsTypedUnreachable()
    {
        var answer = await new Ownership(new Dns { IsSilent = true }, new Key()).ProvenAsync(Shop, CancellationToken.None);

        Assert.Equal("unreachable", answer.Type);
    }

    private sealed class Key : IProofKey
    {
        public byte[] Bytes { get; } = [.. Enumerable.Range(0, 32).Select(index => (byte)index)];
    }

    private sealed class Dns : Dictionary<string, IReadOnlyList<string>>, ISiteDns
    {
        public bool IsSilent { get; init; }

        public Task<IReadOnlyList<string>?> TextsAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult(IsSilent ? null : TryGetValue(name, out var texts) ? texts : (IReadOnlyList<string>?)[]);

        public Task<IReadOnlyList<IPAddress>?> AddressesAsync(string name, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<IPAddress>?>([]);
    }
}
