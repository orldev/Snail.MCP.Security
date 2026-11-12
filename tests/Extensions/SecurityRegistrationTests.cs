using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Snail.MCP.Security.Configuration;
using Snail.MCP.Security.Extensions;
using Snail.Toolkit.Nomad;

namespace Snail.MCP.Security.Tests.Extensions;

/// <summary>What the scans feature registers, read from the settings the server was given.</summary>
public sealed class SecurityRegistrationTests
{
    /// <summary>The Nomad client used to read the settings a second time, by itself: the scanner and its client could name two addresses.</summary>
    [Fact]
    public void AddScans_NomadAddressInTheSettings_IsTheClientsAddress()
    {
        var settings = new ConfigurationBuilder()
            .AddInMemoryCollection([new(nameof(SecurityOptions.NomadAddress), "http://scheduler.test:4646")])
            .Build();
        var services = new ServiceCollection();
        services.AddScans(settings);

        using var provider = services.BuildServiceProvider();
        string address = provider.GetRequiredService<IOptions<NomadOptions>>().Value.Address;

        Assert.Equal("http://scheduler.test:4646", address);
    }
}
