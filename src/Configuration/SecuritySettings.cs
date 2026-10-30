using System.Collections;
using Snail.Sdk.Mcp.Hosting;

namespace Snail.MCP.Security.Configuration;

/// <summary>The settings <see cref="SecurityOptions"/> is bound from: the server's settings file, then its <c>SNAIL_MCP_SECURITY_</c> variables, which win.</summary>
/// <remarks>
/// Built apart from the web host's own configuration on purpose: an <c>appsettings.json</c> or a variable of whoever
/// started the server that happens to share a name is not a setting of this server and must not become one by accident.
/// </remarks>
public static class SecuritySettings
{
    /// <summary>The server's short name, which names its settings file and the prefix of its variables.</summary>
    public const string Name = "security";

    /// <summary>Where the server answers: Url (SNAIL_MCP_SECURITY_URL), a loopback address whose port a container listens on from every interface.</summary>
    public static Uri Url => new(Read()["Url"] ?? "http://127.0.0.1:8829/");

    /// <summary>The settings as they stand: the settings file found, then the process's variables.</summary>
    public static IConfiguration Read() => Read(ServerSettings.FileOf(Name), Environment.GetEnvironmentVariables());

    /// <summary>The settings of <paramref name="file"/>, when there is one, under the server's variables among <paramref name="variables"/>.</summary>
    public static IConfiguration Read(string? file, IDictionary variables) =>
        new ConfigurationBuilder()
            .AddServerSettings(Name, file, variables)
            .Build();
}
