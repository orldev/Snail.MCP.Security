using System.Reflection;
using System.Text.RegularExpressions;
using ModelContextProtocol.Server;
using Snail.MCP.Security.Configuration;
using Snail.MCP.Security.Tools;

namespace Snail.MCP.Security.Tests.Tools;

/// <summary>The descriptions a model reads, held to the code they describe.</summary>
public sealed partial class ToolCatalogTests
{
    private static readonly SecurityOptions Defaults = new();

    private static IEnumerable<string> Tools()
    {
        var methods = typeof(SecurityTools).Assembly.GetTypes()
            .Where(type => type.GetCustomAttribute<McpServerToolTypeAttribute>() is not null)
            .SelectMany(type => type.GetMethods());

        return methods.Select(method => method.GetCustomAttribute<McpServerToolAttribute>()?.Name).OfType<string>();
    }

    [Fact]
    public void Tools_EveryOne_IsNamedForThisServer()
    {
        Assert.Equal(["security_diagnose", "security_findings", "security_scan"], Tools().Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Checks_EveryCheck_IsNamed()
    {
        foreach (var check in Enum.GetValues<Check>())
            Assert.Contains(ToolResponse.Word(check), Words(ToolDescriptions.Checks));
    }

    [Fact]
    public void Severities_EverySeverity_IsNamed()
    {
        foreach (var severity in Enum.GetValues<Severity>())
            Assert.Contains(ToolResponse.Word(severity), Words(ToolDescriptions.Severities));
    }

    /// <summary>Every number a description names is the default it describes.</summary>
    [Theory]
    [InlineData(ToolDescriptions.Scan, nameof(SecurityOptions.ShownFindings))]
    [InlineData(ToolDescriptions.Scan, nameof(SecurityOptions.ScanSeconds))]
    [InlineData(ToolDescriptions.Findings, nameof(SecurityOptions.ShownFindings))]
    [InlineData(ToolDescriptions.Findings, nameof(SecurityOptions.MaxPage))]
    [InlineData(ToolDescriptions.FindingsLimit, nameof(SecurityOptions.ShownFindings))]
    [InlineData(ToolDescriptions.FindingsLimit, nameof(SecurityOptions.MaxPage))]
    public void Description_NumberItNames_IsTheDefault(string description, string option)
    {
        object? value = typeof(SecurityOptions).GetProperty(option)!.GetValue(Defaults);

        Assert.Contains($"{value}", Number().Matches(description).Select(match => match.Value));
    }

    private static IReadOnlyList<string> Words(string text) => [.. text.Split([' ', ',', '.'], StringSplitOptions.RemoveEmptyEntries)];

    [GeneratedRegex(@"\d+")]
    private static partial Regex Number();
}
