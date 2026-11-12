using Snail.Sdk.Mcp.Testing;

namespace Snail.MCP.Security.Tests.Tools;

/// <summary>The program refusing to start on settings it could not scan with: one line naming the variable, exit code 1.</summary>
/// <remarks>Named a contract test, so it runs against the native program the release ships too.</remarks>
public sealed class ProcessContractStartTests
{
    [Fact]
    public async Task Start_ScanSecondsZero_IsRefusedInOneLineNamingTheVariable()
    {
        var exited = await Assert.ThrowsAsync<ServerExitedException>(() => HttpServerProgram.StartAsync(
            "Snail.MCP.Security",
            ProcessContractTests.ServerVariable,
            new Dictionary<string, string?> { ["SNAIL_MCP_SECURITY_SCAN_SECONDS"] = "0" }));

        Assert.Equal(1, exited.ExitCode);
        Assert.Contains("SNAIL_MCP_SECURITY_SCAN_SECONDS", exited.Stderr, StringComparison.Ordinal);
        Assert.DoesNotContain("   at ", exited.Stderr, StringComparison.Ordinal);
        Assert.Single(exited.Stderr.Split("SNAIL_MCP_SECURITY_SCAN_SECONDS (or", StringSplitOptions.None).Skip(1));
    }
}
