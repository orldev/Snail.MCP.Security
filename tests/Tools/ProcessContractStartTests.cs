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

    /// <summary>The built-in catalogs are read from the program's own assembly, and an operator's catalog that is not one refuses the start naming its file.</summary>
    [Fact]
    public async Task Start_CatalogWithAnUnknownCheck_IsRefusedNamingTheVariableAndTheFile()
    {
        var folder = Directory.CreateTempSubdirectory("s3l-catalogs-");
        try
        {
            string file = Path.Combine(folder.FullName, "iso.json");
            await File.WriteAllTextAsync(file, """{ "id": "iso27001", "name": "ISO", "source": "copy", "references": [ { "code": "A.8.8", "title": "t" } ], "checks": [ { "check": "cookies", "references": [ "A.8.8" ] } ] }""");

            var exited = await Assert.ThrowsAsync<ServerExitedException>(() => HttpServerProgram.StartAsync(
                "Snail.MCP.Security",
                ProcessContractTests.ServerVariable,
                new Dictionary<string, string?> { ["SNAIL_MCP_SECURITY_COMPLIANCE_CATALOGS"] = folder.FullName }));

            Assert.Equal(1, exited.ExitCode);
            Assert.Contains("SNAIL_MCP_SECURITY_COMPLIANCE_CATALOGS", exited.Stderr, StringComparison.Ordinal);
            Assert.Contains($"{file}: 'cookies' is not a check", exited.Stderr, StringComparison.Ordinal);
            Assert.DoesNotContain("   at ", exited.Stderr, StringComparison.Ordinal);
        }
        finally
        {
            folder.Delete(recursive: true);
        }
    }
}
