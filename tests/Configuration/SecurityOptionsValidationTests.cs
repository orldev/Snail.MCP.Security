using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Tests.Configuration;

/// <summary>Settings a scan could not run with, refused with the variable that set them.</summary>
public sealed class SecurityOptionsValidationTests
{
    private static readonly SecurityOptionsValidation Validation = new();

    [Fact]
    public void Validate_Defaults_Pass()
    {
        Assert.True(Validation.Validate(null, new SecurityOptions()).Succeeded);
    }

    [Fact]
    public void Validate_ProxyAddressAndPortSet_Pass()
    {
        var options = new SecurityOptions { Proxy = "http://mcp-security:3128", ProxyPort = 3128 };

        Assert.True(Validation.Validate(null, options).Succeeded);
    }

    public static TheoryData<SecurityOptions, string> Refused => new()
    {
        { new SecurityOptions { ScanSeconds = 0 }, "SNAIL_MCP_SECURITY_SCAN_SECONDS" },
        { new SecurityOptions { ShownFindings = -1 }, "SNAIL_MCP_SECURITY_SHOWN_FINDINGS" },
        { new SecurityOptions { MaxPage = 0 }, "SNAIL_MCP_SECURITY_MAX_PAGE" },
        { new SecurityOptions { ShownFindings = 200, MaxPage = 100 }, "SNAIL_MCP_SECURITY_SHOWN_FINDINGS" },
        { new SecurityOptions { ScannerMemoryMegabytes = 0 }, "SNAIL_MCP_SECURITY_SCANNER_MEMORY_MEGABYTES" },
        { new SecurityOptions { ScannerCpu = 0 }, "SNAIL_MCP_SECURITY_SCANNER_CPU" },
        { new SecurityOptions { ProxyPort = 70000 }, "SNAIL_MCP_SECURITY_PROXY_PORT" },
        { new SecurityOptions { NomadAddress = "nomad:4646" }, "SNAIL_MCP_SECURITY_NOMAD_ADDRESS" },
        { new SecurityOptions { NomadAddress = "ftp://nomad" }, "SNAIL_MCP_SECURITY_NOMAD_ADDRESS" },
        { new SecurityOptions { Proxy = "mcp-security:3128" }, "SNAIL_MCP_SECURITY_PROXY" },
        { new SecurityOptions { WorkspacesRoot = "workspaces" }, "SNAIL_MCP_SECURITY_WORKSPACES_ROOT" },
        { new SecurityOptions { TrivyImage = "aquasec/trivy:latest" }, "SNAIL_MCP_SECURITY_TRIVY_IMAGE" },
        { new SecurityOptions { SemgrepImage = "semgrep/semgrep:1.181.0" }, "SNAIL_MCP_SECURITY_SEMGREP_IMAGE" },
        { new SecurityOptions { SdkImage = "mcr.microsoft.com/dotnet/sdk:10.0" }, "SNAIL_MCP_SECURITY_SDK_IMAGE" },
        { new SecurityOptions { NmapImage = "instrumentisto/nmap:latest" }, "SNAIL_MCP_SECURITY_NMAP_IMAGE" },
        { new SecurityOptions { NucleiImage = "projectdiscovery/nuclei:v3" }, "SNAIL_MCP_SECURITY_NUCLEI_IMAGE" },
        { new SecurityOptions { SiteNetwork = "s3l-security" }, "SNAIL_MCP_SECURITY_SITE_NETWORK" },
        { new SecurityOptions { SitePorts = "22,80,70000" }, "SNAIL_MCP_SECURITY_SITE_PORTS" },
        { new SecurityOptions { SitePorts = "1-1024" }, "SNAIL_MCP_SECURITY_SITE_PORTS" },
        { new SecurityOptions { SiteRequestsPerSecond = 0 }, "SNAIL_MCP_SECURITY_SITE_REQUESTS_PER_SECOND" },
        { new SecurityOptions { SitePacketsPerSecond = -5 }, "SNAIL_MCP_SECURITY_SITE_PACKETS_PER_SECOND" },
        { new SecurityOptions { NucleiTemplates = "http://example.com/t.tgz" }, "SNAIL_MCP_SECURITY_NUCLEI_TEMPLATES" },
        { new SecurityOptions { NucleiTemplatesSha256 = "abc" }, "SNAIL_MCP_SECURITY_NUCLEI_TEMPLATES_SHA256" },
        { new SecurityOptions { ComplianceCatalogs = "/no/such/catalogs" }, "SNAIL_MCP_SECURITY_COMPLIANCE_CATALOGS" }
    };

    [Theory]
    [MemberData(nameof(Refused))]
    public void Validate_SettingAScanCannotRunWith_IsRefusedNamingItsVariable(SecurityOptions options, string variable)
    {
        var result = Validation.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(variable, result.FailureMessage, StringComparison.Ordinal);
    }
}
