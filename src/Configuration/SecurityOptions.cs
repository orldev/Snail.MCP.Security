namespace Snail.MCP.Security.Configuration;

/// <summary>Where the scanners run, which images they are, what they may reach, and how long a scan may take.</summary>
/// <remarks>
/// The scanners are pinned by digest, not by tag: in March 2026 Trivy's own release was compromised and its Docker Hub
/// images 0.69.4 to 0.69.6 carried malware (CVE-2026-33634). A scanner reads all of a task's code; a tag that can be moved
/// is not one to give that to.
/// </remarks>
public sealed class SecurityOptions
{
    /// <summary>Nomad's HTTP address, which scans run through.</summary>
    public string NomadAddress { get; set; } = "http://nomad:4646";

    /// <summary>Datacenter scan jobs are placed in.</summary>
    public string Datacenter { get; set; } = "dc1";

    /// <summary>Folder the platform's working copies lie under, as this server sees them, read-only.</summary>
    public string WorkspacesRoot { get; set; } = "/workspaces";

    /// <summary>Nomad host volume holding the same working copies, mounted read-only into every scanner.</summary>
    public string WorkspacesVolume { get; set; } = "workspaces";

    /// <summary>Docker network the scanners run in: internal, so the egress proxy is their only way out.</summary>
    public string Network { get; set; } = "s3l-security";

    /// <summary>Docker volume the scanners keep their databases and packages in between scans.</summary>
    public string CacheVolume { get; set; } = "s3l-security-cache";

    /// <summary>Trivy, which checks packages of every ecosystem, secrets and container and infrastructure files.</summary>
    public string TrivyImage { get; set; } = "aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222";

    /// <summary>Semgrep Community Edition, which checks code.</summary>
    public string SemgrepImage { get; set; } = "semgrep/semgrep:1.181.0@sha256:81474464c1f07483ba0682a44787fd93c91397419762a04abe2bafaae396304b";

    /// <summary>The .NET SDK, which lists the vulnerable NuGet packages of a project from NuGet's own advisories.</summary>
    /// <remarks>
    /// Trivy finds NuGet packages only in a lock file or a central props file; a plain project file it does not read. The
    /// band is the one every Snail repository pins in its global.json, so a restore finds the SDK the copy asks for.
    /// </remarks>
    public string SdkImage { get; set; } = "mcr.microsoft.com/dotnet/sdk:10.0.302@sha256:72dd743782f2ae7e5476fd64f6a460045e3998dc862218b80e6944cba79a01b0";

    /// <summary>The Semgrep rule sets code is checked with, from Semgrep's registry.</summary>
    public string[] SemgrepConfigs { get; set; } = ["p/csharp", "p/default"];

    /// <summary>The egress proxy's address as a scanner reaches it, such as http://mcp-security:3128; null leaves scanners without one.</summary>
    public string? Proxy { get; set; }

    /// <summary>Port the egress proxy listens on inside the server; 0 keeps it off.</summary>
    public int ProxyPort { get; set; }

    /// <summary>Hosts the egress proxy lets through: where the scanners' databases and rules and NuGet's packages come from.</summary>
    public string[] ProxyHosts { get; set; } =
    [
        "mirror.gcr.io", "googlecode.l.googleusercontent.com", "ghcr.io", "pkg-containers.githubusercontent.com",
        "semgrep.dev",
        "api.nuget.org", "globalcdn.nuget.org", "www.nuget.org"
    ];

    /// <summary>Docker network the site scanners run in: one that reaches the internet, never the internal network of the copy scanners.</summary>
    /// <remarks>
    /// A site scanner has to reach the customer's site, which the egress proxy cannot carry: nmap speaks TCP, not HTTP.
    /// What keeps it off private networks is the server — it hands nmap only addresses it checked are public, and runs
    /// Nuclei with -lna — and, on the stand, a firewall on this network that drops private destinations.
    /// </remarks>
    public string SiteNetwork { get; set; } = "s3l-security-sites";

    /// <summary>nmap, which finds a site's open ports, the services behind them and its TLS.</summary>
    public string NmapImage { get; set; } = "instrumentisto/nmap:7.98@sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827";

    /// <summary>Nuclei, which checks a site's TLS, its security headers and what it exposes, with the templates below.</summary>
    public string NucleiImage { get; set; } = "projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb";

    /// <summary>The Nuclei templates, as a release archive: a fixed version, never the moving latest Nuclei fetches by itself.</summary>
    public string NucleiTemplates { get; set; } = "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/tags/v10.5.0";

    /// <summary>The SHA-256 of <see cref="NucleiTemplates"/>: an archive with any other digest is not unpacked and the checks it serves do not run.</summary>
    public string NucleiTemplatesSha256 { get; set; } = "80fbabceca095fac40afecc7f023748df22b9576b9ff10a4422bd2fbf81f9a41";

    /// <summary>The ports nmap looks at: the web's, remote access, mail, file sharing, databases, caches, queues, Docker and Kubernetes.</summary>
    /// <remarks>A list rather than nmap's top ports: Redis (6379), MongoDB (27017) and Elasticsearch (9200), the services least meant to face the internet, are not among nmap's top thousand.</remarks>
    public string SitePorts { get; set; } = "21,22,23,25,53,80,110,111,135,139,143,389,443,445,465,587,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5672,5900,5984,6379,6443,8000,8080,8081,8443,8888,9000,9090,9200,9300,10250,11211,15672,27017";

    /// <summary>Requests a second Nuclei sends a site at most: far from anything that could slow it down.</summary>
    public int SiteRequestsPerSecond { get; set; } = 30;

    /// <summary>Packets a second nmap sends a site at most.</summary>
    public int SitePacketsPerSecond { get; set; } = 50;

    /// <summary>Seconds one scan gets, every check included.</summary>
    public int ScanSeconds { get; set; } = 900;

    /// <summary>Findings a scan's answer names; the rest are read with security_findings.</summary>
    public int ShownFindings { get; set; } = 20;

    /// <summary>Most findings one page of security_findings holds.</summary>
    public int MaxPage { get; set; } = 100;

    /// <summary>Memory, in megabytes, each scanner may use.</summary>
    public int ScannerMemoryMegabytes { get; set; } = 1536;

    /// <summary>CPU, in MHz as Nomad counts it, each scanner may use.</summary>
    public int ScannerCpu { get; set; } = 1000;
}
