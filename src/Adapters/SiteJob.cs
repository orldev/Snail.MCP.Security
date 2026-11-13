using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Adapters;

/// <summary>A site's scan as one Nomad batch job: Nuclei and nmap side by side on the site network, never restarted.</summary>
/// <remarks>
/// <para>
/// Both scanners reach the customer's site, so neither runs on the internal network of the copy scanners: they run on
/// <see cref="SecurityOptions.SiteNetwork"/>. What keeps them off private networks is not that network but the server.
/// nmap is handed the addresses the server resolved and checked are public, never a name it would resolve again; Nuclei,
/// which has to ask by name for the certificate and the virtual host to be the site's, runs with <c>-lna</c>, which refuses
/// any address that is not public, whatever the name resolves to by then.
/// </para>
/// <para>
/// Neither attacks: Nuclei runs only the templates of TLS, of the missing security headers and of what a site exposes,
/// with every intrusive, denial-of-service, fuzzing, brute-force, default-login, out-of-band and headless template left
/// out, and at most <see cref="SecurityOptions.SiteRequestsPerSecond"/> requests a second; nmap opens TCP connections
/// (<c>-sT --unprivileged</c>, no raw packets) to a fixed list of ports, at most
/// <see cref="SecurityOptions.SitePacketsPerSecond"/> a second, and runs only the scripts named here, each of them one
/// handshake or one request.
/// </para>
/// <para>
/// The templates are a release archive of a fixed version, checked against its SHA-256 before it is unpacked and kept in
/// the cache volume under that digest; a template Nuclei would fetch by itself is the moving latest, which no one checked.
/// The reports end as files in the cache volume, as the copy scanners' do, under a folder of the site and of the run.
/// Nomad interpolates <c>${…}</c> in a task's config, so no script here uses that form.
/// </para>
/// </remarks>
public static class SiteJob
{
    /// <summary>The task that runs Nuclei.</summary>
    public const string Nuclei = "nuclei";

    /// <summary>The task that runs nmap.</summary>
    public const string Nmap = "nmap";

    /// <summary>The template tags left out whatever the folders hold: anything that attacks, floods, guesses or calls back.</summary>
    public const string ExcludedTags = "intrusive,dos,fuzz,fuzzing,bruteforce,osint,default-login,oast,headless";

    /// <summary>The nmap scripts run: each one handshake or one request.</summary>
    public const string NmapScripts = "ssl-cert,ssl-enum-ciphers,http-security-headers,http-server-header,ssh2-enum-algos,smtp-commands";

    /// <summary>What every task does first: makes the run's folder and removes the site's older runs.</summary>
    private const string Prepare = """mkdir -p "$S3L_REPORTS" && find "$S3L_RUNS" -mindepth 1 -maxdepth 1 ! -name "$S3L_RUN" -exec rm -rf {} + &&""";

    /// <summary>Unpacks the checked templates into the cache once; a run that finds them there uses them as they are.</summary>
    private const string Templates = """
        if [ ! -f "$S3L_TEMPLATES/.ready" ]; then
          part="$S3L_TEMPLATES.part.$S3L_RUN"
          rm -rf "$part" && mkdir -p "$part"
          wget -q -T 120 -O "$part/templates.tgz" "$S3L_TEMPLATES_URL"
          echo "$S3L_TEMPLATES_SHA256  $part/templates.tgz" | sha256sum -c - >&2
          tar -xzf "$part/templates.tgz" -C "$part"
          rm -f "$part/templates.tgz"
          root=$(find "$part" -mindepth 1 -maxdepth 1 -type d | head -n 1)
          touch "$root/.ready"
          rm -rf "$S3L_TEMPLATES" && mv "$root" "$S3L_TEMPLATES" && rm -rf "$part"
        fi
        """;

    /// <summary>The folder a run's reports are written to, the same inside a scanner and inside the server.</summary>
    public static string ReportsOf(Site site, string run) => $"{RunsOf(site)}/{run}";

    /// <summary>The folder every run of a site writes under.</summary>
    public static string RunsOf(Site site) => $"{ScannerJob.CacheFolder}/sites/{site.Host}";

    /// <summary>The report file a scanner writes.</summary>
    public static string ReportOf(Site site, string run, string task) => $"{ReportsOf(site, run)}/{task}.{(task == Nmap ? "xml" : "jsonl")}";

    /// <summary>Where the checked templates are unpacked: under their digest, so another archive never passes for them.</summary>
    public static string TemplatesOf(SecurityOptions options) => $"{ScannerJob.CacheFolder}/nuclei-templates/{options.NucleiTemplatesSha256}";

    /// <summary>The Nomad job a scan of a site runs as.</summary>
    public static string NameOf(Site site) => $"{ScanJob.Prefix}site-{site.Host}";

    /// <summary>The scanners a set of checks needs: Nuclei for TLS, headers and exposure, nmap for services and TLS.</summary>
    public static IReadOnlyList<string> TasksFor(IReadOnlyCollection<Check> checks)
    {
        List<string> tasks = [];

        if (checks.Contains(Check.Tls) || checks.Contains(Check.Headers) || checks.Contains(Check.Exposure))
            tasks.Add(Nuclei);

        if (checks.Contains(Check.Services) || checks.Contains(Check.Tls))
            tasks.Add(Nmap);

        return tasks;
    }

    /// <summary>The template folders the checks need, relative to the templates' root.</summary>
    public static IReadOnlyList<string> TemplatesFor(IReadOnlyCollection<Check> checks)
    {
        List<string> folders = [];

        if (checks.Contains(Check.Tls))
            folders.Add("ssl/");

        if (checks.Contains(Check.Headers))
            folders.Add("http/misconfiguration/http-missing-security-headers.yaml");

        if (checks.Contains(Check.Exposure))
        {
            folders.Add("http/exposures/");
            folders.Add("http/exposed-panels/");
        }

        return folders;
    }

    /// <summary>The addresses nmap is given: the IPv4 ones when the site has any, its IPv6 ones otherwise — nmap scans one family at a time.</summary>
    public static IReadOnlyList<IPAddress> Targets(IReadOnlyList<IPAddress> addresses)
    {
        var v4 = addresses.Where(address => address.AddressFamily == AddressFamily.InterNetwork).ToList();

        return v4.Count > 0 ? v4 : [.. addresses.Where(address => address.AddressFamily == AddressFamily.InterNetworkV6)];
    }

    /// <summary>The scan's job; each run carries a mark of its own, or Nomad keeps an unchanged batch job and nothing runs again.</summary>
    public static JsonObject Of(Site site, IReadOnlyList<IPAddress> addresses, IReadOnlyCollection<Check> checks, string run, SecurityOptions options)
    {
        JsonArray tasks = [.. TasksFor(checks).Select(task => (JsonNode)Task(task, site, addresses, checks, run, options))];

        var job = new JsonObject
        {
            ["ID"] = NameOf(site),
            ["Name"] = NameOf(site),
            ["Type"] = "batch",
            ["Datacenters"] = new JsonArray(options.Datacenter),
            ["Meta"] = new JsonObject { ["s3l.security.site"] = site.Host, ["s3l.security.run"] = run },
            ["TaskGroups"] = new JsonArray(new JsonObject
            {
                ["Name"] = "site",
                ["Count"] = 1,
                ["RestartPolicy"] = new JsonObject { ["Attempts"] = 0, ["Interval"] = 300 * 1_000_000_000L, ["Delay"] = 5 * 1_000_000_000L, ["Mode"] = "fail" },
                ["ReschedulePolicy"] = new JsonObject { ["Attempts"] = 0, ["Unlimited"] = false },
                ["Tasks"] = tasks
            })
        };

        return job;
    }

    /// <summary>The words of the Nuclei command, after its input: the templates, what is left out, how fast, and where the report goes.</summary>
    public static IReadOnlyList<string> NucleiArguments(IReadOnlyCollection<Check> checks, SecurityOptions options)
    {
        List<string> words = [];

        foreach (string folder in TemplatesFor(checks))
        {
            words.Add("-t");
            words.Add($"\"$S3L_TEMPLATES/{folder}\"");
        }

        words.AddRange(
        [
            "-etags", ExcludedTags, "-lna", "-ni", "-duc",
            "-rl", options.SiteRequestsPerSecond.ToString(CultureInfo.InvariantCulture), "-c", "10", "-bs", "10",
            "-timeout", "10", "-retries", "1", "-jsonl", "-silent", "-nc", "-o", "\"$S3L_REPORTS/nuclei.jsonl\""
        ]);

        return words;
    }

    /// <summary>The words of the nmap command: TCP connections to the listed ports, the services' versions, the named scripts, and the XML report.</summary>
    public static IReadOnlyList<string> NmapArguments(Site site, IReadOnlyList<IPAddress> addresses, SecurityOptions options)
    {
        var targets = Targets(addresses);
        List<string> words = ["-Pn", "-n", "-sT", "--unprivileged", "-sV", "--version-intensity", "5", "-p", options.SitePorts, "-T3"];

        words.AddRange(["--max-rate", options.SitePacketsPerSecond.ToString(CultureInfo.InvariantCulture)]);
        words.AddRange(["--script", NmapScripts, "--script-args", $"tls.servername={site.Host}", "-oX", "\"$S3L_REPORTS/nmap.xml\""]);

        if (targets.Count > 0 && targets[0].AddressFamily == AddressFamily.InterNetworkV6)
            words.Add("-6");

        words.AddRange(targets.Select(address => address.ToString()));

        return words;
    }

    private static JsonObject Task(string name, Site site, IReadOnlyList<IPAddress> addresses, IReadOnlyCollection<Check> checks, string run, SecurityOptions options)
    {
        bool isNuclei = name == Nuclei;
        string script = isNuclei
            ? $"set -e\n{Templates}\n{Prepare} nuclei -u \"$S3L_SITE\" {string.Join(' ', NucleiArguments(checks, options))}"
            : $"set -e\n{Prepare} nmap {string.Join(' ', NmapArguments(site, addresses, options))} >/dev/null";

        var config = new JsonObject
        {
            ["image"] = isNuclei ? options.NucleiImage : options.NmapImage,
            ["entrypoint"] = new JsonArray("sh"),
            ["args"] = new JsonArray("-c", script),
            ["network_mode"] = options.SiteNetwork,
            ["mounts"] = new JsonArray(new JsonObject { ["type"] = "volume", ["source"] = options.CacheVolume, ["target"] = ScannerJob.CacheFolder, ["readonly"] = false })
        };

        var env = new JsonObject
        {
            ["S3L_SITE"] = site.Host,
            ["S3L_RUN"] = run,
            ["S3L_RUNS"] = RunsOf(site),
            ["S3L_REPORTS"] = ReportsOf(site, run),
            ["S3L_TEMPLATES"] = TemplatesOf(options),
            ["S3L_TEMPLATES_URL"] = options.NucleiTemplates,
            ["S3L_TEMPLATES_SHA256"] = options.NucleiTemplatesSha256,
            ["HOME"] = "/tmp",
            ["XDG_CONFIG_HOME"] = "/tmp/.config"
        };

        var task = new JsonObject
        {
            ["Name"] = name,
            ["Driver"] = "docker",
            ["Config"] = config,
            ["Env"] = env,
            ["LogConfig"] = new JsonObject { ["MaxFiles"] = 2, ["MaxFileSizeMB"] = 50 },
            ["Resources"] = new JsonObject { ["CPU"] = options.ScannerCpu, ["MemoryMB"] = options.ScannerMemoryMegabytes }
        };

        return task;
    }
}
