using System.Text.Json.Nodes;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Adapters;

/// <summary>A scan as one Nomad batch job: a task per scanner the checks need, side by side, never restarted.</summary>
/// <remarks>
/// <para>
/// Trivy and Semgrep read the working copy where it lies, mounted read-only with host-to-task propagation (on the stand
/// the workspaces are a named Docker volume inside Docker's data root, which refuses a private bind mount from there).
/// The .NET scanner restores packages, which writes, so it works on a copy of the copy without its bin and obj.
/// </para>
/// <para>
/// Each scanner prints its JSON on standard output and talks on standard error; the .NET scanner prints one document per
/// project with <see cref="ScannerReports.Separator"/> between them. Nomad interpolates <c>${…}</c> in a task's config,
/// so no script here uses that form. Every scanner reaches the world only through the egress proxy.
/// </para>
/// </remarks>
public static class ScannerJob
{
    /// <summary>Where the cache volume is mounted inside every scanner.</summary>
    public const string CacheFolder = "/cache";

    /// <summary>The task that runs Trivy.</summary>
    public const string Trivy = "trivy";

    /// <summary>The task that runs Semgrep.</summary>
    public const string Semgrep = "semgrep";

    /// <summary>The task that lists vulnerable NuGet packages.</summary>
    public const string Dotnet = "dotnet";

    private const long Second = 1_000_000_000;

    private const string DotnetScript = $$"""
        set -e
        rm -rf /tmp/src && mkdir -p /tmp/src && cp -a "$S3L_COPY/." /tmp/src/
        find /tmp/src -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +
        cd /tmp/src
        targets=$(ls *.slnx *.sln 2>/dev/null | head -n 1)
        [ -n "$targets" ] || targets=$(find . -name '*.csproj' -o -name '*.fsproj' | sort)
        for target in $targets; do
          dotnet restore "$target" >&2 || true
          dotnet list "$target" package --vulnerable --include-transitive --format json --no-restore || true
          echo "{{ScannerReports.Separator}}"
        done
        """;

    /// <summary>The tasks a set of checks needs: Trivy for packages, secrets and settings, Semgrep for code, .NET for NuGet packages.</summary>
    public static IReadOnlyList<string> TasksFor(IReadOnlyCollection<Check> checks)
    {
        List<string> tasks = [];

        if (checks.Contains(Check.Packages) || checks.Contains(Check.Secrets) || checks.Contains(Check.Config))
            tasks.Add(Trivy);

        if (checks.Contains(Check.Code))
            tasks.Add(Semgrep);

        if (checks.Contains(Check.Packages))
            tasks.Add(Dotnet);

        return tasks;
    }

    /// <summary>The scan's job; each run carries a mark of its own, or Nomad keeps an unchanged batch job and nothing runs again.</summary>
    public static JsonObject Of(CopyPlace copy, IReadOnlyCollection<Check> checks, string run, SecurityOptions options)
    {
        JsonArray tasks = [.. TasksFor(checks).Select(task => Task(task, copy, checks, options))];

        var job = new JsonObject
        {
            ["ID"] = copy.Job,
            ["Name"] = copy.Job,
            ["Type"] = "batch",
            ["Datacenters"] = new JsonArray(options.Datacenter),
            ["Meta"] = new JsonObject { ["s3l.security.copy"] = copy.Path, ["s3l.security.run"] = run },
            ["TaskGroups"] = new JsonArray(new JsonObject
            {
                ["Name"] = "scan",
                ["Count"] = 1,
                ["RestartPolicy"] = new JsonObject { ["Attempts"] = 0, ["Interval"] = 300 * Second, ["Delay"] = 5 * Second, ["Mode"] = "fail" },
                ["ReschedulePolicy"] = new JsonObject { ["Attempts"] = 0, ["Unlimited"] = false },
                ["Volumes"] = new JsonObject
                {
                    ["workspaces"] = new JsonObject { ["Name"] = "workspaces", ["Type"] = "host", ["Source"] = options.WorkspacesVolume, ["ReadOnly"] = true }
                },
                ["Tasks"] = tasks
            })
        };

        return job;
    }

    private static JsonObject Task(string name, CopyPlace copy, IReadOnlyCollection<Check> checks, SecurityOptions options)
    {
        var config = name switch
        {
            Trivy => new JsonObject
            {
                ["image"] = options.TrivyImage,
                ["args"] = new JsonArray([.. TrivyArguments(copy, checks).Select(argument => (JsonNode)argument)])
            },
            Semgrep => new JsonObject
            {
                ["image"] = options.SemgrepImage,
                ["command"] = "sh",
                ["args"] = new JsonArray("-c", $"""cd "$S3L_COPY" && semgrep scan {string.Join(' ', options.SemgrepConfigs.Select(rules => $"--config {rules}"))} --metrics=off --disable-version-check --json --quiet .""")
            },
            _ => new JsonObject
            {
                ["image"] = options.SdkImage,
                ["command"] = "sh",
                ["args"] = new JsonArray("-c", DotnetScript)
            }
        };

        config["network_mode"] = options.Network;
        config["mounts"] = new JsonArray(new JsonObject { ["type"] = "volume", ["source"] = options.CacheVolume, ["target"] = CacheFolder, ["readonly"] = false });

        var task = new JsonObject
        {
            ["Name"] = name,
            ["Driver"] = "docker",
            ["Config"] = config,
            ["VolumeMounts"] = new JsonArray(new JsonObject
            {
                ["Volume"] = "workspaces",
                ["Destination"] = options.WorkspacesRoot,
                ["ReadOnly"] = true,
                ["PropagationMode"] = "host-to-task"
            }),
            ["Env"] = Env(copy, options),
            ["LogConfig"] = new JsonObject { ["MaxFiles"] = 2, ["MaxFileSizeMB"] = 50 },
            ["Resources"] = new JsonObject { ["CPU"] = options.ScannerCpu, ["MemoryMB"] = options.ScannerMemoryMegabytes }
        };

        return task;
    }

    private static IEnumerable<string> TrivyArguments(CopyPlace copy, IReadOnlyCollection<Check> checks)
    {
        IReadOnlyList<string> scanners =
        [
            .. checks.Contains(Check.Packages) ? ["vuln"] : Array.Empty<string>(),
            .. checks.Contains(Check.Secrets) ? ["secret"] : Array.Empty<string>(),
            .. checks.Contains(Check.Config) ? ["misconfig"] : Array.Empty<string>()
        ];

        return
        [
            "fs", "--scanners", string.Join(',', scanners), "--format", "json", "--quiet", "--exit-code", "0",
            "--skip-version-check", "--disable-telemetry", "--cache-dir", $"{CacheFolder}/trivy", copy.Path
        ];
    }

    private static JsonObject Env(CopyPlace copy, SecurityOptions options)
    {
        var env = new JsonObject
        {
            ["S3L_COPY"] = copy.Path,
            ["HOME"] = "/tmp",
            ["XDG_CACHE_HOME"] = "/tmp/.cache",
            ["SEMGREP_SEND_METRICS"] = "off",
            ["NUGET_PACKAGES"] = $"{CacheFolder}/nuget",
            ["DOTNET_CLI_UI_LANGUAGE"] = "en",
            ["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1",
            ["DOTNET_NOLOGO"] = "1"
        };

        if (options.Proxy is { Length: > 0 } proxy)
        {
            env["HTTP_PROXY"] = proxy;
            env["HTTPS_PROXY"] = proxy;
            env["NO_PROXY"] = "localhost,127.0.0.1";
        }

        return env;
    }
}
