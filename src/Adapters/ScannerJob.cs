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
/// Each scanner writes its JSON report as a file into the shared cache volume, under a folder of the task and of the run,
/// and the server reads it from there: a report read back through Nomad's logs is capped at a megabyte, which a repository
/// with many vulnerable packages passes. A folder per run means a scanner that failed before writing leaves no report
/// rather than the last one; each scanner removes the task's older runs. The .NET scanner writes one document per project
/// with <see cref="ScannerReports.Separator"/> between them. Nomad interpolates <c>${…}</c> in a task's config, so no
/// script here uses that form. Every scanner reaches the world only through the egress proxy.
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

    /// <summary>What every scanner does first: makes the run's folder and removes the task's older runs.</summary>
    private const string Prepare = """mkdir -p "$S3L_REPORTS" && find "$S3L_RUNS" -mindepth 1 -maxdepth 1 ! -name "$S3L_RUN" -exec rm -rf {} + &&""";

    private const string DotnetScript = $$"""
        set -e
        rm -rf /tmp/src && mkdir -p /tmp/src && cp -a "$S3L_COPY/." /tmp/src/
        find /tmp/src -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +
        cd /tmp/src
        targets=$(ls *.slnx *.sln 2>/dev/null | head -n 1)
        [ -n "$targets" ] || targets=$(find . -name '*.csproj' -o -name '*.fsproj' | sort)
        {{Prepare}} true
        for target in $targets; do
          dotnet restore "$target" >&2 || true
          dotnet list "$target" package --vulnerable --include-transitive --format json --no-restore || true
          echo "{{ScannerReports.Separator}}"
        done > "$S3L_REPORTS/dotnet.json"
        """;

    /// <summary>The folder a run's reports are written to, the same inside a scanner and inside the server.</summary>
    public static string ReportsOf(CopyPlace copy, string run) => $"{RunsOf(copy)}/{run}";

    /// <summary>The folder every run of a task writes under.</summary>
    public static string RunsOf(CopyPlace copy) => $"{CacheFolder}/reports/{copy.Task}";

    /// <summary>The report file a scanner writes.</summary>
    public static string ReportOf(CopyPlace copy, string run, string task) => $"{ReportsOf(copy, run)}/{task}.json";

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
        JsonArray tasks = [.. TasksFor(checks).Select(task => Task(task, copy, checks, run, options))];

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

    private static JsonObject Task(string name, CopyPlace copy, IReadOnlyCollection<Check> checks, string run, SecurityOptions options)
    {
        var config = name switch
        {
            Trivy => new JsonObject
            {
                ["image"] = options.TrivyImage,
                ["entrypoint"] = new JsonArray("sh"),
                ["args"] = new JsonArray("-c", $"""{Prepare} trivy {string.Join(' ', TrivyArguments(checks))} --output "$S3L_REPORTS/trivy.json" "$S3L_COPY" """)
            },
            Semgrep => new JsonObject
            {
                ["image"] = options.SemgrepImage,
                ["command"] = "sh",
                ["args"] = new JsonArray("-c", $"""{Prepare} cd "$S3L_COPY" && semgrep scan {string.Join(' ', options.SemgrepConfigs.Select(rules => $"--config {rules}"))} --metrics=off --disable-version-check --json --quiet --output "$S3L_REPORTS/semgrep.json" .""")
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
            ["Env"] = Env(copy, run, options),
            ["LogConfig"] = new JsonObject { ["MaxFiles"] = 2, ["MaxFileSizeMB"] = 50 },
            ["Resources"] = new JsonObject { ["CPU"] = options.ScannerCpu, ["MemoryMB"] = options.ScannerMemoryMegabytes }
        };

        return task;
    }

    private static IEnumerable<string> TrivyArguments(IReadOnlyCollection<Check> checks)
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
            "--skip-version-check", "--disable-telemetry", "--cache-dir", $"{CacheFolder}/trivy"
        ];
    }

    private static JsonObject Env(CopyPlace copy, string run, SecurityOptions options)
    {
        var env = new JsonObject
        {
            ["S3L_COPY"] = copy.Path,
            ["S3L_RUN"] = run,
            ["S3L_RUNS"] = RunsOf(copy),
            ["S3L_REPORTS"] = ReportsOf(copy, run),
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
