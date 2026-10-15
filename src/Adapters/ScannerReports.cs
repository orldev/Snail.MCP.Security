using System.Text.Json;
using System.Text.Json.Nodes;

namespace Snail.MCP.Security.Adapters;

/// <summary>What each scanner printed, read into findings of one shape.</summary>
/// <remarks>
/// Each reader takes the scanner's JSON as it is on standard output and keeps what a person or a model acts on: the
/// advisory or rule, the severity, the file and line, the package and the version that fixes it. Paths are made relative
/// to the working copy, whichever way the scanner was pointed at it.
/// </remarks>
public static class ScannerReports
{
    /// <summary>The line the .NET scanner prints between the JSON of two projects.</summary>
    public const string Separator = "@@S3L-PROJECT@@";

    /// <summary>Trivy's report: vulnerable packages, secrets and misconfigurations.</summary>
    /// <remarks>
    /// Trivy names a vulnerability by its CVE and keeps the GHSA among the vendor ids; the GHSA is taken when there is one,
    /// so the same advisory found by the .NET scanner is one finding, not two. A misconfiguration of a missing instruction
    /// has no line.
    /// </remarks>
    public static IReadOnlyList<Finding> Trivy(string json)
    {
        List<Finding> findings = [];

        foreach (var result in Array(Parse(json)?["Results"]))
        {
            string target = Relative((string?)result?["Target"] ?? string.Empty);

            findings.AddRange(Array(result?["Vulnerabilities"]).Select(vulnerability => Vulnerability(target, vulnerability!)));
            findings.AddRange(Array(result?["Secrets"]).Select(secret => new Finding(
                Check.Secrets,
                SeverityOf((string?)secret!["Severity"]),
                (string?)secret["RuleID"] ?? "secret",
                (string?)secret["Title"] ?? "secret",
                At(target, (int?)secret["StartLine"]))));
            findings.AddRange(Array(result?["Misconfigurations"]).Select(misconfiguration => new Finding(
                Check.Config,
                SeverityOf((string?)misconfiguration!["Severity"]),
                (string?)misconfiguration["ID"] ?? (string?)misconfiguration["AVDID"] ?? "misconfiguration",
                $"{(string?)misconfiguration["Title"]}. {(string?)misconfiguration["Resolution"]}".Trim(' ', '.'),
                At(target, (int?)misconfiguration["CauseMetadata"]?["StartLine"]),
                Link: (string?)misconfiguration["PrimaryURL"])));
        }

        return findings;
    }

    /// <summary>Semgrep's report: insecure code, with the weakness each rule names.</summary>
    /// <remarks>Semgrep without a login prints «requires login» in place of the lines; the file and line are what a fix needs.</remarks>
    public static IReadOnlyList<Finding> Semgrep(string json) =>
        [
            .. Array(Parse(json)?["results"]).Select(result => new Finding(
                IsInfrastructure((string?)result!["check_id"]) ? Check.Config : Check.Code,
                (string?)result!["extra"]?["severity"] switch
                {
                    "ERROR" => Severity.High,
                    "WARNING" => Severity.Medium,
                    "INFO" => Severity.Low,
                    _ => Severity.Unknown
                },
                Short((string?)result["check_id"] ?? "rule"),
                Weakness(result),
                At(Relative((string?)result["path"] ?? string.Empty), (int?)result["start"]?["line"]),
                Link: Array(result["extra"]?["metadata"]?["references"]).Select(reference => (string?)reference).FirstOrDefault()))
        ];

    /// <summary>The .NET scanner's reports, one per project: vulnerable NuGet packages, direct and transitive.</summary>
    /// <remarks>NuGet's advisories carry a severity and the GHSA's address, not the version that fixes it; the advisory page says.</remarks>
    public static IReadOnlyList<Finding> Dotnet(string output)
    {
        List<Finding> findings = [];

        foreach (string document in output.Split(Separator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var project in Array(Parse(document)?["projects"]))
            {
                string path = Relative((string?)project?["path"] ?? string.Empty);
                var frameworks = Array(project?["frameworks"]);
                var packages = frameworks.SelectMany(framework => Array(framework?["topLevelPackages"]).Concat(Array(framework?["transitivePackages"])));

                foreach (var package in packages)
                {
                    string id = (string?)package?["id"] ?? string.Empty;
                    string? version = (string?)package?["resolvedVersion"];

                    findings.AddRange(Array(package?["vulnerabilities"]).Select(vulnerability => new Finding(
                        Check.Packages,
                        SeverityOf((string?)vulnerability!["severity"]),
                        Advisory((string?)vulnerability["advisoryurl"]) ?? "advisory",
                        $"Known vulnerability in {id} {version}",
                        path,
                        id,
                        version,
                        Link: (string?)vulnerability["advisoryurl"])));
                }
            }
        }

        return findings;
    }

    /// <summary>The findings with each problem once: the same advisory on the same package and version found by two scanners is kept with the richer of the two.</summary>
    public static IReadOnlyList<Finding> Merged(IEnumerable<Finding> findings) =>
        [
            .. findings
                .GroupBy(finding => finding.Key, StringComparer.Ordinal)
                .Select(same => same.OrderByDescending(finding => finding.FixedIn is not null).ThenBy(finding => finding.Title.StartsWith("Known vulnerability", StringComparison.Ordinal)).First())
        ];

    private static Finding Vulnerability(string target, JsonNode vulnerability)
    {
        string? ghsa = Array(vulnerability["VendorIDs"]).Select(id => (string?)id).FirstOrDefault(id => id?.StartsWith("GHSA-", StringComparison.Ordinal) == true);
        string package = (string?)vulnerability["PkgName"] ?? string.Empty;

        return new Finding(
            Check.Packages,
            SeverityOf((string?)vulnerability["Severity"]),
            ghsa ?? (string?)vulnerability["VulnerabilityID"] ?? "advisory",
            (string?)vulnerability["Title"] ?? $"Known vulnerability in {package}",
            target,
            package,
            (string?)vulnerability["InstalledVersion"],
            (string?)vulnerability["FixedVersion"] is { Length: > 0 } fixedIn ? fixedIn : null,
            ghsa is null ? (string?)vulnerability["PrimaryURL"] : $"https://github.com/advisories/{ghsa}");
    }

    private static Severity SeverityOf(string? word) => word?.ToUpperInvariant() switch
    {
        "CRITICAL" => Severity.Critical,
        "HIGH" => Severity.High,
        "MEDIUM" or "MODERATE" => Severity.Medium,
        "LOW" => Severity.Low,
        _ => Severity.Unknown
    };

    /// <summary>Whether a Semgrep rule judges a container or infrastructure file rather than code: its registry path says so.</summary>
    private static bool IsInfrastructure(string? rule) =>
        rule is not null && Infrastructure.Any(prefix => rule.StartsWith(prefix, StringComparison.Ordinal));

    private static readonly string[] Infrastructure = ["dockerfile.", "yaml.docker-compose.", "yaml.kubernetes.", "terraform.", "generic.nginx.", "json.aws."];

    /// <summary>The GHSA an advisory's address ends in.</summary>
    private static string? Advisory(string? url) =>
        url?.Split('/').LastOrDefault(part => part.StartsWith("GHSA-", StringComparison.Ordinal));

    /// <summary>The rule's own name, without the registry's path in front of it.</summary>
    private static string Short(string rule) => rule.Split('.').Last();

    private static string Weakness(JsonNode result)
    {
        string message = ((string?)result["extra"]?["message"] ?? string.Empty).ReplaceLineEndings(" ").Trim();
        string? cwe = Array(result["extra"]?["metadata"]?["cwe"]).Select(item => (string?)item).FirstOrDefault();

        return cwe is null ? message : $"{cwe.Split(':')[0]}: {message}";
    }

    private static string At(string path, int? line) => line is { } number ? $"{path}:{number}" : path;

    /// <summary>A path as the working copy names it: no leading ./ or the folder the scanner mounted or copied it to.</summary>
    private static string Relative(string path)
    {
        string trimmed = path.StartsWith("./", StringComparison.Ordinal) ? path[2..] : path;

        string[] mounts = ["/tmp/src/", "/src/"];
        string? mount = mounts.FirstOrDefault(prefix => trimmed.StartsWith(prefix, StringComparison.Ordinal));

        return mount is null ? trimmed.TrimStart('/') : trimmed[mount.Length..];
    }

    private static JsonNode? Parse(string json)
    {
        try
        {
            return JsonNode.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static IEnumerable<JsonNode?> Array(JsonNode? node) => node as JsonArray ?? [];
}
