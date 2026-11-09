using System.Text.Json.Nodes;
using Snail.MCP.Security.Application;
using Snail.MCP.Security.Configuration;

namespace Snail.MCP.Security.Tools;

/// <summary>What the answers carry as their data: a scan, a page of findings, a finding, the server's state — one overload of <c>Of</c> per record.</summary>
/// <remarks>
/// The envelope around it is Snail.Sdk.Mcp.Hosting's (<see cref="ToolAnswer"/>, and <c>JobAnswer</c> for a scan's job). A
/// scan that found problems is a success of the tool: the problems are the copy's, told in the data. Enum values are
/// spelled lower case, every word run together — a contract the platform's workers read.
/// </remarks>
public static class AnswerFields
{
    /// <summary>A page of findings as its answer carries it.</summary>
    public static JsonObject Of(FindingPage page) => new()
    {
        ["total"] = page.Total,
        ["offset"] = page.Offset,
        ["scannedAt"] = ToolAnswer.Moment(page.ScannedAt),
        ["findings"] = new JsonArray([.. page.Findings.Select(Of)])
    };

    /// <summary>A scan as an answer carries it: the verdict, each check's run, the comparison and the worst findings.</summary>
    public static JsonObject Of(ScanReport report, int shown)
    {
        var counts = new JsonObject([.. Enum.GetValues<Severity>().Select(severity => KeyValuePair.Create(ToolAnswer.Word(severity), (JsonNode?)report.Findings.Count(finding => finding.Severity == severity)))]);
        var ordered = report.Ordered;

        var data = new JsonObject
        {
            ["clean"] = report.IsClean,
            ["scannedAt"] = ToolAnswer.Moment(report.At),
            ["counts"] = counts,
            ["runs"] = new JsonArray([.. report.Runs.Select(run => new JsonObject { ["check"] = ToolAnswer.Word(run.Check), ["ran"] = run.HasRun, ["note"] = run.Note })]),
            ["since"] = report.Since is { } since ? new JsonObject { ["fixed"] = since.Fixed, ["new"] = since.New, ["remaining"] = since.Remaining } : null,
            ["findings"] = new JsonArray([.. ordered.Take(shown).Select(Of)]),
            ["more"] = Math.Max(0, ordered.Count - shown),
            ["note"] = report.Runs.Any(run => !run.HasRun) ? Messages.Partial : report.IsClean ? Messages.Clean : Messages.Blocked
        };

        return data;
    }

    /// <summary>A finding as a page and a scan carry it.</summary>
    public static JsonObject Of(Finding finding) => new()
    {
        ["check"] = ToolAnswer.Word(finding.Check),
        ["severity"] = ToolAnswer.Word(finding.Severity),
        ["rule"] = finding.Rule,
        ["title"] = finding.Title,
        ["where"] = finding.Location,
        ["package"] = finding.Package,
        ["version"] = finding.Version,
        ["fixedIn"] = finding.FixedIn,
        ["link"] = finding.Link,
        ["ens"] = new JsonArray([.. Compliance.Ens(finding).Select(reference => JsonValue.Create($"{reference.Code} {reference.Title}"))]),
        ["nis2"] = new JsonArray([.. Compliance.Nis2(finding).Select(reference => JsonValue.Create(reference.Code))])
    };

    /// <summary>What security_diagnose answers: the server's version, Nomad's, and the images, network and proxy scans run with.</summary>
    public static JsonObject Of(string nomad, SecurityOptions settings) => new()
    {
        ["server"] = typeof(AnswerFields).Assembly.GetName().Version?.ToString(3),
        ["nomad"] = nomad,
        ["trivy"] = settings.TrivyImage,
        ["semgrep"] = settings.SemgrepImage,
        ["sdk"] = settings.SdkImage,
        ["semgrepRules"] = new JsonArray([.. settings.SemgrepConfigs.Select(rules => JsonValue.Create(rules))]),
        ["network"] = settings.Network,
        ["proxy"] = settings.Proxy,
        ["proxyHosts"] = new JsonArray([.. settings.ProxyHosts.Select(host => JsonValue.Create(host))])
    };
}
