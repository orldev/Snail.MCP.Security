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
    public static JsonObject Of(FindingPage page, Compliance compliance) => new()
    {
        ["total"] = page.Total,
        ["offset"] = page.Offset,
        ["scannedAt"] = ToolAnswer.Moment(page.ScannedAt),
        ["findings"] = new JsonArray([.. page.Findings.Select(finding => Of(finding, compliance))])
    };

    /// <summary>A scan as an answer carries it: the verdict, each check's run, the comparison and the worst findings.</summary>
    public static JsonObject Of(ScanReport report, int shown, Compliance compliance)
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
            ["findings"] = new JsonArray([.. ordered.Take(shown).Select(finding => Of(finding, compliance))]),
            ["more"] = Math.Max(0, ordered.Count - shown),
            ["note"] = report.Runs.Any(run => !run.HasRun) ? Messages.Partial : report.IsClean ? Messages.Clean : Messages.Blocked
        };

        return data;
    }

    /// <summary>A site proven the customer's, as security_site_prove answers it.</summary>
    public static JsonObject Of(SiteProof proof) => new()
    {
        ["site"] = proof.Site.Host,
        ["provenBy"] = proof.ProvenBy,
        ["record"] = Site.RecordOf(proof.ProvenBy),
        ["note"] = Messages.Proven(proof.Site.Host, proof.ProvenBy)
    };

    /// <summary>A site's scan as security_site_scan answers it: the proof it was made under, then the scan as a copy's is told.</summary>
    public static JsonObject Of(SiteScan scan, int shown, Compliance compliance)
    {
        var data = Of(scan.Report, shown, compliance);
        data.Remove("since");
        data.Insert(0, "site", scan.Proof.Site.Host);
        data.Insert(1, "provenBy", scan.Proof.ProvenBy);

        return data;
    }

    /// <summary>A finding as a page and a scan carry it: what it is, then a field per compliance catalog with the references it falls under.</summary>
    /// <remarks>A catalog that is titled names a reference with its title after the code (<c>ens</c>), any other by its code alone (<c>nis2</c>).</remarks>
    public static JsonObject Of(Finding finding, Compliance compliance)
    {
        var data = new JsonObject
        {
            ["check"] = ToolAnswer.Word(finding.Check),
            ["severity"] = ToolAnswer.Word(finding.Severity),
            ["rule"] = finding.Rule,
            ["title"] = finding.Title,
            ["where"] = finding.Location,
            ["package"] = finding.Package,
            ["version"] = finding.Version,
            ["fixedIn"] = finding.FixedIn,
            ["link"] = finding.Link
        };

        foreach (var catalog in compliance.Catalogs)
            data[catalog.Id] = new JsonArray([.. catalog.Of(finding).Select(reference => JsonValue.Create(catalog.Shown(reference)))]);

        return data;
    }

    /// <summary>What security_diagnose answers: the server's version, Nomad's, the images, network and proxy copy scans run with, what site scans run with, and the compliance catalogs findings are placed in.</summary>
    public static JsonObject Of(string nomad, SecurityOptions settings, Compliance compliance) => new()
    {
        ["server"] = typeof(AnswerFields).Assembly.GetName().Version?.ToString(3),
        ["nomad"] = nomad,
        ["trivy"] = settings.TrivyImage,
        ["semgrep"] = settings.SemgrepImage,
        ["sdk"] = settings.SdkImage,
        ["semgrepRules"] = new JsonArray([.. settings.SemgrepConfigs.Select(rules => JsonValue.Create(rules))]),
        ["network"] = settings.Network,
        ["proxy"] = settings.Proxy,
        ["proxyHosts"] = new JsonArray([.. settings.ProxyHosts.Select(host => JsonValue.Create(host))]),
        ["sites"] = new JsonObject
        {
            ["nmap"] = settings.NmapImage,
            ["nuclei"] = settings.NucleiImage,
            ["templates"] = settings.NucleiTemplates,
            ["templatesSha256"] = settings.NucleiTemplatesSha256,
            ["network"] = settings.SiteNetwork,
            ["ports"] = settings.SitePorts,
            ["requestsPerSecond"] = settings.SiteRequestsPerSecond,
            ["packetsPerSecond"] = settings.SitePacketsPerSecond
        },
        ["catalogs"] = new JsonArray([.. compliance.Catalogs.Select(catalog => new JsonObject
        {
            ["id"] = catalog.Id,
            ["name"] = catalog.Name,
            ["source"] = catalog.Source,
            ["checked"] = catalog.Checked,
            ["from"] = catalog.From
        })])
    };
}
