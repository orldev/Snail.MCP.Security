using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using Snail.MCP.Security.Application;
using Snail.Sdk.Mcp.Hosting.Jobs;

namespace Snail.MCP.Security.Tools;

/// <summary>Answers as tool results: JSON with an ok flag, the data on success, error and hint otherwise.</summary>
/// <remarks>A scan that found problems is a success of the tool: the problems are the copy's, told in the data.</remarks>
public static class ToolResponse
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>A job as a tool result: its report, with the scan as its result once it ended.</summary>
    /// <remarks>The report is the structured content, which a job client reads; the text carries it under ok and data, as every answer of this server does.</remarks>
    public static CallToolResult Job(JobReport report) => Success(JsonNode.Parse(report.ToJson())!.AsObject());

    /// <summary>A page of findings as a tool result.</summary>
    public static CallToolResult From(Answer<FindingPage> answer) =>
        answer.Value is { } page
            ? Success(new JsonObject
            {
                ["total"] = page.Total,
                ["offset"] = page.Offset,
                ["scannedAt"] = page.ScannedAt.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                ["findings"] = new JsonArray([.. page.Findings.Select(Data)])
            })
            : Failure(answer.Error ?? "The findings were not read.", answer.Hint);

    /// <summary>A result carrying the data.</summary>
    public static CallToolResult Success(JsonObject data) => new()
    {
        Content = [new TextContentBlock { Text = new JsonObject { ["ok"] = true, ["data"] = data.DeepClone() }.ToJsonString(Options) }],
        StructuredContent = JsonSerializer.SerializeToElement(data, Options)
    };

    /// <summary>A result saying why nothing happened.</summary>
    public static CallToolResult Failure(string error, string? hint) => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = new JsonObject { ["ok"] = false, ["error"] = error, ["hint"] = hint }.ToJsonString(Options) }],
        StructuredContent = JsonSerializer.SerializeToElement(new JsonObject { ["error"] = error, ["hint"] = hint }, Options)
    };

    /// <summary>An enum value as the answer spells it.</summary>
    public static string Word<TEnum>(TEnum value) where TEnum : struct, Enum => value.ToString().ToLowerInvariant();

    /// <summary>A scan as an answer carries it: the verdict, each check's run, the comparison and the worst findings.</summary>
    public static JsonObject Scan(ScanReport report, int shown)
    {
        var counts = new JsonObject([.. Enum.GetValues<Severity>().Select(severity => KeyValuePair.Create(Word(severity), (JsonNode?)report.Findings.Count(finding => finding.Severity == severity)))]);
        var ordered = report.Ordered;

        var data = new JsonObject
        {
            ["clean"] = report.IsClean,
            ["scannedAt"] = report.At.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
            ["counts"] = counts,
            ["runs"] = new JsonArray([.. report.Runs.Select(run => new JsonObject { ["check"] = Word(run.Check), ["ran"] = run.HasRun, ["note"] = run.Note })]),
            ["since"] = report.Since is { } since ? new JsonObject { ["fixed"] = since.Fixed, ["new"] = since.New, ["remaining"] = since.Remaining } : null,
            ["findings"] = new JsonArray([.. ordered.Take(shown).Select(Data)]),
            ["more"] = Math.Max(0, ordered.Count - shown),
            ["note"] = report.Runs.Any(run => !run.HasRun) ? Messages.Partial : report.IsClean ? Messages.Clean : Messages.Blocked
        };

        return data;
    }

    private static JsonObject Data(Finding finding) => new()
    {
        ["check"] = Word(finding.Check),
        ["severity"] = Word(finding.Severity),
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
}
