using System.Text.Json;
using System.Text.Json.Serialization;

namespace Snail.MCP.Security.Adapters;

/// <summary>The compliance catalogs as files: ENS and NIS2 built into the server, and any an operator's folder adds or replaces.</summary>
/// <remarks>
/// <para>
/// A catalog is one JSON file: its <c>id</c>, which becomes the field of a finding that carries its references; its
/// <c>name</c> and <c>source</c>; the <c>references</c> it names, each a <c>code</c> and a <c>title</c>; and its
/// <c>checks</c>, lines that place the findings of a check — or only those whose rule contains a word
/// (<c>ruleContains</c>) — under some of those codes, the first line that places a finding deciding. <c>titled</c> says
/// whether an answer names a reference with its title; <c>checked</c> and <c>notes</c> are for the human who keeps it.
/// </para>
/// <para>
/// Every <c>*.json</c> of the folder is a catalog. One whose id is a built-in catalog's takes its place; any other is
/// named after the built-in ones, in the order of the files' names. A check no line places has no references in that
/// catalog. A file that is not a catalog is not skipped: the start is refused naming the file and what is wrong.
/// </para>
/// </remarks>
public static class CatalogFiles
{
    /// <summary>Where a catalog the server carries itself is said to come from.</summary>
    public const string BuiltIn = "built-in";

    private static readonly string[] Embedded = ["ens", "nis2"];

    private static readonly string[] FindingFields = ["check", "severity", "rule", "title", "where", "package", "version", "link"];

    /// <summary>The catalogs: the built-in ones, with the folder's, when one is named, in their place or after them.</summary>
    /// <param name="folder">The operator's folder of catalogs; null or empty for the built-in ones alone.</param>
    /// <exception cref="InvalidDataException">A catalog is not one; <see cref="Problems"/> says what, and the settings' check refuses the start with it first.</exception>
    public static Compliance Read(string? folder)
    {
        var reading = Load(folder);
        if (reading.Problems.Count > 0)
            throw new InvalidDataException(string.Join(" ", reading.Problems));

        return new Compliance(reading.Catalogs);
    }

    /// <summary>What is wrong with the catalogs <see cref="Read"/> would read, each problem naming its file; empty when nothing is.</summary>
    public static IReadOnlyList<string> Problems(string? folder) => Load(folder).Problems;

    private static Reading Load(string? folder)
    {
        List<string> problems = [];
        List<Catalog> catalogs = [];

        foreach (string id in Embedded)
        {
            using var stream = typeof(CatalogFiles).Assembly.GetManifestResourceStream($"Catalogs.{id}.json")
                ?? throw new InvalidOperationException($"The built-in catalog '{id}' is not in the server's assembly.");

            if (Parse(stream, BuiltIn, problems) is { } catalog)
                catalogs.Add(catalog);
        }

        if (string.IsNullOrWhiteSpace(folder))
            return new Reading(catalogs, problems);

        if (!Directory.Exists(folder))
        {
            problems.Add($"'{folder}' is not a folder; it is a folder of catalog files, *.json, or empty for the built-in ENS and NIS2 alone.");

            return new Reading(catalogs, problems);
        }

        Dictionary<string, string> seen = new(StringComparer.Ordinal);
        foreach (string file in Directory.GetFiles(folder, "*.json").Order(StringComparer.Ordinal))
        {
            var catalog = ReadFile(file, problems);
            if (catalog is null)
                continue;

            if (seen.TryGetValue(catalog.Id, out string? first))
            {
                problems.Add($"{file}: the id '{catalog.Id}' is already {first}'s; a catalog's id is its own.");
                continue;
            }

            seen[catalog.Id] = file;

            int replaced = catalogs.FindIndex(builtIn => string.Equals(builtIn.Id, catalog.Id, StringComparison.Ordinal));
            if (replaced >= 0)
                catalogs[replaced] = catalog;
            else
                catalogs.Add(catalog);
        }

        return new Reading(catalogs, problems);
    }

    private static Catalog? ReadFile(string file, List<string> problems)
    {
        try
        {
            using var stream = File.OpenRead(file);

            return Parse(stream, file, problems);
        }
        catch (Exception unreadable) when (unreadable is IOException or UnauthorizedAccessException)
        {
            problems.Add($"{file}: {unreadable.Message}");

            return null;
        }
    }

    private static Catalog? Parse(Stream stream, string from, List<string> problems)
    {
        CatalogFile? file;
        try
        {
            file = JsonSerializer.Deserialize(stream, CatalogJson.Default.CatalogFile);
        }
        catch (JsonException invalid)
        {
            problems.Add($"{from}: {invalid.Message}");

            return null;
        }

        if (file is null)
        {
            problems.Add($"{from}: the file holds null, not a catalog.");

            return null;
        }

        int before = problems.Count;

        if (!IsWord(file.Id))
            problems.Add($"{from}: the id '{file.Id}' is not a word of lower-case letters and digits, such as iso27001.");
        else if (FindingFields.Contains(file.Id, StringComparer.Ordinal))
            problems.Add($"{from}: the id '{file.Id}' is a field every finding already has.");

        var references = References(file, from, problems);
        var lines = Lines(file, references, from, problems);

        if (problems.Count > before)
            return null;

        return new Catalog(file.Id, file.Name, file.Source, file.Checked, file.IsTitled, lines, from);
    }

    private static Dictionary<string, Reference> References(CatalogFile file, string from, List<string> problems)
    {
        Dictionary<string, Reference> references = new(StringComparer.Ordinal);

        foreach (var reference in file.References)
        {
            if (string.IsNullOrWhiteSpace(reference.Code) || string.IsNullOrWhiteSpace(reference.Title))
                problems.Add($"{from}: a reference has no code or no title.");
            else if (!references.TryAdd(reference.Code, new Reference(reference.Code, reference.Title)))
                problems.Add($"{from}: the reference '{reference.Code}' is named twice.");
        }

        return references;
    }

    private static List<CatalogLine> Lines(CatalogFile file, Dictionary<string, Reference> references, string from, List<string> problems)
    {
        List<CatalogLine> lines = [];

        if (file.Checks.Count == 0)
            problems.Add($"{from}: the catalog has no checks, so it places no finding.");

        foreach (var line in file.Checks)
        {
            if (!IsCheck(line.Check, out var check))
            {
                problems.Add($"{from}: '{line.Check}' is not a check; the checks are {string.Join(", ", Enum.GetValues<Check>().Select(each => ToolAnswer.Word(each)))}.");
                continue;
            }

            if (line.References.Count == 0)
                problems.Add($"{from}: the line of '{line.Check}' names no reference.");

            string[] unknown = [.. line.References.Where(code => code is null || !references.ContainsKey(code))];
            if (unknown.Length > 0)
            {
                problems.Add($"{from}: the line of '{line.Check}' names {string.Join(", ", unknown.Select(code => $"'{code}'"))}, which the catalog's references do not.");
                continue;
            }

            string? word = string.IsNullOrWhiteSpace(line.RuleContains) ? null : line.RuleContains;
            lines.Add(new CatalogLine(check, word, [.. line.References.Select(code => references[code])]));
        }

        return lines;
    }

    private static bool IsCheck(string word, out Check check)
    {
        check = default;

        return word.Length > 0 && word.All(char.IsAsciiLetterLower) && Enum.TryParse(word, ignoreCase: true, out check);
    }

    private static bool IsWord(string id) => id.Length > 0 && char.IsAsciiLetterLower(id[0]) && id.All(letter => char.IsAsciiLetterLower(letter) || char.IsAsciiDigit(letter));

    private sealed record Reading(IReadOnlyList<Catalog> Catalogs, IReadOnlyList<string> Problems);
}

/// <summary>A catalog as its file holds it.</summary>
internal sealed record CatalogFile(
    string Id,
    string Name,
    string Source,
    IReadOnlyList<ReferenceFile> References,
    IReadOnlyList<LineFile> Checks,
    string? Checked = null,
    [property: JsonPropertyName("titled")] bool IsTitled = false,
    IReadOnlyList<string>? Notes = null);

/// <summary>A reference as a catalog file holds it.</summary>
internal sealed record ReferenceFile(string Code, string Title);

/// <summary>A line as a catalog file holds it.</summary>
internal sealed record LineFile(string Check, IReadOnlyList<string> References, string? RuleContains = null);

/// <summary>A catalog file, read without reflection: a field it does not know, or one it lacks, is a problem rather than a default.</summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    RespectNullableAnnotations = true,
    RespectRequiredConstructorParameters = true,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    ReadCommentHandling = JsonCommentHandling.Skip,
    AllowTrailingCommas = true)]
[JsonSerializable(typeof(CatalogFile))]
internal sealed partial class CatalogJson : JsonSerializerContext;
