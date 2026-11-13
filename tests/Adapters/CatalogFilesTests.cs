using Snail.MCP.Security.Adapters;

namespace Snail.MCP.Security.Tests.Adapters;

/// <summary>An operator's folder of catalogs: added after the built-in ones, replacing one by its id, and refused naming the file when one is not a catalog.</summary>
public sealed class CatalogFilesTests : IDisposable
{
    private const string Iso =
        """
        {
          "id": "iso27001",
          "name": "ISO/IEC 27001:2022, Annex A",
          "source": "the operator's licensed copy",
          "references": [ { "code": "A.8.8", "title": "Management of technical vulnerabilities" },
                          { "code": "A.8.24", "title": "Use of cryptography" } ],
          "checks": [ { "check": "secrets", "ruleContains": "private-key", "references": [ "A.8.24" ] },
                      { "check": "packages", "references": [ "A.8.8" ] } ]
        }
        """;

    private readonly DirectoryInfo _folder = Directory.CreateTempSubdirectory("s3l-catalogs-");

    public void Dispose() => _folder.Delete(recursive: true);

    private string Write(string name, string json)
    {
        string file = Path.Combine(_folder.FullName, name);
        File.WriteAllText(file, json);

        return file;
    }

    private static Finding Of(Check check, string rule = "rule") => new(check, Severity.High, rule, "title", "file");

    [Fact]
    public void Read_FolderWithACatalog_AddsItAfterTheBuiltInOnes()
    {
        string file = Write("iso.json", Iso);

        var compliance = CatalogFiles.Read(_folder.FullName);

        Assert.Equal(["ens", "nis2", "iso27001"], compliance.Catalogs.Select(catalog => catalog.Id));
        var iso = compliance.Of("iso27001")!;
        Assert.Equal(file, iso.From);
        Assert.Equal(["A.8.8"], iso.Of(Of(Check.Packages)).Select(reference => reference.Code));
        Assert.Equal(["A.8.24"], iso.Of(Of(Check.Secrets, "PRIVATE-KEY")).Select(reference => reference.Code));
    }

    /// <summary>A check the catalog has no line for is placed under nothing of it, and the other catalogs still place it.</summary>
    [Fact]
    public void Read_CheckWithoutALine_HasNoReferencesInThatCatalog()
    {
        Write("iso.json", Iso);

        var compliance = CatalogFiles.Read(_folder.FullName);

        Assert.Empty(compliance.Of("iso27001")!.Of(Of(Check.Secrets, "github-pat")));
        Assert.NotEmpty(compliance.Of("ens")!.Of(Of(Check.Secrets, "github-pat")));
    }

    [Fact]
    public void Read_CatalogWithABuiltInId_TakesItsPlace()
    {
        string file = Write("ens.json", Iso.Replace("\"iso27001\"", "\"ens\"", StringComparison.Ordinal));

        var compliance = CatalogFiles.Read(_folder.FullName);

        Assert.Equal(["ens", "nis2"], compliance.Catalogs.Select(catalog => catalog.Id));
        Assert.Equal(file, compliance.Of("ens")!.From);
        Assert.Equal(["A.8.8"], compliance.Of("ens")!.Of(Of(Check.Packages)).Select(reference => reference.Code));
    }

    public static TheoryData<string, string> NotCatalogs => new()
    {
        { Iso.Replace("\"check\": \"packages\"", "\"check\": \"cookies\"", StringComparison.Ordinal), "'cookies' is not a check" },
        { Iso.Replace("[ \"A.8.8\" ]", "[ \"A.5.1\" ]", StringComparison.Ordinal), "'A.5.1'" },
        { Iso.Replace("\"source\"", "\"sourse\"", StringComparison.Ordinal), "sourse" },
        { Iso.Replace("\"iso27001\"", "\"rule\"", StringComparison.Ordinal), "a field every finding already has" },
        { Iso.Replace("\"iso27001\"", "\"ISO 27001\"", StringComparison.Ordinal), "not a word" },
        { Iso.Replace("A.8.24", "A.8.8", StringComparison.Ordinal), "named twice" },
        { Iso.Replace("\"references\": [ \"A.8.8\" ]", "\"references\": [ ]", StringComparison.Ordinal), "names no reference" },
        { "{ \"id\": ", "iso.json" },
        { "null", "holds null" }
    };

    [Theory]
    [MemberData(nameof(NotCatalogs))]
    public void Problems_FileThatIsNotACatalog_NamesTheFileAndWhatIsWrong(string json, string said)
    {
        string file = Write("iso.json", json);

        var problems = CatalogFiles.Problems(_folder.FullName);

        string problem = Assert.Single(problems);
        Assert.StartsWith(file, problem, StringComparison.Ordinal);
        Assert.Contains(said, problem, StringComparison.Ordinal);
        Assert.Throws<InvalidDataException>(() => CatalogFiles.Read(_folder.FullName));
    }

    [Fact]
    public void Problems_TwoFilesWithOneId_RefusesTheSecond()
    {
        Write("a.json", Iso);
        string second = Write("b.json", Iso);

        string problem = Assert.Single(CatalogFiles.Problems(_folder.FullName));

        Assert.StartsWith(second, problem, StringComparison.Ordinal);
        Assert.Contains("already", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Problems_FolderThatIsNotThere_SaysSo()
    {
        string problem = Assert.Single(CatalogFiles.Problems(Path.Combine(_folder.FullName, "missing")));

        Assert.Contains("is not a folder", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void Problems_BuiltInCatalogs_HaveNone()
    {
        Assert.Empty(CatalogFiles.Problems(null));
        Assert.Empty(CatalogFiles.Problems(_folder.FullName));
    }
}
