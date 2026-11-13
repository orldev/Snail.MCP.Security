using Snail.MCP.Security.Adapters;
using Snail.MCP.Security.Tools;

namespace Snail.MCP.Security.Tests.Tools;

/// <summary>A finding as an answer carries it: a field per compliance catalog, titled or by code.</summary>
public sealed class AnswerFieldsTests
{
    private static readonly Finding Package = new(Check.Packages, Severity.High, "CVE-2026-0001", "title", "app.csproj", "Foo", "1.0.0");

    [Fact]
    public void Of_Finding_NamesEnsWithTitlesAndNis2ByCode()
    {
        var data = AnswerFields.Of(Package, CatalogFiles.Read(null));

        Assert.Equal(["op.exp.4 Mantenimiento y actualizaciones de seguridad", "op.ext.3 Protección de la cadena de suministro"], data["ens"]!.AsArray().Select(node => node!.GetValue<string>()));
        Assert.Equal(["NIS2 21(2)(e)", "NIS2 21(2)(d)"], data["nis2"]!.AsArray().Select(node => node!.GetValue<string>()));
    }

    [Fact]
    public void Of_FindingWithAnOperatorsCatalog_CarriesItsFieldToo()
    {
        var iso = new Catalog("iso27001", "ISO/IEC 27001", "licensed copy", null, IsTitled: false,
            [new CatalogLine(Check.Packages, null, [new Reference("A.8.8", "Management of technical vulnerabilities")])], "/catalogs/iso.json");
        var compliance = new Compliance([.. CatalogFiles.Read(null).Catalogs, iso]);

        var data = AnswerFields.Of(Package, compliance);

        Assert.Equal(["A.8.8"], data["iso27001"]!.AsArray().Select(node => node!.GetValue<string>()));
        Assert.NotNull(data["ens"]);
    }
}
