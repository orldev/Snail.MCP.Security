using Snail.MCP.Security.Adapters;

namespace Snail.MCP.Security.Tests.Domain;

/// <summary>The built-in catalogs place every finding as ENS and NIS2 do: the references the server answered with before they were data.</summary>
public sealed class ComplianceTests
{
    private static readonly Compliance BuiltIn = CatalogFiles.Read(null);

    private static Finding Of(Check check, string rule = "rule") => new(check, Severity.High, rule, "title", "file");

    private static IEnumerable<string> Ens(Finding finding) => BuiltIn.Of("ens")!.Of(finding).Select(reference => reference.Code);

    private static IEnumerable<string> Nis2(Finding finding) => BuiltIn.Of("nis2")!.Of(finding).Select(reference => reference.Code);

    [Fact]
    public void BuiltIn_IsEnsThenNis2()
    {
        Assert.Equal(["ens", "nis2"], BuiltIn.Catalogs.Select(catalog => catalog.Id));
        Assert.All(BuiltIn.Catalogs, catalog => Assert.Equal(CatalogFiles.BuiltIn, catalog.From));
    }

    [Fact]
    public void Ens_VulnerablePackage_IsMaintenanceAndSupplyChain()
    {
        Assert.Equal(["op.exp.4", "op.ext.3"], Ens(Of(Check.Packages)));
        Assert.Equal(["NIS2 21(2)(e)", "NIS2 21(2)(d)"], Nis2(Of(Check.Packages)));
    }

    [Fact]
    public void Ens_PrivateKeyInTheFiles_AddsTheProtectionOfKeysAndCryptography()
    {
        var key = Of(Check.Secrets, "private-key");

        Assert.Equal(["op.acc.6", "op.acc.5", "op.exp.10"], Ens(key));
        Assert.Equal(["NIS2 21(2)(i)", "NIS2 21(2)(h)"], Nis2(key));
        Assert.Equal(["op.acc.6", "op.acc.5"], Ens(Of(Check.Secrets, "github-pat")));
        Assert.Equal(["NIS2 21(2)(i)"], Nis2(Of(Check.Secrets, "github-pat")));
    }

    [Fact]
    public void Ens_SettingsAndCode_AreConfigurationAndDevelopment()
    {
        Assert.Equal(["op.exp.2", "op.exp.3"], Ens(Of(Check.Config)));
        Assert.Equal(["mp.sw.1", "mp.sw.2"], Ens(Of(Check.Code)));
    }

    public static TheoryData<Check, string[], string[]> Sites => new()
    {
        { Check.Tls, ["mp.com.2", "mp.com.3", "mp.s.2"], ["NIS2 21(2)(h)", "NIS2 21(2)(e)"] },
        { Check.Headers, ["mp.s.2", "op.exp.2"], ["NIS2 21(2)(e)"] },
        { Check.Mail, ["mp.s.1"], ["NIS2 21(2)(e)"] },
        { Check.Exposure, ["mp.s.2", "op.exp.2"], ["NIS2 21(2)(e)", "NIS2 21(2)(i)"] },
        { Check.Services, ["op.exp.2", "op.exp.4", "mp.com.1"], ["NIS2 21(2)(e)", "NIS2 21(2)(i)"] }
    };

    [Theory]
    [MemberData(nameof(Sites))]
    public void SiteFinding_FallsUnderItsMeasures(Check check, string[] ens, string[] nis2)
    {
        Assert.Equal(ens, Ens(Of(check)));
        Assert.Equal(nis2, Nis2(Of(check)));
    }

    /// <summary>Every check falls under at least one reference of each built-in catalog: a new check fails here until it is placed.</summary>
    [Fact]
    public void EveryCheck_FallsUnderBothFrameworks()
    {
        foreach (var check in Enum.GetValues<Check>())
        {
            Assert.NotEmpty(Ens(Of(check)));
            Assert.NotEmpty(Nis2(Of(check)));
        }
    }

    [Fact]
    public void Shown_TitledCatalog_NamesTheTitleAndTheOtherTheCode()
    {
        var ens = BuiltIn.Of("ens")!;
        var nis2 = BuiltIn.Of("nis2")!;

        Assert.Equal("op.exp.4 Mantenimiento y actualizaciones de seguridad", ens.Shown(ens.Of(Of(Check.Packages))[0]));
        Assert.Equal("NIS2 21(2)(e)", nis2.Shown(nis2.Of(Of(Check.Packages))[0]));
    }
}
