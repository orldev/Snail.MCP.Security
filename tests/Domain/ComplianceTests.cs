namespace Snail.MCP.Security.Tests.Domain;

public sealed class ComplianceTests
{
    private static Finding Of(Check check, string rule = "rule") => new(check, Severity.High, rule, "title", "file");

    [Fact]
    public void Ens_VulnerablePackage_IsMaintenanceAndSupplyChain()
    {
        Assert.Equal(["op.exp.4", "op.ext.3"], Compliance.Ens(Of(Check.Packages)).Select(reference => reference.Code));
        Assert.Equal(["NIS2 21(2)(e)", "NIS2 21(2)(d)"], Compliance.Nis2(Of(Check.Packages)).Select(reference => reference.Code));
    }

    [Fact]
    public void Ens_PrivateKeyInTheFiles_AddsTheProtectionOfKeysAndCryptography()
    {
        var key = Of(Check.Secrets, "private-key");

        Assert.Contains("op.exp.10", Compliance.Ens(key).Select(reference => reference.Code));
        Assert.Contains("NIS2 21(2)(h)", Compliance.Nis2(key).Select(reference => reference.Code));
        Assert.DoesNotContain("op.exp.10", Compliance.Ens(Of(Check.Secrets, "github-pat")).Select(reference => reference.Code));
    }

    [Fact]
    public void Ens_SettingsAndCode_AreConfigurationAndDevelopment()
    {
        Assert.Equal(["op.exp.2", "op.exp.3"], Compliance.Ens(Of(Check.Config)).Select(reference => reference.Code));
        Assert.Equal(["mp.sw.1", "mp.sw.2"], Compliance.Ens(Of(Check.Code)).Select(reference => reference.Code));
    }

    /// <summary>Every check falls under at least one measure of each: a new check fails here until it is placed.</summary>
    [Fact]
    public void EveryCheck_FallsUnderBothFrameworks()
    {
        foreach (var check in Enum.GetValues<Check>())
        {
            Assert.NotEmpty(Compliance.Ens(Of(check)));
            Assert.NotEmpty(Compliance.Nis2(Of(check)));
        }
    }
}
