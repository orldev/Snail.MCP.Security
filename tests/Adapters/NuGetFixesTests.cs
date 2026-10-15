using System.Text.Json.Nodes;
using Snail.MCP.Security.Adapters;

namespace Snail.MCP.Security.Tests.Adapters;

public sealed class NuGetFixesTests
{
    [Theory]
    [InlineData("(, 13.0.1)", "13.0.1")]
    [InlineData("[4.3.0, 4.3.4)", "4.3.4")]
    [InlineData("(, 2.1.0]", null)]
    [InlineData("[1.0.0, )", null)]
    public void FixedIn_Range_IsItsExcludedUpperBound(string range, string? fixedIn)
    {
        Assert.Equal(fixedIn, NuGetFixes.FixedIn(range));
    }

    [Fact]
    public void RangesIn_NuGetsFile_AreKeyedByPackageAndGhsa()
    {
        var file = JsonNode.Parse("""{"newtonsoft.json":[{"url":"https://github.com/advisories/GHSA-5crp-9r3c-p9vr","severity":2,"versions":"(, 13.0.1)"}]}""");

        var ranges = NuGetFixes.RangesIn(file).ToDictionary();

        Assert.Equal("(, 13.0.1)", ranges["newtonsoft.json|GHSA-5crp-9r3c-p9vr"]);
    }
}
