namespace Snail.MCP.Security.Domain;

/// <summary>What a domain's SPF and DMARC records say about how well its mail is protected from being forged.</summary>
/// <remarks>
/// Read from the records themselves rather than from scanner templates: a template that detects a DMARC record says
/// nothing when the record is missing, and the missing record is the finding. A domain with no SPF or no DMARC can be
/// spoofed; DMARC at p=none only reports and blocks nothing.
/// </remarks>
public static class MailPolicy
{
    /// <summary>The findings of the domain's records: none when both are present and DMARC enforces.</summary>
    public static IReadOnlyList<Finding> Findings(string domain, IReadOnlyList<string> texts, IReadOnlyList<string> dmarcTexts)
    {
        List<Finding> findings = [];
        var spf = texts.Where(text => text.StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)).ToList();
        var dmarc = dmarcTexts.FirstOrDefault(text => text.StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));

        if (spf.Count == 0)
            findings.Add(new Finding(Check.Mail, Severity.Medium, "spf-missing", "No SPF record: anyone can send mail as this domain", domain));
        else if (spf.Count > 1)
            findings.Add(new Finding(Check.Mail, Severity.Medium, "spf-multiple", "More than one SPF record: receivers treat SPF as failed", domain));
        else if (spf[0].TrimEnd().EndsWith("+all", StringComparison.OrdinalIgnoreCase))
            findings.Add(new Finding(Check.Mail, Severity.High, "spf-allows-all", "SPF ends in +all: it authorises every server on the internet", domain));

        if (dmarc is null)
            findings.Add(new Finding(Check.Mail, Severity.Medium, "dmarc-missing", "No DMARC record: forged mail from this domain is delivered", $"_dmarc.{domain}"));
        else if (PolicyOf(dmarc) is "none")
            findings.Add(new Finding(Check.Mail, Severity.Low, "dmarc-not-enforced", "DMARC policy is none: forged mail is reported but still delivered", $"_dmarc.{domain}"));

        return findings;
    }

    private static string? PolicyOf(string dmarc) =>
        dmarc.Split(';').Select(part => part.Trim()).FirstOrDefault(part => part.StartsWith("p=", StringComparison.OrdinalIgnoreCase))?[2..].Trim().ToLowerInvariant();
}
