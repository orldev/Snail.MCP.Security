namespace Snail.MCP.Security.Domain;

/// <summary>A measure, control or letter of a catalog — an ENS measure, a letter of NIS2's Article 21(2) — with its official title.</summary>
public sealed record Reference(string Code, string Title);

/// <summary>One line of a catalog: the findings of a check, or only those whose rule names a word, fall under these references.</summary>
/// <param name="Check">The check whose findings the line places.</param>
/// <param name="RuleContains">A word the finding's rule has to contain, case aside, such as <c>private-key</c>; null places every finding of the check.</param>
/// <param name="References">The references the findings fall under, in the order an answer names them.</param>
public sealed record CatalogLine(Check Check, string? RuleContains, IReadOnlyList<Reference> References)
{
    /// <summary>Whether the line places <paramref name="finding"/>.</summary>
    public bool Places(Finding finding) =>
        finding.Check == Check && (RuleContains is null || finding.Rule.Contains(RuleContains, StringComparison.OrdinalIgnoreCase));
}

/// <summary>A framework a finding is placed in — ENS, NIS2, or one an operator adds — as data, read from a catalog file.</summary>
/// <param name="Id">The catalog's word, which is also the field of a finding that carries its references: <c>ens</c>, <c>nis2</c>.</param>
/// <param name="Name">What the framework is called.</param>
/// <param name="Source">The text it was read from: the official journal or register and the document's identifier.</param>
/// <param name="Checked">The day the references were last checked against <paramref name="Source"/>, when the catalog says.</param>
/// <param name="IsTitled">Whether an answer names a reference with its title after the code, or the code alone.</param>
/// <param name="Lines">The lines, the first that places a finding deciding its references.</param>
/// <param name="From">Where the catalog was read from: <c>built-in</c>, or the operator's file.</param>
public sealed record Catalog(string Id, string Name, string Source, string? Checked, bool IsTitled, IReadOnlyList<CatalogLine> Lines, string From)
{
    /// <summary>The references <paramref name="finding"/> falls under: those of the first line that places it, none when no line does.</summary>
    public IReadOnlyList<Reference> Of(Finding finding) => Lines.FirstOrDefault(line => line.Places(finding))?.References ?? [];

    /// <summary>A reference as an answer names it: the code, with the title after it when the catalog is titled.</summary>
    public string Shown(Reference reference) => IsTitled ? $"{reference.Code} {reference.Title}" : reference.Code;
}

/// <summary>The catalogs every finding is placed in, as a reference for the human, not a certification.</summary>
/// <remarks>
/// <para>
/// The server carries ENS (Real Decreto 311/2022, Anexo II, BOE-A-2022-7191) and NIS2 (Directive (EU) 2022/2555,
/// Article 21(2), CELEX 32022L2555) as catalog files of its own; an operator's folder adds others — ISO/IEC 27001,
/// the CIS Controls, whose texts are licensed and not the server's to carry — or replaces a built-in one by its id, such
/// as NIS2 once Spain transposes it. Where a reading is interpretation rather than the letter, the catalog's notes say so.
/// </para>
/// </remarks>
/// <param name="Catalogs">The catalogs, built-in ones first, in the order a finding's answer names them.</param>
public sealed record Compliance(IReadOnlyList<Catalog> Catalogs)
{
    /// <summary>The catalog of <paramref name="id"/>, or null when there is none.</summary>
    public Catalog? Of(string id) => Catalogs.FirstOrDefault(catalog => string.Equals(catalog.Id, id, StringComparison.Ordinal));
}
