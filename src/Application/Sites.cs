using System.Net;
using Snail.MCP.Security.Application.Ports;
using Snail.Sdk.Mcp.Hosting;

namespace Snail.MCP.Security.Application;

/// <summary>A customer's site: whether it is proven theirs, and what its TLS, headers, exposure, services and mail show.</summary>
/// <remarks>
/// <para>
/// A site is checked only when the customer authorised it, and only where the internet can reach it. The authorisation is
/// the TXT record only someone who controls the domain can publish (<see cref="Ownership"/>), read again on every call,
/// so a customer who removes it withdraws it from that moment. Where the internet can reach it is every address the site
/// resolves to being public: a name pointed at a private, loopback or link-local address would turn the scanners against
/// the stand's own network, so such a site is refused whole (<see cref="Addresses.IsPublic"/>), and the scanners are given
/// the addresses checked here, never the name to resolve again.
/// </para>
/// <para>
/// The checks never attack: no exploitation, no guessing of passwords, no flood (see <c>SiteJob</c>). Mail is read from
/// the public DNS alone and needs no address.
/// </para>
/// </remarks>
public sealed class Sites(Ownership ownership, ISiteDns dns, ISiteScanner scanner, TimeProvider clock)
{
    /// <summary>The checks of a site a caller may name, as the tools spell them.</summary>
    public static readonly IReadOnlyDictionary<string, Check> Words = Checks.Site.ToDictionary(check => ToolAnswer.Word(check), check => check, StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether the site the caller named is proven the customer's: the domain whose record proves it, or the record to publish.</summary>
    public async Task<Answer<SiteProof>> ProveAsync(string? named, CancellationToken cancellationToken)
    {
        if (Site.Of(named) is not { } site)
            return Answer.Failed(Messages.NotASite(named ?? string.Empty), type: ToolFailures.Arguments);

        var proven = await ownership.ProvenAsync(site, cancellationToken);
        if (!proven.TryGet(out var domain))
            return proven.As<SiteProof>();

        return Answer.Ok(new SiteProof(site, domain));
    }

    /// <summary>The scan the caller asks for: the site proven, the checks named — every one when none is — and the public addresses the checks that reach the site go to.</summary>
    /// <remarks>Read while the call is still going: the scan itself runs as a job, after the call that started it may have ended.</remarks>
    public async Task<Answer<SitePlan>> PlanAsync(string? named, IReadOnlyList<string>? checks, CancellationToken cancellationToken)
    {
        var unknown = (checks ?? []).Where(word => !Words.ContainsKey(word)).ToList();
        if (unknown.Count > 0)
            return Answer.Failed(Messages.UnknownChecks(unknown, Words.Keys), type: ToolFailures.Arguments);

        IReadOnlyCollection<Check> wanted = checks is { Count: > 0 } ? [.. checks.Select(word => Words[word]).Distinct()] : Checks.Site;

        var proof = await ProveAsync(named, cancellationToken);
        if (!proof.TryGet(out var proven))
            return proof.As<SitePlan>();

        if (wanted.All(check => check == Check.Mail))
            return Answer.Ok(new SitePlan(proven, [], wanted));

        string host = proven.Site.Host;
        var addresses = await dns.AddressesAsync(host, cancellationToken);
        if (addresses is null)
            return Answer.Failed(Messages.DnsUnanswered(host), type: FailureTypes.Unreachable);

        if (addresses.Count == 0)
            return Answer.Failed(Messages.Unresolved(host), type: FailureTypes.Unresolved);

        if (addresses.FirstOrDefault(address => !Addresses.IsPublic(address)) is { } inner)
            return Answer.Failed(Messages.NotPublic(host, inner.ToString()), type: FailureTypes.NotPublic);

        return Answer.Ok(new SitePlan(proven, addresses, wanted));
    }

    /// <summary>Runs the planned checks: the scanners for the ones that reach the site, the public DNS for mail.</summary>
    public async Task<SiteScan> RunAsync(SitePlan plan, CancellationToken cancellationToken)
    {
        var active = plan.Checks.Where(check => check != Check.Mail).ToList();
        var outcome = active.Count > 0
            ? await scanner.ScanAsync(plan.Proof.Site, plan.Addresses, active, cancellationToken)
            : new ScanOutcome([], []);

        List<Finding> findings = [.. outcome.Findings];
        List<CheckRun> runs = [.. outcome.Runs];

        if (plan.Checks.Contains(Check.Mail))
        {
            var mail = await MailAsync(plan.Proof.Site.Host, cancellationToken);
            findings.AddRange(mail.Findings);
            runs.AddRange(mail.Runs);
        }

        var report = new ScanReport(clock.GetUtcNow(), findings, [.. runs.OrderBy(run => run.Check)], null);

        return new SiteScan(plan.Proof, report);
    }

    /// <summary>The domain's SPF and DMARC, from the public DNS; a DNS that did not answer is a check that did not run.</summary>
    private async Task<ScanOutcome> MailAsync(string host, CancellationToken cancellationToken)
    {
        var texts = await dns.TextsAsync(host, cancellationToken);
        var dmarc = await dns.TextsAsync($"_dmarc.{host}", cancellationToken);

        if (texts is null || dmarc is null)
            return new ScanOutcome([], [new CheckRun(Check.Mail, false, Messages.DnsUnanswered(texts is null ? host : $"_dmarc.{host}"))]);

        return new ScanOutcome(MailPolicy.Findings(host, texts, dmarc), [new CheckRun(Check.Mail, true)]);
    }
}

/// <summary>A site proven the customer's, and the domain whose record proves it: the site itself or a parent of it.</summary>
public sealed record SiteProof(Site Site, string ProvenBy);

/// <summary>A scan of a site about to run: its proof, the public addresses its scanners may go to, and the checks.</summary>
public sealed record SitePlan(SiteProof Proof, IReadOnlyList<IPAddress> Addresses, IReadOnlyCollection<Check> Checks);

/// <summary>A proven site's scan: the proof it was made under, and what the checks found.</summary>
public sealed record SiteScan(SiteProof Proof, ScanReport Report);
