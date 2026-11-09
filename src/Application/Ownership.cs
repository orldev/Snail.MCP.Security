using System.Security.Cryptography;
using System.Text;
using Snail.MCP.Security.Application.Ports;

namespace Snail.MCP.Security.Application;

/// <summary>Whether a customer has proven a site is theirs: a TXT record with the server's code for the domain, under _snail-challenge.</summary>
/// <remarks>
/// <para>
/// Scanning a system without its owner's authorisation is a crime in Spain: article 197 bis of the Código Penal punishes
/// access «vulnerando las medidas de seguridad… y sin estar debidamente autorizado», article 264 bis an obstruction
/// «sin estar autorizado y de manera grave». The proof is how the authorisation is shown: only someone who controls the
/// domain's zone can publish the record, as with Google's and Let's Encrypt's verification.
/// </para>
/// <para>
/// The code is an HMAC of the domain under the server's secret: the same domain always gets the same code, no list of
/// issued codes is kept, and nobody without the secret can make one. It is read again before every scan, so a customer
/// who removes the record withdraws the authorisation from that moment on.
/// </para>
/// </remarks>
public sealed class Ownership(ISiteDns dns, IProofKey key)
{
    /// <summary>The value the customer publishes to prove <paramref name="domain"/>.</summary>
    public string CodeOf(string domain)
    {
        byte[] mac = HMACSHA256.HashData(key.Bytes, Encoding.UTF8.GetBytes(domain.ToLowerInvariant()));

        return $"snail-verify={Convert.ToHexStringLower(mac.AsSpan(0, 20))}";
    }

    /// <summary>The domain whose record proves the site — the site itself or a parent of it — or why none does.</summary>
    public async Task<Answer<string>> ProvenAsync(Site site, CancellationToken cancellationToken)
    {
        foreach (string domain in site.Provers)
        {
            var texts = await dns.TextsAsync(Site.RecordOf(domain), cancellationToken);
            if (texts is null)
                return Answer.Failed(Messages.DnsUnanswered(Site.RecordOf(domain)), type: FailureTypes.Unreachable);

            if (texts.Contains(CodeOf(domain), StringComparer.Ordinal))
                return Answer.Ok(domain);
        }

        return Answer.Failed(Messages.NotProven(site.Host), Messages.ProveHint(Site.RecordOf(site.Host), CodeOf(site.Host)), FailureTypes.NotProven);
    }
}
