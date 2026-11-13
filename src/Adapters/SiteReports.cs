using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;

namespace Snail.MCP.Security.Adapters;

/// <summary>What the site scanners printed, read into findings of the shape a copy's scan has.</summary>
/// <remarks>
/// <para>
/// Nuclei prints one JSON document a line, one per match; nmap one XML document. Both are read as they come from a real
/// run, kept in the tests as fixtures. Where a finding is is what a person opens to see it: an address for Nuclei,
/// <c>host:port</c> for nmap.
/// </para>
/// <para>
/// What the scanners call «info» is mostly inventory — the TLS versions a site offers, the server it runs — and is left
/// out, with two exceptions that are a weakness however a template rates them: a missing security header among the
/// ones every site should send, and an admin panel or a file that faces the internet.
/// </para>
/// </remarks>
public static class SiteReports
{
    /// <summary>The headers whose absence is a finding: the ones every site should send, as OWASP's secure headers project names them.</summary>
    public static readonly IReadOnlySet<string> RequiredHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy"
    };

    /// <summary>Services that should never face the internet, by port, with how bad it is when one does.</summary>
    /// <remarks>Remote administration in clear text, file sharing, databases, caches, queues, and the control planes of Docker and Kubernetes.</remarks>
    public static readonly IReadOnlyDictionary<int, (string Service, Severity Severity)> Exposed = new Dictionary<int, (string, Severity)>
    {
        [21] = ("FTP", Severity.High),
        [23] = ("Telnet", Severity.High),
        [111] = ("RPC portmapper", Severity.High),
        [135] = ("Windows RPC", Severity.High),
        [139] = ("NetBIOS", Severity.High),
        [445] = ("SMB file sharing", Severity.High),
        [1433] = ("SQL Server", Severity.High),
        [1521] = ("Oracle Database", Severity.High),
        [2049] = ("NFS", Severity.High),
        [2375] = ("Docker API without TLS", Severity.Critical),
        [2376] = ("Docker API", Severity.High),
        [3306] = ("MySQL", Severity.High),
        [3389] = ("Remote Desktop", Severity.High),
        [5432] = ("PostgreSQL", Severity.High),
        [5601] = ("Kibana", Severity.High),
        [5672] = ("AMQP message broker", Severity.High),
        [5900] = ("VNC", Severity.High),
        [5984] = ("CouchDB", Severity.High),
        [6379] = ("Redis", Severity.High),
        [6443] = ("Kubernetes API", Severity.High),
        [9200] = ("Elasticsearch", Severity.High),
        [9300] = ("Elasticsearch transport", Severity.High),
        [10250] = ("Kubernetes kubelet", Severity.Critical),
        [11211] = ("Memcached", Severity.High),
        [15672] = ("RabbitMQ management", Severity.High),
        [27017] = ("MongoDB", Severity.High)
    };

    /// <summary>The web's ports, whose being open is the site itself rather than a finding.</summary>
    private static readonly HashSet<int> Web = [80, 443];

    /// <summary>How nmap's XML is read: its DOCTYPE skipped, and no entity of any document resolved.</summary>
    private static readonly XmlReaderSettings Reading = new() { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null };

    /// <summary>The protocol versions no site should offer any more.</summary>
    private static readonly HashSet<string> OldProtocols = new(StringComparer.Ordinal) { "SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1" };

    /// <summary>Nuclei's matches: TLS, missing headers, and what the site exposes.</summary>
    public static IReadOnlyList<Finding> Nuclei(string jsonl)
    {
        List<Finding> findings = [];

        foreach (string line in jsonl.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (Parse(line) is not { } match)
                continue;

            if (FindingOf(match) is { } finding)
                findings.Add(finding);
        }

        return [.. findings.DistinctBy(finding => finding.Identity, StringComparer.Ordinal)];
    }

    /// <summary>nmap's report: services that should not face the internet, other open services, and old or weak TLS.</summary>
    /// <returns>The findings, or null when the text is not nmap's XML.</returns>
    public static IReadOnlyList<Finding>? Nmap(string xml)
    {
        XDocument document;
        try
        {
            using var text = new StringReader(xml);
            using var reader = XmlReader.Create(text, Reading);
            document = XDocument.Load(reader, LoadOptions.None);
        }
        catch (XmlException)
        {
            return null;
        }

        if (document.Root?.Name.LocalName != "nmaprun")
            return null;

        List<Finding> findings = [];

        foreach (var host in document.Root.Elements("host"))
        {
            string address = (string?)host.Elements("address").FirstOrDefault(element => (string?)element.Attribute("addrtype") is "ipv4" or "ipv6")?.Attribute("addr") ?? "host";

            foreach (var port in host.Element("ports")?.Elements("port") ?? [])
            {
                if ((string?)port.Element("state")?.Attribute("state") != "open")
                    continue;

                findings.AddRange(PortFindings(address, port));
            }
        }

        return findings;
    }

    private static Finding? FindingOf(JsonNode match)
    {
        string id = (string?)match["template-id"] ?? "nuclei";
        string path = ((string?)match["template-path"] ?? string.Empty).Replace('\\', '/');
        string at = (string?)match["matched-at"] ?? (string?)match["host"] ?? string.Empty;
        string name = (string?)match["info"]?["name"] ?? id;
        string? link = (string?)match["template-url"];
        string severity = ((string?)match["info"]?["severity"] ?? "unknown").ToLowerInvariant();

        if (id == "http-missing-security-headers")
        {
            string header = (string?)match["matcher-name"] ?? string.Empty;
            if (!RequiredHeaders.Contains(header))
                return null;

            return new Finding(Check.Headers, Severity.Low, $"{id}:{header}", $"Missing security header {header}", at, Link: link);
        }

        bool isTls = path.Contains("/ssl/", StringComparison.Ordinal) || (string?)match["type"] == "ssl";
        bool isExposure = path.Contains("/exposures/", StringComparison.Ordinal) || path.Contains("/exposed-panels/", StringComparison.Ordinal);

        if (severity == "info" && !isExposure)
            return null;

        var check = isTls ? Check.Tls : Check.Exposure;

        return new Finding(check, severity == "info" ? Severity.Low : SeverityOf(severity), id, name, at, Link: link);
    }

    private static IEnumerable<Finding> PortFindings(string address, XElement port)
    {
        int number = int.TryParse((string?)port.Attribute("portid"), NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) ? parsed : 0;
        string at = $"{address}:{number}";
        var service = port.Element("service");
        string described = Described(service);

        if (Exposed.TryGetValue(number, out var exposed))
            yield return new Finding(Check.Services, exposed.Severity, $"exposed-{number}", $"{exposed.Service} faces the internet{described}", at);
        else if (!Web.Contains(number))
            yield return new Finding(Check.Services, Severity.Low, $"open-{number}", $"Port {number} is open{described}", at);

        foreach (var finding in TlsFindings(at, port))
            yield return finding;
    }

    /// <summary>What ssl-enum-ciphers found: protocol versions no site should offer, and cipher suites below the grade a site should hold.</summary>
    private static IEnumerable<Finding> TlsFindings(string at, XElement port)
    {
        var ciphers = port.Elements("script").FirstOrDefault(script => (string?)script.Attribute("id") == "ssl-enum-ciphers");
        if (ciphers is null)
            yield break;

        foreach (var protocol in ciphers.Elements("table"))
        {
            string version = (string?)protocol.Attribute("key") ?? string.Empty;
            if (OldProtocols.Contains(version))
                yield return new Finding(Check.Tls, Severity.Medium, $"old-protocol-{version}", $"{version} is offered: it is broken and no client needs it", at);
        }

        string? grade = ciphers.Elements("elem").FirstOrDefault(element => (string?)element.Attribute("key") == "least strength")?.Value;
        if (grade is { Length: > 0 } and not "A")
            yield return new Finding(Check.Tls, grade == "B" ? Severity.Low : Severity.Medium, "weak-ciphers", $"The weakest cipher suite offered is graded {grade}", at);
    }

    private static string Described(XElement? service)
    {
        string product = $"{(string?)service?.Attribute("product")} {(string?)service?.Attribute("version")}".Trim();

        return product.Length > 0 ? $": {product}" : string.Empty;
    }

    private static Severity SeverityOf(string severity) => severity switch
    {
        "critical" => Severity.Critical,
        "high" => Severity.High,
        "medium" => Severity.Medium,
        "low" => Severity.Low,
        _ => Severity.Unknown
    };

    private static JsonNode? Parse(string json)
    {
        try
        {
            return JsonNode.Parse(json);
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
