# Sites

## <code>security_<wbr>site_<wbr>prove</code>

Prove that a customer's site is theirs before anything is checked on it, or learn how to. A site is proven by a
TXT record under _snail-challenge on the site's domain or a parent of it, holding the code this server gives that
domain; a parent's record covers its subdomains. Proven, the answer names the domain whose record proves it;
not proven, it is refused with type notProven and its hint names the exact record and value to publish. Only
someone who controls the domain's DNS can publish it, which is how the customer authorises the checks. The
record is read again on every call, so removing it withdraws the authorisation. Reads the public DNS through
two resolvers that have to agree; never reaches the site.

*read-only · repeat-safe · may reach outside services.*

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `site` | `string` | yes | — | The site: a public domain name, such as shop.example.com, or an address on it; never an IP address. |

<details><summary>JSON Schema</summary>

```json
{
  "type": "object",
  "properties": {
    "site": {
      "description": "The site: a public domain name, such as shop.example.com, or an address on it; never an IP address.",
      "type": "string"
    }
  },
  "required": [
    "site"
  ]
}
```

</details>

## <code>security_<wbr>site_<wbr>scan</code>

Scan a customer's proven site and get back what weakens it, each finding with the ENS measures and NIS2 letters
it falls under. The checks are tls, headers, mail, exposure and services: TLS — old protocol versions, weak ciphers, a certificate that is
self-signed, expired or for another name; the security headers every site should send; admin panels and files the
site exposes, such as .git/config; open ports and the services behind them, databases and remote administration
facing the internet first; and whether the domain's SPF and DMARC stop mail from being forged. Nothing attacks:
no exploit, no password guessed, at most a few dozen requests a second. A site that is not proven is refused
with type notProven — prove it with security_site_prove first — and one whose name points at an address that is
not public with type notPublic, before anything reaches it. The answer names the 20 worst findings. A scan takes
up to 900 seconds and runs as a job: the answer is the job's report, with the scan as its result when it ends
within the wait, or the running job, whose resource job://security/site/&lt;id&gt; carries the scan once it ends.
Asking for the same scan again within 10 minutes answers with that scan, not a second one.

*read-only · repeat-safe · may reach outside services.*

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `site` | `string` | yes | — | The site: a public domain name, such as shop.example.com, or an address on it; never an IP address. |
| `checks` | `array?` | — | `null` | Which checks to run, any of tls, headers, mail, exposure and services; every one when not given. |
| `wait` | `integer` | — | `60` | Seconds to wait for the scan before answering with the running job, 0 or more; 60 when not given, 0 answers with the job at once. |

<details><summary>JSON Schema</summary>

```json
{
  "type": "object",
  "properties": {
    "site": {
      "description": "The site: a public domain name, such as shop.example.com, or an address on it; never an IP address.",
      "type": "string"
    },
    "checks": {
      "description": "Which checks to run, any of tls, headers, mail, exposure and services; every one when not given.",
      "type": [
        "array",
        "null"
      ],
      "items": {
        "type": [
          "string",
          "null"
        ]
      },
      "default": null
    },
    "wait": {
      "description": "Seconds to wait for the scan before answering with the running job, 0 or more; 60 when not given, 0 answers with the job at once.",
      "type": "integer",
      "default": 60
    }
  },
  "required": [
    "site"
  ]
}
```

</details>

