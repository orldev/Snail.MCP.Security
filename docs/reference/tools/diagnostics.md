# Diagnostics

## <code>security_<wbr>diagnose</code>

Say whether this server can scan at all: Nomad's version, the scanner images, the network they run in and the
hosts the egress proxy lets through, and for sites the nmap and Nuclei images, the templates' version, the
network, the ports and how fast the site scanners go, and the compliance catalogs findings are placed in.
Changes nothing.

*read-only · repeat-safe · stays on this machine.*

Takes no parameters.

<details><summary>JSON Schema</summary>

```json
{
  "type": "object",
  "properties": {}
}
```

</details>

