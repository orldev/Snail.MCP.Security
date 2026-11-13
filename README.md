# Snail.MCP.Security

Security checks of a working copy and of a proven site, mapped to ENS and NIS2

Its tools: [docs/reference/tools](docs/reference/tools/index.md), written from the server itself. Built on
[Snail.Sdk](https://github.com/orldev/Snail.Sdk): the rules, the dotnet tool package, publishing into `~/.s3l-mcp`, the
shared workflows.

```bash
dotnet publish src -c Release -r osx-arm64 -p:SnailMcpInstall=true    # ~/.s3l-mcp/Snail.MCP.Security/current
```

## Compliance catalogs

Every finding carries the references it falls under, a field per catalog: `ens` (Real Decreto 311/2022, Anexo II) and
`nis2` (Directive (EU) 2022/2555, Article 21(2)) are built in, as [src/Catalogs](src/Catalogs). A folder named by
`SNAIL_MCP_SECURITY_COMPLIANCE_CATALOGS` adds others, one `*.json` each, or replaces a built-in one by its `id`:

```json
{
  "id": "iso27001",
  "name": "ISO/IEC 27001:2022, Annex A",
  "source": "the organisation's licensed copy",
  "checked": "2026-11-13",
  "titled": false,
  "references": [ { "code": "A.8.8", "title": "Management of technical vulnerabilities" } ],
  "checks": [ { "check": "packages", "references": [ "A.8.8" ] } ]
}
```

A line places the findings of a `check` (packages, secrets, config, code, tls, headers, mail, exposure, services), or
only those whose rule contains `ruleContains`; the first line that places a finding decides. A check with no line has no
references in that catalog. A file that is not a catalog refuses the start, naming the file and what is wrong.
`security_diagnose` lists the catalogs in use and where each was read from.
