# Tools

3 tools in 2 families.
The names, descriptions and schemas are generated from the server itself, so they are exactly what the model receives in `tools/list`.

| Tool | Family | What it does |
| --- | --- | --- |
| [`security_scan`](scans.md#security_scan) | Scans | Scan the task's working copy for security problems and get back what blocks the work. |
| [`security_findings`](scans.md#security_findings) | Scans | Read the findings of the task's last scan page by page, worst first, with where each one is, what fixes it and the ENS measures and NIS2 letters it falls under. |
| [`security_diagnose`](diagnostics.md#security_diagnose) | Diagnostics | Say whether this server can scan at all: Nomad's version, the scanner images, the network they run in and the hosts the egress proxy lets through. |
