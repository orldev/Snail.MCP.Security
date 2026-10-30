# Scans

## <code>security_<wbr>scan</code>

Scan the task's working copy for security problems and get back what blocks the work. The checks are
packages, secrets, config and code: packages with a published vulnerability (NuGet from NuGet's own advisories, every other ecosystem by
Trivy), secrets written into files, insecure Dockerfile, compose and Kubernetes settings, and insecure code found
by Semgrep. Each finding carries a severity — critical, high, medium, low or unknown — where it is, the version that fixes a package when
one is known, and the ENS measures and NIS2 letters it falls under. The scan is clean when nothing is critical or
high and every check ran. The answer names the 20 worst findings and how this scan compares with the task's scan
before it: fixed, new, remaining. A scan takes up to 900 seconds; scans run one at a time. The scan runs as a job:
the answer is the job's report, with the scan as its result when it ends within the wait, or the running job,
whose resource job://security/scan/&lt;id&gt; carries the scan once it ends; the last scan is also read with
security_findings. Asking for the same scan while it runs answers with that scan's job, not a second scan.

*read-only · repeat-safe · stays on this machine.*

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `checks` | `array?` | — | `null` | Which checks to run, any of packages, secrets, config and code; every one when not given. |
| `wait` | `integer` | — | `60` | Seconds to wait for the scan before answering with the running job; 60 when not given, 0 answers with the job at once. |

<details><summary>JSON Schema</summary>

```json
{
  "type": "object",
  "properties": {
    "checks": {
      "description": "Which checks to run, any of packages, secrets, config and code; every one when not given.",
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
      "description": "Seconds to wait for the scan before answering with the running job; 60 when not given, 0 answers with the job at once.",
      "type": "integer",
      "default": 60
    }
  }
}
```

</details>

## <code>security_<wbr>findings</code>

Read the findings of the task's last scan page by page, worst first, with where each one is, what fixes it and
the ENS measures and NIS2 letters it falls under. Narrow by severity and by check. A page holds 20 findings unless
asked for more, at most 100.

*read-only · repeat-safe · stays on this machine.*

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `severity` | `string?` | — | `null` | Only findings this severe or worse: critical, high, medium, low or unknown; all when not given. |
| `check` | `string?` | — | `null` | Only findings of one check: packages, secrets, config and code; all when not given. |
| `offset` | `integer` | — | `0` | How many findings to skip, for the next page; 0 when not given. |
| `limit` | `integer?` | — | `null` | How many findings one page holds; 20 when not given, at most 100. |

<details><summary>JSON Schema</summary>

```json
{
  "type": "object",
  "properties": {
    "severity": {
      "description": "Only findings this severe or worse: critical, high, medium, low or unknown; all when not given.",
      "type": [
        "string",
        "null"
      ],
      "default": null
    },
    "check": {
      "description": "Only findings of one check: packages, secrets, config and code; all when not given.",
      "type": [
        "string",
        "null"
      ],
      "default": null
    },
    "offset": {
      "description": "How many findings to skip, for the next page; 0 when not given.",
      "type": "integer",
      "default": 0
    },
    "limit": {
      "description": "How many findings one page holds; 20 when not given, at most 100.",
      "type": [
        "integer",
        "null"
      ],
      "default": null
    }
  }
}
```

</details>

