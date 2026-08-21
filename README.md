# AWS IAM AccessLens

Paste an AWS IAM policy, see exactly what it grants — get a security score, plain-English findings for wildcards, missing `Condition` blocks, and privilege-escalation paths. **No data leaves the browser.**

[Live Demo](https://aws-iam-accesslens.onrender.com/) · [Report Issues](https://github.com/Enelination/aws-iam-accesslens/issues)

## Features

- **Security Score (0–100)** — composite risk score with grade (A–F) based on IAM best practices
- **Plain-English summaries** — each statement card explains what the policy allows in human-readable language
- **Risk analysis** — color-coded findings: 🔴 Critical, 🟡 Review, 🟢 Scoped
- **Escalation detection** — flags `iam:PassRole`, `iam:CreateAccessKey`, `sts:AssumeRole`, and other sensitive actions without conditions
- **NotAction / NotResource checks** — catches the patterns AWS says never to use
- **Condition block validation** — highlights when MFA, TLS, IP, or other conditions are missing
- **12 built-in sample policies** — from safe scoped reads to dangerous escalation chains
- **Export Report** — download a styled markdown report for your team

## Tools

### CLI

Analyze IAM policy files directly from the terminal:

```sh
npx aws-iam-accesslens policy.json
npx aws-iam-accesslens policy.json --json
npx aws-iam-accesslens policy.json --score-only
```

### GitHub Action

Add to `.github/workflows/iam-lint.yml`:

```yaml
name: IAM Policy Linter
on: [pull_request]
jobs:
  iam-lint:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - uses: Enelination/aws-iam-accesslens/.github/actions/iam-lint@main
        with:
          policy-files: "**/*.json"
          fail-on-danger: "false"
```

This runs on every PR, posts findings as a comment, and optionally fails if HIGH RISK issues are found.

## How the score works

Base score is **100**. Deductions are applied per statement, then a condition bonus is added.

| Finding | Deduction |
|---|---|
| 🔴 Critical finding | −20 |
| 🟡 Warning finding | −6 |
| Full admin (`Action:* + Resource:*`) | −40 |
| Sensitive actions without condition | −15 |

| Bonus | Gain |
|---|---|
| Condition block present | +8 (scaled by % of statements with conditions) |

Minimum 0, maximum 100.

### Grades

| Grade | Score |
|---|---|
| A | 90–100 — follows least-privilege |
| B | 75–89 — some issues, low risk |
| C | 55–74 — several risky patterns |
| D | 35–54 — significant security concerns |
| F | 0–34 — full admin or multiple criticals |

## What it flags

| Finding | Severity |
|---|---|
| `Action: "*" + Resource: "*"` — full admin | 🔴 Critical |
| `NotAction + Resource "*"` — inverts actions on all resources | 🔴 Critical |
| `Action "*" + NotResource` — AWS says "never use this" | 🔴 Critical |
| `iam:PassRole` without condition | 🔴 Critical |
| `iam:CreateAccessKey` / `CreateLoginProfile` without condition | 🔴 Critical |
| Sensitive actions on wildcarded ARNs without condition | 🔴 Critical |
| Service wildcard (`iam:*`) on broad resources | 🔴 Critical |
| `NotAction` or `NotResource` usage | 🟡 Review |
| Wildcard resources or actions | 🟡 Review |
| Sensitive actions without conditions | 🟡 Review |
| Condition block present | 🟢 Scoped |
| MFA / TLS conditions detected | 🟢 Scoped |

## Run locally

```sh
npm install
npm run dev
```

## Build

```sh
npm run build
```

## Deploy to Render

This repo includes `render.yaml` and `server.cjs`. Push to deploy as a static site.

## Tech stack

- React 18 + TypeScript
- Vite
- Zero runtime dependencies — no analytics, no backend, everything runs in the browser

## License

MIT · Built by [Enelination](https://github.com/Enelination)
