# AWS IAM AccessLens

Paste an AWS IAM policy, see exactly what it grants — and get plain-English findings for wildcards, missing `Condition` blocks, and privilege-escalation paths. **No data leaves the browser.**

## What it does

- **Plain-English summaries** — each statement card explains what the policy allows in human-readable language
- **Risk analysis** — color-coded findings for high risk, review, and scoped statements
- **Escalation detection** — flags `iam:PassRole`, `iam:CreateAccessKey`, `sts:AssumeRole`, and other sensitive actions without conditions
- **AWS best practices** — checks based on the official [IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html), including `NotAction`/`NotResource` misuse detection
- **12 built-in sample policies** — from safe scoped reads to dangerous escalation chains

## What it flags

| Finding | Severity |
|---|---|
| `Action: "*" + Resource: "*"` — full admin | HIGH RISK |
| `NotAction + Resource "*"` — inverts actions on all resources | HIGH RISK |
| `Action "*" + NotResource` — AWS says "never use this" | HIGH RISK |
| `iam:PassRole` without condition | HIGH RISK |
| `iam:CreateAccessKey` / `CreateLoginProfile` without condition | HIGH RISK |
| Sensitive actions on wildcarded ARNs without condition | HIGH RISK |
| Service wildcard (`iam:*`) on broad resources | HIGH RISK |
| `NotAction` or `NotResource` usage | REVIEW |
| Wildcard resources or actions | REVIEW |
| Sensitive actions without conditions | REVIEW |
| Condition block present | PASSED |
| MFA / TLS conditions detected | PASSED |

## Run locally

```sh
npm install
npm run dev
```

## Build

```sh
npm run build
```

## Tech stack

- React 18 + TypeScript
- Vite
- Zero dependencies — no analytics, no backend, everything runs in the browser

## License

MIT
