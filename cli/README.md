# aws-iam-accesslens

CLI tool to analyze AWS IAM policies for security risks, wildcards, privilege escalation paths, and AWS best practice violations.

## Install

```sh
npm install -g aws-iam-accesslens
```

Or use directly with npx:

```sh
npx aws-iam-accesslens policy.json
```

## Usage

```sh
# Analyze a policy file
iam-accesslens policy.json

# Output as JSON
iam-accesslens policy.json --json

# Score only (no report)
iam-accesslens policy.json --score-only
```

## Example

```sh
$ iam-accesslens policy.json

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  IAM Policy Security Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Score:  64/100  Grade: C
  Moderate — several risky patterns detected.

  🔴 Critical: 1  🟡 Warning: 3  🟢 Passed: 1

  #1 AllowS3ReadOnly  REVIEW
  Allows read S3 objects, list S3 bucket contents on arn:aws:s3:::company-data (gated by conditions).
    ! Resource is not scoped to specific ARNs.
    ✓ Condition block present.

  #2 IAMUserMgmt  HIGH RISK
  Allows create IAM users, create access keys for any user.
    ! Resource is not scoped to specific ARNs.
    ✗ Sensitive actions (iam:createuser, iam:createaccesskey) on broad resources without condition.

  #3 LambdaDeploy  REVIEW
  Allows create Lambda functions, invoke Lambda functions on all resources.
    ! Resource is not scoped to specific ARNs.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## What it flags

| Finding | Severity |
|---|---|
| `Action: "*" + Resource: "*"` — full admin | 🔴 Critical |
| `NotAction + Resource "*"` — inverts actions on all resources | 🔴 Critical |
| `iam:PassRole` without condition | 🔴 Critical |
| `iam:CreateAccessKey` / `CreateLoginProfile` without condition | 🔴 Critical |
| Sensitive actions on wildcarded ARNs without condition | 🔴 Critical |
| Service wildcard (`iam:*`) on broad resources | 🔴 Critical |
| `NotAction` or `NotResource` usage | 🟡 Review |
| Wildcard resources or actions | 🟡 Review |
| Condition block present | 🟢 Scoped |

## How the score works

Base score is 100. Deductions per statement:

| Finding | Deduction |
|---|---|
| 🔴 Critical | -20 |
| 🟡 Warning | -6 |
| Full admin (`Action:* + Resource:*`) | -40 |
| Sensitive actions without condition | -15 |

Bonus: Condition block present (+8, scaled by % of statements with conditions)

| Grade | Score |
|---|---|
| A | 90–100 |
| B | 75–89 |
| C | 55–74 |
| D | 35–54 |
| F | 0–34 |

## Links

- [GitHub](https://github.com/Enelination/aws-iam-accesslens)
- [Live Web UI](https://aws-iam-accesslens.onrender.com/)
- [Report Issues](https://github.com/Enelination/aws-iam-accesslens/issues)

## License

MIT
