import React, { useState } from "react";
import { C, mono, sans } from "../lib/theme";

type Tab = "web" | "cli" | "github" | "docker" | "mcp" | "scoring";

const TABS: { key: Tab; label: string }[] = [
  { key: "web", label: "Web UI" },
  { key: "cli", label: "CLI" },
  { key: "github", label: "GitHub Action" },
  { key: "docker", label: "Docker" },
  { key: "mcp", label: "MCP Server" },
  { key: "scoring", label: "Scoring" },
];

const code: Record<Tab, { title: string; desc: string; blocks: { label: string; code: string }[] }> = {
  web: {
    title: "Web UI",
    desc: "Paste an IAM policy into the editor. Analysis runs instantly in your browser — no data ever leaves your machine.",
    blocks: [
      {
        label: "How to use",
        code: `1. Paste your IAM policy JSON into the editor
2. Review the security score (0–100) and grade (A–F)
3. Read each statement card — findings are color-coded:
   🔴 Critical — must fix
   🟡 Review — should fix
   🟢 Passed — scoped correctly
4. Click "Export Report" to download a markdown report`,
      },
    ],
  },
  cli: {
    title: "CLI",
    desc: "Analyze policy files directly from your terminal. Install globally or run with npx.",
    blocks: [
      {
        label: "Install",
        code: `npm install -g aws-iam-accesslens`,
      },
      {
        label: "Usage",
        code: `# Analyze a policy file
npx aws-iam-accesslens policy.json

# JSON output
npx aws-iam-accesslens policy.json --json

# Score only
npx aws-iam-accesslens policy.json --score-only

# Pipe from stdin
cat policy.json | npx aws-iam-accesslens --json`,
      },
    ],
  },
  github: {
    title: "GitHub Action",
    desc: "Automatically lint IAM policies on every pull request. Posts findings as a PR comment and optionally fails on critical issues.",
    blocks: [
      {
        label: ".github/workflows/iam-lint.yml",
        code: `name: IAM Policy Linter
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
          fail-on-danger: "false"`,
      },
    ],
  },
  docker: {
    title: "Docker",
    desc: "Run the analyzer in an isolated container. No Node.js or npm required.",
    blocks: [
      {
        label: "Usage",
        code: `# Analyze a local policy file
docker run --rm -v $(pwd):/policies enel1/aws-iam-accesslens /policies/policy.json

# JSON output
docker run --rm -v $(pwd):/policies enel1/aws-iam-accesslens /policies/policy.json --json

# Pipe from stdin
cat policy.json | docker run --rm -i enel1/aws-iam-accesslens --json`,
      },
    ],
  },
  mcp: {
    title: "MCP Server",
    desc: "Let AI agents (Claude Desktop, Cursor, ChatGPT) analyze IAM policies directly from chat. The agent calls the analyzer as a tool.",
    blocks: [
      {
        label: "Claude Desktop / Cursor config",
        code: `{
  "mcpServers": {
    "iam-accesslens": {
      "command": "npx",
      "args": ["aws-iam-accesslens-mcp"]
    }
  }
}`,
      },
      {
        label: "Available tools",
        code: `analyze_policy    — Analyze a full IAM policy document
analyze_statement — Analyze a single IAM statement`,
      },
    ],
  },
  scoring: {
    title: "Security Score",
    desc: "Each policy starts at 100. Deductions are applied per finding, then a bonus is added for condition blocks.",
    blocks: [
      {
        label: "Deductions",
        code: `🔴 Critical finding          −20
🟡 Warning finding            −6
Full admin (Action:* + Res:*) −40
Sensitive actions no condition −15`,
      },
      {
        label: "Bonus",
        code: `Condition block present      +8 (scaled by % of statements)`,
      },
      {
        label: "Grades",
        code: `A  90–100  Follows least-privilege
B  75–89   Some issues, low risk
C  55–74   Several risky patterns
D  35–54   Significant security concerns
F  0–34    Full admin or multiple criticals`,
      },
    ],
  },
};

export function Docs() {
  const [tab, setTab] = useState<Tab>("web");
  const t = code[tab];

  return (
    <div
      style={{
        background: C.surface,
        borderRadius: 12,
        border: `1px solid ${C.border}`,
        overflow: "hidden",
        marginTop: 32,
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          background: C.bg,
          display: "flex",
          alignItems: "center",
          gap: 10,
        }}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke={C.accent} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z" />
          <path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z" />
        </svg>
        <span
          style={{
            fontFamily: mono,
            fontSize: 12,
            fontWeight: 700,
            color: C.text,
            letterSpacing: -0.3,
          }}
        >
          How to use IAM AccessLens
        </span>
      </div>

      {/* Tabs */}
      <div
        style={{
          display: "flex",
          borderBottom: `1px solid ${C.border}`,
          overflowX: "auto",
          scrollbarWidth: "none",
        }}
      >
        {TABS.map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              background: tab === t.key ? C.surface : "transparent",
              color: tab === t.key ? C.accent : C.muted,
              border: "none",
              borderBottom: tab === t.key ? `2px solid ${C.accent}` : `2px solid transparent`,
              fontFamily: mono,
              fontSize: 11,
              fontWeight: tab === t.key ? 700 : 500,
              padding: "10px 16px",
              cursor: "pointer",
              whiteSpace: "nowrap",
              transition: "all 0.15s",
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ padding: "20px 24px" }}>
        <div
          style={{
            fontFamily: sans,
            fontSize: 14,
            color: C.muted,
            marginBottom: 16,
            lineHeight: 1.5,
          }}
        >
          {t.desc}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {t.blocks.map((b, i) => (
            <div key={i}>
              <div
                style={{
                  fontFamily: mono,
                  fontSize: 10,
                  fontWeight: 600,
                  color: C.faint,
                  textTransform: "uppercase",
                  letterSpacing: 1,
                  marginBottom: 6,
                }}
              >
                {b.label}
              </div>
              <pre
                style={{
                  background: C.bg,
                  border: `1px solid ${C.border}`,
                  borderRadius: 8,
                  padding: "12px 16px",
                  fontFamily: mono,
                  fontSize: 12,
                  lineHeight: 1.6,
                  color: C.text,
                  overflowX: "auto",
                  margin: 0,
                  whiteSpace: "pre",
                }}
              >
                {b.code}
              </pre>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
