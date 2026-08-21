#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { analyzePolicy, analyzeSingleStatement } from "./analyze.js";

const server = new McpServer({
  name: "aws-iam-accesslens",
  version: "0.1.0",
});

server.tool(
  "analyze_policy",
  "Analyze a full AWS IAM policy document for security risks, privilege escalation paths, wildcard overuse, and best-practice violations",
  {
    policy: z.string().describe("IAM policy JSON as a string"),
  },
  async ({ policy }) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(policy);
    } catch {
      return {
        content: [{ type: "text" as const, text: "Error: Invalid JSON. Provide a valid IAM policy document." }],
      };
    }

    const report = analyzePolicy(parsed);

    if (report.statements.length === 0) {
      return {
        content: [{ type: "text" as const, text: "No statements found in the policy." }],
      };
    }

    const lines: string[] = [];
    lines.push(`Security Score: ${report.score}/100 (Grade: ${report.grade})`);
    lines.push(`Statements: ${report.statements.length}`);
    lines.push(`Findings: ${report.totalDanger} danger, ${report.totalWarn} warning, ${report.totalSafe} safe`);
    lines.push("");

    for (const s of report.statements) {
      const icon = s.worstLevel === "danger" ? "🔴" : s.worstLevel === "warn" ? "🟡" : "🟢";
      lines.push(`${icon} ${s.sid} (${s.effect})`);
      lines.push(`  ${s.summary}`);
      for (const f of s.findings) {
        const ficon = f.level === "danger" ? "  ⛔" : f.level === "warn" ? "  ⚠️" : "  ✅";
        lines.push(`${ficon} ${f.msg}`);
      }
      lines.push("");
    }

    return {
      content: [{ type: "text" as const, text: lines.join("\n") }],
    };
  }
);

server.tool(
  "analyze_statement",
  "Analyze a single IAM policy statement for security risks",
  {
    statement: z.string().describe("A single IAM policy statement JSON object as a string"),
  },
  async ({ statement }) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(statement);
    } catch {
      return {
        content: [{ type: "text" as const, text: "Error: Invalid JSON. Provide a valid IAM policy statement." }],
      };
    }

    const s = analyzeSingleStatement(parsed as Record<string, unknown>);

    const lines: string[] = [];
    const icon = s.worstLevel === "danger" ? "🔴" : s.worstLevel === "warn" ? "🟡" : "🟢";
    lines.push(`${icon} ${s.sid} (${s.effect})`);
    lines.push(`  ${s.summary}`);
    lines.push("");
    for (const f of s.findings) {
      const ficon = f.level === "danger" ? "⛔" : f.level === "warn" ? "⚠️" : "✅";
      lines.push(`${ficon} ${f.msg}`);
    }

    return {
      content: [{ type: "text" as const, text: lines.join("\n") }],
    };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch(err => {
  console.error("MCP server error:", err);
  process.exit(1);
});
