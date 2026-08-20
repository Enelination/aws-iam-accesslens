#!/usr/bin/env node

const fs = require("fs");
const path = require("path");

// ── Colors ──────────────────────────────────────────────────────────────
const C = {
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
  dim: "\x1b[2m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
  gray: "\x1b[90m",
  bg: {
    red: "\x1b[41m",
    yellow: "\x1b[43m",
    green: "\x1b[42m",
  },
};

// ── Analysis ────────────────────────────────────────────────────────────
const SENSITIVE = new Set([
  "iam:passrole", "iam:createaccesskey", "iam:createloginprofile",
  "iam:updateloginprofile", "iam:attachuserpolicy", "iam:attachrolepolicy",
  "iam:attachgrouppolicy", "iam:putuserpolicy", "iam:putrolepolicy",
  "iam:putgrouppolicy", "iam:createpolicyversion", "iam:setdefaultpolicyversion",
  "iam:createuser", "sts:assumerole", "sts:assumerolewithsaml",
  "sts:assumerolewithwebidentity", "kms:decrypt", "kms:disablekey",
  "kms:schedulekeydeletion", "organizations:leaveorganization",
  "s3:putbucketpolicy", "s3:putaccesspointpolicy",
  "lambda:createeventmapping", "glue:createdevendpoint",
  "cloudformation:createstack", "cloudformation:updatestack",
]);

const ACTION_NAMES = {
  "*": "any action",
  "iam:passrole": "pass any IAM role",
  "iam:createaccesskey": "create access keys for any user",
  "iam:createloginprofile": "create console password for any user",
  "iam:attachuserpolicy": "attach managed policy to any user",
  "iam:attachrolepolicy": "attach managed policy to any role",
  "iam:putuserpolicy": "embed inline policy on any user",
  "iam:putrolepolicy": "embed inline policy on any role",
  "iam:createpolicyversion": "overwrite managed policies",
  "iam:setdefaultpolicyversion": "switch active policy version",
  "iam:createuser": "create IAM users",
  "sts:assumerole": "assume any IAM role",
  "kms:decrypt": "decrypt KMS-encrypted data",
  "kms:disablekey": "disable KMS keys",
  "organizations:leaveorganization": "leave the AWS organization",
  "s3:getobject": "read S3 objects",
  "s3:putobject": "write S3 objects",
  "s3:deleteobject": "delete S3 objects",
  "s3:listbucket": "list S3 bucket contents",
  "s3:putbucketpolicy": "set bucket policies (can grant public access)",
  "lambda:createfunction": "create Lambda functions",
  "lambda:updatefunctioncode": "update Lambda function code",
  "lambda:invokefunction": "invoke Lambda functions",
  "ec2:runinstances": "launch EC2 instances",
  "ec2:describeinstances": "list EC2 instances",
  "cloudformation:createstack": "create CloudFormation stacks",
};

function normalize(v) {
  if (v == null) return [];
  return (Array.isArray(v) ? v : [v]).map(String);
}

function analyzeStatement(stmt, idx) {
  const findings = [];
  const actions = normalize(stmt.Action ?? stmt.NotAction);
  const resources = normalize(stmt.Resource ?? stmt.NotResource);
  const hasCondition = !!stmt.Condition && Object.keys(stmt.Condition).length > 0;
  const effect = stmt.Effect || "Allow";
  const isAllow = effect === "Allow";
  const hasNotAction = "NotAction" in stmt;
  const hasNotResource = "NotResource" in stmt;

  const hasWildcardAction = actions.some(a => a === "*" || a.endsWith(":*"));
  const hasFullWildcard = actions.includes("*");
  const hasWildcardResource = resources.some(r => r === "*");
  const hasWildcardedArn = resources.some(r => r !== "*" && r.includes("*"));

  const lower = actions.map(a => a.toLowerCase());
  const sensitiveHits = lower.filter(a => SENSITIVE.has(a));

  // NotAction / NotResource
  if (isAllow && hasNotAction && hasWildcardResource) {
    findings.push({ level: "danger", msg: 'NotAction + Resource "*" — allows everything except listed actions on all resources.' });
  } else if (isAllow && hasNotAction) {
    findings.push({ level: "warn", msg: "NotAction inverts the action list — everything not listed is allowed." });
  }
  if (isAllow && hasNotResource && hasFullWildcard) {
    findings.push({ level: "danger", msg: 'Action "*" + NotResource — AWS warns: "never use this combination."' });
  } else if (isAllow && hasNotResource) {
    findings.push({ level: "warn", msg: "NotResource inverts the resource list — all unlisted resources are in scope." });
  }

  // Wildcards
  if (isAllow && hasFullWildcard && hasWildcardResource) {
    findings.push({ level: "danger", msg: "Full administrative access — every action on every resource." });
  } else {
    if (isAllow && hasWildcardAction) findings.push({ level: "warn", msg: "Uses a wildcard action (service:*)." });
    if (isAllow && (hasWildcardResource || hasWildcardedArn) && actions.length > 0) {
      findings.push({ level: "warn", msg: "Resource is not scoped to specific ARNs." });
    }
  }

  // PassRole
  if (isAllow && lower.includes("iam:passrole") && !hasCondition) {
    findings.push({ level: "danger", msg: "iam:PassRole without condition — privilege escalation." });
  }

  // Sensitive + wildcards
  if (isAllow && sensitiveHits.length > 0 && (hasWildcardResource || hasWildcardedArn) && !hasCondition) {
    findings.push({ level: "danger", msg: `Sensitive actions (${[...new Set(sensitiveHits)].join(", ")}) on broad resources without condition.` });
  }

  // Sensitive without condition
  if (isAllow && sensitiveHits.length > 0 && !hasWildcardResource && !hasWildcardedArn && !hasCondition) {
    findings.push({ level: "warn", msg: `Sensitive actions (${[...new Set(sensitiveHits)].join(", ")}) without Condition block.` });
  }

  // Safe
  if (isAllow && !hasCondition && !hasWildcardAction && !hasWildcardResource && !hasWildcardedArn && !hasNotAction && !hasNotResource) {
    findings.push({ level: "safe", msg: "Scoped actions and resources." });
  } else if (isAllow && hasCondition) {
    findings.push({ level: "safe", msg: "Condition block present." });
  }

  const worstLevel = findings.some(f => f.level === "danger") ? "danger"
    : findings.some(f => f.level === "warn") ? "warn" : "safe";

  // Describe
  const verb = isAllow ? "Allows" : "Denies";
  let actionDesc;
  if (actions.includes("*")) actionDesc = "any action";
  else if (hasNotAction) actionDesc = `any action except ${actions.join(", ")}`;
  else actionDesc = actions.map(a => ACTION_NAMES[a.toLowerCase()] || a).join(", ");

  let resourceDesc;
  if (resources.length === 0) resourceDesc = "no resources";
  else if (resources.every(r => r === "*")) resourceDesc = "all resources";
  else resourceDesc = resources.map(r => r === "*" ? "all resources" : r).join(", ");

  const summary = `${verb} ${actionDesc} on ${resourceDesc}${hasCondition ? " (gated by conditions)" : ""}.`;

  return {
    idx,
    sid: stmt.Sid || `Statement ${idx + 1}`,
    effect,
    actions,
    resources,
    hasCondition,
    findings,
    worstLevel,
    summary,
  };
}

function analyzePolicy(json) {
  const raw = json.Statement;
  const arr = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return arr.map((s, i) => analyzeStatement(s, i));
}

function computeScore(statements) {
  if (statements.length === 0) return { score: 100, grade: "A" };
  let deductions = 0;
  for (const s of statements) {
    const dCount = s.findings.filter(f => f.level === "danger").length;
    const wCount = s.findings.filter(f => f.level === "warn").length;
    deductions += dCount * 20;
    deductions += wCount * 6;
    const hasFullAdmin = s.actions.includes("*") && s.resources.includes("*");
    if (hasFullAdmin) deductions += 40;
    const sensitiveNoCondition = s.findings.some(f =>
      f.level === "danger" && (f.msg.includes("PassRole") || f.msg.includes("CreateAccessKey") || f.msg.includes("CreateLoginProfile"))
    ) && !s.hasCondition;
    if (sensitiveNoCondition) deductions += 15;
  }
  const withCond = statements.filter(s => s.hasCondition).length;
  deductions -= Math.floor((withCond / statements.length) * 8);
  const score = Math.max(0, Math.min(100, 100 - deductions));
  const grade = score >= 90 ? "A" : score >= 75 ? "B" : score >= 55 ? "C" : score >= 35 ? "D" : "F";
  return { score, grade };
}

// ── Output ──────────────────────────────────────────────────────────────
function printReport(statements, score, grade) {
  const gradeColors = { A: C.green, B: C.green, C: C.yellow, D: C.red, F: C.red };
  const gradeMessages = {
    A: "Excellent — follows least-privilege best practices.",
    B: "Good — a few items worth reviewing.",
    C: "Moderate — several risky patterns detected.",
    D: "Poor — significant security concerns.",
    F: "Failing — grants excessive permissions.",
  };

  console.log();
  console.log(`${C.bold}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}`);
  console.log(`${C.bold}  IAM Policy Security Report${C.reset}`);
  console.log(`${C.bold}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}`);
  console.log();
  console.log(`  Score:  ${gradeColors[grade]}${C.bold}${score}/100${C.reset}  Grade: ${gradeColors[grade]}${C.bold}${grade}${C.reset}`);
  console.log(`  ${C.dim}${gradeMessages[grade]}${C.reset}`);
  console.log();

  let danger = 0, warn = 0, safe = 0;
  for (const s of statements) {
    for (const f of s.findings) {
      if (f.level === "danger") danger++;
      else if (f.level === "warn") warn++;
      else safe++;
    }
  }

  console.log(`  ${C.red}🔴 Critical: ${danger}${C.reset}  ${C.yellow}🟡 Warning: ${warn}${C.reset}  ${C.green}🟢 Passed: ${safe}${C.reset}`);
  console.log();

  for (const s of statements) {
    const lvl = s.worstLevel === "danger" ? `${C.red}HIGH RISK${C.reset}`
      : s.worstLevel === "warn" ? `${C.yellow}REVIEW${C.reset}`
      : `${C.green}SCOPED${C.reset}`;

    console.log(`  ${C.bold}#${s.idx + 1} ${s.sid}${C.reset}  ${lvl}`);
    console.log(`  ${C.dim}${s.summary}${C.reset}`);

    for (const f of s.findings) {
      const icon = f.level === "danger" ? `${C.red}✗${C.reset}` : f.level === "warn" ? `${C.yellow}!${C.reset}` : `${C.green}✓${C.reset}`;
      console.log(`    ${icon} ${f.msg}`);
    }
    console.log();
  }

  console.log(`${C.bold}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C.reset}`);
  console.log(`${C.dim}  Generated by IAM Visualizer — github.com/Enelination/aws-iam-accesslens${C.reset}`);
  console.log();
}

// ── Main ────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);

if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
  console.log(`
  ${C.bold}IAM Visualizer CLI${C.reset}

  Usage:  iam-accesslens <policy.json> [options]

  Options:
    --help, -h      Show this help
    --json          Output as JSON instead of report
    --score-only    Only output the score
  `);
  process.exit(0);
}

const filePath = args[0];
const jsonOutput = args.includes("--json");
const scoreOnly = args.includes("--score-only");

let raw;
try {
  raw = fs.readFileSync(path.resolve(filePath), "utf-8");
} catch (e) {
  console.error(`${C.red}Error: Could not read file "${filePath}"${C.reset}`);
  process.exit(1);
}

let policy;
try {
  policy = JSON.parse(raw);
} catch (e) {
  console.error(`${C.red}Error: Invalid JSON — ${e.message}${C.reset}`);
  process.exit(1);
}

const statements = analyzePolicy(policy);
const { score, grade } = computeScore(statements);

if (scoreOnly) {
  console.log(score);
  process.exit(0);
}

if (jsonOutput) {
  let danger = 0, warn = 0, safe = 0;
  for (const s of statements) {
    for (const f of s.findings) {
      if (f.level === "danger") danger++;
      else if (f.level === "warn") warn++;
      else safe++;
    }
  }
  console.log(JSON.stringify({ score, grade, totalDanger: danger, totalWarn: warn, totalSafe: safe, statements }, null, 2));
  process.exit(0);
}

printReport(statements, score, grade);
