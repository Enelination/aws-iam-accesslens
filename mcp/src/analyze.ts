// ── Types ───────────────────────────────────────────────────────────────
export type Level = "danger" | "warn" | "safe";

export interface Finding {
  level: Level;
  msg: string;
}

export interface AnalyzedStatement {
  idx: number;
  sid: string;
  effect: string;
  actions: string[];
  resources: string[];
  hasCondition: boolean;
  findings: Finding[];
  worstLevel: Level;
  summary: string;
}

export interface PolicyReport {
  statements: AnalyzedStatement[];
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  totalDanger: number;
  totalWarn: number;
  totalSafe: number;
}

// ── Sensitive Actions ───────────────────────────────────────────────────
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

const ACTION_NAMES: Record<string, string> = {
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

// ── Helpers ─────────────────────────────────────────────────────────────
function normalize(v: unknown): string[] {
  if (v == null) return [];
  return (Array.isArray(v) ? v : [v]).map(String);
}

// ── Statement Analysis ──────────────────────────────────────────────────
function analyzeStatement(stmt: Record<string, unknown>, idx: number): AnalyzedStatement {
  const findings: Finding[] = [];
  const actions = normalize(stmt.Action ?? stmt.NotAction);
  const resources = normalize(stmt.Resource ?? stmt.NotResource);
  const hasCondition = !!stmt.Condition && Object.keys(stmt.Condition as Record<string, unknown>).length > 0;
  const effect = (stmt.Effect as string) || "Allow";
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

  const worstLevel: Level = findings.some(f => f.level === "danger") ? "danger"
    : findings.some(f => f.level === "warn") ? "warn" : "safe";

  // Describe
  const verb = isAllow ? "Allows" : "Denies";
  let actionDesc: string;
  if (actions.includes("*")) actionDesc = "any action";
  else if (hasNotAction) actionDesc = `any action except ${actions.join(", ")}`;
  else actionDesc = actions.map(a => ACTION_NAMES[a.toLowerCase()] || a).join(", ");

  let resourceDesc: string;
  if (resources.length === 0) resourceDesc = "no resources";
  else if (resources.every(r => r === "*")) resourceDesc = "all resources";
  else resourceDesc = resources.map(r => r === "*" ? "all resources" : r).join(", ");

  const summary = `${verb} ${actionDesc} on ${resourceDesc}${hasCondition ? " (gated by conditions)" : ""}.`;

  return {
    idx,
    sid: (stmt.Sid as string) || `Statement ${idx + 1}`,
    effect,
    actions,
    resources,
    hasCondition,
    findings,
    worstLevel,
    summary,
  };
}

// ── Scoring ─────────────────────────────────────────────────────────────
function computeScore(statements: AnalyzedStatement[]): { score: number; grade: "A" | "B" | "C" | "D" | "F" } {
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
  const grade = score >= 90 ? "A" as const : score >= 75 ? "B" as const : score >= 55 ? "C" as const : score >= 35 ? "D" as const : "F" as const;
  return { score, grade };
}

// ── Public API ──────────────────────────────────────────────────────────
export function analyzePolicy(policyJson: unknown): PolicyReport {
  if (!policyJson || typeof policyJson !== "object") {
    return { statements: [], score: 100, grade: "A", totalDanger: 0, totalWarn: 0, totalSafe: 0 };
  }
  const raw = (policyJson as { Statement?: unknown }).Statement;
  const arr: Record<string, unknown>[] = Array.isArray(raw) ? raw as Record<string, unknown>[] : raw ? [raw as Record<string, unknown>] : [];
  const statements = arr.map((s, i) => analyzeStatement(s, i));
  const { score, grade } = computeScore(statements);

  let totalDanger = 0;
  let totalWarn = 0;
  let totalSafe = 0;
  for (const s of statements) {
    for (const f of s.findings) {
      if (f.level === "danger") totalDanger++;
      else if (f.level === "warn") totalWarn++;
      else totalSafe++;
    }
  }

  return { statements, score, grade, totalDanger, totalWarn, totalSafe };
}

export function analyzeSingleStatement(stmt: Record<string, unknown>): AnalyzedStatement {
  return analyzeStatement(stmt, 0);
}
