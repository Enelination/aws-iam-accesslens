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
  condition?: Record<string, unknown>;
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

// Actions that are high-value escalation paths or data-exfil primitives.
// Grouped by category for clearer messages.
const ESCALATION_ACTIONS: Record<string, string> = {
  "iam:passrole": "Privilege escalation — hands any role to a service.",
  "iam:createaccesskey": "Credential theft — creates access keys for any user.",
  "iam:createloginprofile": "Account takeover — creates console password for any user.",
  "iam:updateloginprofile": "Account takeover — resets console password for any user.",
  "iam:attachuserpolicy": "Privilege escalation — attaches any managed policy to any user.",
  "iam:attachrolepolicy": "Privilege escalation — attaches any managed policy to any role.",
  "iam:attachgrouppolicy": "Privilege escalation — attaches any managed policy to any group.",
  "iam:putuserpolicy": "Privilege escalation — embeds inline policy on any user.",
  "iam:putrolepolicy": "Privilege escalation — embeds inline policy on any role.",
  "iam:putgrouppolicy": "Privilege escalation — embeds inline policy on any group.",
  "iam:createpolicyversion": "Policy modification — can overwrite existing managed policies.",
  "iam:setdefaultpolicyversion": "Policy modification — can switch active policy version.",
  "iam:createuser": "Identity manipulation — creates new IAM users.",
  "sts:assumerole": "Cross-account / privilege escalation — assumes any role.",
  "sts:assumerolewithsaml": "Cross-account escalation — assumes role with SAML.",
  "sts:assumerolewithwebidentity": "Cross-account escalation — assumes role with web identity.",
  "kms:createkey": "Key management — creates KMS keys.",
  "kms:decrypt": "Data access — decrypts KMS-encrypted data.",
  "kms:reencryptdata": "Data access — re-encrypts data with different keys.",
  "kms:createdgrant": "Key access — creates grants on KMS keys.",
  "kms:putkeypolicy": "Key management — modifies KMS key policies.",
  "kms:disablekey": "Denial of service — disables KMS keys.",
  "kms:schedulekeydeletion": "Destructive — schedules KMS key deletion.",
  "organizations:leaveorganization": "Boundary escape — leaves the organization.",
  "s3:putbucketpolicy": "Data exposure — can set bucket policies to grant public access.",
  "s3:putaccesspointpolicy": "Data exposure — can set access point policies.",
  "lambda:createeventmapping": "Data access — can wire event sources to invoke Lambda.",
  "glue:createdevendpoint": "Privilege escalation — dev endpoints assume IAM roles.",
  "datapipeline:createpipeline": "Privilege escalation — pipelines assume IAM roles.",
  "datapipeline:activatepipeline": "Privilege escalation — activates pipeline with role access.",
  "ec2:runinstances": "Compute access — launches instances, can leverage attached roles.",
  "codebuild:createproject": "Privilege escalation — CodeBuild projects assume roles.",
  "cloudformation:createstack": "Privilege escalation — stacks can create arbitrary resources.",
  "cloudformation:updatestack": "Privilege escalation — can modify stack to create new resources.",
  "stepfunctions:createstatemachine": "Privilege escalation — state machines can assume roles.",
  "events:putrule": "Privilege escalation — event rules can invoke services with roles.",
};

// Actions that strongly need a Condition block per AWS best practices.
// These are escalation paths or data-access actions that should be gated.
const NEEDS_CONDITION_ACTIONS = new Set(Object.keys(ESCALATION_ACTIONS));

// Human-readable action descriptions for key AWS actions.
const ACTION_DESCRIPTIONS: Record<string, string> = {
  "*": "perform any action",
  // IAM
  "iam:createaccesskey": "create access keys for any user",
  "iam:createloginprofile": "create a console password for any user",
  "iam:updateloginprofile": "reset a console password for any user",
  "iam:attachuserpolicy": "attach any managed policy to any user",
  "iam:attachrolepolicy": "attach any managed policy to any role",
  "iam:attachgrouppolicy": "attach any managed policy to any group",
  "iam:putuserpolicy": "embed an inline policy on any user",
  "iam:putrolepolicy": "embed an inline policy on any role",
  "iam:putgrouppolicy": "embed an inline policy on any group",
  "iam:createpolicyversion": "create new versions of any managed policy",
  "iam:setdefaultpolicyversion": "change the active version of any managed policy",
  "iam:passrole": "pass any IAM role to a service",
  "iam:createuser": "create new IAM users",
  "iam:deleteuser": "delete IAM users",
  "iam:creategroup": "create IAM groups",
  "iam:addusertogroup": "add users to any group",
  "iam:listusers": "list all IAM users",
  "iam:listroles": "list all IAM roles",
  "iam:listpolicies": "list all IAM policies",
  "iam:getpolicy": "view any managed policy",
  "iam:getpolicyversion": "view any policy version",
  "iam:getrole": "view role details",
  "iam:getuser": "view user details",
  // STS
  "sts:assumerole": "assume any IAM role",
  "sts:assumerolewithsaml": "assume a role using SAML",
  "sts:assumerolewithwebidentity": "assume a role using a web identity",
  "sts:getsessiontoken": "get a session token",
  // S3
  "s3:getobject": "read objects from S3 buckets",
  "s3:putobject": "write objects to S3 buckets",
  "s3:deleteobject": "delete objects from S3 buckets",
  "s3:listbucket": "list contents of S3 buckets",
  "s3:listallmybuckets": "list all S3 buckets in the account",
  "s3:createbucket": "create new S3 buckets",
  "s3:deletebucket": "delete S3 buckets",
  "s3:putbucketacl": "modify S3 bucket ACLs",
  "s3:putbucketpolicy": "set bucket policies (can grant public access)",
  "s3:putaccesspointpolicy": "set access point policies",
  "s3:getbucketacl": "read S3 bucket ACLs",
  "s3:getbucketpolicy": "read S3 bucket policies",
  // EC2
  "ec2:runinstances": "launch EC2 instances",
  "ec2:stopinstances": "stop EC2 instances",
  "ec2:terminateinstances": "terminate EC2 instances",
  "ec2:describeinstances": "list and describe EC2 instances",
  "ec2:createnetworkinterface": "create network interfaces",
  "ec2:attachnetworkinterface": "attach network interfaces to instances",
  "ec2:modifyinstanceattribute": "modify EC2 instance attributes",
  "ec2:createvolume": "create EBS volumes",
  "ec2:attachvolume": "attach EBS volumes",
  "ec2:deletevolume": "delete EBS volumes",
  "ec2:creat Securitygroup": "create security groups",
  "ec2:authorizesecuritygroupingress": "add inbound rules to security groups",
  // Lambda
  "lambda:createfunction": "create Lambda functions",
  "lambda:updatefunctioncode": "update Lambda function code",
  "lambda:updatefunctionconfiguration": "update Lambda function config",
  "lambda:invokefunction": "invoke Lambda functions",
  "lambda:deletefunction": "delete Lambda functions",
  "lambda:listfunctions": "list all Lambda functions",
  "lambda:createeventmapping": "wire event sources to Lambda functions",
  // KMS
  "kms:decrypt": "decrypt KMS-encrypted data",
  "kms:encrypt": "encrypt data with KMS keys",
  "kms:reencryptdata": "re-encrypt data with different keys",
  "kms:createkey": "create new KMS keys",
  "kms:createdgrant": "create grants on KMS keys",
  "kms:putkeypolicy": "modify KMS key policies",
  "kms:disablekey": "disable KMS keys",
  "kms:enablekey": "enable KMS keys",
  "kms:schedulekeydeletion": "schedule KMS key deletion",
  "kms:listkeys": "list all KMS keys",
  "kms:describekey": "view KMS key details",
  // CloudFormation
  "cloudformation:createstack": "create CloudFormation stacks",
  "cloudformation:updatestack": "update CloudFormation stacks",
  "cloudformation:deletestack": "delete CloudFormation stacks",
  "cloudformation:describestacks": "view CloudFormation stacks",
  "cloudformation:estimatecost": "estimate stack costs",
  // Organizations
  "organizations:leaveorganization": "leave the AWS organization",
  // Logs
  "logs:createLogGroup": "create CloudWatch log groups",
  "logs:putLogEvents": "write to CloudWatch logs",
  "logs:describeloggroups": "list CloudWatch log groups",
  // CodeBuild
  "codebuild:createproject": "create CodeBuild projects",
  "codebuild:startbuild": "start CodeBuild builds",
  // Glue
  "glue:createdevendpoint": "create Glue dev endpoints",
  "glue:getdevendpoint": "view Glue dev endpoints",
  // Data Pipeline
  "datapipeline:createpipeline": "create Data Pipelines",
  "datapipeline:activatepipeline": "activate Data Pipelines",
  // Step Functions
  "stepfunctions:createstatemachine": "create Step Functions state machines",
  "stepfunctions:startexecution": "execute Step Functions",
  // Systems Manager
  "ssm:startsession": "start SSM sessions on instances",
  "ssm:getparameter": "read SSM parameters",
  "ssm:putparameter": "write SSM parameters",
  // RDS
  "rds:createdbinstance": "create RDS instances",
  "rds:deletedbinstance": "delete RDS instances",
  "rds:modifydbinstance": "modify RDS instances",
  // DynamoDB
  "dynamodb:getitem": "read items from DynamoDB tables",
  "dynamodb:putitem": "write items to DynamoDB tables",
  "dynamodb:deleteitem": "delete items from DynamoDB tables",
  "dynamodb:scantable": "scan DynamoDB tables",
  "dynamodb:querytable": "query DynamoDB tables",
  "dynamodb:createtable": "create DynamoDB tables",
  "dynamodb:deletetable": "delete DynamoDB tables",
  // SQS
  "sqs:sendmessage": "send messages to SQS queues",
  "sqs:receivemessage": "receive messages from SQS queues",
  "sqs:deletemessage": "delete messages from SQS queues",
  // SNS
  "sns:publish": "publish messages to SNS topics",
  "sns:createtopic": "create SNS topics",
  // Secrets Manager
  "secretsmanager:getsecretvalue": "read secrets from Secrets Manager",
  "secretsmanager:createsecret": "create secrets",
  // EventBridge
  "events:putrule": "create EventBridge rules",
  "events:puttargets": "set targets on EventBridge rules",
};

// Service-level human-readable names
const SERVICE_NAMES: Record<string, string> = {
  iam: "IAM (Identity and Access Management)",
  sts: "STS (Security Token Service)",
  s3: "S3 (Simple Storage Service)",
  ec2: "EC2 (Elastic Compute Cloud)",
  lambda: "Lambda (serverless functions)",
  kms: "KMS (Key Management Service)",
  cloudformation: "CloudFormation (infrastructure as code)",
  organizations: "Organizations",
  logs: "CloudWatch Logs",
  codebuild: "CodeBuild",
  glue: "Glue (data integration)",
  "datapipeline": "Data Pipeline",
  stepfunctions: "Step Functions (workflows)",
  ssm: "Systems Manager",
  rds: "RDS (Relational Database Service)",
  dynamodb: "DynamoDB (NoSQL database)",
  sqs: "SQS (Simple Queue Service)",
  sns: "SNS (Simple Notification Service)",
  secretsmanager: "Secrets Manager",
  events: "EventBridge (event bus)",
  ecs: "ECS (container service)",
  eks: "EKS (Kubernetes)",
  cloudwatch: "CloudWatch",
};

function getActionDescription(action: string): string {
  const lower = action.toLowerCase();
  if (ACTION_DESCRIPTIONS[lower]) return ACTION_DESCRIPTIONS[lower];
  // Fallback: "perform <action> on <service>"
  const parts = lower.split(":");
  if (parts.length === 2) {
    const [svc, act] = parts;
    const readable = act.replace(/([A-Z])/g, " $1").replace(/-/g, " ").trim();
    return `${readable} on ${svc.toUpperCase()}`;
  }
  return `perform ${action}`;
}

function getServiceName(svc: string): string {
  return SERVICE_NAMES[svc.toLowerCase()] || svc.toUpperCase();
}

function describeResource(resources: string[], hasNotResource: boolean): string {
  if (resources.length === 0) return "no resources specified";

  const allWildcard = resources.every((r) => r === "*");
  if (allWildcard) {
    return hasNotResource
      ? "all resources except the listed ARNs"
      : "all resources";
  }

  const hasWildcard = resources.some((r) => r === "*" || r.includes("*"));

  // Try to extract meaningful ARN info
  const described = resources.map((r) => {
    if (r === "*") return "all resources";
    const parts = r.split(":");
    if (parts.length >= 7) {
      const svc = parts[2];
      const resource = parts[6];
      if (resource === "*") return `all ${svc.toUpperCase()} resources`;
      // Try to extract bucket name, instance ID, etc.
      if (svc === "s3") {
        const bucket = parts[5] || resource;
        if (resource.includes("*")) return `S3 bucket "${bucket}" and its contents`;
        return `S3 resource "${resource}"`;
      }
      if (svc === "iam") {
        if (resource.includes("role/")) {
          const roleName = resource.split("/").pop();
          return `IAM role "${roleName}"`;
        }
        if (resource.includes("user/")) {
          const userName = resource.split("/").pop();
          return `IAM user "${userName}"`;
        }
        if (resource.includes("policy/")) {
          const polName = resource.split("/").pop();
          return `IAM policy "${polName}"`;
        }
        if (resource.includes("*")) return `all IAM resources`;
        return `IAM resource "${resource}"`;
      }
      if (svc === "kms") {
        if (resource.includes("*")) return "all KMS keys";
        return `KMS key "${resource}"`;
      }
      if (svc === "lambda") {
        if (resource.includes("*")) return "all Lambda functions";
        return `Lambda function "${resource}"`;
      }
      if (svc === "ec2") {
        if (resource.includes("*")) return "all EC2 resources";
        return `EC2 resource "${resource}"`;
      }
      if (svc === "dynamodb") {
        if (resource.includes("table/")) {
          const tableName = resource.split("/").pop();
          return `DynamoDB table "${tableName}"`;
        }
        return `DynamoDB resource "${resource}"`;
      }
      if (resource.includes("*")) return `all ${svc.toUpperCase()} resources matching "${resource}"`;
      return `${svc.toUpperCase()} resource "${resource}"`;
    }
    // If it looks like an S3 bucket ARN
    if (r.startsWith("arn:aws:s3:::")) {
      const bucket = r.replace("arn:aws:s3:::", "");
      if (bucket.includes("*")) return `S3 buckets matching "${bucket}"`;
      return `S3 bucket "${bucket}"`;
    }
    return r;
  });

  if (described.length === 1) return described[0];
  if (hasNotResource) {
    return `${described[0]} (and other resources, excluding the listed ARNs)`;
  }
  return described.join(", ");
}

function describeCondition(condition: Record<string, unknown> | undefined): string {
  if (!condition || Object.keys(condition).length === 0) return "";
  const parts: string[] = [];

  for (const [op, val] of Object.entries(condition)) {
    if (typeof val !== "object" || val === null) continue;
    const keys = Object.keys(val as Record<string, unknown>);
    for (const key of keys) {
      if (key === "aws:SecureTransport") {
        parts.push("only over HTTPS");
      } else if (key === "aws:MultiFactorAuthPresent") {
        parts.push("only when MFA is present");
      } else if (key === "aws:SourceIp") {
        parts.push("only from specific IP ranges");
      } else if (key === "aws:RequestedRegion") {
        parts.push("only in specific AWS regions");
      } else if (key === "aws:PrincipalArn") {
        parts.push("only for specific principals");
      } else if (key === "s3:ExistingObjectTag/Confidentiality") {
        parts.push("only for objects with specific tags");
      } else if (key === "aws:PrincipalOrgID") {
        parts.push("only for principals in the organization");
      } else if (key.includes("vpc")) {
        parts.push("only within a VPC");
      } else if (key.includes("source")) {
        parts.push("only from a specific source");
      } else {
        parts.push(`when "${key}" meets the condition`);
      }
    }
  }
  return parts.length > 0 ? parts.join(" and ") : "";
}

function describeStatement(stmt: RawStatement): string {
  const effect = stmt.Effect || "Allow";
  const isAllow = effect === "Allow";
  const hasNotAction = "NotAction" in stmt && stmt.NotAction !== undefined;
  const hasNotResource = "NotResource" in stmt && stmt.NotResource !== undefined;
  const actions = normalizeToArray(stmt.Action ?? stmt.NotAction);
  const resources = normalizeToArray(stmt.Resource ?? stmt.NotResource);
  const hasCondition = !!stmt.Condition && Object.keys(stmt.Condition).length > 0;

  const verb = isAllow ? "Allows" : "Denies";
  const lowerActions = actions.map((a) => a.toLowerCase());

  // Group actions by service
  const byService = new Map<string, string[]>();
  for (const a of lowerActions) {
    const parts = a.split(":");
    const svc = parts[0] || "unknown";
    if (!byService.has(svc)) byService.set(svc, []);
    byService.get(svc)!.push(a);
  }

  let actionPhrase: string;
  if (hasNotAction) {
    if (actions.includes("*")) {
      actionPhrase = "any action";
    } else {
      actionPhrase = `any action except ${actions.map((a) => getActionDescription(a)).join(", ")}`;
    }
  } else if (actions.includes("*")) {
    actionPhrase = "any action";
  } else if (lowerActions.length === 1) {
    actionPhrase = getActionDescription(lowerActions[0]);
  } else if (byService.size === 1) {
    const [svc, acts] = [...byService.entries()][0];
    if (acts.length <= 3) {
      actionPhrase = acts.map((a) => getActionDescription(a)).join(", ");
    } else {
      actionPhrase = `any ${svc.toUpperCase()} action (${acts.length} actions including ${getActionDescription(acts[0])}, ${getActionDescription(acts[1])}, and more)`;
    }
  } else {
    // Multiple services
    const servicePhrases = [...byService.entries()].map(([svc, acts]) => {
      if (acts.length === 1) return getActionDescription(acts[0]);
      return `${acts.length} ${svc.toUpperCase()} actions (including ${getActionDescription(acts[0])})`;
    });
    actionPhrase = servicePhrases.join(", ");
  }

  const resourcePhrase = describeResource(resources, hasNotResource);
  const conditionPhrase = describeCondition(stmt.Condition);

  let result = `${verb} ${actionPhrase}`;
  if (!hasNotResource || resources.length > 0) {
    result += ` on ${resourcePhrase}`;
  } else if (hasNotResource) {
    result += ` on ${resourcePhrase}`;
  }
  if (conditionPhrase) {
    result += `, gated by: ${conditionPhrase}`;
  }

  return result + ".";
}

function isWildcardArn(r: string): boolean {
  return r !== "*" && r.includes("*");
}

function normalizeToArray(v: unknown): string[] {
  if (v == null) return [];
  return (Array.isArray(v) ? v : [v]).map(String);
}

function hasMfaCondition(
  condition: Record<string, unknown> | undefined
): boolean {
  if (!condition) return false;
  const keys = Object.keys(condition);
  return keys.some(
    (op) =>
      typeof condition[op] === "object" &&
      condition[op] !== null &&
      "aws:MultiFactorAuthPresent" in (condition[op] as Record<string, unknown>)
  );
}

function hasSecureTransportCondition(
  condition: Record<string, unknown> | undefined
): boolean {
  if (!condition) return false;
  return Object.keys(condition).some((op) => {
    const val = condition[op];
    return (
      typeof val === "object" &&
      val !== null &&
      "aws:SecureTransport" in (val as Record<string, unknown>)
    );
  });
}

interface RawStatement {
  Sid?: string;
  Effect?: string;
  Action?: unknown;
  NotAction?: unknown;
  Resource?: unknown;
  NotResource?: unknown;
  Condition?: Record<string, unknown>;
}

export function analyzeStatement(
  stmt: RawStatement,
  idx: number
): AnalyzedStatement {
  const findings: Finding[] = [];
  const hasNotAction = "NotAction" in stmt && stmt.NotAction !== undefined;
  const hasNotResource =
    "NotResource" in stmt && stmt.NotResource !== undefined;
  const actions = normalizeToArray(stmt.Action ?? stmt.NotAction);
  const resources = normalizeToArray(stmt.Resource ?? stmt.NotResource);
  const hasCondition =
    !!stmt.Condition && Object.keys(stmt.Condition).length > 0;
  const effect = stmt.Effect || "Allow";
  const isAllow = effect === "Allow";

  const hasWildcardAction = actions.some((a) => a === "*" || a.endsWith(":*"));
  const hasFullWildcardAction = actions.includes("*");
  const hasWildcardResource = resources.some((r) => r === "*");
  const hasWildcardedArn = resources.some(isWildcardArn);

  const lowerActions = actions.map((a) => a.toLowerCase());
  const sensitiveHits = lowerActions.filter((a) =>
    NEEDS_CONDITION_ACTIONS.has(a)
  );

  // ── NotAction / NotResource dangers ──────────────────────────────────

  if (isAllow && hasNotAction && hasWildcardResource) {
    findings.push({
      level: "danger",
      msg: 'NotAction + Resource "*" — allows everything except listed actions on all resources. AWS warns this almost always grants more than intended.',
    });
  } else if (isAllow && hasNotAction && hasWildcardedArn) {
    findings.push({
      level: "danger",
      msg: "NotAction with wildcarded resource ARN — allows unlisted actions across broad resource scope.",
    });
  } else if (isAllow && hasNotAction) {
    findings.push({
      level: "warn",
      msg: "NotAction inverts the action list — everything not listed is allowed. Review carefully to ensure only intended actions are excluded.",
    });
  }

  if (isAllow && hasNotResource && hasFullWildcardAction) {
    findings.push({
      level: "danger",
      msg: 'Action "*" + NotResource — allows every action on all resources except listed ARNs. AWS explicitly warns: "You should never use this combination."',
    });
  } else if (isAllow && hasNotResource) {
    findings.push({
      level: "warn",
      msg: "NotResource inverts the resource list — all unlisted resources are in scope. This can be broader than intended.",
    });
  }

  // ── Wildcard combinations ────────────────────────────────────────────

  if (isAllow && hasFullWildcardAction && hasWildcardResource) {
    findings.push({
      level: "danger",
      msg: "Grants every action on every resource — full administrative access.",
    });
  } else {
    if (isAllow && hasWildcardAction) {
      findings.push({
        level: "warn",
        msg: "Uses a wildcard action (service:*) — broader than most least-privilege policies need.",
      });
    }
    if (
      isAllow &&
      (hasWildcardResource || hasWildcardedArn) &&
      actions.length > 0
    ) {
      findings.push({
        level: "warn",
        msg: "Resource is not scoped to specific ARNs — uses wildcards.",
      });
    }
  }

  // ── Escalation: iam:PassRole ────────────────────────────────────────

  if (isAllow && lowerActions.includes("iam:passrole") && !hasCondition) {
    findings.push({
      level: "danger",
      msg: "iam:PassRole with no condition — can hand any role to any service, a classic privilege-escalation path.",
    });
  } else if (
    isAllow &&
    lowerActions.includes("iam:passrole") &&
    hasCondition
  ) {
    // Check if condition is specific enough
    const hasArnCondition = Object.keys(stmt.Condition ?? {}).some(
      (op) =>
        typeof stmt.Condition![op] === "object" &&
        stmt.Condition![op] !== null &&
        Object.keys(stmt.Condition![op] as Record<string, unknown>).some(
          (k) => k.toLowerCase().includes("arn") || k.toLowerCase().includes("resource")
        )
    );
    if (!hasArnCondition) {
      findings.push({
        level: "warn",
        msg: "iam:PassRole has a condition but it doesn't appear to scope by ARN — verify the condition limits which roles can be passed.",
      });
    }
  }

  // ── Sensitive actions + wildcarded ARNs ──────────────────────────────

  if (
    isAllow &&
    sensitiveHits.length > 0 &&
    hasWildcardedArn &&
    !hasCondition
  ) {
    const unique = [...new Set(sensitiveHits)];
    const details = unique
      .map((a) => `${a} — ${ESCALATION_ACTIONS[a]}`)
      .join("; ");
    findings.push({
      level: "danger",
      msg: `Sensitive actions on wildcarded ARN with no condition: ${details}`,
    });
  }

  // ── Sensitive actions + wildcard resource ────────────────────────────

  if (isAllow && sensitiveHits.length > 0 && hasWildcardResource && !hasCondition) {
    const unique = [...new Set(sensitiveHits)];
    const details = unique
      .map((a) => `${a} — ${ESCALATION_ACTIONS[a]}`)
      .join("; ");
    findings.push({
      level: "danger",
      msg: `Sensitive actions on resource "*" with no condition: ${details}`,
    });
  }

  // ── Sensitive actions, no condition (any resource) ──────────────────

  if (
    isAllow &&
    sensitiveHits.length > 0 &&
    !hasWildcardResource &&
    !hasWildcardedArn &&
    !hasCondition
  ) {
    const unique = [...new Set(sensitiveHits)];
    findings.push({
      level: "warn",
      msg: `Sensitive action${unique.length > 1 ? "s" : ""} (${unique.join(
        ", "
      )}) allowed with no Condition block — consider scoping with conditions.`,
    });
  }

  // ── Missing Condition on sensitive actions (high-priv + wildcard) ───

  if (
    isAllow &&
    sensitiveHits.length > 0 &&
    (hasWildcardAction || hasWildcardResource || hasWildcardedArn) &&
    !hasCondition
  ) {
    // Already flagged above, but reinforce with specific escalation message
    const hasPassRole = lowerActions.includes("iam:passrole");
    const hasCreateKey = lowerActions.includes("iam:createaccesskey");
    const hasCreateLogin = lowerActions.includes("iam:createloginprofile") || lowerActions.includes("iam:updateloginprofile");

    if (hasPassRole && !hasCondition) {
      findings.push({
        level: "danger",
        msg: "iam:PassRole on broad resources without a Condition — allows escalation to any role in the account.",
      });
    }
    if (hasCreateKey && !hasCondition) {
      findings.push({
        level: "danger",
        msg: "iam:CreateAccessKey on broad resources without a Condition — allows stealing credentials for any user.",
      });
    }
    if (hasCreateLogin && !hasCondition) {
      findings.push({
        level: "danger",
        msg: "iam:CreateLoginProfile/UpdateLoginProfile on broad resources without a Condition — allows console takeover of any user.",
      });
    }
  }

  // ── Wildcard action + specific sensitive actions ─────────────────────

  if (isAllow && hasWildcardAction) {
    const highPrivServices = ["iam:", "sts:", "kms:", "organizations:", "s3:put"];
    const broadSensitive = lowerActions.filter((a) =>
      highPrivServices.some((svc) => a.startsWith(svc))
    );
    if (broadSensitive.length > 0 && !hasCondition) {
      findings.push({
        level: "danger",
        msg: `Service wildcard grants high-privilege actions (${[...new Set(broadSensitive)].slice(0, 5).join(", ")}${broadSensitive.length > 5 ? "…" : ""}) without conditions.`,
      });
    }
  }

  // ── Safe findings ────────────────────────────────────────────────────

  if (
    isAllow &&
    !hasCondition &&
    !hasWildcardAction &&
    !hasWildcardResource &&
    !hasWildcardedArn &&
    !hasNotAction &&
    !hasNotResource
  ) {
    findings.push({
      level: "safe",
      msg: "Scoped actions and resources — reasonable least-privilege shape.",
    });
  } else if (isAllow && hasCondition) {
    const msgs: string[] = [];
    msgs.push("Condition block present — access is gated, not unconditional.");
    if (hasMfaCondition(stmt.Condition)) {
      msgs.push("MFA condition detected — good practice for human access.");
    }
    if (hasSecureTransportCondition(stmt.Condition)) {
      msgs.push("TLS enforcement detected — traffic must use HTTPS.");
    }
    findings.push({
      level: "safe",
      msg: msgs.join(" "),
    });
  }

  const worstLevel: Level = findings.some((f) => f.level === "danger")
    ? "danger"
    : findings.some((f) => f.level === "warn")
    ? "warn"
    : "safe";

  return {
    idx,
    sid: stmt.Sid || `Statement ${idx + 1}`,
    effect,
    actions,
    resources,
    hasCondition,
    condition: stmt.Condition,
    findings,
    worstLevel,
    summary: describeStatement(stmt),
  };
}

function computeScore(statements: AnalyzedStatement[]): {
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
} {
  if (statements.length === 0) return { score: 100, grade: "A" };

  let deductions = 0;

  for (const s of statements) {
    const dangerCount = s.findings.filter((f) => f.level === "danger").length;
    const warnCount = s.findings.filter((f) => f.level === "warn").length;

    // Each danger finding deducts heavily
    deductions += dangerCount * 20;
    // Each warn deducts moderately
    deductions += warnCount * 6;

    // Extra penalty for wildcard action + wildcard resource (full admin)
    const hasFullAdmin = s.actions.includes("*") && s.resources.includes("*");
    if (hasFullAdmin) deductions += 40;

    // Extra penalty for sensitive actions without conditions
    const sensitiveNoCondition =
      s.findings.some(
        (f) =>
          f.level === "danger" &&
          (f.msg.includes("PassRole") ||
            f.msg.includes("CreateAccessKey") ||
            f.msg.includes("CreateLoginProfile"))
      ) && !s.hasCondition;
    if (sensitiveNoCondition) deductions += 15;
  }

  // Bonus for conditions present
  const withCondition = statements.filter((s) => s.hasCondition).length;
  const conditionBonus = Math.floor(
    (withCondition / statements.length) * 8
  );

  const score = Math.max(0, Math.min(100, 100 - deductions + conditionBonus));

  let grade: "A" | "B" | "C" | "D" | "F";
  if (score >= 90) grade = "A";
  else if (score >= 75) grade = "B";
  else if (score >= 55) grade = "C";
  else if (score >= 35) grade = "D";
  else grade = "F";

  return { score, grade };
}

export function analyzePolicy(policyJson: unknown): PolicyReport {
  if (!policyJson || typeof policyJson !== "object")
    return {
      statements: [],
      score: 100,
      grade: "A",
      totalDanger: 0,
      totalWarn: 0,
      totalSafe: 0,
    };
  const raw = (policyJson as { Statement?: unknown }).Statement;
  const arr: RawStatement[] = Array.isArray(raw)
    ? (raw as RawStatement[])
    : raw
    ? [raw as RawStatement]
    : [];
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
