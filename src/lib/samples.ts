export const SAMPLES: Record<string, unknown> = {
  "Overly broad admin": {
    Version: "2012-10-17",
    Statement: [
      { Sid: "FullAdmin", Effect: "Allow", Action: "*", Resource: "*" },
    ],
  },
  "PassRole without condition": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "LaunchEC2",
        Effect: "Allow",
        Action: ["ec2:RunInstances", "iam:PassRole"],
        Resource: "*",
      },
    ],
  },
  "Scoped S3 read (safe)": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "ReadBucket",
        Effect: "Allow",
        Action: ["s3:GetObject", "s3:ListBucket"],
        Resource: [
          "arn:aws:s3:::test-reports",
          "arn:aws:s3:::test-reports/*",
        ],
        Condition: {
          Bool: { "aws:SecureTransport": "true" },
        },
      },
    ],
  },
  "Wildcard IAM write": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "IamWrite",
        Effect: "Allow",
        Action: "iam:*",
        Resource: "*",
      },
    ],
  },
  "NotAction abuse": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "EverythingButIAM",
        Effect: "Allow",
        NotAction: "iam:*",
        Resource: "*",
      },
    ],
  },
  "Cross-account AssumeRole": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "CrossAccountAssume",
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Resource: "arn:aws:iam::*:role/*",
      },
    ],
  },
  "Credential theft chain": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "StealKeys",
        Effect: "Allow",
        Action: [
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:UpdateLoginProfile",
        ],
        Resource: "*",
      },
    ],
  },
  "MFA-gated read (safe)": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "MFARead",
        Effect: "Allow",
        Action: ["s3:GetObject", "s3:ListBucket"],
        Resource: [
          "arn:aws:s3:::secure-bucket",
          "arn:aws:s3:::secure-bucket/*",
        ],
        Condition: {
          Bool: {
            "aws:MultiFactorAuthPresent": "true",
            "aws:SecureTransport": "true",
          },
        },
      },
    ],
  },
  "NotResource + * action": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "DangerousCombo",
        Effect: "Allow",
        Action: "*",
        NotResource: "arn:aws:s3:::protected-bucket",
      },
    ],
  },
  "Lambda + PassRole escalation": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "LambdaEscalate",
        Effect: "Allow",
        Action: [
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:InvokeFunction",
          "iam:PassRole",
          "logs:CreateLogGroup",
        ],
        Resource: "*",
      },
    ],
  },
  "Policy overwrite": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "PolicyOverwrite",
        Effect: "Allow",
        Action: [
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:AttachUserPolicy",
          "iam:PutUserPolicy",
        ],
        Resource: "*",
      },
    ],
  },
  "S3 public exposure": {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "S3Public",
        Effect: "Allow",
        Action: ["s3:PutBucketPolicy", "s3:PutAccessPointPolicy"],
        Resource: "*",
      },
    ],
  },
};
