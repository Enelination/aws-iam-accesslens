import React from "react";
import { AnalyzedStatement } from "../lib/analyze";
import { C, mono, sans, levelColor, levelBg, levelLabel } from "../lib/theme";
import { Badge, Chip } from "./Primitives";

export function StatementCard({ s }: { s: AnalyzedStatement }) {
  const dangerCount = s.findings.filter((f) => f.level === "danger").length;
  const warnCount = s.findings.filter((f) => f.level === "warn").length;
  const safeCount = s.findings.filter((f) => f.level === "safe").length;

  return (
    <div
      style={{
        background: C.surface,
        borderRadius: 12,
        overflow: "hidden",
        border: `1px solid ${C.border}`,
      }}
    >
      {/* Header bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "14px 20px",
          borderBottom: `1px solid ${C.border}`,
          background: levelBg(s.worstLevel) + "18",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span
            style={{
              fontFamily: mono,
              fontSize: 11,
              color: C.faint,
              background: C.bg,
              padding: "3px 9px",
              borderRadius: 6,
              border: `1px solid ${C.border}`,
            }}
          >
            #{s.idx + 1}
          </span>
          <span
            style={{
              fontFamily: mono,
              fontWeight: 700,
              fontSize: 14,
              color: C.text,
            }}
          >
            {s.sid}
          </span>
          <Badge color={s.effect === "Allow" ? C.safe : C.danger} filled>
            {s.effect}
          </Badge>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {dangerCount > 0 && (
            <span
              style={{
                fontFamily: mono,
                fontSize: 11,
                color: C.danger,
                display: "flex",
                alignItems: "center",
                gap: 4,
              }}
            >
              <Dot color={C.danger} /> {dangerCount}
            </span>
          )}
          {warnCount > 0 && (
            <span
              style={{
                fontFamily: mono,
                fontSize: 11,
                color: C.warn,
                display: "flex",
                alignItems: "center",
                gap: 4,
              }}
            >
              <Dot color={C.warn} /> {warnCount}
            </span>
          )}
          {safeCount > 0 && (
            <span
              style={{
                fontFamily: mono,
                fontSize: 11,
                color: C.safe,
                display: "flex",
                alignItems: "center",
                gap: 4,
              }}
            >
              <Dot color={C.safe} /> {safeCount}
            </span>
          )}
          <Badge color={levelColor(s.worstLevel)}>
            {levelLabel(s.worstLevel)}
          </Badge>
        </div>
      </div>

      {/* Body */}
      <div style={{ padding: "16px 20px" }}>
        {/* Plain English Summary */}
        <div
          style={{
            marginBottom: 16,
            padding: "12px 16px",
            borderRadius: 8,
            background: C.bg,
            border: `1px solid ${C.border}`,
            fontFamily: sans,
            fontSize: 13.5,
            lineHeight: 1.6,
            color: C.text,
          }}
        >
          <span
            style={{
              fontFamily: mono,
              fontSize: 10,
              fontWeight: 600,
              color: C.faint,
              textTransform: "uppercase",
              letterSpacing: 1,
              display: "block",
              marginBottom: 6,
            }}
          >
            In plain English
          </span>
          {s.summary}
        </div>

        {/* Actions + Resources */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 20,
            marginBottom: s.hasCondition || s.findings.length > 0 ? 16 : 0,
          }}
        >
          <div>
            <SectionLabel>Actions</SectionLabel>
            <div>
              {s.actions.map((a, i) => (
                <Chip
                  key={i}
                  muted={a !== "*" && !a.endsWith(":*")}
                  danger={a === "*" || a.endsWith(":*")}
                >
                  {a}
                </Chip>
              ))}
            </div>
          </div>
          <div>
            <SectionLabel>Resources</SectionLabel>
            <div>
              {s.resources.length === 0 ? (
                <Chip muted>—</Chip>
              ) : (
                s.resources.map((r, i) => (
                  <Chip key={i} danger={r === "*" || r.includes("*")}>
                    {r}
                  </Chip>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Condition block */}
        {s.hasCondition && (
          <div style={{ marginBottom: 16 }}>
            <SectionLabel>Condition</SectionLabel>
            <pre
              style={{
                margin: 0,
                fontFamily: mono,
                fontSize: 11,
                lineHeight: 1.5,
                color: C.muted,
                background: C.bg,
                border: `1px solid ${C.border}`,
                borderRadius: 8,
                padding: "10px 14px",
                overflowX: "auto",
              }}
            >
              {JSON.stringify(s.condition, null, 2)}
            </pre>
          </div>
        )}

        {/* Findings */}
        {s.findings.length > 0 && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 8,
              borderTop: `1px solid ${C.border}`,
              paddingTop: 14,
            }}
          >
            {s.findings.map((f, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  gap: 10,
                  alignItems: "flex-start",
                  fontSize: 12.5,
                  lineHeight: 1.5,
                  fontFamily: sans,
                  color: C.text,
                  padding: "8px 12px",
                  borderRadius: 8,
                  background: `${levelColor(f.level)}08`,
                  border: `1px solid ${levelColor(f.level)}20`,
                }}
              >
                <Dot color={levelColor(f.level)} style={{ marginTop: 5 }} />
                <span>{f.msg}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div
      style={{
        fontSize: 10,
        fontWeight: 600,
        color: C.faint,
        fontFamily: mono,
        textTransform: "uppercase",
        letterSpacing: 1,
        marginBottom: 8,
      }}
    >
      {children}
    </div>
  );
}

function Dot({
  color,
  style,
}: {
  color: string;
  style?: React.CSSProperties;
}) {
  return (
    <span
      style={{
        width: 7,
        height: 7,
        borderRadius: "50%",
        background: color,
        flexShrink: 0,
        ...style,
      }}
    />
  );
}
