import React from "react";
import { C, mono, sans } from "../lib/theme";

export function Badge({
  children,
  color,
  filled,
}: {
  children: React.ReactNode;
  color: string;
  filled?: boolean;
}) {
  return (
    <span
      style={{
        fontFamily: mono,
        fontSize: 10,
        fontWeight: 600,
        padding: "3px 10px",
        borderRadius: 100,
        border: "none",
        color: filled ? "#fff" : color,
        background: filled ? color : `${color}22`,
        letterSpacing: 0.8,
        whiteSpace: "nowrap",
        textTransform: "uppercase",
      }}
    >
      {children}
    </span>
  );
}

export function Chip({
  children,
  muted,
  danger,
}: {
  children: React.ReactNode;
  muted?: boolean;
  danger?: boolean;
}) {
  return (
    <span
      style={{
        fontFamily: mono,
        fontSize: 11.5,
        padding: "4px 10px",
        borderRadius: 6,
        background: danger ? `${C.danger}15` : C.surface,
        border: `1px solid ${danger ? `${C.danger}44` : C.border}`,
        color: danger ? C.danger : muted ? C.muted : C.text,
        marginRight: 6,
        marginBottom: 6,
        display: "inline-block",
      }}
    >
      {children}
    </span>
  );
}

export function RiskBar({
  level,
  label,
  count,
  total,
}: {
  level: "danger" | "warn" | "safe";
  label: string;
  count: number;
  total: number;
}) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  const color =
    level === "danger" ? C.danger : level === "warn" ? C.warn : C.safe;

  return (
    <div style={{ flex: 1 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          marginBottom: 6,
        }}
      >
        <span
          style={{
            fontFamily: sans,
            fontSize: 12,
            fontWeight: 500,
            color: C.muted,
            textTransform: "uppercase",
            letterSpacing: 0.5,
          }}
        >
          {label}
        </span>
        <span
          style={{
            fontFamily: mono,
            fontSize: 18,
            fontWeight: 700,
            color,
          }}
        >
          {count}
        </span>
      </div>
      <div
        style={{
          height: 4,
          borderRadius: 2,
          background: C.surface,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: color,
            borderRadius: 2,
            transition: "width 0.3s ease",
          }}
        />
      </div>
    </div>
  );
}
