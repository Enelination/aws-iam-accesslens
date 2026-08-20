export const C = {
  bg: "#0f172a",
  surface: "#1e293b",
  surface2: "#334155",
  border: "#475569",
  borderLight: "#64748b",
  text: "#f1f5f9",
  muted: "#94a3b8",
  faint: "#64748b",
  safe: "#22c55e",
  safeDim: "#166534",
  warn: "#f59e0b",
  warnDim: "#92400e",
  danger: "#ef4444",
  dangerDim: "#991b1b",
  accent: "#6366f1",
  accentDim: "#312e81",
} as const;

export const mono = `"JetBrains Mono", "Fira Code", "SF Mono", Menlo, monospace`;
export const sans = `"Inter", -apple-system, "Segoe UI", sans-serif`;

export function levelColor(level: "danger" | "warn" | "safe"): string {
  if (level === "danger") return C.danger;
  if (level === "warn") return C.warn;
  return C.safe;
}

export function levelBg(level: "danger" | "warn" | "safe"): string {
  if (level === "danger") return C.dangerDim;
  if (level === "warn") return C.warnDim;
  return C.safeDim;
}

export function levelLabel(level: "danger" | "warn" | "safe"): string {
  if (level === "danger") return "HIGH RISK";
  if (level === "warn") return "REVIEW";
  return "SCOPED";
}
