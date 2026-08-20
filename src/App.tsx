import React, { useMemo, useState } from "react";
import { analyzePolicy } from "./lib/analyze";
import { SAMPLES } from "./lib/samples";
import { C, mono, sans } from "./lib/theme";
import { StatementCard } from "./components/StatementCard";
import { Footer } from "./components/Footer";
import { RiskBar } from "./components/Primitives";

const DEFAULT_POLICY = SAMPLES["Overly broad admin"];

export default function App() {
  const [raw, setRaw] = useState(JSON.stringify(DEFAULT_POLICY, null, 2));
  const [error, setError] = useState<string | null>(null);
  const [selectedSample, setSelectedSample] = useState("");

  const parsed = useMemo(() => {
    try {
      const obj = JSON.parse(raw);
      setError(null);
      return obj;
    } catch (e) {
      setError((e as Error).message);
      return null;
    }
  }, [raw]);

  const statements = useMemo(() => (parsed ? analyzePolicy(parsed) : []), [
    parsed,
  ]);

  const summary = useMemo(() => {
    const counts = { danger: 0, warn: 0, safe: 0 };
    statements.forEach((s) => s.findings.forEach((f) => counts[f.level]++));
    return counts;
  }, [statements]);

  const totalFindings = summary.danger + summary.warn + summary.safe;

  return (
    <div
      style={{
        minHeight: "100vh",
        background: C.bg,
        color: C.text,
        fontFamily: sans,
      }}
    >
      {/* Top bar */}
      <header
        style={{
          borderBottom: `1px solid ${C.border}`,
          background: C.surface + "80",
          backdropFilter: "blur(12px)",
          position: "sticky",
          top: 0,
          zIndex: 100,
        }}
      >
        <div
          style={{
            maxWidth: 1200,
            margin: "0 auto",
            padding: "14px 24px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: `linear-gradient(135deg, ${C.accent}, ${C.danger})`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <span
              style={{
                fontFamily: mono,
                fontWeight: 700,
                fontSize: 16,
                letterSpacing: -0.5,
              }}
            >
              IAM Visualizer
            </span>
          </div>
          <div
            style={{
              fontFamily: mono,
              fontSize: 11,
              color: C.faint,
              display: "flex",
              alignItems: "center",
              gap: 16,
            }}
          >
            <span>client-side only</span>
            <span
              style={{
                width: 1,
                height: 14,
                background: C.border,
                display: "inline-block",
              }}
            />
            <span>
              Built by{" "}
              <a
                href="https://github.com/Enelination"
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: C.accent, fontWeight: 600, textDecoration: "none" }}
              >
                Enelination
              </a>
            </span>
          </div>
        </div>
      </header>

      <main
        style={{
          maxWidth: 1200,
          margin: "0 auto",
          padding: "28px 24px 60px",
        }}
      >
        {/* Editor */}
        <div
          style={{
            background: C.surface,
            borderRadius: 12,
            border: `1px solid ${error ? C.danger : C.border}`,
            overflow: "hidden",
            marginBottom: 24,
          }}
        >
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "10px 16px",
              borderBottom: `1px solid ${C.border}`,
              background: C.bg,
            }}
          >
            <span
              style={{
                fontFamily: mono,
                fontSize: 11,
                fontWeight: 600,
                color: C.faint,
                textTransform: "uppercase",
                letterSpacing: 1,
              }}
            >
              policy.json
            </span>
            <select
              value={selectedSample}
              onChange={(e) => {
                const key = e.target.value;
                setSelectedSample(key);
                const sample = SAMPLES[key];
                if (sample) setRaw(JSON.stringify(sample, null, 2));
              }}
              style={{
                background: C.surface,
                color: C.text,
                border: `1px solid ${C.border}`,
                borderRadius: 6,
                fontFamily: mono,
                fontSize: 11,
                padding: "5px 10px",
                cursor: "pointer",
                outline: "none",
              }}
            >
              <option value="">Load sample policy…</option>
              {Object.keys(SAMPLES).map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </div>

          <textarea
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              setSelectedSample("");
            }}
            spellCheck={false}
            style={{
              width: "100%",
              height: 360,
              background: "transparent",
              color: C.text,
              border: "none",
              padding: "16px 20px",
              fontFamily: mono,
              fontSize: 12.5,
              lineHeight: 1.6,
              resize: "vertical",
              outline: "none",
              boxSizing: "border-box",
            }}
          />
        </div>

        {error && (
          <div
            style={{
              padding: "12px 16px",
              borderRadius: 8,
              background: C.dangerDim + "30",
              border: `1px solid ${C.danger}44`,
              color: C.danger,
              fontFamily: mono,
              fontSize: 12,
              marginBottom: 24,
            }}
          >
            Invalid JSON — {error}
          </div>
        )}

        {/* Risk summary bar */}
        {!error && statements.length > 0 && (
          <div
            style={{
              background: C.surface,
              borderRadius: 12,
              border: `1px solid ${C.border}`,
              padding: "18px 24px",
              marginBottom: 24,
              display: "flex",
              gap: 32,
              alignItems: "center",
            }}
          >
            <div style={{ flex: "0 0 auto", paddingRight: 20, borderRight: `1px solid ${C.border}` }}>
              <div
                style={{
                  fontFamily: mono,
                  fontSize: 10,
                  fontWeight: 600,
                  color: C.faint,
                  textTransform: "uppercase",
                  letterSpacing: 1,
                  marginBottom: 4,
                }}
              >
                Findings
              </div>
              <div style={{ fontFamily: mono, fontSize: 28, fontWeight: 700, color: C.text }}>
                {totalFindings}
              </div>
            </div>
            <RiskBar level="danger" label="Critical" count={summary.danger} total={totalFindings} />
            <RiskBar level="warn" label="Warning" count={summary.warn} total={totalFindings} />
            <RiskBar level="safe" label="Passed" count={summary.safe} total={totalFindings} />
          </div>
        )}

        {/* Statements */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {statements.length === 0 && !error && (
            <div
              style={{
                border: `1px dashed ${C.border}`,
                borderRadius: 12,
                padding: 60,
                textAlign: "center",
                color: C.faint,
                fontFamily: mono,
                fontSize: 13,
              }}
            >
              Paste a policy above to see the analysis
            </div>
          )}
          {statements.map((s) => (
            <StatementCard key={s.idx} s={s} />
          ))}
        </div>
      </main>

      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px" }}>
        <Footer />
      </div>
    </div>
  );
}
