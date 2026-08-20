import React from "react";
import { C, mono, sans } from "../lib/theme";

export function Footer() {
  return (
    <div
      style={{
        maxWidth: 1200,
        margin: "48px auto 0",
        paddingTop: 20,
        borderTop: `1px solid ${C.border}`,
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        flexWrap: "wrap",
        gap: 12,
      }}
    >
      <span
        style={{
          fontFamily: sans,
          fontSize: 12,
          color: C.faint,
        }}
      >
        No data leaves the browser. All analysis runs locally.
      </span>
      <span
        style={{
          fontFamily: sans,
          fontSize: 12,
          color: C.muted,
          display: "flex",
          alignItems: "center",
          gap: 4,
        }}
      >
        Built by{" "}
        <a
          href="https://github.com/Enelination"
          target="_blank"
          rel="noopener noreferrer"
          style={{
            color: C.accent,
            fontWeight: 600,
            textDecoration: "none",
            borderBottom: `1px solid ${C.accent}44`,
          }}
        >
          Enelination
        </a>
      </span>
    </div>
  );
}
