import { useState } from "react";
import VerdictBadge from "./VerdictBadge";
import { t } from "./chatTheme";
export default function ThreatReport() { return null; } {
  const [copied, setCopied] = useState(false);
  const th = t(darkMode);
  const score = data.score || 0;
  const scoreColor = score > 70 ? "#f87171" : score > 40 ? "#fb923c" : "#4ade80";

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{
      background: darkMode ? "rgba(4,12,24,0.95)" : "rgba(245,250,255,0.98)",
      border: `1px solid ${th.borderActive}`, borderRadius: "8px",
      padding: "14px 16px", marginTop: "8px",
      fontSize: "11px", fontFamily: "'JetBrains Mono',monospace",
      boxShadow: "0 4px 20px rgba(0,168,255,0.08)",
    }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px", paddingBottom: "10px", borderBottom: `1px solid ${th.border}` }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ display: "inline-block", width: "6px", height: "6px", borderRadius: "50%", background: th.accent, boxShadow: `0 0 6px ${th.accent}` }} />
          <span style={{ color: th.accent, fontWeight: "700", letterSpacing: "2px", fontSize: "10px" }}>THREAT INTELLIGENCE REPORT</span>
        </div>
        <button onClick={handleCopy} style={{
          background: "transparent", border: `1px solid ${copied ? "#4ade80" : th.border}`,
          color: copied ? "#4ade80" : th.textMuted, padding: "3px 10px", borderRadius: "4px",
          fontSize: "9px", cursor: "pointer", letterSpacing: "1.5px", transition: "all 0.2s",
        }}>{copied ? "✓ COPIÉ" : "⎘ COPIER"}</button>
      </div>

      {/* IOC */}
      <div style={{ marginBottom: "10px", display: "flex", alignItems: "center", gap: "8px" }}>
        <span style={{ color: th.textFaint, fontSize: "9px", letterSpacing: "2px" }}>IOC</span>
        <span style={{ color: th.accent, background: th.accentSubtle, border: `1px solid ${th.border}`, padding: "2px 8px", borderRadius: "3px", fontSize: "11px" }}>{data.ioc}</span>
      </div>

      {/* Score */}
      <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "12px" }}>
        <VerdictBadge verdict={data.verdict} />
        <div style={{ flex: 1 }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "5px" }}>
            <span style={{ color: th.textFaint, fontSize: "9px", letterSpacing: "2px" }}>THREAT SCORE</span>
            <span style={{ color: scoreColor, fontWeight: "700", fontSize: "12px" }}>{score}<span style={{ color: th.textFaint, fontSize: "9px" }}>/100</span></span>
          </div>
          <div style={{ height: "3px", background: "rgba(255,255,255,0.06)", borderRadius: "2px", overflow: "hidden" }}>
            <div style={{
              height: "100%", width: `${score}%`,
              background: `linear-gradient(90deg, ${scoreColor}88, ${scoreColor})`,
              borderRadius: "2px", boxShadow: `0 0 8px ${scoreColor}60`,
              transition: "width 1.2s cubic-bezier(0.4,0,0.2,1)",
            }} />
          </div>
        </div>
      </div>

      {/* CVEs */}
      {data.cves?.length > 0 && (
        <div style={{ marginBottom: "10px" }}>
          <div style={{ color: th.textFaint, fontSize: "9px", letterSpacing: "2px", marginBottom: "6px" }}>CVEs ASSOCIÉES</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "5px" }}>
            {data.cves.map(c => (
              <span key={c} style={{ padding: "3px 9px", background: "rgba(251,146,60,0.08)", border: "1px solid rgba(251,146,60,0.28)", borderRadius: "3px", color: "#fb923c", fontSize: "10px" }}>{c}</span>
            ))}
          </div>
        </div>
      )}

      {/* Sources */}
      {data.sources?.length > 0 && (
        <div>
          <div style={{ color: th.textFaint, fontSize: "9px", letterSpacing: "2px", marginBottom: "6px" }}>SOURCES</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "5px" }}>
            {data.sources.map(s => (
              <span key={s} style={{ padding: "3px 9px", background: th.accentSubtle, border: `1px solid ${th.border}`, borderRadius: "3px", color: th.textMuted, fontSize: "10px" }}>→ {s}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}