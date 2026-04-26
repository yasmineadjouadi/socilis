import { useState } from "react";
import { t } from "./chatTheme";

function VerdictBadge({ verdict }) {
  const map = {
    malicious:  { bg: "rgba(248,113,113,0.1)", border: "#f87171", text: "#fca5a5", label: "⚠ MALICIEUX" },
    clean:      { bg: "rgba(74,222,128,0.1)",  border: "#4ade80", text: "#86efac", label: "✓ PROPRE"    },
    suspicious: { bg: "rgba(251,146,60,0.1)",  border: "#fb923c", text: "#fdba74", label: "⚡ SUSPECT"  },
    critical:   { bg: "rgba(239,68,68,0.12)",  border: "#ef4444", text: "#fca5a5", label: "🔴 CRITIQUE" },
  };
  const c = map[verdict] || map.suspicious;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: "4px",
      padding: "3px 10px", borderRadius: "4px",
      background: c.bg, border: `1px solid ${c.border}`, color: c.text,
      fontSize: "9px", fontWeight: "700", letterSpacing: "2px",
      fontFamily: "'JetBrains Mono', monospace", whiteSpace: "nowrap",
    }}>{c.label}</span>
  );
}

// ── Export helpers ────────────────────────────────────────────────────────────
function dlCSV(report) {
  const rows = [
    ["Champ", "Valeur"],
    ["Indicateur", report.ioc],
    ["Type", report.type || ""],
    ["Verdict", report.verdict],
    ["Score", report.score],
    ["Niveau menace", report.threat_level || ""],
    ["Tags", (report.tags || []).join(", ")],
    ["Message", (report.message || "").replace(/"/g, "'")],
    // verdict details
    ...(report.isp        ? [["ISP", report.isp]] : []),
    ...(report.asn        ? [["ASN", report.asn]] : []),
    ...(report.country    ? [["Pays", report.country]] : []),
    ...(report.vt_malicious != null ? [["VT Malicious", report.vt_malicious]] : []),
    ...(report.vt_suspicious != null ? [["VT Suspicious", report.vt_suspicious]] : []),
    ...(report.abuseipdb  != null ? [["AbuseIPDB Score", report.abuseipdb]] : []),
    ...(report.otx_pulses != null ? [["OTX Pulses", report.otx_pulses]] : []),
    ...(report.file_type  ? [["Type Fichier", report.file_type]] : []),
    ...(report.first_seen ? [["Premier vu", report.first_seen]] : []),
    ...(report.vt_undetected != null ? [["VT Undetected", report.vt_undetected]] : []),
    ...(report.registrar  ? [["Registrar", report.registrar]] : []),
    ...(report.created    ? [["Créé le", report.created]] : []),
    ...(report.subdomains_count != null ? [["Sous-domaines", report.subdomains_count]] : []),
    ...(report.global_risk_score != null ? [["Global Risk Score", report.global_risk_score]] : []),
    ...(report.domain     ? [["Domaine", report.domain]] : []),
    ...(report.ip         ? [["IP", report.ip]] : []),
    ...(report.vt_malicious_url != null ? [["VT Malicious (URL)", report.vt_malicious_url]] : []),
    ...(report.gsb_threats ? [["Google Safe Browsing", report.gsb_threats.join(", ")]] : []),
    ...(report.phishtank  ? [["PhishTank", report.phishtank]] : []),
    ...(report.mail_domain ? [["Mail Domain", report.mail_domain]] : []),
    ...(report.provider   ? [["Provider", report.provider]] : []),
    ...(report.mx         ? [["MX", report.mx]] : []),
    ...(report.spf        ? [["SPF", report.spf]] : []),
    ...(report.dmarc      ? [["DMARC", report.dmarc]] : []),
    ...(report.severity   ? [["Sévérité", report.severity]] : []),
    ...(report.cvss_score != null ? [["CVSS Score", report.cvss_score]] : []),
    ...(report.cvss_vector ? [["CVSS Vector", report.cvss_vector]] : []),
    ...(report.cwe        ? [["CWE", report.cwe.join(", ")]] : []),
    ...(report.published  ? [["Publié le", report.published]] : []),
    ...((report.associated_domains || []).map((d,i) => [`Domaine associé ${i+1}`, d])),
    ...((report.associated_files   || []).map((f,i) => [`Fichier associé ${i+1}`, f])),
    ...((report.alerts             || []).map((a,i) => [`Alerte ${i+1}`, a])),
    ...((report.mitre_attack       || []).map(m => [`MITRE ${m.technique_id}`, `${m.technique_name} (${m.matched_on})`])),
  ];
  const csv = rows.map(r => r.map(v => `"${v}"`).join(",")).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" }));
  a.download = `socilis_${report.ioc?.replace(/[^a-z0-9]/gi,"_")}.csv`;
  a.click();
}

function dlJSON(report) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }));
  a.download = `socilis_${report.ioc?.replace(/[^a-z0-9]/gi,"_")}.json`;
  a.click();
}

function dlPDF(report) {
  const now = new Date().toLocaleDateString("fr-FR", { day:"2-digit", month:"long", year:"numeric", hour:"2-digit", minute:"2-digit" });
  const sc = report.score || 0;
  const scColor = sc >= 80 ? "#ef4444" : sc >= 60 ? "#f97316" : sc >= 35 ? "#eab308" : "#22c55e";
  const threatMeta = {
    critical: { color:"#ef4444", bg:"rgba(239,68,68,0.1)",  border:"rgba(239,68,68,0.4)",  label:"CRITIQUE" },
    high:     { color:"#f97316", bg:"rgba(249,115,22,0.1)", border:"rgba(249,115,22,0.4)", label:"ÉLEVÉ"    },
    medium:   { color:"#eab308", bg:"rgba(234,179,8,0.1)",  border:"rgba(234,179,8,0.4)",  label:"MOYEN"    },
    low:      { color:"#22c55e", bg:"rgba(34,197,94,0.1)",  border:"rgba(34,197,94,0.4)",  label:"FAIBLE"   },
    malicious:{ color:"#ef4444", bg:"rgba(239,68,68,0.1)",  border:"rgba(239,68,68,0.4)",  label:"MALICIEUX"},
    clean:    { color:"#22c55e", bg:"rgba(34,197,94,0.1)",  border:"rgba(34,197,94,0.4)",  label:"PROPRE"   },
  };
  const tm = threatMeta[report.threat_level] || threatMeta[report.verdict] || threatMeta.medium;
  const typeIcons = { ip:"◈", hash:"⬡", domain:"◎", url:"⬔", mail:"✉", cve:"⚠" };
  const typeColors = { ip:"#22d3ee", hash:"#a78bfa", domain:"#fb923c", url:"#4ade80", mail:"#f472b6", cve:"#ef4444" };
  const typeIcon  = typeIcons[report.type]  || "◆";
  const typeColor = typeColors[report.type] || "#00a8ff";

  const row = (label, value, color) =>
    `<div style="display:flex;gap:0;margin-bottom:7px;border-bottom:1px solid rgba(0,168,255,0.06);padding-bottom:7px">
      <span style="min-width:160px;font-size:9px;letter-spacing:1.5px;color:rgba(160,210,255,0.35)">${label}</span>
      <span style="font-size:10px;color:${color||"#e2f0ff"};word-break:break-all">${value}</span>
    </div>`;

  const section = (title, content) =>
    `<div style="margin-bottom:20px">
      <div style="font-size:8px;letter-spacing:3px;color:rgba(160,210,255,0.3);margin-bottom:10px;padding-bottom:6px;border-bottom:1px solid rgba(0,168,255,0.08)">${title}</div>
      ${content}
    </div>`;

  const tagHtml = (report.tags||[]).map(tag =>
    `<span style="display:inline-block;padding:2px 9px;background:rgba(0,168,255,0.07);border:1px solid rgba(0,168,255,0.2);border-radius:3px;color:#00a8ff;font-size:9px;margin:2px">${tag}</span>`
  ).join("");

  // ── Sections selon le type ──
  let tiSection = "";

  if (report.type === "ip") {
    tiSection += section("INFORMATIONS RÉSEAU",
      (report.isp     ? row("ISP", report.isp) : "") +
      (report.asn     ? row("ASN", report.asn) : "") +
      (report.country ? row("PAYS", report.country) : row("PAYS", "N/A"))
    );
    tiSection += section("RÉPUTATION",
      row("VT MALICIOUS",   report.vt_malicious  ?? 0, report.vt_malicious  > 0 ? "#ef4444" : "#22c55e") +
      row("VT SUSPICIOUS",  report.vt_suspicious ?? 0, report.vt_suspicious > 0 ? "#eab308" : "#22c55e") +
      row("ABUSEIPDB SCORE",report.abuseipdb     ?? 0, report.abuseipdb     > 0 ? "#f97316" : "#22c55e") +
      row("OTX PULSES",     report.otx_pulses    ?? 0)
    );
    if ((report.associated_domains||[]).length > 0)
      tiSection += section("DOMAINES ASSOCIÉS",
        report.associated_domains.map(d => `<div style="font-size:9px;color:#fb923c;margin-bottom:4px">→ ${d}</div>`).join("")
      );
    if ((report.associated_files||[]).length > 0)
      tiSection += section("FICHIERS ASSOCIÉS",
        report.associated_files.map(f => `<div style="font-size:8px;color:rgba(160,210,255,0.5);margin-bottom:3px;word-break:break-all;font-family:monospace">${f}</div>`).join("")
      );
  }

  if (report.type === "hash") {
    tiSection += section("INFORMATIONS FICHIER",
      (report.file_type  ? row("TYPE", report.file_type) : "") +
      (report.first_seen ? row("PREMIER VU", report.first_seen) : "")
    );
    tiSection += section("DÉTECTIONS",
      row("VT MALICIOUS",  report.vt_malicious  ?? 0, report.vt_malicious  > 0 ? "#ef4444" : "#22c55e") +
      row("VT UNDETECTED", report.vt_undetected ?? 0) +
      row("OTX PULSES",    report.otx_pulses    ?? 0)
    );
    if ((report.mitre_attack||[]).length > 0)
      tiSection += section("MITRE ATT&CK",
        report.mitre_attack.map(m =>
          `<div style="display:flex;gap:8px;margin-bottom:8px;padding:8px;background:rgba(167,139,250,0.05);border:1px solid rgba(167,139,250,0.15);border-radius:4px">
            <span style="padding:2px 8px;background:rgba(167,139,250,0.1);border:1px solid rgba(167,139,250,0.3);border-radius:3px;color:#a78bfa;font-size:9px;white-space:nowrap;flex-shrink:0">${m.technique_id}</span>
            <div>
              <div style="font-size:9px;color:#e2f0ff;margin-bottom:2px">${m.technique_name}</div>
              <div style="font-size:8px;color:rgba(160,210,255,0.35)">source: ${m.source} · matched: ${m.matched_on}</div>
            </div>
          </div>`
        ).join("")
      );
  }

  if (report.type === "domain") {
    tiSection += section("INFORMATIONS DOMAINE",
      (report.registrar ? row("REGISTRAR", report.registrar) : "") +
      (report.created   ? row("DATE CRÉATION", report.created) : "") +
      (report.ip_domain ? row("IP", report.ip_domain) : "") +
      (report.subdomains_count != null ? row("SOUS-DOMAINES", report.subdomains_count) : "") 
    );
    tiSection += section("DÉTECTIONS",
      row("VT MALICIOUS", report.vt_malicious ?? 0, report.vt_malicious > 0 ? "#ef4444" : "#22c55e")
    );
  }

  if (report.type === "url") {
    tiSection += section("INFORMATIONS URL",
      (report.domain ? row("DOMAINE", report.domain) : "") +
      (report.ip     ? row("IP", report.ip) : "") 
    );
    tiSection += section("DÉTECTIONS",
      row("VT MALICIOUS",  report.vt_malicious  ?? 0, report.vt_malicious  > 0 ? "#ef4444" : "#22c55e") +
      row("VT SUSPICIOUS", report.vt_suspicious ?? 0, report.vt_suspicious > 0 ? "#eab308" : "#22c55e") +
      ((report.gsb_threats||[]).length > 0 ? row("GOOGLE SAFE BROWSING", report.gsb_threats.join(", "), "#ef4444") : "") +
      (report.phishtank ? row("PHISHTANK", report.phishtank, report.phishtank==="clean"?"#22c55e":"#ef4444") : "")
    );
  }

  if (report.type === "mail") {
    tiSection += section("INFORMATIONS EMAIL",
      (report.mail_domain ? row("DOMAINE", report.mail_domain) : "") +
      (report.provider    ? row("PROVIDER", report.provider) : "")
    );
    tiSection += section("AUTHENTIFICATION",
      `<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:8px">
        ${["mx","spf","dmarc"].map(k => {
          const v = report[k] || "missing";
          const ok = v !== "missing";
          return `<div style="padding:8px;background:${ok?"rgba(34,197,94,0.06)":"rgba(239,68,68,0.06)"};border:1px solid ${ok?"rgba(34,197,94,0.2)":"rgba(239,68,68,0.2)"};border-radius:5px;text-align:center">
            <div style="font-size:8px;letter-spacing:1px;color:rgba(160,210,255,0.35);margin-bottom:4px">${k.toUpperCase()}</div>
            <div style="font-size:10px;font-weight:700;color:${ok?"#22c55e":"#ef4444"}">${v.toUpperCase()}</div>
          </div>`;
        }).join("")}
      </div>`
    );
    if ((report.alerts||[]).length > 0)
      tiSection += section("ALERTES",
        report.alerts.map(a =>
          `<div style="padding:6px 10px;background:rgba(248,113,113,0.06);border:1px solid rgba(248,113,113,0.15);border-radius:3px;color:#f87171;font-size:9px;margin-bottom:4px">⚠ ${a}</div>`
        ).join("")
      );
  }

  if (report.type === "cve") {
    tiSection += section("INFORMATIONS CVE",
      (report.severity   ? row("SÉVÉRITÉ", report.severity, "#ef4444") : "") +
      (report.cvss_score != null ? row("CVSS SCORE", report.cvss_score, report.cvss_score>=9?"#ef4444":report.cvss_score>=7?"#f97316":"#eab308") : "") +
      (report.cvss_vector ? row("CVSS VECTOR", report.cvss_vector) : "") +
      ((report.cwe||[]).length > 0 ? row("CWE", report.cwe.join(", ")) : "") +
      (report.published  ? row("PUBLIÉ LE", report.published) : "")
    );
  }

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/>
<title>SOCILIS — Rapport ${report.ioc}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#050b12;color:#e2f0ff;font-family:'JetBrains Mono',monospace;padding:40px 48px;font-size:11px;line-height:1.6;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  @page{size:A4;margin:20mm}
  @media print{body{padding:0}.no-print{display:none!important}}
</style></head><body>

<div class="no-print" style="position:fixed;top:16px;right:16px;z-index:999">
  <button onclick="window.print()" style="background:#00a8ff;border:none;color:#fff;padding:8px 20px;border-radius:5px;cursor:pointer;font-family:'JetBrains Mono',monospace;font-size:11px;letter-spacing:1px">🖨 IMPRIMER / PDF</button>
</div>

<!-- Header -->
<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid rgba(0,168,255,0.15)">
  <div>
    <div style="font-size:8px;letter-spacing:4px;color:rgba(160,210,255,0.3);margin-bottom:8px">SOCILIS THREAT INTELLIGENCE PLATFORM</div>
    <div style="font-size:24px;font-weight:700;color:#00a8ff;letter-spacing:2px;margin-bottom:4px">RAPPORT D'ANALYSE IOC</div>
    <div style="font-size:9px;color:rgba(160,210,255,0.35);letter-spacing:2px">GÉNÉRÉ LE ${now}</div>
  </div>
  <div style="padding:8px 18px;background:${tm.bg};border:1px solid ${tm.border};border-radius:6px;text-align:center">
    <div style="font-size:8px;letter-spacing:2px;color:rgba(160,210,255,0.3);margin-bottom:4px">NIVEAU DE MENACE</div>
    <div style="font-size:14px;font-weight:700;color:${tm.color};letter-spacing:2px">${tm.label}</div>
  </div>
</div>

<!-- IOC Identity -->
<div style="background:rgba(4,12,24,0.98);border:1px solid ${tm.border};border-radius:10px;padding:24px;margin-bottom:24px">
  <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px">
    <div style="flex:1">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <span style="color:${typeColor};font-size:18px">${typeIcon}</span>
        <span style="font-size:8px;letter-spacing:3px;color:${typeColor}">${(report.type||"").toUpperCase()}</span>
      </div>
      <div style="font-size:16px;font-weight:700;color:#00a8ff;word-break:break-all;margin-bottom:12px">${report.ioc}</div>
      ${tagHtml ? `<div style="margin-top:8px">${tagHtml}</div>` : ""}
    </div>
    <div style="flex-shrink:0;text-align:center">
      <div style="font-size:8px;letter-spacing:2px;color:rgba(160,210,255,0.3);margin-bottom:8px">THREAT SCORE</div>
      <div style="font-size:42px;font-weight:700;color:${scColor};line-height:1">${sc}</div>
      <div style="font-size:10px;color:rgba(160,210,255,0.3)">/100</div>
      <div style="width:80px;height:4px;background:rgba(255,255,255,0.05);border-radius:2px;margin:10px auto 0;overflow:hidden">
        <div style="height:100%;width:${sc}%;background:${scColor};border-radius:2px"></div>
      </div>
    </div>
  </div>
</div>

<!-- Message analyse -->
<div style="padding:14px 18px;background:rgba(0,168,255,0.03);border-left:2px solid rgba(0,168,255,0.35);border-radius:0 6px 6px 0;margin-bottom:24px">
  <div style="font-size:8px;letter-spacing:3px;color:rgba(160,210,255,0.3);margin-bottom:6px">ANALYSE</div>
  <div style="font-size:10px;color:rgba(160,210,255,0.7);line-height:1.8">${report.message || ""}</div>
</div>

<!-- TI Sections -->
${tiSection}

<!-- Footer -->
<div style="margin-top:48px;padding-top:16px;border-top:1px solid rgba(0,168,255,0.1);display:flex;justify-content:space-between">
  <span style="font-size:8px;letter-spacing:2px;color:rgba(160,210,255,0.2)">SOCILIS THREAT INTELLIGENCE · RAPPORT CONFIDENTIEL</span>
  <span style="font-size:8px;letter-spacing:2px;color:rgba(160,210,255,0.2)">${new Date().getFullYear()}</span>
</div>

</body></html>`;

  const w = window.open("", "_blank");
  w.document.write(html);
  w.document.close();
}

// ── Report Card ───────────────────────────────────────────────────────────────
function ReportCard({ report, darkMode }) {
  const th = t(darkMode);
  const sc = report.score || 0;
  const scColor = sc >= 80 ? "#ef4444" : sc >= 60 ? "#f97316" : sc >= 35 ? "#eab308" : "#22c55e";
  const typeColors = { ip:"#22d3ee", hash:"#a78bfa", domain:"#fb923c", url:"#4ade80", mail:"#f472b6", cve:"#ef4444" };
  const typeIcons  = { ip:"◈", hash:"⬡", domain:"◎", url:"⬔", mail:"✉", cve:"⚠" };
  const typeColor  = typeColors[report.type] || "#00a8ff";
  const typeIcon   = typeIcons[report.type]  || "◆";

  const Field = ({ label, value, color, mono }) => (
    <div style={{ marginBottom:"8px" }}>
      <div style={{ fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"2px" }}>{label}</div>
      <div style={{ fontSize:"10px", color:color||th.text, fontFamily:mono?"'JetBrains Mono',monospace":"inherit", wordBreak:"break-all", lineHeight:"1.5" }}>{value}</div>
    </div>
  );

  const Section = ({ title, children }) => (
    <div style={{ marginBottom:"14px", paddingTop:"12px", borderTop:`1px solid ${th.border}` }}>
      <div style={{ fontSize:"8px", letterSpacing:"3px", color:th.textFaint, marginBottom:"10px" }}>{title}</div>
      {children}
    </div>
  );

  return (
    <div style={{
      background: darkMode ? "rgba(4,12,24,0.97)" : "rgba(245,250,255,0.98)",
      border: `1px solid ${th.borderActive}`,
      borderRadius: "10px", padding: "16px 18px", marginTop: "10px",
      fontSize: "11px", fontFamily: "'JetBrains Mono', monospace",
      boxShadow: "0 4px 24px rgba(0,168,255,0.08)",
    }}>

      {/* ── Header ── */}
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:"14px", paddingBottom:"12px", borderBottom:`1px solid ${th.border}` }}>
        <div style={{ display:"flex", alignItems:"center", gap:"8px" }}>
          <span style={{ display:"inline-block", width:"6px", height:"6px", borderRadius:"50%", background:th.accent, boxShadow:`0 0 6px ${th.accent}` }}/>
          <span style={{ color:th.accent, fontWeight:"700", letterSpacing:"2px", fontSize:"10px" }}>THREAT INTELLIGENCE REPORT</span>
        </div>
        {/* Download buttons */}
        <div style={{ display:"flex", gap:"5px" }}>
          {[
            { label:"CSV",  action: () => dlCSV(report)  },
            { label:"JSON", action: () => dlJSON(report) },
            { label:"PDF",  action: () => dlPDF(report)  },
          ].map(({ label, action }) => (
            <button key={label} onClick={action} style={{
              background:"transparent", border:`1px solid ${th.border}`,
              color:th.textMuted, padding:"3px 9px", borderRadius:"4px",
              fontSize:"8px", cursor:"pointer", letterSpacing:"1.5px",
              fontFamily:"'JetBrains Mono',monospace", transition:"all 0.2s",
            }}
              onMouseEnter={e=>{ e.currentTarget.style.borderColor=th.borderActive; e.currentTarget.style.color=th.accent; }}
              onMouseLeave={e=>{ e.currentTarget.style.borderColor=th.border;       e.currentTarget.style.color=th.textMuted; }}
            >↓ {label}</button>
          ))}
        </div>
      </div>

      {/* ── IOC + Type ── */}
      <div style={{ display:"flex", alignItems:"center", gap:"8px", marginBottom:"10px" }}>
        <span style={{ color:typeColor, fontSize:"14px" }}>{typeIcon}</span>
        <span style={{ fontSize:"8px", letterSpacing:"2px", color:typeColor }}>{(report.type||"").toUpperCase()}</span>
        <span style={{ color:th.accent, background:th.accentSubtle, border:`1px solid ${th.border}`, padding:"2px 10px", borderRadius:"3px", fontSize:"11px", wordBreak:"break-all" }}>{report.ioc}</span>
      </div>

      {/* ── Score + Verdict ── */}
      <div style={{ display:"flex", alignItems:"center", gap:"12px", marginBottom:"14px" }}>
        <VerdictBadge verdict={report.verdict}/>
        <div style={{ flex:1 }}>
          <div style={{ display:"flex", justifyContent:"space-between", marginBottom:"5px" }}>
            <span style={{ color:th.textFaint, fontSize:"9px", letterSpacing:"2px" }}>THREAT SCORE</span>
            <span style={{ color:scColor, fontWeight:"700", fontSize:"13px" }}>{sc}<span style={{ color:th.textFaint, fontSize:"9px" }}>/100</span></span>
          </div>
          <div style={{ height:"3px", background:"rgba(255,255,255,0.06)", borderRadius:"2px", overflow:"hidden" }}>
            <div style={{ height:"100%", width:`${sc}%`, background:`linear-gradient(90deg,${scColor}88,${scColor})`, borderRadius:"2px", boxShadow:`0 0 8px ${scColor}60`, transition:"width 1.2s cubic-bezier(0.4,0,0.2,1)" }}/>
          </div>
        </div>
      </div>

      {/* ── Message ── */}
      {report.message && (
        <div style={{ padding:"9px 12px", background:darkMode?"rgba(0,168,255,0.03)":"rgba(0,100,200,0.03)", borderLeft:`2px solid rgba(0,168,255,0.3)`, borderRadius:"0 4px 4px 0", marginBottom:"14px" }}>
          <div style={{ fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"4px" }}>ANALYSE</div>
          <div style={{ fontSize:"10px", color:th.textMuted, lineHeight:"1.7" }}>{report.message}</div>
        </div>
      )}

      {/* ── Tags ── */}
      {(report.tags||[]).length > 0 && (
        <div style={{ display:"flex", flexWrap:"wrap", gap:"4px", marginBottom:"12px" }}>
          {report.tags.map(tag => (
            <span key={tag} style={{ fontSize:"9px", padding:"2px 9px", background:"rgba(0,168,255,0.07)", border:"1px solid rgba(0,168,255,0.2)", borderRadius:"3px", color:"#00a8ff" }}>{tag}</span>
          ))}
        </div>
      )}

      {/* ══════════ SECTIONS PAR TYPE ══════════ */}

      {/* IP */}
      {report.type === "ip" && (<>
        <Section title="INFORMATIONS RÉSEAU">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="ISP"  value={report.isp  || "N/A"}/>
            <Field label="ASN"  value={report.asn  || "N/A"}/>
            <Field label="PAYS" value={report.country || "N/A"}/>
          </div>
        </Section>
        <Section title="RÉPUTATION">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="VT MALICIOUS"    value={report.vt_malicious  ?? 0} color={report.vt_malicious  > 0 ? "#ef4444" : "#22c55e"}/>
            <Field label="VT SUSPICIOUS"   value={report.vt_suspicious ?? 0} color={report.vt_suspicious > 0 ? "#eab308" : "#22c55e"}/>
            <Field label="ABUSEIPDB SCORE" value={report.abuseipdb     ?? 0} color={report.abuseipdb     > 0 ? "#f97316" : "#22c55e"}/>
            <Field label="OTX PULSES"      value={report.otx_pulses    ?? 0}/>
          </div>
        </Section>
        {(report.associated_domains||[]).length > 0 && (
          <Section title="DOMAINES ASSOCIÉS">
            {report.associated_domains.map(d => (
              <div key={d} style={{ fontSize:"10px", color:"#fb923c", marginBottom:"3px" }}>→ {d}</div>
            ))}
          </Section>
        )}
        {(report.associated_files||[]).length > 0 && (
          <Section title="FICHIERS ASSOCIÉS">
            {report.associated_files.map(f => (
              <div key={f} style={{ fontSize:"9px", color:th.textMuted, marginBottom:"3px", wordBreak:"break-all", fontFamily:"monospace" }}>{f}</div>
            ))}
          </Section>
        )}
      </>)}

      {/* HASH */}
      {report.type === "hash" && (<>
        <Section title="INFORMATIONS FICHIER">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="TYPE FICHIER" value={report.file_type  || "N/A"}/>
            <Field label="PREMIER VU"   value={report.first_seen || "N/A"}/>
          </div>
        </Section>
        <Section title="DÉTECTIONS">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="VT MALICIOUS"  value={report.vt_malicious  ?? 0} color={report.vt_malicious  > 0 ? "#ef4444" : "#22c55e"}/>
            <Field label="VT UNDETECTED" value={report.vt_undetected ?? 0}/>
            <Field label="OTX PULSES"    value={report.otx_pulses    ?? 0}/>
          </div>
        </Section>
        {(report.mitre_attack||[]).length > 0 && (
          <Section title="MITRE ATT&CK">
            {report.mitre_attack.map(m => (
              <div key={m.technique_id} style={{ display:"flex", gap:"8px", marginBottom:"7px", padding:"8px 10px", background:"rgba(167,139,250,0.05)", border:"1px solid rgba(167,139,250,0.15)", borderRadius:"5px" }}>
                <span style={{ padding:"2px 8px", background:"rgba(167,139,250,0.1)", border:"1px solid rgba(167,139,250,0.3)", borderRadius:"3px", color:"#a78bfa", fontSize:"9px", whiteSpace:"nowrap", flexShrink:0, alignSelf:"flex-start" }}>{m.technique_id}</span>
                <div>
                  <div style={{ fontSize:"10px", color:th.text, marginBottom:"2px" }}>{m.technique_name}</div>
                  <div style={{ fontSize:"8px", color:th.textFaint }}>source: {m.source} · matched: {m.matched_on}</div>
                </div>
              </div>
            ))}
          </Section>
        )}
      </>)}

      {/* DOMAIN */}
      {report.type === "domain" && (<>
        <Section title="INFORMATIONS DOMAINE">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="IP"              value={report.ip_domain           || "N/A"}/>
            <Field label="REGISTRAR"       value={report.registrar           || "N/A"}/>
            <Field label="DATE CRÉATION"   value={report.created             || "N/A"}/>
            <Field label="SOUS-DOMAINES"   value={report.subdomains_count    ?? "N/A"}/>
          </div>
        </Section>
        <Section title="DÉTECTIONS">
          <Field label="VT MALICIOUS" value={report.vt_malicious ?? 0} color={report.vt_malicious > 0 ? "#ef4444" : "#22c55e"}/>
        </Section>
      </>)}

      {/* URL */}
      {report.type === "url" && (<>
        <Section title="INFORMATIONS URL">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="DOMAINE"         value={report.domain            || "N/A"}/>
            <Field label="IP"              value={report.ip                || "N/A"}/>
            <Field label="GLOBAL RISK"     value={report.global_risk_score ?? "N/A"} color="#f97316"/>
          </div>
        </Section>
        <Section title="DÉTECTIONS">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="VT MALICIOUS"      value={report.vt_malicious  ?? 0} color={report.vt_malicious  > 0 ? "#ef4444" : "#22c55e"}/>
            <Field label="VT SUSPICIOUS"     value={report.vt_suspicious ?? 0} color={report.vt_suspicious > 0 ? "#eab308" : "#22c55e"}/>
            {(report.gsb_threats||[]).length > 0 && <Field label="GOOGLE SAFE BROWSING" value={report.gsb_threats.join(", ")} color="#ef4444"/>}
            {report.phishtank && <Field label="PHISHTANK" value={report.phishtank} color={report.phishtank==="clean"?"#22c55e":"#ef4444"}/>}
          </div>
        </Section>
      </>)}

      {/* MAIL */}
      {report.type === "mail" && (<>
        <Section title="INFORMATIONS EMAIL">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="DOMAINE"  value={report.mail_domain || "N/A"}/>
            <Field label="PROVIDER" value={report.provider    || "N/A"}/>
          </div>
        </Section>
        <Section title="AUTHENTIFICATION">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:"8px", marginBottom:"8px" }}>
            {["mx","spf","dmarc"].map(k => {
              const v = report[k] || "missing";
              const ok = v !== "missing";
              return (
                <div key={k} style={{ padding:"8px", background:ok?"rgba(34,197,94,0.06)":"rgba(239,68,68,0.06)", border:`1px solid ${ok?"rgba(34,197,94,0.2)":"rgba(239,68,68,0.2)"}`, borderRadius:"5px", textAlign:"center" }}>
                  <div style={{ fontSize:"8px", letterSpacing:"1px", color:th.textFaint, marginBottom:"3px" }}>{k.toUpperCase()}</div>
                  <div style={{ fontSize:"10px", fontWeight:"700", color:ok?"#22c55e":"#ef4444" }}>{v.toUpperCase()}</div>
                </div>
              );
            })}
          </div>
        </Section>
        {(report.alerts||[]).length > 0 && (
          <Section title="ALERTES">
            {report.alerts.map(a => (
              <div key={a} style={{ padding:"5px 10px", background:"rgba(248,113,113,0.06)", border:"1px solid rgba(248,113,113,0.15)", borderRadius:"3px", color:"#f87171", fontSize:"9px", marginBottom:"4px" }}>⚠ {a}</div>
            ))}
          </Section>
        )}
      </>)}

      {/* CVE */}
      {report.type === "cve" && (
        <Section title="INFORMATIONS CVE">
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"8px" }}>
            <Field label="SÉVÉRITÉ"    value={report.severity    || "N/A"} color="#ef4444"/>
            <Field label="CVSS SCORE"  value={report.cvss_score  ?? "N/A"} color={report.cvss_score>=9?"#ef4444":report.cvss_score>=7?"#f97316":"#eab308"}/>
            <Field label="PUBLIÉ LE"   value={report.published   || "N/A"}/>
            {(report.cwe||[]).length > 0 && <Field label="CWE" value={report.cwe.join(", ")}/>}
          </div>
          {report.cvss_vector && <Field label="CVSS VECTOR" value={report.cvss_vector} mono/>}
        </Section>
      )}

    </div>
  );
}

// ── Message Bubble ────────────────────────────────────────────────────────────
export default function MessageBubble({ msg, darkMode }) {
  const th = t(darkMode);
  const isUser = msg.role === "user";

  return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:isUser?"flex-end":"flex-start", marginBottom:"18px", animation:"fadeInUp 0.25s ease-out" }}>
      <div style={{ display:"flex", alignItems:"center", gap:"8px", flexDirection:isUser?"row-reverse":"row", marginBottom:"5px" }}>
        <div style={{ width:"22px", height:"22px", borderRadius:"50%", background:isUser?`linear-gradient(135deg,${th.accentDim},${th.accent})`:"linear-gradient(135deg,#1a2a3a,#2a4060)", border:`1px solid ${isUser?th.borderActive:th.border}`, display:"flex", alignItems:"center", justifyContent:"center", fontSize:"10px", flexShrink:0, boxShadow:isUser?`0 0 8px ${th.accentGlow}`:"none" }}>
          {isUser ? "▲" : "🛡"}
        </div>
        <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", fontWeight:"700", letterSpacing:"2px", color:isUser?th.accent:"#4ade80" }}>
          {isUser ? "ANALYST" : "TI-ENGINE"}
        </span>
        <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:th.textFaint }}>{msg.timestamp}</span>
      </div>

      <div style={{ maxWidth:"80%", background:isUser?th.userBubble:th.botBubble, border:`1px solid ${isUser?th.borderActive:th.border}`, borderRadius:isUser?"10px 10px 2px 10px":"10px 10px 10px 2px", padding:"11px 15px", color:th.text, fontSize:"12px", lineHeight:"1.65", fontFamily:"'JetBrains Mono',monospace", boxShadow:isUser?`0 2px 12px ${th.accentGlow}`:"none" }}>
        {msg.content}
      </div>

      {msg.report && (
        <div style={{ maxWidth:"92%", width:"100%" }}>
          <ReportCard report={msg.report} darkMode={darkMode}/>
        </div>
      )}
    </div>
  );
}