import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { t } from "../components/chat/chatTheme";

const REPORT_DATA = [
  {
    message: "This IP address does not show any signs of malicious activity according to available information.",
    indicator: "172.66.213.38", type: "ip",
    verdict: { threat_level: "low", score: 10, tags: [] },
    ti_summary: { asn: 13335, isp: "Cloudflare, Inc.", reputation: { virustotal: { malicious: 0, suspicious: 0 }, abuseipdb: { score: 0 }, otx: { pulses: 0 } }, associated_domains: ["mci.libercdn.xyz","ffh2.gsmbax.net","mci.ircf.space","mci.netplan.sbs","mci.ahwazjob.ir"], associated_files: ["0342425019e5...","129d3aa1c2a9...","9141dc30cade...","9da93532c81f...","dff155f493a4..."] },
  },
  {
    message: "Multiple vendors have flagged this PowerShell script as potentially malicious. It likely downloads and executes additional components which could lead to system instability or data exfiltration. Investigate immediately.",
    indicator: "44d88612fea8a8f36de82e1278abb02f", type: "hash",
    verdict: { threat_level: "high", score: 90, tags: ["malware","powershell","ransomware"] },
    ti_summary: { file_type: "Powershell", first_seen: "2006-05-22", detection: { virustotal: { malicious: 67, undetected: 2 }, otx: { pulses: 46 } }, mitre_attack: [{ technique_id: "T1059", technique_name: "Command and Scripting Interpreter" },{ technique_id: "T1055", technique_name: "Process Injection" },{ technique_id: "T1219", technique_name: "Remote Access Software" }] },
  },
  {
    message: "This domain has been flagged for potential involvement in malware distribution due to its association with known malicious activities and lack of legitimate purpose.",
    indicator: "tools.usps-packagestrack.com", type: "domain",
    verdict: { threat_level: "high", score: 75, tags: ["malware-distribution","suspicious-domain","phishing"] },
    ti_summary: { registrar: "ALIBABA.COM SINGAPORE E-COMMERCE PRIVATE LIMITED", created: "2023-08-17", detection: { virustotal: { malicious: 13 } }, subdomains_count: 0, global_risk_score: 130 },
  },
  {
    message: "This domain has been flagged as malicious based on multiple detection reports and its association with potentially harmful activities.",
    indicator: "http://www.amazonwebclone.vercel.app/", type: "url",
    verdict: { threat_level: "high", score: 75, tags: ["malicious-vt","google-sb"] },
    ti_summary: { domain: "www.amazonwebclone.vercel.app", ip: "216.198.79.3", detection: { virustotal: { malicious: 18, suspicious: 1 }, google_safe_browsing: { threats: ["SOCIAL_ENGINEERING"] }, phishtank: { verdict: "clean" } }, global_risk_score: 100 },
  },
  {
    message: "This email exhibits several red flags indicative of phishing activity. The lack of proper authentication mechanisms such as SPF, DKIM, and DMARC raises concerns regarding its legitimacy.",
    indicator: "security@paypal-update-info.com", type: "mail",
    verdict: { threat_level: "high", score: 95, tags: [] },
    ti_summary: { domain: "paypal-update-info.com", security: { mx: "missing", spf: "missing", dmarc: "missing" }, alerts: ["Aucun serveur MX","SPF absent","DMARC absent","Imite paypal"], provider: "Inconnu" },
  },
  {
    message: "A vulnerability has been identified in Microsoft .NET Framework where improper input validation can lead to privilege escalation via a network connection.",
    indicator: "CVE-2026-40372", type: "cve",
    verdict: { threat_level: "critical", score: 85, tags: ["authentication bypass","privilege escalation","web application security"] },
    ti_summary: { severity: "CRITICAL", cvss_score: 9.1, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", cwe: ["CWE-347"], published: "2026-04-21" },
  },
];

const THREAT_META = {
  critical: { color: "#ef4444", glow: "rgba(239,68,68,0.15)", label: "CRITIQUE", bg: "rgba(239,68,68,0.08)", border: "rgba(239,68,68,0.35)" },
  high:     { color: "#f97316", glow: "rgba(249,115,22,0.15)", label: "ÉLEVÉ",   bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.35)" },
  medium:   { color: "#eab308", glow: "rgba(234,179,8,0.15)",  label: "MOYEN",   bg: "rgba(234,179,8,0.08)",  border: "rgba(234,179,8,0.35)"  },
  low:      { color: "#22c55e", glow: "rgba(34,197,94,0.15)",  label: "FAIBLE",  bg: "rgba(34,197,94,0.08)",  border: "rgba(34,197,94,0.35)"  },
};

const TYPE_META = {
  ip:     { color: "#22d3ee", icon: "◈", label: "IP" },
  hash:   { color: "#a78bfa", icon: "⬡", label: "HASH" },
  domain: { color: "#fb923c", icon: "◎", label: "DOMAIN" },
  url:    { color: "#4ade80", icon: "⬔", label: "URL" },
  mail:   { color: "#f472b6", icon: "✉", label: "MAIL" },
  cve:    { color: "#ef4444", icon: "⚠", label: "CVE" },
};

function scoreColor(s) {
  return s >= 80 ? "#ef4444" : s >= 60 ? "#f97316" : s >= 35 ? "#eab308" : "#22c55e";
}

// ── Export CSV ────────────────────────────────────────────────────────────────
function exportCSV() {
  const headers = ["Indicateur","Type","Niveau Menace","Score","Tags","Message"];
  const rows = REPORT_DATA.map(d => [
    `"${d.indicator}"`, d.type, d.verdict.threat_level, d.verdict.score,
    `"${d.verdict.tags.join(", ")}"`, `"${d.message.replace(/"/g,"'")}"`
  ]);
  const csv = [headers,...rows].map(r => r.join(",")).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob(["\uFEFF"+csv], { type: "text/csv;charset=utf-8;" }));
  a.download = "socilis_rapport_ti.csv"; a.click();
}

// ── Export JSON ───────────────────────────────────────────────────────────────
function exportJSON() {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(REPORT_DATA, null, 2)], { type: "application/json" }));
  a.download = "socilis_rapport_ti.json"; a.click();
}

// ── Export PDF (print) ────────────────────────────────────────────────────────
function exportPDF() {
  const now = new Date().toLocaleDateString("fr-FR", { day:"2-digit", month:"long", year:"numeric", hour:"2-digit", minute:"2-digit" });
  const avg = Math.round(REPORT_DATA.reduce((s,d)=>s+d.verdict.score,0)/REPORT_DATA.length);

  const iocCards = REPORT_DATA.map(d => {
    const tm = THREAT_META[d.verdict.threat_level] || THREAT_META.medium;
    const tyM = TYPE_META[d.type] || { color:"#00a8ff", icon:"◆", label: d.type.toUpperCase() };
    const sc = d.verdict.score;
    const sc_color = sc>=80?"#ef4444":sc>=60?"#f97316":sc>=35?"#eab308":"#22c55e";
    const s = d.ti_summary;

    const mitre = s.mitre_attack ? s.mitre_attack.map(m=>`
      <div style="display:flex;gap:8px;margin-bottom:4px;align-items:center">
        <span style="padding:2px 7px;background:rgba(167,139,250,0.12);border:1px solid rgba(167,139,250,0.3);border-radius:3px;color:#a78bfa;font-size:9px;white-space:nowrap">${m.technique_id}</span>
        <span style="color:rgba(160,210,255,0.55);font-size:9px">${m.technique_name}</span>
      </div>`).join("") : "";

    const alerts = s.alerts ? s.alerts.map(a=>`<div style="color:#f87171;font-size:9px;margin-bottom:3px">⚠ ${a}</div>`).join("") : "";
    const domains = s.associated_domains ? s.associated_domains.map(d=>`<span style="display:inline-block;padding:2px 8px;background:rgba(251,146,60,0.08);border:1px solid rgba(251,146,60,0.2);border-radius:3px;color:#fb923c;font-size:9px;margin:2px">${d}</span>`).join("") : "";
    const tags = d.verdict.tags.length ? d.verdict.tags.map(tag=>`<span style="display:inline-block;padding:2px 8px;background:rgba(0,168,255,0.07);border:1px solid rgba(0,168,255,0.18);border-radius:3px;color:#00a8ff;font-size:9px;margin:2px">${tag}</span>`).join("") : "";

    return `
    <div style="background:rgba(4,12,24,0.98);border:1px solid ${tm.border};border-radius:10px;padding:20px 24px;margin-bottom:20px;page-break-inside:avoid">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:14px;padding-bottom:14px;border-bottom:1px solid rgba(0,168,255,0.1)">
        <div>
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
            <span style="color:${tyM.color};font-size:15px">${tyM.icon}</span>
            <span style="color:rgba(160,210,255,0.35);font-size:8px;letter-spacing:2px">${tyM.label}</span>
          </div>
          <div style="color:#00a8ff;font-size:13px;font-weight:700;word-break:break-all;max-width:480px">${d.indicator}</div>
        </div>
        <div style="text-align:right;flex-shrink:0;margin-left:16px">
          <div style="padding:4px 12px;background:${tm.bg};border:1px solid ${tm.border};border-radius:4px;color:${tm.color};font-size:9px;font-weight:700;letter-spacing:2px;margin-bottom:6px">${tm.label}</div>
          <div style="font-size:22px;font-weight:700;color:${sc_color}">${sc}<span style="font-size:10px;color:rgba(160,210,255,0.3)">/100</span></div>
        </div>
      </div>

      <div style="height:3px;background:rgba(255,255,255,0.05);border-radius:2px;margin-bottom:14px;overflow:hidden">
        <div style="height:100%;width:${sc}%;background:linear-gradient(90deg,${sc_color}66,${sc_color});border-radius:2px"></div>
      </div>

      <div style="color:rgba(160,210,255,0.5);font-size:9px;line-height:1.7;margin-bottom:14px;font-style:italic;padding:10px 12px;background:rgba(0,168,255,0.03);border-left:2px solid rgba(0,168,255,0.25);border-radius:0 4px 4px 0">${d.message}</div>

      ${tags ? `<div style="margin-bottom:12px">${tags}</div>` : ""}

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:9px">
        ${s.isp ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">ISP </span><span style="color:#e2f0ff">${s.isp}</span></div>` : ""}
        ${s.asn ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">ASN </span><span style="color:#e2f0ff">${s.asn}</span></div>` : ""}
        ${s.file_type ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">TYPE </span><span style="color:#e2f0ff">${s.file_type}</span></div>` : ""}
        ${s.first_seen ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">PREMIER VU </span><span style="color:#e2f0ff">${s.first_seen}</span></div>` : ""}
        ${s.registrar ? `<div style="grid-column:1/-1"><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">REGISTRAR </span><span style="color:#e2f0ff">${s.registrar}</span></div>` : ""}
        ${s.created ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">CRÉÉ </span><span style="color:#e2f0ff">${s.created}</span></div>` : ""}
        ${s.global_risk_score ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">RISK SCORE </span><span style="color:#f97316;font-weight:700">${s.global_risk_score}</span></div>` : ""}
        ${s.cvss_score ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">CVSS </span><span style="color:#ef4444;font-weight:700">${s.cvss_score} (${s.severity})</span></div>` : ""}
        ${s.cwe ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">CWE </span><span style="color:#e2f0ff">${s.cwe.join(", ")}</span></div>` : ""}
        ${s.published ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">PUBLIÉ </span><span style="color:#e2f0ff">${s.published}</span></div>` : ""}
        ${s.detection?.virustotal ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">VIRUSTOTAL </span><span style="color:#ef4444;font-weight:700">${s.detection.virustotal.malicious} détections</span></div>` : ""}
        ${s.detection?.otx?.pulses !== undefined ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">OTX PULSES </span><span style="color:#e2f0ff">${s.detection.otx.pulses}</span></div>` : ""}
        ${s.reputation?.abuseipdb ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">ABUSEIPDB </span><span style="color:#e2f0ff">${s.reputation.abuseipdb.score}</span></div>` : ""}
        ${s.ip ? `<div><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">IP </span><span style="color:#e2f0ff">${s.ip}</span></div>` : ""}
        ${s.detection?.google_safe_browsing ? `<div style="grid-column:1/-1"><span style="color:rgba(160,210,255,0.3);letter-spacing:1px">GOOGLE SB </span><span style="color:#ef4444">${s.detection.google_safe_browsing.threats?.join(", ")}</span></div>` : ""}
      </div>

      ${alerts ? `<div style="margin-top:10px">${alerts}</div>` : ""}
      ${mitre ? `<div style="margin-top:12px"><div style="color:rgba(160,210,255,0.3);font-size:8px;letter-spacing:2px;margin-bottom:6px">MITRE ATT&CK</div>${mitre}</div>` : ""}
      ${domains ? `<div style="margin-top:10px"><div style="color:rgba(160,210,255,0.3);font-size:8px;letter-spacing:2px;margin-bottom:6px">DOMAINES ASSOCIÉS</div>${domains}</div>` : ""}
    </div>`;
  }).join("");

  const html = `<!DOCTYPE html><html><head><meta charset="utf-8"/>
<title>SOCILIS — Rapport Threat Intelligence</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#050b12;color:#e2f0ff;font-family:'JetBrains Mono',monospace;padding:40px 48px;font-size:11px;line-height:1.6}
  @media print{body{padding:24px 32px} .no-print{display:none}}
</style></head><body>
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid rgba(0,168,255,0.15)">
    <div>
      <div style="font-size:8px;letter-spacing:4px;color:rgba(160,210,255,0.3);margin-bottom:8px">SOCILIS THREAT INTELLIGENCE PLATFORM</div>
      <div style="font-size:28px;font-weight:700;color:#00a8ff;letter-spacing:2px;margin-bottom:4px">RAPPORT D'ANALYSE</div>
      <div style="font-size:9px;color:rgba(160,210,255,0.4);letter-spacing:2px">GÉNÉRÉ LE ${now}</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:8px;letter-spacing:2px;color:rgba(160,210,255,0.3);margin-bottom:4px">STATUT</div>
      <div style="padding:6px 16px;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.4);border-radius:4px;color:#f87171;font-size:10px;font-weight:700;letter-spacing:2px">⚠ MENACES DÉTECTÉES</div>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:32px">
    ${[
      ["TOTAL IOCs", REPORT_DATA.length, "#00a8ff"],
      ["CRITIQUES",  REPORT_DATA.filter(d=>d.verdict.threat_level==="critical").length, "#ef4444"],
      ["ÉLEVÉS",     REPORT_DATA.filter(d=>d.verdict.threat_level==="high").length, "#f97316"],
      ["SCORE MOY.", avg, "#eab308"],
      ["FAIBLES",    REPORT_DATA.filter(d=>d.verdict.threat_level==="low").length, "#22c55e"],
    ].map(([label, val, col]) => `
      <div style="background:rgba(${col==='#00a8ff'?'0,168,255':col==='#ef4444'?'239,68,68':col==='#f97316'?'249,115,22':col==='#eab308'?'234,179,8':'34,197,94'},0.07);border:1px solid ${col}30;border-radius:8px;padding:14px 16px">
        <div style="font-size:8px;letter-spacing:2px;color:rgba(160,210,255,0.35);margin-bottom:8px">${label}</div>
        <div style="font-size:28px;font-weight:700;color:${col}">${val}</div>
      </div>`).join("")}
  </div>

  ${iocCards}

  <div style="margin-top:40px;padding-top:20px;border-top:1px solid rgba(0,168,255,0.1);display:flex;justify-content:space-between;align-items:center">
    <div style="font-size:8px;letter-spacing:2px;color:rgba(160,210,255,0.25)">SOCILIS THREAT INTELLIGENCE PLATFORM · RAPPORT CONFIDENTIEL</div>
    <div style="font-size:8px;letter-spacing:2px;color:rgba(160,210,255,0.25)">${new Date().getFullYear()} · ${REPORT_DATA.length} IOCs ANALYSÉS</div>
  </div>
</body></html>`;

  const w = window.open("","_blank");
  w.document.write(html);
  w.document.close();
  setTimeout(()=>w.print(), 600);
}

// ── Radial Score Ring ─────────────────────────────────────────────────────────
function ScoreRing({ score, size = 72 }) {
  const r = 28, cx = size/2, cy = size/2;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const sc = scoreColor(score);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="4"/>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={sc} strokeWidth="4"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`} opacity="0.9"/>
      <text x={cx} y={cy+1} textAnchor="middle" dominantBaseline="middle"
        fill={sc} fontSize="13" fontWeight="700" fontFamily="JetBrains Mono,monospace">{score}</text>
    </svg>
  );
}

// ── Threat Bar (horizontal) ───────────────────────────────────────────────────
function ThreatBar({ darkMode }) {
  const th = t(darkMode);
  const byLevel = Object.entries(
    REPORT_DATA.reduce((acc, d) => { acc[d.verdict.threat_level] = (acc[d.verdict.threat_level]||0)+1; return acc; }, {})
  );
  const total = REPORT_DATA.length;
  return (
    <div>
      <div style={{ display:"flex", height:"8px", borderRadius:"4px", overflow:"hidden", marginBottom:"10px" }}>
        {byLevel.map(([lvl, cnt]) => {
          const tm = THREAT_META[lvl] || THREAT_META.medium;
          return <div key={lvl} style={{ flex: cnt/total, background: tm.color, opacity:0.8 }} title={`${lvl}: ${cnt}`}/>;
        })}
      </div>
      <div style={{ display:"flex", gap:"14px", flexWrap:"wrap" }}>
        {byLevel.map(([lvl, cnt]) => {
          const tm = THREAT_META[lvl] || THREAT_META.medium;
          return (
            <div key={lvl} style={{ display:"flex", alignItems:"center", gap:"5px" }}>
              <span style={{ width:"8px", height:"8px", borderRadius:"2px", background:tm.color, display:"inline-block", opacity:0.8 }}/>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:th.textMuted, letterSpacing:"1px" }}>{tm.label} ({cnt})</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── IOC Card (liste) ──────────────────────────────────────────────────────────
function IOCCard({ ioc, darkMode, selected, onSelect }) {
  const th = t(darkMode);
  const tm = THREAT_META[ioc.verdict.threat_level] || THREAT_META.medium;
  const tyM = TYPE_META[ioc.type] || { color:"#00a8ff", icon:"◆" };
  const sc = ioc.verdict.score;

  return (
    <div onClick={() => onSelect(ioc)} style={{
      padding: "14px 16px",
      background: selected
        ? (darkMode ? `rgba(0,168,255,0.06)` : `rgba(0,100,200,0.06)`)
        : "transparent",
      border: `1px solid ${selected ? tm.border : "transparent"}`,
      borderRadius: "8px", cursor: "pointer",
      transition: "all 0.18s", marginBottom: "4px",
      display: "flex", alignItems: "center", gap: "14px",
    }}
      onMouseEnter={e => { if(!selected) e.currentTarget.style.background = darkMode?"rgba(10,28,50,0.5)":"rgba(220,237,255,0.5)"; }}
      onMouseLeave={e => { if(!selected) e.currentTarget.style.background = "transparent"; }}
    >
      {/* Score ring */}
      <ScoreRing score={sc} size={56}/>

      {/* Info */}
      <div style={{ flex:1, overflow:"hidden" }}>
        <div style={{ display:"flex", alignItems:"center", gap:"6px", marginBottom:"4px" }}>
          <span style={{ color:tyM.color, fontSize:"11px" }}>{tyM.icon}</span>
          <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:tyM.color, letterSpacing:"1.5px" }}>{ioc.type.toUpperCase()}</span>
          <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", padding:"1px 7px", background:tm.bg, border:`1px solid ${tm.border}`, color:tm.color, borderRadius:"3px", letterSpacing:"1px" }}>{tm.label}</span>
        </div>
        <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"11px", color:th.text, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", marginBottom:"4px" }}>{ioc.indicator}</div>
        <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:th.textFaint, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{ioc.message.slice(0,70)}...</div>
      </div>

      <span style={{ color:th.textFaint, fontSize:"12px", flexShrink:0 }}>›</span>
    </div>
  );
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
function DetailPanel({ ioc, darkMode }) {
  const th = t(darkMode);
  if (!ioc) return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", height:"100%", gap:"12px" }}>
      <span style={{ fontSize:"32px", opacity:0.15 }}>◈</span>
      <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", letterSpacing:"3px", color:th.textFaint }}>SÉLECTIONNER UN IOC</span>
    </div>
  );

  const tm = THREAT_META[ioc.verdict.threat_level] || THREAT_META.medium;
  const tyM = TYPE_META[ioc.type] || { color:"#00a8ff", icon:"◆" };
  const sc = ioc.verdict.score;
  const scC = scoreColor(sc);
  const s = ioc.ti_summary;

  const Field = ({ label, value, color }) => (
    <div style={{ marginBottom:"10px" }}>
      <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"3px" }}>{label}</div>
      <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"10px", color:color||th.text, wordBreak:"break-all", lineHeight:"1.5" }}>{value}</div>
    </div>
  );

  return (
    <div style={{ padding:"20px", overflowY:"auto", height:"100%", scrollbarWidth:"thin", scrollbarColor:`rgba(0,168,255,0.18) transparent` }}>
      {/* Header */}
      <div style={{ marginBottom:"20px" }}>
        <div style={{ display:"flex", alignItems:"center", gap:"8px", marginBottom:"10px" }}>
          <span style={{ fontSize:"20px", color:tyM.color }}>{tyM.icon}</span>
          <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", letterSpacing:"2px", color:tyM.color }}>{ioc.type.toUpperCase()}</span>
          <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", padding:"2px 10px", background:tm.bg, border:`1px solid ${tm.border}`, color:tm.color, borderRadius:"3px", letterSpacing:"1.5px", fontWeight:"700" }}>{tm.label}</span>
        </div>
        <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"12px", color:"#00a8ff", wordBreak:"break-all", lineHeight:"1.6", marginBottom:"14px" }}>{ioc.indicator}</div>

        {/* Big score */}
        <div style={{ display:"flex", alignItems:"center", gap:"16px", padding:"14px 16px", background:darkMode?"rgba(4,12,24,0.8)":"rgba(245,250,255,0.9)", border:`1px solid ${scC}25`, borderRadius:"8px", marginBottom:"14px" }}>
          <ScoreRing score={sc} size={68}/>
          <div style={{ flex:1 }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"6px" }}>THREAT SCORE</div>
            <div style={{ height:"4px", background:"rgba(255,255,255,0.05)", borderRadius:"2px", overflow:"hidden" }}>
              <div style={{ height:"100%", width:`${sc}%`, background:`linear-gradient(90deg,${scC}66,${scC})`, borderRadius:"2px", boxShadow:`0 0 10px ${scC}50`, transition:"width 0.8s ease" }}/>
            </div>
          </div>
        </div>

        {/* Message */}
        <div style={{ padding:"12px 14px", background:darkMode?"rgba(0,168,255,0.03)":"rgba(0,100,200,0.03)", borderLeft:`2px solid rgba(0,168,255,0.3)`, borderRadius:"0 6px 6px 0", marginBottom:"16px" }}>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"6px" }}>ANALYSE</div>
          <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"10px", color:th.textMuted, lineHeight:"1.7" }}>{ioc.message}</div>
        </div>

        {/* Tags */}
        {ioc.verdict.tags.length > 0 && (
          <div style={{ marginBottom:"16px" }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"6px" }}>TAGS</div>
            <div style={{ display:"flex", flexWrap:"wrap", gap:"5px" }}>
              {ioc.verdict.tags.map(tag => (
                <span key={tag} style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", padding:"3px 10px", background:"rgba(0,168,255,0.07)", border:"1px solid rgba(0,168,255,0.2)", borderRadius:"3px", color:"#00a8ff" }}>{tag}</span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* TI Data */}
      <div style={{ borderTop:`1px solid ${th.border}`, paddingTop:"16px" }}>
        <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"3px", color:th.textFaint, marginBottom:"14px" }}>THREAT INTELLIGENCE</div>

        {s.isp && <Field label="ISP" value={s.isp}/>}
        {s.asn && <Field label="ASN" value={s.asn}/>}
        {s.file_type && <Field label="TYPE FICHIER" value={s.file_type}/>}
        {s.first_seen && <Field label="PREMIER VU" value={s.first_seen}/>}
        {s.registrar && <Field label="REGISTRAR" value={s.registrar}/>}
        {s.created && <Field label="DATE CRÉATION" value={s.created}/>}
        {s.global_risk_score && <Field label="GLOBAL RISK SCORE" value={s.global_risk_score} color="#f97316"/>}
        {s.ip && <Field label="IP" value={s.ip}/>}
        {s.domain && <Field label="DOMAINE" value={s.domain}/>}
        {s.cvss_score && <Field label="CVSS SCORE" value={`${s.cvss_score} — ${s.severity}`} color="#ef4444"/>}
        {s.cvss_vector && <Field label="CVSS VECTOR" value={s.cvss_vector}/>}
        {s.cwe && <Field label="CWE" value={s.cwe.join(", ")}/>}
        {s.published && <Field label="PUBLIÉ LE" value={s.published}/>}

        {s.reputation && (
          <>
            <Field label="VIRUSTOTAL" value={`${s.reputation.virustotal?.malicious ?? 0} malveillant · ${s.reputation.virustotal?.suspicious ?? 0} suspect`} color={s.reputation.virustotal?.malicious > 0 ? "#f87171" : th.text}/>
            <Field label="ABUSEIPDB SCORE" value={s.reputation.abuseipdb?.score}/>
            <Field label="OTX PULSES" value={s.reputation.otx?.pulses}/>
          </>
        )}

        {s.detection?.virustotal && (
          <Field label="VIRUSTOTAL DÉTECTIONS" value={`${s.detection.virustotal.malicious} malveillantes`} color="#ef4444"/>
        )}
        {s.detection?.otx?.pulses !== undefined && (
          <Field label="OTX PULSES" value={s.detection.otx.pulses}/>
        )}
        {s.detection?.google_safe_browsing && (
          <Field label="GOOGLE SAFE BROWSING" value={s.detection.google_safe_browsing.threats?.join(", ")} color="#ef4444"/>
        )}
        {s.detection?.phishtank && (
          <Field label="PHISHTANK" value={s.detection.phishtank.verdict}/>
        )}

        {s.security && (
          <div style={{ marginBottom:"14px" }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"8px" }}>SÉCURITÉ EMAIL</div>
            {Object.entries(s.security).map(([k,v]) => (
              <div key={k} style={{ display:"flex", justifyContent:"space-between", marginBottom:"5px", padding:"5px 10px", background:v==="missing"?"rgba(239,68,68,0.06)":"rgba(34,197,94,0.06)", border:`1px solid ${v==="missing"?"rgba(239,68,68,0.2)":"rgba(34,197,94,0.2)"}`, borderRadius:"4px" }}>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:th.textMuted, letterSpacing:"1px" }}>{k.toUpperCase()}</span>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:v==="missing"?"#f87171":"#4ade80", fontWeight:"700" }}>{v.toUpperCase()}</span>
              </div>
            ))}
          </div>
        )}

        {s.alerts?.length > 0 && (
          <div style={{ marginBottom:"14px" }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"8px" }}>ALERTES</div>
            {s.alerts.map(a => (
              <div key={a} style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:"#f87171", marginBottom:"4px", padding:"4px 10px", background:"rgba(248,113,113,0.06)", border:"1px solid rgba(248,113,113,0.15)", borderRadius:"3px" }}>⚠ {a}</div>
            ))}
          </div>
        )}

        {s.mitre_attack?.length > 0 && (
          <div style={{ marginBottom:"14px" }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"8px" }}>MITRE ATT&CK</div>
            {s.mitre_attack.map(m => (
              <div key={m.technique_id} style={{ display:"flex", gap:"8px", marginBottom:"6px", alignItems:"flex-start", padding:"6px 10px", background:"rgba(167,139,250,0.04)", border:"1px solid rgba(167,139,250,0.15)", borderRadius:"4px" }}>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", padding:"2px 7px", background:"rgba(167,139,250,0.1)", border:"1px solid rgba(167,139,250,0.3)", borderRadius:"3px", color:"#a78bfa", whiteSpace:"nowrap", flexShrink:0 }}>{m.technique_id}</span>
                <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:th.textMuted, lineHeight:"1.5" }}>{m.technique_name}</span>
              </div>
            ))}
          </div>
        )}

        {s.associated_domains?.length > 0 && (
          <div style={{ marginBottom:"14px" }}>
            <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"8px" }}>DOMAINES ASSOCIÉS</div>
            {s.associated_domains.map(d => (
              <div key={d} style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"9px", color:"#fb923c", marginBottom:"3px", padding:"3px 0" }}>→ {d}</div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Main Dashboard ────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [darkMode, setDarkMode]       = useState(true);
  const [selectedIOC, setSelectedIOC] = useState(null);
  const [filter, setFilter]           = useState("all");
  const [exportOpen, setExportOpen]   = useState(false);
  const navigate = useNavigate();
  const th = t(darkMode);

  const avg = Math.round(REPORT_DATA.reduce((s,d)=>s+d.verdict.score,0)/REPORT_DATA.length);

  const FILTERS = [
    { key:"all", label:"TOUS" },
    { key:"critical", label:"CRITIQUE" },
    { key:"high",     label:"ÉLEVÉ" },
    { key:"low",      label:"FAIBLE" },
    { key:"ip",    label:"IP" },
    { key:"hash",  label:"HASH" },
    { key:"domain",label:"DOMAIN" },
    { key:"url",   label:"URL" },
    { key:"mail",  label:"MAIL" },
    { key:"cve",   label:"CVE" },
  ];

  const filtered = filter === "all"
    ? REPORT_DATA
    : REPORT_DATA.filter(d => d.verdict.threat_level === filter || d.type === filter);

  const Btn = ({ label, action }) => (
    <button onClick={action} style={{ display:"block", width:"100%", padding:"10px 18px", background:"transparent", border:"none", color:th.text, fontSize:"10px", letterSpacing:"1.5px", cursor:"pointer", textAlign:"left", fontFamily:"'JetBrains Mono',monospace", transition:"background 0.15s" }}
      onMouseEnter={e=>e.currentTarget.style.background=th.accentSubtle}
      onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
      {label}
    </button>
  );

  return (
    <div style={{ display:"flex", flexDirection:"column", height:"100vh", background:th.bg, color:th.text, overflow:"hidden", fontFamily:"'JetBrains Mono',monospace" }}>
      {/* Grid bg */}
      <div style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:0, backgroundImage:darkMode?`linear-gradient(rgba(0,168,255,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,168,255,0.02) 1px,transparent 1px)`:"none", backgroundSize:"40px 40px" }}/>

      {/* ── TOPBAR ── */}
      <div style={{ height:"54px", display:"flex", alignItems:"center", padding:"0 24px", gap:"12px", borderBottom:`1px solid ${th.border}`, background:darkMode?"rgba(5,11,18,0.98)":"rgba(240,246,255,0.98)", backdropFilter:"blur(10px)", flexShrink:0, zIndex:20, position:"relative" }}>
        <button onClick={()=>navigate("/chat")} style={{ background:"transparent", border:`1px solid ${th.border}`, borderRadius:"5px", padding:"5px 12px", color:th.textMuted, fontSize:"9px", letterSpacing:"2px", cursor:"pointer", fontFamily:"'JetBrains Mono',monospace", transition:"all 0.2s" }}
          onMouseEnter={e=>{e.currentTarget.style.borderColor=th.borderActive;e.currentTarget.style.color=th.accent;}}
          onMouseLeave={e=>{e.currentTarget.style.borderColor=th.border;e.currentTarget.style.color=th.textMuted;}}>
          ← CHAT
        </button>

        <div style={{ width:"1px", height:"22px", background:th.border }}/>

        <div style={{ display:"flex", alignItems:"center", gap:"8px" }}>
          <span style={{ color:th.accent, fontSize:"13px" }}>◈</span>
          <span style={{ color:th.accent, fontSize:"11px", fontWeight:"700", letterSpacing:"3px" }}>DASHBOARD</span>
          <span style={{ color:th.textFaint, fontSize:"9px", letterSpacing:"2px" }}>/ THREAT INTELLIGENCE</span>
        </div>

        <div style={{ flex:1 }}/>

        {/* Export */}
        <div style={{ position:"relative" }}>
          <button onClick={()=>setExportOpen(v=>!v)} style={{ display:"flex", alignItems:"center", gap:"8px", background:exportOpen?th.accentSubtle:"transparent", border:`1px solid ${exportOpen?th.borderActive:th.border}`, borderRadius:"6px", padding:"6px 16px", color:exportOpen?th.accent:th.textMuted, fontSize:"9px", letterSpacing:"2px", cursor:"pointer", fontFamily:"'JetBrains Mono',monospace", transition:"all 0.2s" }}>
            <span>↓</span> EXPORTER <span style={{ fontSize:"7px" }}>▾</span>
          </button>
          {exportOpen && (
            <div style={{ position:"absolute", right:0, top:"calc(100% + 8px)", background:darkMode?"#060d16":"#fff", border:`1px solid ${th.borderActive}`, borderRadius:"8px", overflow:"hidden", zIndex:200, minWidth:"200px", boxShadow:"0 12px 40px rgba(0,0,0,0.5)" }}>
              <div style={{ padding:"8px 18px 6px", borderBottom:`1px solid ${th.border}` }}>
                <span style={{ fontSize:"8px", letterSpacing:"2px", color:th.textFaint }}>FORMAT</span>
              </div>
              <Btn label="📄  CSV" action={()=>{exportCSV();setExportOpen(false);}}/>
              <Btn label="📋  JSON" action={()=>{exportJSON();setExportOpen(false);}}/>
              <Btn label="🖨  PDF (Imprimer)" action={()=>{exportPDF();setExportOpen(false);}}/>
            </div>
          )}
        </div>

        <button onClick={()=>setDarkMode(v=>!v)} style={{ background:"transparent", border:`1px solid ${th.border}`, borderRadius:"5px", padding:"5px 10px", color:th.textMuted, fontSize:"12px", cursor:"pointer", transition:"all 0.2s" }}
          onMouseEnter={e=>{e.currentTarget.style.borderColor=th.borderActive;}}
          onMouseLeave={e=>{e.currentTarget.style.borderColor=th.border;}}>
          {darkMode?"☀":"◑"}
        </button>
      </div>

      {/* ── STATS ROW ── */}
      <div style={{ padding:"16px 24px", borderBottom:`1px solid ${th.border}`, display:"flex", gap:"12px", flexShrink:0, flexWrap:"wrap", zIndex:1, position:"relative" }}>
        {[
          { label:"TOTAL IOCs",   value: REPORT_DATA.length, color:"#00a8ff" },
          { label:"CRITIQUES",    value: REPORT_DATA.filter(d=>d.verdict.threat_level==="critical").length, color:"#ef4444" },
          { label:"ÉLEVÉS",       value: REPORT_DATA.filter(d=>d.verdict.threat_level==="high").length, color:"#f97316" },
          { label:"SCORE MOYEN",  value: avg, color:"#eab308" },
          { label:"FAIBLES",      value: REPORT_DATA.filter(d=>d.verdict.threat_level==="low").length, color:"#22c55e" },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ display:"flex", flexDirection:"column", gap:"5px", padding:"12px 18px", background:darkMode?"rgba(6,16,28,0.92)":"rgba(255,255,255,0.95)", border:`1px solid ${color}20`, borderRadius:"8px", flex:"1 1 100px", minWidth:"100px", boxShadow:`0 0 20px ${color}08` }}>
            <span style={{ fontSize:"8px", letterSpacing:"2px", color:th.textFaint }}>{label}</span>
            <span style={{ fontSize:"28px", fontWeight:"700", color, lineHeight:1 }}>{value}</span>
          </div>
        ))}

        {/* Threat distribution bar */}
        <div style={{ flex:"2 1 220px", padding:"12px 18px", background:darkMode?"rgba(6,16,28,0.92)":"rgba(255,255,255,0.95)", border:`1px solid ${th.border}`, borderRadius:"8px" }}>
          <div style={{ fontSize:"8px", letterSpacing:"2px", color:th.textFaint, marginBottom:"10px" }}>RÉPARTITION DES MENACES</div>
          <ThreatBar darkMode={darkMode}/>
        </div>
      </div>

      {/* ── BODY ── */}
      <div style={{ flex:1, display:"flex", overflow:"hidden", zIndex:1, position:"relative" }}>

        {/* Left: IOC list */}
        <div style={{ flex:"0 0 48%", borderRight:`1px solid ${th.border}`, display:"flex", flexDirection:"column", overflow:"hidden" }}>
          {/* Filter */}
          <div style={{ padding:"10px 16px", borderBottom:`1px solid ${th.border}`, display:"flex", gap:"5px", flexWrap:"wrap", flexShrink:0, background:darkMode?"rgba(5,11,18,0.6)":"rgba(240,246,255,0.6)" }}>
            {FILTERS.map(f => {
              const active = filter === f.key;
              const tColor = f.key === "all" ? th.accent
                : THREAT_META[f.key] ? THREAT_META[f.key].color
                : TYPE_META[f.key] ? TYPE_META[f.key].color
                : th.accent;
              return (
                <button key={f.key} onClick={()=>setFilter(f.key)} style={{ padding:"3px 10px", background:active?`${tColor}12`:"transparent", border:`1px solid ${active?tColor:th.border}`, borderRadius:"3px", color:active?tColor:th.textMuted, fontSize:"8px", letterSpacing:"1.5px", cursor:"pointer", fontFamily:"'JetBrains Mono',monospace", transition:"all 0.15s" }}>
                  {f.label}
                </button>
              );
            })}
            <span style={{ marginLeft:"auto", fontSize:"8px", color:th.textFaint, alignSelf:"center", letterSpacing:"1px" }}>{filtered.length} IOC{filtered.length>1?"s":""}</span>
          </div>

          {/* List */}
          <div style={{ flex:1, overflowY:"auto", padding:"10px 12px", scrollbarWidth:"thin", scrollbarColor:`rgba(0,168,255,0.18) transparent` }}>
            {filtered.map(ioc => (
              <IOCCard key={ioc.indicator} ioc={ioc} darkMode={darkMode} selected={selectedIOC?.indicator===ioc.indicator} onSelect={setSelectedIOC}/>
            ))}
          </div>
        </div>

        {/* Right: Detail */}
        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
          <div style={{ padding:"10px 20px", borderBottom:`1px solid ${th.border}`, flexShrink:0, background:darkMode?"rgba(5,11,18,0.6)":"rgba(240,246,255,0.6)" }}>
            <span style={{ fontSize:"8px", letterSpacing:"3px", color:th.textFaint }}>DÉTAIL IOC</span>
          </div>
          <div style={{ flex:1, overflow:"hidden" }}>
            <DetailPanel ioc={selectedIOC} darkMode={darkMode}/>
          </div>
        </div>
      </div>

      {exportOpen && <div onClick={()=>setExportOpen(false)} style={{ position:"fixed", inset:0, zIndex:10 }}/>}

      <style>{`
        ::-webkit-scrollbar { width: 3px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(0,168,255,0.18); border-radius: 2px; }
      `}</style>
    </div>
  );
}