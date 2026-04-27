import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { historyApi, statsApi, exportApi, authApi } from "../services/api";
import { useAuth } from "../context/AuthContext";

// ── Design tokens ─────────────────────────────────────────────────────────────
const C = {
  bg:          "#040a12",
  surface:     "rgba(8,16,28,0.95)",
  surfaceHover:"rgba(12,22,38,0.9)",
  border:      "rgba(127,216,50,0.09)",
  borderHover: "rgba(127,216,50,0.22)",
  green:       "#7FD832",
  cyan:        "#00c8ff",
  text:        "#c8dff0",
  textMuted:   "rgba(200,223,240,0.45)",
  textFaint:   "rgba(200,223,240,0.22)",
};

const THREAT = {
  critical: { color: "#ef4444", label: "CRITIQUE", bg: "rgba(239,68,68,0.07)",  border: "rgba(239,68,68,0.25)"  },
  high:     { color: "#f97316", label: "ÉLEVÉ",    bg: "rgba(249,115,22,0.07)", border: "rgba(249,115,22,0.25)" },
  medium:   { color: "#eab308", label: "MOYEN",    bg: "rgba(234,179,8,0.07)",  border: "rgba(234,179,8,0.25)"  },
  low:      { color: "#22c55e", label: "FAIBLE",   bg: "rgba(34,197,94,0.07)",  border: "rgba(34,197,94,0.25)"  },
};

const IOC_TYPE = {
  ip:     { color: "#22d3ee", icon: "IP",     symbol: "◈" },
  hash:   { color: "#a78bfa", icon: "HASH",   symbol: "⬡" },
  domain: { color: "#fb923c", icon: "DOMAIN", symbol: "◎" },
  url:    { color: "#4ade80", icon: "URL",    symbol: "⬔" },
  mail:   { color: "#f472b6", icon: "MAIL",   symbol: "✉" },
  cve:    { color: "#ef4444", icon: "CVE",    symbol: "⚠" },
};

const FILTERS = [
  { key: "all",      label: "TOUS"     },
  { key: "critical", label: "CRITIQUE" },
  { key: "high",     label: "ÉLEVÉ"    },
  { key: "medium",   label: "MOYEN"    },
  { key: "low",      label: "FAIBLE"   },
  { key: "ip",       label: "IP"       },
  { key: "hash",     label: "HASH"     },
  { key: "domain",   label: "DOMAIN"   },
  { key: "url",      label: "URL"      },
  { key: "mail",     label: "MAIL"     },
  { key: "cve",      label: "CVE"      },
];

function scoreColor(s) {
  return s >= 80 ? "#ef4444" : s >= 60 ? "#f97316" : s >= 35 ? "#eab308" : "#22c55e";
}

// ── Score Ring ────────────────────────────────────────────────────────────────
function ScoreRing({ score, size = 52 }) {
  const r = size / 2 - 5;
  const circ = 2 * Math.PI * r;
  const dash = (score / 100) * circ;
  const cx = size / 2, cy = size / 2;
  const sc = scoreColor(score);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ flexShrink: 0 }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="3" />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={sc} strokeWidth="3"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`} />
      <text x={cx} y={cy + 0.5} textAnchor="middle" dominantBaseline="middle"
        fill={sc} fontSize={size > 60 ? "14" : "11"} fontWeight="700"
        fontFamily="'DM Mono',monospace">{score}</text>
    </svg>
  );
}

// ── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({ label, value, color }) {
  return (
    <div style={{
      flex: "1 1 100px", minWidth: "100px",
      padding: "16px 20px",
      background: C.surface,
      border: `1px solid ${color}18`,
      borderRadius: "10px",
      display: "flex", flexDirection: "column", gap: "6px",
    }}>
      <span style={{ fontSize: "0.55rem", letterSpacing: "0.2em", color: C.textFaint, textTransform: "uppercase", fontFamily: "'DM Mono',monospace" }}>{label}</span>
      <span style={{ fontSize: "1.8rem", fontWeight: 800, color, fontFamily: "'Syne',sans-serif", lineHeight: 1 }}>{value}</span>
    </div>
  );
}

// ── Threat Distribution Bar ───────────────────────────────────────────────────
function ThreatBar({ data }) {
  const counts = data.reduce((acc, d) => {
    const lvl = d.final_verdict || "unknown";
    acc[lvl] = (acc[lvl] || 0) + 1;
    return acc;
  }, {});
  const entries = Object.entries(counts);
  const total = data.length || 1;
  return (
    <div style={{ flex: "2 1 240px", minWidth: "240px", padding: "16px 20px", background: C.surface, border: `1px solid ${C.border}`, borderRadius: "10px" }}>
      <span style={{ fontSize: "0.55rem", letterSpacing: "0.2em", color: C.textFaint, textTransform: "uppercase", fontFamily: "'DM Mono',monospace", display: "block", marginBottom: "12px" }}>Répartition des menaces</span>
      <div style={{ display: "flex", height: "6px", borderRadius: "3px", overflow: "hidden", marginBottom: "12px" }}>
        {entries.map(([lvl, cnt]) => (
          <div key={lvl} style={{ flex: cnt / total, background: (THREAT[lvl]?.color || "#64748b"), opacity: 0.85 }} />
        ))}
      </div>
      <div style={{ display: "flex", gap: "14px", flexWrap: "wrap" }}>
        {entries.map(([lvl, cnt]) => {
          const tm = THREAT[lvl] || { color: "#64748b", label: lvl };
          return (
            <div key={lvl} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
              <span style={{ width: "7px", height: "7px", borderRadius: "2px", background: tm.color, display: "inline-block" }} />
              <span style={{ fontSize: "0.58rem", color: C.textMuted, letterSpacing: "0.1em", fontFamily: "'DM Mono',monospace" }}>{tm.label} ({cnt})</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── IOC Row ───────────────────────────────────────────────────────────────────
function IOCRow({ ioc, selected, onSelect }) {
  const tm  = THREAT[ioc.final_verdict] || THREAT.low;
  const tyM = IOC_TYPE[ioc.ioc_type] || { color: C.cyan, icon: "IOC", symbol: "◆" };
  const [hover, setHover] = useState(false);

  return (
    <div
      onClick={() => onSelect(ioc)}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        display: "flex", alignItems: "center", gap: "14px",
        padding: "12px 16px",
        background: selected ? "rgba(127,216,50,0.04)" : hover ? "rgba(12,22,38,0.7)" : "transparent",
        border: `1px solid ${selected ? C.green + "30" : "transparent"}`,
        borderRadius: "8px",
        cursor: "pointer",
        transition: "all 0.15s",
        marginBottom: "2px",
      }}
    >
      <ScoreRing score={ioc.risk_score || 0} size={48} />

      <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column", gap: "4px" }}>
        {/* Type + threat badge */}
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <span style={{
            fontSize: "0.55rem", letterSpacing: "0.15em", color: tyM.color,
            fontFamily: "'DM Mono',monospace",
            padding: "1px 6px", border: `1px solid ${tyM.color}30`,
            borderRadius: "3px", background: `${tyM.color}08`,
          }}>{tyM.icon}</span>
          <span style={{
            fontSize: "0.55rem", letterSpacing: "0.12em", color: tm.color,
            fontFamily: "'DM Mono',monospace",
            padding: "1px 6px", border: `1px solid ${tm.border}`,
            borderRadius: "3px", background: tm.bg,
          }}>{tm.label}</span>
        </div>
        {/* Indicator */}
        <div style={{
          fontFamily: "'DM Mono',monospace", fontSize: "0.75rem",
          color: C.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        }}>{ioc.indicator}</div>
        {/* Date */}
        <div style={{ fontFamily: "'DM Mono',monospace", fontSize: "0.58rem", color: C.textFaint }}>
          {ioc.created_at?.slice(0, 16)}
        </div>
      </div>

      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={C.textFaint} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
        <path d="M9 18l6-6-6-6"/>
      </svg>
    </div>
  );
}

// ── Detail Panel ──────────────────────────────────────────────────────────────
function DetailPanel({ ioc }) {
  if (!ioc) return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: "14px" }}>
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke={C.textFaint} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
      </svg>
      <span style={{ fontFamily: "'DM Mono',monospace", fontSize: "0.6rem", letterSpacing: "0.2em", color: C.textFaint }}>SÉLECTIONNER UN IOC</span>
    </div>
  );

  const tm  = THREAT[ioc.final_verdict] || THREAT.low;
  const tyM = IOC_TYPE[ioc.ioc_type] || { color: C.cyan, icon: "IOC", symbol: "◆" };
  const sc  = ioc.risk_score || 0;
  const scC = scoreColor(sc);

  const Field = ({ label, value, color }) => (
    <div style={{ marginBottom: "14px" }}>
      <div style={{ fontSize: "0.55rem", letterSpacing: "0.18em", color: C.textFaint, marginBottom: "4px", fontFamily: "'DM Mono',monospace" }}>{label}</div>
      <div style={{ fontFamily: "'DM Mono',monospace", fontSize: "0.78rem", color: color || C.text, wordBreak: "break-all", lineHeight: 1.6 }}>{value}</div>
    </div>
  );

  return (
    <div style={{ padding: "24px", overflowY: "auto", height: "100%", scrollbarWidth: "thin", scrollbarColor: "rgba(127,216,50,0.12) transparent" }}>

      {/* Type + badge */}
      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px" }}>
        <span style={{ fontSize: "0.6rem", letterSpacing: "0.15em", color: tyM.color, fontFamily: "'DM Mono',monospace", padding: "3px 10px", border: `1px solid ${tyM.color}35`, borderRadius: "4px", background: `${tyM.color}08` }}>
          {tyM.symbol} {tyM.icon}
        </span>
        <span style={{ fontSize: "0.6rem", letterSpacing: "0.12em", color: tm.color, fontFamily: "'DM Mono',monospace", padding: "3px 10px", border: `1px solid ${tm.border}`, borderRadius: "4px", background: tm.bg, fontWeight: 700 }}>
          {tm.label}
        </span>
      </div>

      {/* Indicator */}
      <div style={{ fontFamily: "'DM Mono',monospace", fontSize: "0.82rem", color: C.cyan, wordBreak: "break-all", lineHeight: 1.7, marginBottom: "20px", padding: "12px 14px", background: "rgba(0,200,255,0.04)", borderLeft: `2px solid rgba(0,200,255,0.3)`, borderRadius: "0 6px 6px 0" }}>
        {ioc.indicator}
      </div>

      {/* Score block */}
      <div style={{
        display: "flex", alignItems: "center", gap: "18px",
        padding: "16px", background: C.surface,
        border: `1px solid ${scC}20`, borderRadius: "10px", marginBottom: "20px",
      }}>
        <ScoreRing score={sc} size={68} />
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: "0.55rem", letterSpacing: "0.18em", color: C.textFaint, marginBottom: "8px", fontFamily: "'DM Mono',monospace" }}>RISK SCORE</div>
          <div style={{ height: "4px", background: "rgba(255,255,255,0.04)", borderRadius: "2px", overflow: "hidden" }}>
            <div style={{ height: "100%", width: `${sc}%`, background: `linear-gradient(90deg,${scC}55,${scC})`, borderRadius: "2px", transition: "width 0.8s ease" }} />
          </div>
          <div style={{ marginTop: "8px", fontFamily: "'Syne',sans-serif", fontSize: "1.4rem", fontWeight: 800, color: scC }}>{sc}<span style={{ fontSize: "0.7rem", fontFamily: "'DM Mono',monospace", color: C.textFaint, fontWeight: 400 }}>/100</span></div>
        </div>
      </div>

      <Field label="VERDICT" value={(ioc.final_verdict || "UNKNOWN").toUpperCase()} color={tm.color} />
      <Field label="DATE D'ANALYSE" value={ioc.created_at?.slice(0, 16)} />

      <div style={{ marginTop: "4px" }}>
        <span style={{ fontFamily: "'DM Mono',monospace", fontSize: "0.6rem", padding: "3px 10px", background: "rgba(0,200,255,0.05)", border: "1px solid rgba(0,200,255,0.15)", borderRadius: "4px", color: C.cyan }}>
          {ioc.is_favorite ? "⭐ FAVORI" : "☆ NON FAVORI"}
        </span>
      </div>
    </div>
  );
}

// ── Topbar Button ─────────────────────────────────────────────────────────────
function TopBtn({ label, onClick, icon }) {
  return (
    <button onClick={onClick} style={{
      background: "transparent", border: `1px solid ${C.border}`,
      borderRadius: "6px", padding: "6px 12px",
      color: C.textMuted, fontSize: "0.6rem", letterSpacing: "0.12em",
      cursor: "pointer", fontFamily: "'DM Mono',monospace", transition: "all 0.18s",
      display: "flex", alignItems: "center", gap: "5px",
    }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = C.borderHover; e.currentTarget.style.color = C.green; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.textMuted; }}
    >
      {icon && <span style={{ fontSize: "0.65rem" }}>{icon}</span>}
      {label}
    </button>
  );
}

// ── Main Dashboard ────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [selectedIOC,    setSelectedIOC]    = useState(null);
  const [filter,         setFilter]         = useState("all");
  const [scans,          setScans]          = useState([]);
  const [stats,          setStats]          = useState(null);
  const [loading,        setLoading]        = useState(true);
  const [resetRequests,  setResetRequests]  = useState([]);
  const [approveModal,   setApproveModal]   = useState(null);
  const [newPassword,    setNewPassword]    = useState("");
  const [approveLoading, setApproveLoading] = useState(false);
  const navigate = useNavigate();
  const { isAdmin } = useAuth();

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const [histRes, statsRes] = await Promise.all([historyApi.get({ limit: 100 }), statsApi.get()]);
        setScans(histRes.results || []);
        setStats(statsRes);
      } catch (e) { console.error(e); }
      finally { setLoading(false); }
    })();
  }, []);

  useEffect(() => {
    if (isAdmin) authApi.getResetRequests().then(setResetRequests).catch(() => {});
  }, [isAdmin]);

  const pendingResets = resetRequests.filter(r => r.status === "pending");

  const handleApprove = async () => {
    if (!newPassword || newPassword.length < 6) return;
    setApproveLoading(true);
    try {
      await authApi.approveReset(approveModal.id, newPassword);
      setResetRequests(prev => prev.map(r => r.id === approveModal.id ? { ...r, status: "approved" } : r));
      setApproveModal(null); setNewPassword("");
    } catch (e) { console.error(e); }
    finally { setApproveLoading(false); }
  };

  const handleReject = async (id) => {
    try {
      await authApi.rejectReset(id);
      setResetRequests(prev => prev.map(r => r.id === id ? { ...r, status: "rejected" } : r));
    } catch (e) { console.error(e); }
  };

  const filtered = filter === "all" ? scans : scans.filter(d => d.final_verdict === filter || d.ioc_type === filter);
  const totalScans    = stats?.total_scans         || scans.length;
  const avgScore      = stats?.avg_risk_score       || 0;
  const criticalCount = stats?.by_verdict?.critical || 0;
  const highCount     = stats?.by_verdict?.high     || 0;
  const lowCount      = stats?.by_verdict?.low      || 0;

  if (loading) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: C.bg, fontFamily: "'DM Mono',monospace" }}>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: "16px" }}>
        <div style={{ width: "32px", height: "32px", border: `2px solid ${C.green}30`, borderTop: `2px solid ${C.green}`, borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
        <span style={{ fontSize: "0.6rem", letterSpacing: "0.25em", color: C.textFaint }}>CHARGEMENT...</span>
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: C.bg, color: C.text, overflow: "hidden", fontFamily: "'DM Mono',monospace" }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Mono:wght@400;500&display=swap');
        ::-webkit-scrollbar{width:3px} ::-webkit-scrollbar-track{background:transparent} ::-webkit-scrollbar-thumb{background:rgba(127,216,50,0.15);border-radius:2px}
        @keyframes spin{to{transform:rotate(360deg)}}
      `}</style>

      {/* Grid bg */}
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        backgroundImage: `linear-gradient(rgba(127,216,50,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(127,216,50,0.02) 1px,transparent 1px)`,
        backgroundSize: "40px 40px" }} />

      {/* ── TOPBAR ── */}
      <div style={{
        height: "56px", display: "flex", alignItems: "center", padding: "0 24px", gap: "10px",
        borderBottom: `1px solid ${C.border}`,
        background: "rgba(4,10,18,0.98)",
        backdropFilter: "blur(20px)", flexShrink: 0, zIndex: 20, position: "relative",
      }}>
        <TopBtn label="← CHAT" onClick={() => navigate("/chat")} />

        <div style={{ width: "1px", height: "20px", background: C.border, margin: "0 4px" }} />

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={C.green} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/>
          </svg>
          <span style={{ color: C.green, fontSize: "0.75rem", fontWeight: 700, letterSpacing: "0.2em" }}>DASHBOARD</span>
          <span style={{ color: C.textFaint, fontSize: "0.6rem", letterSpacing: "0.12em" }}>/ THREAT INTELLIGENCE</span>
        </div>

        <div style={{ flex: 1 }} />

        {["csv", "json", "pdf"].map(fmt => (
          <TopBtn key={fmt} label={fmt.toUpperCase()} onClick={() => exportApi[fmt]()} icon="↓" />
        ))}

        {isAdmin && pendingResets.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: "6px", padding: "5px 12px", background: "rgba(249,115,22,0.08)", border: "1px solid rgba(249,115,22,0.25)", borderRadius: "6px" }}>
            <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#f97316", animation: "spin 2s linear infinite" }} />
            <span style={{ fontSize: "0.58rem", color: "#f97316", letterSpacing: "0.12em" }}>{pendingResets.length} RESET{pendingResets.length > 1 ? "S" : ""}</span>
          </div>
        )}
      </div>

      {/* ── STATS ROW ── */}
      <div style={{
        padding: "16px 24px", borderBottom: `1px solid ${C.border}`,
        display: "flex", gap: "10px", flexShrink: 0, flexWrap: "wrap",
        zIndex: 1, position: "relative",
      }}>
        <StatCard label="Total IOCs"  value={totalScans}    color={C.cyan} />
        <StatCard label="Critiques"   value={criticalCount} color="#ef4444" />
        <StatCard label="Élevés"      value={highCount}     color="#f97316" />
        <StatCard label="Score moyen" value={Math.round(avgScore)} color="#eab308" />
        <StatCard label="Faibles"     value={lowCount}      color="#22c55e" />
        <ThreatBar data={scans} />
      </div>

      {/* ── BODY ── */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden", zIndex: 1, position: "relative" }}>

        {/* ── IOC List ── */}
        <div style={{ flex: "0 0 48%", borderRight: `1px solid ${C.border}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>

          {/* Filters */}
          <div style={{
            padding: "10px 16px", borderBottom: `1px solid ${C.border}`,
            display: "flex", gap: "5px", flexWrap: "wrap", flexShrink: 0, alignItems: "center",
            background: "rgba(4,10,18,0.7)",
          }}>
            {FILTERS.map(f => {
              const active = filter === f.key;
              const color = THREAT[f.key]?.color || IOC_TYPE[f.key]?.color || C.green;
              return (
                <button key={f.key} onClick={() => setFilter(f.key)} style={{
                  padding: "3px 10px",
                  background: active ? `${color}10` : "transparent",
                  border: `1px solid ${active ? color + "50" : C.border}`,
                  borderRadius: "4px",
                  color: active ? color : C.textMuted,
                  fontSize: "0.58rem", letterSpacing: "0.12em",
                  cursor: "pointer", fontFamily: "'DM Mono',monospace", transition: "all 0.15s",
                }}>
                  {f.label}
                </button>
              );
            })}
            <span style={{ marginLeft: "auto", fontSize: "0.58rem", color: C.textFaint, letterSpacing: "0.1em" }}>
              {filtered.length} IOC{filtered.length > 1 ? "s" : ""}
            </span>
          </div>

          {/* List */}
          <div style={{ flex: 1, overflowY: "auto", padding: "10px 12px" }}>
            {filtered.length === 0 ? (
              <div style={{ textAlign: "center", color: C.textFaint, fontSize: "0.6rem", letterSpacing: "0.2em", marginTop: "48px" }}>AUCUN IOC</div>
            ) : filtered.map(ioc => (
              <IOCRow key={ioc.id} ioc={ioc} selected={selectedIOC?.id === ioc.id} onSelect={setSelectedIOC} />
            ))}
          </div>
        </div>

        {/* ── Detail Panel ── */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{
            padding: "12px 24px", borderBottom: `1px solid ${C.border}`,
            background: "rgba(4,10,18,0.7)", flexShrink: 0,
            display: "flex", alignItems: "center", justifyContent: "space-between",
          }}>
            <span style={{ fontSize: "0.58rem", letterSpacing: "0.2em", color: C.textFaint }}>DÉTAIL IOC</span>
            {selectedIOC && (
              <button onClick={() => setSelectedIOC(null)} style={{
                background: "transparent", border: "none", cursor: "pointer",
                color: C.textFaint, fontSize: "0.6rem", fontFamily: "'DM Mono',monospace",
                letterSpacing: "0.1em", padding: 0, transition: "color 0.15s",
              }}
                onMouseEnter={e => e.currentTarget.style.color = C.text}
                onMouseLeave={e => e.currentTarget.style.color = C.textFaint}
              >✕ FERMER</button>
            )}
          </div>
          <div style={{ flex: 1, overflow: "hidden" }}>
            <DetailPanel ioc={selectedIOC} />
          </div>
        </div>
      </div>

      {/* ── Reset Requests Panel ── */}
      {isAdmin && pendingResets.length > 0 && (
        <div style={{
          position: "fixed", bottom: "20px", right: "20px", zIndex: 50,
          width: "320px",
          background: "rgba(4,10,18,0.98)",
          border: "1px solid rgba(249,115,22,0.25)",
          borderRadius: "10px",
          padding: "16px",
          backdropFilter: "blur(20px)",
        }}>
          <div style={{ fontSize: "0.6rem", letterSpacing: "0.18em", color: "#f97316", marginBottom: "12px", fontFamily: "'DM Mono',monospace" }}>
            ⚠ DEMANDES RESET ({pendingResets.length})
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px", maxHeight: "200px", overflowY: "auto" }}>
            {pendingResets.map(r => (
              <div key={r.id} style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                padding: "8px 12px",
                background: "rgba(249,115,22,0.05)",
                border: "1px solid rgba(249,115,22,0.15)",
                borderRadius: "6px",
              }}>
                <span style={{ fontFamily: "'DM Mono',monospace", fontSize: "0.7rem", color: C.text, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.email}</span>
                <div style={{ display: "flex", gap: "6px", flexShrink: 0, marginLeft: "8px" }}>
                  <button onClick={() => { setApproveModal(r); setNewPassword(""); }}
                    style={{ padding: "4px 10px", background: "rgba(34,197,94,0.08)", border: "1px solid rgba(34,197,94,0.3)", color: "#22c55e", fontSize: "0.6rem", letterSpacing: "0.1em", cursor: "pointer", fontFamily: "'DM Mono',monospace", borderRadius: "4px" }}>
                    OK
                  </button>
                  <button onClick={() => handleReject(r.id)}
                    style={{ padding: "4px 10px", background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)", color: "#ef4444", fontSize: "0.6rem", letterSpacing: "0.1em", cursor: "pointer", fontFamily: "'DM Mono',monospace", borderRadius: "4px" }}>
                    ✕
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Approve Modal ── */}
      {approveModal && (
        <div style={{ position: "fixed", inset: 0, zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(4,10,18,0.9)", backdropFilter: "blur(12px)" }}
          onClick={() => setApproveModal(null)}>
          <div style={{
            width: "100%", maxWidth: "360px", margin: "0 16px",
            background: "rgba(6,14,26,0.99)",
            border: `1px solid ${C.green}25`,
            borderRadius: "12px", padding: "28px",
          }}
            onClick={e => e.stopPropagation()}>
            <div style={{ fontSize: "0.58rem", letterSpacing: "0.2em", color: C.green, marginBottom: "6px", fontFamily: "'DM Mono',monospace" }}>// RESET PASSWORD</div>
            <div style={{ fontFamily: "'Syne',sans-serif", fontSize: "1rem", fontWeight: 700, color: C.text, marginBottom: "20px" }}>{approveModal.email}</div>

            <div style={{ fontSize: "0.58rem", letterSpacing: "0.15em", color: C.textFaint, marginBottom: "6px", fontFamily: "'DM Mono',monospace" }}>NOUVEAU MOT DE PASSE</div>
            <input
              type="text"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              placeholder="min. 6 caractères"
              style={{
                width: "100%", boxSizing: "border-box", padding: "10px 14px",
                background: "rgba(127,216,50,0.03)", border: `1px solid ${C.border}`,
                borderRadius: "6px", color: C.text, fontSize: "0.82rem",
                fontFamily: "'DM Mono',monospace", outline: "none", marginBottom: "16px",
                transition: "border-color 0.2s",
              }}
              onFocus={e => e.target.style.borderColor = C.green + "50"}
              onBlur={e => e.target.style.borderColor = C.border}
            />

            <div style={{ display: "flex", gap: "10px" }}>
              <button onClick={handleApprove} disabled={approveLoading || newPassword.length < 6}
                style={{
                  flex: 1, padding: "10px",
                  background: newPassword.length >= 6 ? C.green : "rgba(127,216,50,0.1)",
                  border: "none", borderRadius: "6px",
                  color: newPassword.length >= 6 ? "#040a12" : C.textFaint,
                  fontSize: "0.65rem", letterSpacing: "0.15em",
                  cursor: newPassword.length < 6 ? "not-allowed" : "pointer",
                  fontFamily: "'DM Mono',monospace", fontWeight: 600, transition: "all 0.2s",
                }}>
                {approveLoading ? "..." : "CONFIRMER"}
              </button>
              <button onClick={() => setApproveModal(null)}
                style={{
                  padding: "10px 18px", background: "transparent",
                  border: `1px solid ${C.border}`, borderRadius: "6px",
                  color: C.textMuted, fontSize: "0.65rem", letterSpacing: "0.1em",
                  cursor: "pointer", fontFamily: "'DM Mono',monospace", transition: "all 0.2s",
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = C.borderHover; e.currentTarget.style.color = C.text; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.color = C.textMuted; }}
              >
                ANNULER
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}