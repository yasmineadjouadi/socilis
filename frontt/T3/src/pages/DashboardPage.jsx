import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { t } from "../components/chat/chatTheme";
import { historyApi, statsApi, exportApi, authApi } from "../services/api";
import { useAuth } from "../context/AuthContext";

const THREAT_META = {
  critical: { color: "#ef4444", label: "CRITIQUE", bg: "rgba(239,68,68,0.08)",  border: "rgba(239,68,68,0.35)"  },
  high:     { color: "#f97316", label: "ÉLEVÉ",    bg: "rgba(249,115,22,0.08)", border: "rgba(249,115,22,0.35)" },
  medium:   { color: "#eab308", label: "MOYEN",    bg: "rgba(234,179,8,0.08)",  border: "rgba(234,179,8,0.35)"  },
  low:      { color: "#22c55e", label: "FAIBLE",   bg: "rgba(34,197,94,0.08)",  border: "rgba(34,197,94,0.35)"  },
};

const TYPE_META = {
  ip:     { color: "#22d3ee", icon: "◈", label: "IP"     },
  hash:   { color: "#a78bfa", icon: "⬡", label: "HASH"   },
  domain: { color: "#fb923c", icon: "◎", label: "DOMAIN" },
  url:    { color: "#4ade80", icon: "⬔", label: "URL"    },
  mail:   { color: "#f472b6", icon: "✉", label: "MAIL"   },
  cve:    { color: "#ef4444", icon: "⚠", label: "CVE"    },
};

function scoreColor(s) {
  return s >= 80 ? "#ef4444" : s >= 60 ? "#f97316" : s >= 35 ? "#eab308" : "#22c55e";
}

function ScoreRing({ score, size = 72 }) {
  const r = 28, cx = size / 2, cy = size / 2;
  const circ = 2 * Math.PI * r;
  const dash  = (score / 100) * circ;
  const sc    = scoreColor(score);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="4" />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={sc} strokeWidth="4"
        strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`} opacity="0.9" />
      <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="middle"
        fill={sc} fontSize="13" fontWeight="700" fontFamily="JetBrains Mono,monospace">{score}</text>
    </svg>
  );
}

function ThreatBar({ data, darkMode }) {
  const th = t(darkMode);
  const byLevel = Object.entries(
    data.reduce((acc, d) => {
      const lvl = d.final_verdict || "unknown";
      acc[lvl] = (acc[lvl] || 0) + 1;
      return acc;
    }, {})
  );
  const total = data.length || 1;
  return (
    <div>
      <div style={{ display: "flex", height: "8px", borderRadius: "4px", overflow: "hidden", marginBottom: "10px" }}>
        {byLevel.map(([lvl, cnt]) => {
          const tm = THREAT_META[lvl] || { color: "#64748b" };
          return <div key={lvl} style={{ flex: cnt / total, background: tm.color, opacity: 0.8 }} title={`${lvl}: ${cnt}`} />;
        })}
      </div>
      <div style={{ display: "flex", gap: "14px", flexWrap: "wrap" }}>
        {byLevel.map(([lvl, cnt]) => {
          const tm = THREAT_META[lvl] || { color: "#64748b", label: lvl };
          return (
            <div key={lvl} style={{ display: "flex", alignItems: "center", gap: "5px" }}>
              <span style={{ width: "8px", height: "8px", borderRadius: "2px", background: tm.color, display: "inline-block", opacity: 0.8 }} />
              <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", color: th.textMuted, letterSpacing: "1px" }}>{tm.label || lvl} ({cnt})</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function IOCCard({ ioc, darkMode, selected, onSelect }) {
  const th  = t(darkMode);
  const tm  = THREAT_META[ioc.final_verdict] || THREAT_META.low;
  const tyM = TYPE_META[ioc.ioc_type] || { color: "#00a8ff", icon: "◆" };
  const sc  = ioc.risk_score || 0;
  return (
    <div
      onClick={() => onSelect(ioc)}
      style={{ padding: "14px 16px", background: selected ? (darkMode ? "rgba(0,168,255,0.06)" : "rgba(0,100,200,0.06)") : "transparent", border: `1px solid ${selected ? tm.border : "transparent"}`, borderRadius: "8px", cursor: "pointer", transition: "all 0.18s", marginBottom: "4px", display: "flex", alignItems: "center", gap: "14px" }}
      onMouseEnter={e => { if (!selected) e.currentTarget.style.background = darkMode ? "rgba(10,28,50,0.5)" : "rgba(220,237,255,0.5)"; }}
      onMouseLeave={e => { if (!selected) e.currentTarget.style.background = "transparent"; }}
    >
      <ScoreRing score={sc} size={56} />
      <div style={{ flex: 1, overflow: "hidden" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "4px" }}>
          <span style={{ color: tyM.color, fontSize: "11px" }}>{tyM.icon}</span>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", color: tyM.color, letterSpacing: "1.5px" }}>{(ioc.ioc_type || "").toUpperCase()}</span>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", padding: "1px 7px", background: tm.bg, border: `1px solid ${tm.border}`, color: tm.color, borderRadius: "3px", letterSpacing: "1px" }}>{tm.label}</span>
        </div>
        <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "11px", color: th.text, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: "4px" }}>{ioc.indicator}</div>
        <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", color: th.textFaint }}>{ioc.created_at?.slice(0, 16)}</div>
      </div>
      <span style={{ color: th.textFaint, fontSize: "12px", flexShrink: 0 }}>›</span>
    </div>
  );
}

function DetailPanel({ ioc, darkMode }) {
  const th = t(darkMode);
  if (!ioc) return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", gap: "12px" }}>
      <span style={{ fontSize: "32px", opacity: 0.15 }}>◈</span>
      <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", letterSpacing: "3px", color: th.textFaint }}>SÉLECTIONNER UN IOC</span>
    </div>
  );

  const tm  = THREAT_META[ioc.final_verdict] || THREAT_META.low;
  const tyM = TYPE_META[ioc.ioc_type] || { color: "#00a8ff", icon: "◆" };
  const sc  = ioc.risk_score || 0;
  const scC = scoreColor(sc);

  const Field = ({ label, value, color }) => (
    <div style={{ marginBottom: "10px" }}>
      <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "8px", letterSpacing: "2px", color: th.textFaint, marginBottom: "3px" }}>{label}</div>
      <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "10px", color: color || th.text, wordBreak: "break-all", lineHeight: "1.5" }}>{value}</div>
    </div>
  );

  return (
    <div style={{ padding: "20px", overflowY: "auto", height: "100%", scrollbarWidth: "thin", scrollbarColor: "rgba(0,168,255,0.18) transparent" }}>
      {/* Header */}
      <div style={{ marginBottom: "20px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "10px" }}>
          <span style={{ fontSize: "20px", color: tyM.color }}>{tyM.icon}</span>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", letterSpacing: "2px", color: tyM.color }}>{(ioc.ioc_type || "").toUpperCase()}</span>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", padding: "2px 10px", background: tm.bg, border: `1px solid ${tm.border}`, color: tm.color, borderRadius: "3px", letterSpacing: "1.5px", fontWeight: "700" }}>{tm.label}</span>
        </div>

        <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "12px", color: "#00a8ff", wordBreak: "break-all", lineHeight: "1.6", marginBottom: "14px" }}>{ioc.indicator}</div>

        {/* Score */}
        <div style={{ display: "flex", alignItems: "center", gap: "16px", padding: "14px 16px", background: darkMode ? "rgba(4,12,24,0.8)" : "rgba(245,250,255,0.9)", border: `1px solid ${scC}25`, borderRadius: "8px", marginBottom: "14px" }}>
          <ScoreRing score={sc} size={68} />
          <div style={{ flex: 1 }}>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "8px", letterSpacing: "2px", color: th.textFaint, marginBottom: "6px" }}>RISK SCORE</div>
            <div style={{ height: "4px", background: "rgba(255,255,255,0.05)", borderRadius: "2px", overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${sc}%`, background: `linear-gradient(90deg,${scC}66,${scC})`, borderRadius: "2px", transition: "width 0.8s ease" }} />
            </div>
          </div>
        </div>

        {/* Verdict */}
        <div style={{ padding: "12px 14px", background: darkMode ? "rgba(0,168,255,0.03)" : "rgba(0,100,200,0.03)", borderLeft: "2px solid rgba(0,168,255,0.3)", borderRadius: "0 6px 6px 0", marginBottom: "16px" }}>
          <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "8px", letterSpacing: "2px", color: th.textFaint, marginBottom: "6px" }}>VERDICT</div>
          <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "10px", color: tm.color, fontWeight: "700" }}>{(ioc.final_verdict || "UNKNOWN").toUpperCase()}</div>
        </div>

        <Field label="DATE" value={ioc.created_at?.slice(0, 16)} />

        <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", padding: "2px 10px", background: "rgba(0,168,255,0.07)", border: "1px solid rgba(0,168,255,0.2)", borderRadius: "3px", color: "#00a8ff" }}>
            {ioc.is_favorite ? "⭐ FAVORI" : "☆ NON FAVORI"}
          </span>
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const [darkMode,       setDarkMode]       = useState(true);
  const [selectedIOC,    setSelectedIOC]    = useState(null);
  const [filter,         setFilter]         = useState("all");
  const [scans,          setScans]          = useState([]);
  const [stats,          setStats]          = useState(null);
  const [loading,        setLoading]        = useState(true);
  const [resetRequests,  setResetRequests]  = useState([]);
  const [approveModal,   setApproveModal]   = useState(null); // { id, email }
  const [newPassword,    setNewPassword]    = useState("");
  const [approveLoading, setApproveLoading] = useState(false);
  const navigate = useNavigate();
  const th = t(darkMode);
  const { isAdmin } = useAuth();

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const [histRes, statsRes] = await Promise.all([
          historyApi.get({ limit: 100 }),
          statsApi.get(),
        ]);
        setScans(histRes.results || []);
        setStats(statsRes);
      } catch (e) {
        console.error("Dashboard load error:", e);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  useEffect(() => {
    if (!isAdmin) return;
    authApi.getResetRequests().then(setResetRequests).catch(() => {});
  }, [isAdmin]);

  const pendingResets = resetRequests.filter(r => r.status === "pending");

  const handleApprove = async () => {
    if (!newPassword || newPassword.length < 6) return;
    setApproveLoading(true);
    try {
      await authApi.approveReset(approveModal.id, newPassword);
      setResetRequests(prev => prev.map(r => r.id === approveModal.id ? { ...r, status: "approved" } : r));
      setApproveModal(null);
      setNewPassword("");
    } catch (e) {
      console.error(e);
    } finally {
      setApproveLoading(false);
    }
  };

  const handleReject = async (id) => {
    try {
      await authApi.rejectReset(id);
      setResetRequests(prev => prev.map(r => r.id === id ? { ...r, status: "rejected" } : r));
    } catch (e) {
      console.error(e);
    }
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

  const filtered = filter === "all"
    ? scans
    : scans.filter(d => d.final_verdict === filter || d.ioc_type === filter);

  const totalScans    = stats?.total_scans        || scans.length;
  const avgScore      = stats?.avg_risk_score      || 0;
  const criticalCount = stats?.by_verdict?.critical || 0;
  const highCount     = stats?.by_verdict?.high     || 0;
  const lowCount      = stats?.by_verdict?.low      || 0;

  if (loading) return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100vh", background: "#050b12", color: "#00a8ff", fontFamily: "'JetBrains Mono',monospace", fontSize: "12px", letterSpacing: "3px" }}>
      CHARGEMENT...
    </div>
  );

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100vh", background: th.bg, color: th.text, overflow: "hidden", fontFamily: "'JetBrains Mono',monospace" }}>
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0, backgroundImage: darkMode ? `linear-gradient(rgba(0,168,255,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,168,255,0.02) 1px,transparent 1px)` : "none", backgroundSize: "40px 40px" }} />

      {/* ── TOPBAR ── */}
      <div style={{ height: "54px", display: "flex", alignItems: "center", padding: "0 24px", gap: "12px", borderBottom: `1px solid ${th.border}`, background: darkMode ? "rgba(5,11,18,0.98)" : "rgba(240,246,255,0.98)", backdropFilter: "blur(10px)", flexShrink: 0, zIndex: 20, position: "relative" }}>
        <button onClick={() => navigate("/chat")} style={{ background: "transparent", border: `1px solid ${th.border}`, borderRadius: "5px", padding: "5px 12px", color: th.textMuted, fontSize: "9px", letterSpacing: "2px", cursor: "pointer", fontFamily: "'JetBrains Mono',monospace", transition: "all 0.2s" }}
          onMouseEnter={e => { e.currentTarget.style.borderColor = th.borderActive; e.currentTarget.style.color = th.accent; }}
          onMouseLeave={e => { e.currentTarget.style.borderColor = th.border;       e.currentTarget.style.color = th.textMuted; }}>
          ← CHAT
        </button>

        <div style={{ width: "1px", height: "22px", background: th.border }} />

        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <span style={{ color: th.accent, fontSize: "13px" }}>◈</span>
          <span style={{ color: th.accent, fontSize: "11px", fontWeight: "700", letterSpacing: "3px" }}>DASHBOARD</span>
          <span style={{ color: th.textFaint, fontSize: "9px", letterSpacing: "2px" }}>/ THREAT INTELLIGENCE</span>
        </div>

        <div style={{ flex: 1 }} />

        {/* Export buttons */}
        {["csv", "json", "pdf"].map(fmt => (
          <button key={fmt} onClick={() => exportApi[fmt]()} style={{ background: "transparent", border: `1px solid ${th.border}`, borderRadius: "5px", padding: "5px 10px", color: th.textMuted, fontSize: "9px", letterSpacing: "1.5px", cursor: "pointer", fontFamily: "'JetBrains Mono',monospace", transition: "all 0.2s" }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = th.borderActive; e.currentTarget.style.color = th.accent; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = th.border;       e.currentTarget.style.color = th.textMuted; }}>
            ↓ {fmt.toUpperCase()}
          </button>
        ))}

        <button onClick={() => setDarkMode(v => !v)} style={{ background: "transparent", border: `1px solid ${th.border}`, borderRadius: "5px", padding: "5px 10px", color: th.textMuted, fontSize: "12px", cursor: "pointer", transition: "all 0.2s" }}
          onMouseEnter={e => e.currentTarget.style.borderColor = th.borderActive}
          onMouseLeave={e => e.currentTarget.style.borderColor = th.border}>
          {darkMode ? "☀" : "◑"}
        </button>
      </div>

      {/* ── STATS ROW ── */}
      <div style={{ padding: "16px 24px", borderBottom: `1px solid ${th.border}`, display: "flex", gap: "12px", flexShrink: 0, flexWrap: "wrap", zIndex: 1, position: "relative" }}>
        {[
          { label: "TOTAL IOCs",  value: totalScans,    color: "#00a8ff" },
          { label: "CRITIQUES",   value: criticalCount, color: "#ef4444" },
          { label: "ÉLEVÉS",      value: highCount,     color: "#f97316" },
          { label: "SCORE MOYEN", value: avgScore,      color: "#eab308" },
          { label: "FAIBLES",     value: lowCount,      color: "#22c55e" },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ display: "flex", flexDirection: "column", gap: "5px", padding: "12px 18px", background: darkMode ? "rgba(6,16,28,0.92)" : "rgba(255,255,255,0.95)", border: `1px solid ${color}20`, borderRadius: "8px", flex: "1 1 100px", minWidth: "100px", boxShadow: `0 0 20px ${color}08` }}>
            <span style={{ fontSize: "8px", letterSpacing: "2px", color: th.textFaint }}>{label}</span>
            <span style={{ fontSize: "28px", fontWeight: "700", color, lineHeight: 1 }}>{value}</span>
          </div>
        ))}

        <div style={{ flex: "2 1 220px", padding: "12px 18px", background: darkMode ? "rgba(6,16,28,0.92)" : "rgba(255,255,255,0.95)", border: `1px solid ${th.border}`, borderRadius: "8px" }}>
          <div style={{ fontSize: "8px", letterSpacing: "2px", color: th.textFaint, marginBottom: "10px" }}>RÉPARTITION DES MENACES</div>
          <ThreatBar data={scans} darkMode={darkMode} />
        </div>
      </div>

      {/* ── BODY ── */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden", zIndex: 1, position: "relative" }}>

        {/* Left: IOC list */}
        <div style={{ flex: "0 0 48%", borderRight: `1px solid ${th.border}`, display: "flex", flexDirection: "column", overflow: "hidden" }}>

          {/* Filters */}
          <div style={{ padding: "10px 16px", borderBottom: `1px solid ${th.border}`, display: "flex", gap: "5px", flexWrap: "wrap", flexShrink: 0, background: darkMode ? "rgba(5,11,18,0.6)" : "rgba(240,246,255,0.6)" }}>
            {FILTERS.map(f => {
              const active = filter === f.key;
              const tColor = f.key === "all" ? th.accent : THREAT_META[f.key]?.color || TYPE_META[f.key]?.color || th.accent;
              return (
                <button key={f.key} onClick={() => setFilter(f.key)} style={{ padding: "3px 10px", background: active ? `${tColor}12` : "transparent", border: `1px solid ${active ? tColor : th.border}`, borderRadius: "3px", color: active ? tColor : th.textMuted, fontSize: "8px", letterSpacing: "1.5px", cursor: "pointer", fontFamily: "'JetBrains Mono',monospace", transition: "all 0.15s" }}>
                  {f.label}
                </button>
              );
            })}
            <span style={{ marginLeft: "auto", fontSize: "8px", color: th.textFaint, alignSelf: "center", letterSpacing: "1px" }}>{filtered.length} IOC{filtered.length > 1 ? "s" : ""}</span>
          </div>

          {/* List */}
          <div style={{ flex: 1, overflowY: "auto", padding: "10px 12px", scrollbarWidth: "thin", scrollbarColor: "rgba(0,168,255,0.18) transparent" }}>
            {filtered.length === 0 ? (
              <div style={{ textAlign: "center", color: th.textFaint, fontSize: "9px", letterSpacing: "2px", marginTop: "40px" }}>AUCUN IOC</div>
            ) : (
              filtered.map(ioc => (
                <IOCCard key={ioc.id} ioc={ioc} darkMode={darkMode} selected={selectedIOC?.id === ioc.id} onSelect={setSelectedIOC} />
              ))
            )}
          </div>
        </div>

        {/* Right: Detail */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ padding: "10px 20px", borderBottom: `1px solid ${th.border}`, flexShrink: 0, background: darkMode ? "rgba(5,11,18,0.6)" : "rgba(240,246,255,0.6)" }}>
            <span style={{ fontSize: "8px", letterSpacing: "3px", color: th.textFaint }}>DÉTAIL IOC</span>
          </div>
          <div style={{ flex: 1, overflow: "hidden" }}>
            <DetailPanel ioc={selectedIOC} darkMode={darkMode} />
          </div>
        </div>
      </div>

      <style>{`
        ::-webkit-scrollbar { width: 3px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(0,168,255,0.18); border-radius: 2px; }
      `}</style>

      {/* ── RESET REQUESTS PANEL (superadmin only) ── */}
      {isAdmin && pendingResets.length > 0 && (
        <div style={{
          position: "fixed", bottom: "20px", right: "20px", zIndex: 50,
          width: "320px", background: "rgba(4,16,32,0.97)",
          border: "1px solid rgba(255,165,0,0.35)",
          boxShadow: "0 0 30px rgba(255,165,0,0.12)",
          padding: "16px",
        }}>
          <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", letterSpacing: "2px", color: "#f97316", marginBottom: "10px" }}>
            ⚠ DEMANDES RESET MOT DE PASSE ({pendingResets.length})
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "8px", maxHeight: "200px", overflowY: "auto" }}>
            {pendingResets.map(r => (
              <div key={r.id} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "8px 10px", background: "rgba(249,115,22,0.06)", border: "1px solid rgba(249,115,22,0.20)" }}>
                <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "10px", color: "#c8dff0", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.email}</span>
                <div style={{ display: "flex", gap: "6px", flexShrink: 0 }}>
                  <button onClick={() => { setApproveModal(r); setNewPassword(""); }}
                    style={{ padding: "3px 8px", background: "rgba(34,197,94,0.12)", border: "1px solid rgba(34,197,94,0.4)", color: "#22c55e", fontSize: "8px", letterSpacing: "1px", cursor: "pointer", fontFamily: "'JetBrains Mono',monospace" }}>
                    ✓ OK
                  </button>
                  <button onClick={() => handleReject(r.id)}
                    style={{ padding: "3px 8px", background: "rgba(239,68,68,0.10)", border: "1px solid rgba(239,68,68,0.35)", color: "#ef4444", fontSize: "8px", letterSpacing: "1px", cursor: "pointer", fontFamily: "'JetBrains Mono',monospace" }}>
                    ✕
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── APPROVE MODAL ── */}
      {approveModal && (
        <div style={{ position: "fixed", inset: 0, zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center", background: "rgba(2,11,24,0.85)", backdropFilter: "blur(8px)" }}
          onClick={() => setApproveModal(null)}>
          <div style={{ width: "100%", maxWidth: "360px", margin: "0 16px", background: "rgba(4,16,32,0.98)", border: "1px solid rgba(127,216,50,0.25)", padding: "28px 28px" }}
            onClick={e => e.stopPropagation()}>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", letterSpacing: "2px", color: "#7FD832", marginBottom: "6px" }}>// RESET PASSWORD</div>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "13px", color: "#c8dff0", marginBottom: "18px" }}>{approveModal.email}</div>
            <div style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: "9px", letterSpacing: "1px", color: "rgba(127,216,50,0.7)", marginBottom: "6px" }}>NOUVEAU MOT DE PASSE</div>
            <input
              type="text"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              placeholder="min. 6 caractères"
              style={{ width: "100%", boxSizing: "border-box", padding: "8px 12px", background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.2)", color: "#c8dff0", fontSize: "13px", fontFamily: "'JetBrains Mono',monospace", outline: "none", marginBottom: "16px" }}
            />
            <div style={{ display: "flex", gap: "10px" }}>
              <button onClick={handleApprove} disabled={approveLoading || newPassword.length < 6}
                style={{ flex: 1, padding: "8px", background: "rgba(127,216,50,0.10)", border: "1px solid #7FD832", color: "#7FD832", fontSize: "9px", letterSpacing: "2px", cursor: newPassword.length < 6 ? "not-allowed" : "pointer", fontFamily: "'JetBrains Mono',monospace", opacity: newPassword.length < 6 ? 0.5 : 1 }}>
                {approveLoading ? "..." : "CONFIRMER"}
              </button>
              <button onClick={() => setApproveModal(null)}
                style={{ padding: "8px 16px", background: "transparent", border: "1px solid rgba(255,255,255,0.15)", color: "#5a80a0", fontSize: "9px", cursor: "pointer", fontFamily: "'JetBrains Mono',monospace" }}>
                ANNULER
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}