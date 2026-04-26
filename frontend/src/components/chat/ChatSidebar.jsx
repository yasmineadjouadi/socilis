import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { t } from "./ChatTheme";
import api from "../../api/api";

// ── Helpers ───────────────────────────────────────────────────

function formatDate(dateStr) {
  if (!dateStr) return "";
  const date = new Date(dateStr);
  const now  = new Date();
  const diff = Math.floor((now - date) / (1000 * 60 * 60 * 24));
  if (diff === 0) return "Aujourd'hui";
  if (diff === 1) return "Hier";
  if (diff < 7)  return `Il y a ${diff} jours`;
  return date.toLocaleDateString("fr-FR", { day: "2-digit", month: "short" });
}

function formatPreview(scan) {
  const verdict = scan.final_verdict || scan.risk_level || "—";
  const score   = scan.risk_score != null ? `Score: ${scan.risk_score}/100` : "";
  return [score, verdict].filter(Boolean).join(" · ");
}

function formatTitle(scan) {
  const type      = scan.ioc_type ? scan.ioc_type.toUpperCase() : "";
  const indicator = scan.indicator || "";
  const short     = indicator.length > 20 ? indicator.slice(0, 20) + "…" : indicator;
  return type ? `${type} ${short}` : short;
}

// ── Composant ─────────────────────────────────────────────────

export default function ChatSidebar({ open, darkMode, selectedChat, onSelectChat, onNewChat }) {
  const th       = t(darkMode);
  const navigate = useNavigate();

  const [history,  setHistory]  = useState([]);
  const [search,   setSearch]   = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState(null);

  // ── Charger l'historique depuis le backend ─────────────────
  const fetchHistory = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await api.get("/history/", { params: { limit: 50 } });
      setHistory(data.results || []);
    } catch (err) {
      setError("Impossible de charger l'historique");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) fetchHistory();
  }, [open, fetchHistory]);

  // ── Recherche : locale si < 3 chars, API sinon ─────────────
  useEffect(() => {
    if (search.length < 3) {
      if (search.length === 0) fetchHistory();
      return;
    }
    const timer = setTimeout(async () => {
      setLoading(true);
      try {
        const { data } = await api.get("/history/search", { params: { q: search } });
        setHistory(data.results || []);
      } catch {
        setError("Erreur de recherche");
      } finally {
        setLoading(false);
      }
    }, 400); // debounce 400ms
    return () => clearTimeout(timer);
  }, [search]);

  // ── Filtrage local pour < 3 chars ──────────────────────────
  const filtered = search.length > 0 && search.length < 3
    ? history.filter(s =>
        (s.indicator || "").toLowerCase().includes(search.toLowerCase()) ||
        (s.ioc_type  || "").toLowerCase().includes(search.toLowerCase())
      )
    : history;

  // ── Highlight ──────────────────────────────────────────────
  const highlight = (text) => {
    if (!search || !text) return text;
    const idx = text.toLowerCase().indexOf(search.toLowerCase());
    if (idx === -1) return text;
    return (
      <>
        {text.slice(0, idx)}
        <mark style={{ background: `${th.accent}30`, color: th.accent, borderRadius: "2px", padding: "0 1px" }}>
          {text.slice(idx, idx + search.length)}
        </mark>
        {text.slice(idx + search.length)}
      </>
    );
  };

  // ── Render ─────────────────────────────────────────────────
  return (
    <div style={{
      width: open ? "260px" : "0px",
      minWidth: open ? "260px" : "0px",
      background: th.sidebar,
      borderRight: `1px solid ${th.border}`,
      display: "flex", flexDirection: "column",
      overflow: "hidden", transition: "all 0.3s ease",
    }}>
      {open && (
        <>
          {/* Logo */}
          <div style={{ padding: "20px 16px", borderBottom: `1px solid ${th.border}`, display: "flex", alignItems: "center", gap: "10px" }}>
            <img src="/logo socilis.webp" alt="SOCILIS" style={{ width: "32px", height: "32px", objectFit: "contain" }} />
            <div>
              <div style={{ fontWeight: "700", fontSize: "14px", letterSpacing: "2px", fontFamily: "'JetBrains Mono', monospace" }}>
                <span style={{ color: th.text }}>SOC</span>
                <span style={{ color: "#7FD832" }}>ILIS</span>
              </div>
              <div style={{ color: th.textMuted, fontSize: "9px", letterSpacing: "2px", fontFamily: "'JetBrains Mono', monospace" }}>
                THREAT INTELLIGENCE
              </div>
            </div>
          </div>

          {/* Boutons */}
          <div style={{ padding: "12px", display: "flex", flexDirection: "column", gap: "6px" }}>
            <button onClick={onNewChat} style={{
              width: "100%", padding: "8px", background: "transparent",
              border: `1px dashed ${th.borderActive}`, borderRadius: "6px",
              color: th.accent, fontSize: "11px", letterSpacing: "2px",
              cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", transition: "all 0.2s",
            }}
              onMouseEnter={e => e.currentTarget.style.background = th.accentSubtle}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >+ NOUVELLE ANALYSE</button>

            <button onClick={() => navigate("/dashboard")} style={{
              width: "100%", padding: "8px", background: "transparent",
              border: "1px solid rgba(34,197,94,0.35)", borderRadius: "6px",
              color: "#22c55e", fontSize: "11px", letterSpacing: "2px",
              cursor: "pointer", fontFamily: "'JetBrains Mono', monospace", transition: "all 0.2s",
              display: "flex", alignItems: "center", justifyContent: "center", gap: "6px",
            }}
              onMouseEnter={e => e.currentTarget.style.background = "rgba(34,197,94,0.07)"}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}
            >◈ DASHBOARD</button>
          </div>

          {/* Barre de recherche */}
          <div style={{ padding: "0 12px 10px" }}>
            <div style={{
              display: "flex", alignItems: "center", gap: "6px",
              background: th.input, border: `1px solid ${th.border}`,
              borderRadius: "6px", padding: "6px 10px", transition: "border-color 0.2s",
            }}
              onFocusCapture={e => e.currentTarget.style.borderColor = th.borderActive}
              onBlurCapture={e => e.currentTarget.style.borderColor = th.border}
            >
              <span style={{ color: th.textFaint, fontSize: "11px", flexShrink: 0 }}>🔍</span>
              <input
                type="text" value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Rechercher..."
                style={{
                  flex: 1, background: "transparent", border: "none", outline: "none",
                  color: th.text, fontSize: "10px", letterSpacing: "0.5px",
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              />
              {search && (
                <button onClick={() => setSearch("")} style={{ background: "transparent", border: "none", color: th.textFaint, cursor: "pointer", fontSize: "12px", lineHeight: 1, padding: 0 }}>×</button>
              )}
            </div>
          </div>

          {/* Liste historique */}
          <div style={{ flex: 1, overflowY: "auto", padding: "0 8px" }}>
            <div style={{
              fontSize: "9px", color: th.textFaint, letterSpacing: "3px",
              padding: "4px 8px 6px", fontFamily: "'JetBrains Mono', monospace",
              display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span>HISTORIQUE</span>
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                {search && <span style={{ color: th.accent, fontSize: "8px" }}>{filtered.length} résultat{filtered.length !== 1 ? "s" : ""}</span>}
                <button onClick={fetchHistory} title="Rafraîchir" style={{
                  background: "transparent", border: "none", color: th.textFaint,
                  cursor: "pointer", fontSize: "10px", padding: "0 2px",
                }}>↻</button>
              </div>
            </div>

            {/* États */}
            {loading && (
              <div style={{ padding: "20px 10px", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", color: th.textFaint, letterSpacing: "1px" }}>
                Chargement…
              </div>
            )}

            {error && !loading && (
              <div style={{ padding: "12px 10px", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: "9px", color: "#f87171", letterSpacing: "1px" }}>
                {error}
                <button onClick={fetchHistory} style={{ display: "block", margin: "6px auto 0", background: "transparent", border: `1px solid #f87171`, color: "#f87171", fontSize: "8px", padding: "3px 8px", borderRadius: "4px", cursor: "pointer", fontFamily: "'JetBrains Mono', monospace" }}>
                  Réessayer
                </button>
              </div>
            )}

            {!loading && !error && filtered.length === 0 && (
              <div style={{ padding: "20px 10px", textAlign: "center", fontFamily: "'JetBrains Mono', monospace", fontSize: "10px", color: th.textFaint, letterSpacing: "1px" }}>
                {search ? "Aucun résultat" : "Aucun historique"}
              </div>
            )}

            {!loading && !error && filtered.map(scan => {
              const title   = formatTitle(scan);
              const preview = formatPreview(scan);
              const date    = formatDate(scan.created_at);

              return (
                <div key={scan.id} onClick={() => onSelectChat(scan.id)} style={{
                  padding: "10px", borderRadius: "6px", marginBottom: "2px", cursor: "pointer",
                  background: selectedChat === scan.id ? th.accentSubtle : "transparent",
                  border: selectedChat === scan.id ? `1px solid ${th.borderActive}` : "1px solid transparent",
                  transition: "all 0.2s",
                }}
                  onMouseEnter={e => { if (selectedChat !== scan.id) e.currentTarget.style.background = th.surfaceHover; }}
                  onMouseLeave={e => { if (selectedChat !== scan.id) e.currentTarget.style.background = "transparent"; }}
                >
                  <div style={{ fontSize: "11px", color: th.text, marginBottom: "3px", overflow: "hidden", whiteSpace: "nowrap", textOverflow: "ellipsis", fontFamily: "'JetBrains Mono', monospace" }}>
                    {highlight(title)}
                  </div>
                  <div style={{ fontSize: "10px", color: th.textMuted, fontFamily: "'JetBrains Mono', monospace" }}>
                    {highlight(preview)}
                  </div>
                  <div style={{ fontSize: "9px", color: th.textFaint, marginTop: "2px", fontFamily: "'JetBrains Mono', monospace" }}>
                    {date}
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}
