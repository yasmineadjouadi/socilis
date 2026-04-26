import { LOGO_URL, MOBILIS_LOGO_URL } from "../constants";

// ── Palette ──────────────────────────────────────────────────────────────────
const BRAND_GREEN = "#7FD832";
const BG          = "#020c18";

// ── NavButton : bouton réutilisable ──────────────────────────────────────────
function NavButton({ label, onClick, fullWidth = false }) {
  return (
    <button
      onClick={onClick}
      style={{
        display:        "flex",
        alignItems:     "center",
        justifyContent: "space-between",
        width:          fullWidth ? "100%" : undefined,
        padding:        "11px 16px",
        background:     "rgba(127,216,50,0.05)",
        border:         "1px solid rgba(127,216,50,0.35)",
        borderRadius:   "4px",
        color:          BRAND_GREEN,
        fontSize:       "0.72rem",
        letterSpacing:  "0.12em",
        textTransform:  "uppercase",
        fontFamily:     "'JetBrains Mono', 'Courier New', monospace",
        fontWeight:     700,
        cursor:         "pointer",
        transition:     "all 0.18s",
        whiteSpace:     "nowrap",
      }}
      onMouseEnter={e => {
        e.currentTarget.style.background  = "rgba(127,216,50,0.12)";
        e.currentTarget.style.borderColor = "rgba(127,216,50,0.70)";
        e.currentTarget.style.boxShadow   = "0 0 14px rgba(127,216,50,0.20)";
      }}
      onMouseLeave={e => {
        e.currentTarget.style.background  = "rgba(127,216,50,0.05)";
        e.currentTarget.style.borderColor = "rgba(127,216,50,0.35)";
        e.currentTarget.style.boxShadow   = "none";
      }}
    >
      {label}
      <span style={{ fontSize: "12px", opacity: 0.7, marginLeft: "8px" }}>›</span>
    </button>
  );
}

// ── GlowingSphere ────────────────────────────────────────────────────────────
function GlowingSphere() {
  return (
    <div className="pointer-events-none absolute right-[-4vw] top-1/2 -translate-y-1/2 w-[48vw] max-w-[620px] aspect-square z-[1]">
      <div
        className="relative w-full h-full rounded-full animate-[spherePulse_6s_ease-in-out_infinite]"
        style={{
          background:
            "radial-gradient(circle at 35% 35%, rgba(0,180,255,0.18) 0%, rgba(0,80,150,0.12) 35%, rgba(0,212,255,0.06) 60%, transparent 75%)",
        }}
      >
        {/* Ring 1 — cyan */}
        <div className="absolute inset-[6%] rounded-full border border-[rgba(0,212,255,0.15)] animate-[ringRotate_20s_linear_infinite]" />
        {/* Ring 2 — green */}
        <div className="absolute inset-[16%] rounded-full border border-[rgba(0,255,157,0.18)] animate-[ringRotate_14s_linear_infinite_reverse]" />
        {/* Ring 3 — cyan */}
        <div className="absolute inset-[27%] rounded-full border border-[rgba(0,212,255,0.22)] animate-[ringRotate_9s_linear_infinite]" />

        {/* Core glow */}
        <div
          className="absolute inset-[36%] rounded-full animate-[corePulse_3s_ease-in-out_infinite]"
          style={{
            background: "radial-gradient(circle, rgba(0,212,255,0.35), rgba(0,80,180,0.2), transparent)",
          }}
        />

        {/* ✅ Logo Socilis centré — qui danse */}
        <div className="absolute inset-0 flex items-center justify-center">
          <img
            src={LOGO_URL}
            alt="Socilis"
            className="w-[36%] h-auto drop-shadow-[0_0_32px_rgba(0,212,255,0.95)] animate-[corePulse_4s_ease-in-out_infinite]"
            style={{ filter: "drop-shadow(0 0 18px rgba(127,216,50,0.6)) drop-shadow(0 0 40px rgba(0,212,255,0.5))" }}
          />
        </div>

        {/* Orbiting dots */}
        <div className="absolute top-[12%] left-1/2 w-[6px] h-[6px] rounded-full bg-accent shadow-[0_0_8px_#00d4ff] animate-[dotOrbit_12s_linear_infinite]" />
        <div className="absolute top-1/2 right-[8%] w-[5px] h-[5px] rounded-full bg-[#00ff9d] shadow-[0_0_10px_#00ff9d] animate-[dotOrbit_8s_linear_infinite] [animation-delay:-3s]" />
        <div className="absolute bottom-[15%] left-[30%] w-[5px] h-[5px] rounded-full bg-accent shadow-[0_0_8px_#00d4ff] animate-[dotOrbit_10s_linear_infinite] [animation-delay:-6s]" />
      </div>
    </div>
  );
}

// ── Composant principal ───────────────────────────────────────────────────────
export default function Home({ onNavigate }) {
  return (
    <div
      className="relative min-h-screen flex flex-col overflow-hidden"
      style={{ background: BG }}
    >

      {/* ── Blobs ────────────────────────────────────────────────────────── */}
      <div className="absolute pointer-events-none" style={{
        top: 0, left: 0, width: "55vw", height: "100vh",
        background: "radial-gradient(ellipse at 30% 50%, #0a1f3d 0%, #050e1f 50%, transparent 80%)",
        zIndex: 0,
      }} />
      <div className="absolute pointer-events-none" style={{
        top: "-10%", right: "-5%", width: "60vw", height: "80vh",
        background: "radial-gradient(ellipse at 60% 40%, rgba(20,180,160,0.35) 0%, rgba(10,100,120,0.20) 35%, transparent 65%)",
        filter: "blur(40px)", zIndex: 0,
      }} />
      <div className="absolute pointer-events-none" style={{
        bottom: "-10%", right: "5%", width: "50vw", height: "60vh",
        background: "radial-gradient(ellipse at 70% 70%, rgba(120,180,60,0.25) 0%, rgba(60,120,40,0.12) 40%, transparent 70%)",
        filter: "blur(50px)", zIndex: 0,
      }} />
      <div className="absolute pointer-events-none" style={{
        bottom: 0, left: 0, width: "45vw", height: "50vh",
        background: "radial-gradient(ellipse at 20% 80%, rgba(10,40,100,0.50) 0%, transparent 70%)",
        filter: "blur(30px)", zIndex: 0,
      }} />

      {/* ── Grid fine ────────────────────────────────────────────────────── */}
      <div className="absolute inset-0 pointer-events-none" style={{
        backgroundImage: `
          linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px)
        `,
        backgroundSize: "50px 50px",
        zIndex: 1,
      }} />

      {/* ── GlowingSphere ────────────────────────────────────────────────── */}
      <GlowingSphere />

      {/* ── Navbar — logo img à gauche + LOG IN à droite ─────────────────── */}
      <nav
        className="relative flex items-center justify-between px-10 py-4 border-b border-[rgba(0,212,255,0.08)] bg-[rgba(2,11,24,0.40)] backdrop-blur-[14px]"
        style={{ zIndex: 10 }}
      >
        {/* Logo seul — sans texte */}
        <img
          
        />

        {/* LOG IN */}
        <button
          onClick={() => onNavigate("auth")}
          style={{
            display: "flex", alignItems: "center", gap: "8px",
            padding: "8px 22px",
            background: "rgba(127,216,50,0.08)",
            border: `1.5px solid ${BRAND_GREEN}`,
            borderRadius: "999px",
            color: BRAND_GREEN,
            fontSize: "0.78rem", letterSpacing: "0.2em",
            fontFamily: "'JetBrains Mono', monospace",
            fontWeight: 700, cursor: "pointer",
            boxShadow: "0 0 16px rgba(127,216,50,0.22)",
            transition: "all 0.2s",
          }}
          onMouseEnter={e => {
            e.currentTarget.style.background = "rgba(127,216,50,0.18)";
            e.currentTarget.style.boxShadow  = "0 0 28px rgba(127,216,50,0.40)";
          }}
          onMouseLeave={e => {
            e.currentTarget.style.background = "rgba(127,216,50,0.08)";
            e.currentTarget.style.boxShadow  = "0 0 16px rgba(127,216,50,0.22)";
          }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
            stroke={BRAND_GREEN} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
            <circle cx="12" cy="7" r="4"/>
          </svg>
          LOG IN
        </button>
      </nav>

      {/* ── Hero ─────────────────────────────────────────────────────────── */}
      <div
        className="relative flex-1 flex items-center px-10 py-8"
        style={{ zIndex: 5 }}
      >
        <div style={{ maxWidth: "520px" }}>

          <h1
            className="font-display font-black tracking-[0.06em] leading-none mb-3"
            style={{ fontSize: "clamp(3rem,7vw,5.5rem)" }}
          >
            <span className="text-white">SOC</span>
            <span style={{
              color: BRAND_GREEN,
              filter: "drop-shadow(0 0 22px rgba(127,216,50,0.55))",
            }}>ILIS</span>
          </h1>

          <p style={{
            fontSize: "1.05rem", letterSpacing: "0.16em",
            color: "#7aa3c0", textTransform: "uppercase",
            fontWeight: 300, marginBottom: "2.5rem",
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            Detect faster. Respond smarter.
          </p>

          {/* ── Boutons ── */}
          <div style={{ display: "flex", flexDirection: "column", gap: "10px", maxWidth: "480px" }}>

            {/* Ligne 1 : Models | Platform Overview */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
              <NavButton label="Models"            onClick={() => onNavigate("models")}   />
              <NavButton label="Platform Overview" onClick={() => onNavigate("platform")} />
            </div>

            {/* Ligne 2 : Mission & Objectives — centré */}
            <div style={{ display: "flex", justifyContent: "center" }}>
              <div style={{ width: "calc(50% - 5px)" }}>
                <NavButton
                  label="Mission & Objectives"
                  onClick={() => onNavigate("mission")}
                  fullWidth
                />
              </div>
            </div>

          </div>
        </div>
      </div>

      {/* ── Logo Mobilis bas gauche — en couleur ─────────────────────────── */}
      <div
        style={{
          position: "fixed", bottom: "20px", left: "28px", zIndex: 20,
          opacity: 0.85, transition: "opacity 0.2s",
        }}
        onMouseEnter={e => e.currentTarget.style.opacity = "1"}
        onMouseLeave={e => e.currentTarget.style.opacity = "0.85"}
      >
        <img
          src={MOBILIS_LOGO_URL}
          alt="Mobilis"
          style={{ height: "32px", width: "auto", display: "block" }}
        />
      </div>

      {/* ── Keyframes ────────────────────────────────────────────────────── */}
      <style>{`
        @keyframes spherePulse {
          0%, 100% { opacity: 1;    transform: scale(1);    }
          50%       { opacity: 0.85; transform: scale(1.03); }
        }
        @keyframes ringRotate {
          from { transform: rotate(0deg);   }
          to   { transform: rotate(360deg); }
        }
        @keyframes corePulse {
          0%, 100% { opacity: 1;   transform: scale(1);    }
          50%       { opacity: 0.7; transform: scale(1.08); }
        }
        @keyframes dotOrbit {
          from { transform: rotate(0deg)   translateX(140px) rotate(0deg);    }
          to   { transform: rotate(360deg) translateX(140px) rotate(-360deg); }
        }
      `}</style>

    </div>
  );
}