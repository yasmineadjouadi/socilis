import { LOGO_URL, MOBILIS_LOGO_URL } from "../constants";

const G = "#7FD832";

function Navbar({ onNavigate }) {
  return (
    <nav style={{
      position: "fixed", top: 0, left: 0, right: 0, zIndex: 100,
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "0 48px", height: "64px",
      background: "rgba(5,10,18,0.75)",
      borderBottom: "1px solid rgba(127,216,50,0.08)",
      backdropFilter: "blur(20px)",
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
        
        <span style={{
          fontSize: "0.85rem", letterSpacing: "0.2em", color: "rgba(127,216,50,0.45)",
          padding: "2px 8px", border: "1px solid rgba(127,216,50,0.15)", borderRadius: "20px",
          fontFamily: "'DM Mono', monospace",
        }}>
          THREAT INTEL
        </span>
      </div>

      

      <button
        onClick={() => onNavigate("auth")}
        style={{
          display: "flex", alignItems: "center", gap: "8px",
          padding: "9px 20px", borderRadius: "8px",
          background: "rgba(127,216,50,0.03)",
          border: "1px solid rgba(127,216,50,0.15)",
          color: "rgba(127,216,50,0.7)",
          fontSize: "0.65rem", letterSpacing: "0.18em",
          fontFamily: "'DM Mono', monospace", fontWeight: 500,
          cursor: "pointer", transition: "all 0.2s",
          textTransform: "uppercase",
        }}
        onMouseEnter={e => {
          e.currentTarget.style.background = "rgba(127,216,50,0.07)";
          e.currentTarget.style.borderColor = "rgba(127,216,50,0.35)";
          e.currentTarget.style.color = G;
          e.currentTarget.style.transform = "translateY(-1px)";
        }}
        onMouseLeave={e => {
          e.currentTarget.style.background = "rgba(127,216,50,0.03)";
          e.currentTarget.style.borderColor = "rgba(127,216,50,0.15)";
          e.currentTarget.style.color = "rgba(127,216,50,0.7)";
          e.currentTarget.style.transform = "translateY(0)";
        }}
      >
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
        </svg>
        LOG IN
      </button>
    </nav>
  );
}

function Stats() {
  const items = [
    { val: "50K+",   label: "IOCs analyzed",  color: "#00c8ff" },
    { val: "99.2%",  label: "Detection rate", color: G },
    { val: "<10s",   label: "Response time",  color: "#fff" },
    { val: "Phi-3   Gemma", label: "2 LLMs",  color: G },
  ];
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "repeat(4, 1fr)",
      border: "1px solid rgba(127,216,50,0.1)",
      borderRadius: "10px", overflow: "hidden",
      background: "rgba(127,216,50,0.02)",
      width: "100%", maxWidth: "480px",
    }}>
      {items.map((s, i) => (
        <div key={i} style={{
          padding: "16px 12px", display: "flex", flexDirection: "column",
          alignItems: "center", gap: "5px",
          borderLeft: i > 0 ? "1px solid rgba(127,216,50,0.07)" : "none",
        }}>
          <span style={{
            fontFamily: "'Syne', sans-serif",
            fontSize: "1.1rem",
            fontWeight: 800, color: s.color,
            textAlign: "center", lineHeight: 1.2,
          }}>
            {s.val}
          </span>
          <span style={{
            fontSize: "0.58rem", letterSpacing: "0.12em",
            color: "rgba(255,255,255,0.25)", textTransform: "uppercase",
            fontFamily: "'DM Mono', monospace", textAlign: "center",
          }}>
            {s.label}
          </span>
        </div>
      ))}
    </div>
  );
}

function NavButton({ label, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        width: "100%", padding: "13px 18px",
        background: "rgba(127,216,50,0.03)",
        border: "1px solid rgba(127,216,50,0.15)",
        borderRadius: "8px",
        color: "rgba(127,216,50,0.7)",
        fontSize: "0.65rem", letterSpacing: "0.14em", textTransform: "uppercase",
        fontFamily: "'DM Mono', monospace",
        fontWeight: 500, cursor: "pointer", transition: "all 0.2s",
      }}
      onMouseEnter={e => {
        e.currentTarget.style.background = "rgba(127,216,50,0.07)";
        e.currentTarget.style.borderColor = "rgba(127,216,50,0.35)";
        e.currentTarget.style.color = G;
        e.currentTarget.style.transform = "translateY(-1px)";
      }}
      onMouseLeave={e => {
        e.currentTarget.style.background = "rgba(127,216,50,0.03)";
        e.currentTarget.style.borderColor = "rgba(127,216,50,0.15)";
        e.currentTarget.style.color = "rgba(127,216,50,0.7)";
        e.currentTarget.style.transform = "translateY(0)";
      }}
    >
      {label}
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M5 12h14M12 5l7 7-7 7"/>
      </svg>
    </button>
  );
}

function LogoOrb() {
  return (
    <div style={{ position: "relative", width: "340px", height: "340px", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div style={{
        position: "absolute", inset: 0, borderRadius: "50%",
        background: "radial-gradient(circle, rgba(127,216,50,0.08) 0%, transparent 70%)",
      }} />
      {[340, 265, 190].map((size, i) => (
        <div key={i} style={{
          position: "absolute",
          width: size, height: size,
          border: `1px solid rgba(127,216,50,${[0.08, 0.12, 0.18][i]})`,
          borderRadius: "50%",
          animation: `ringRotate ${[22, 15, 9][i]}s linear infinite ${i % 2 === 1 ? "reverse" : ""}`,
        }} />
      ))}
      <img
        src={LOGO_URL}
        alt="Socilis"
        style={{
          width: "130px", height: "auto", position: "relative", zIndex: 2,
          filter: "drop-shadow(0 0 20px rgba(0,200,255,0.45)) drop-shadow(0 0 40px rgba(127,216,50,0.2))",
          animation: "corePulse 4s ease-in-out infinite",
        }}
      />
    </div>
  );
}

export default function Home({ onNavigate }) {
  return (
    <div style={{
      position: "relative", minHeight: "100vh", display: "flex", flexDirection: "column",
      background: "#040a12", overflow: "hidden", fontFamily: "'DM Mono', monospace",
    }}>

      {/* Grid */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        backgroundImage: `linear-gradient(rgba(127,216,50,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(127,216,50,0.025) 1px, transparent 1px)`,
        backgroundSize: "44px 44px",
      }} />

      {/* Dégradé principal — bleu nuit haut-gauche, vert bas-droite très subtil */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        background: "linear-gradient(135deg, rgba(0,20,60,0.55) 0%, transparent 40%, rgba(10,70,5,0.08) 85%, rgba(20,100,10,0.12) 100%)",
      }} />

      {/* Vignette centrale */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        background: "radial-gradient(ellipse 75% 65% at 50% 50%, transparent 10%, #040a12 80%)",
      }} />

      {/* Blob bleu nuit — haut gauche */}
      <div style={{
        position: "absolute", top: "-10%", left: "-10%", width: "55vw", height: "55vw",
        borderRadius: "50%", pointerEvents: "none",
        background: "radial-gradient(circle, rgba(0,40,120,0.18) 0%, transparent 65%)",
      }} />

      {/* Blob vert — coin bas droite, très subtil */}
      <div style={{
        position: "absolute", bottom: "-40%", right: "-30%", width: "80vw", height: "80vw",
        borderRadius: "50%", pointerEvents: "none",
        background: "radial-gradient(circle, rgba(30,110,20,0.12) 0%, rgba(10,60,5,0.06) 40%, transparent 65%)",
      }} />

      {/* Liseré haut */}
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, height: "1px", pointerEvents: "none",
        background: "linear-gradient(90deg, transparent, rgba(0,80,200,0.3) 40%, rgba(127,216,50,0.2) 60%, transparent)",
      }} />

      <Navbar onNavigate={onNavigate} />

      {/* Hero */}
      <div style={{ flex: 1, display: "flex", alignItems: "center", padding: "64px 0 40px", position: "relative", zIndex: 5 }}>

        {/* Left */}
        <div style={{ flex: "0 0 52%", padding: "0 48px 0 72px", paddingTop: "80px", display: "flex", flexDirection: "column" }}>

          {/* Badge */}
          <div style={{
            display: "inline-flex", alignItems: "center", gap: "8px",
            padding: "5px 14px", borderRadius: "20px",
            border: "1px solid rgba(0,200,255,0.2)", background: "rgba(0,200,255,0.04)",
            marginBottom: "28px", width: "fit-content",
          }}>
            <span style={{ width: 6, height: 6, borderRadius: "50%", background: "#00c8ff", display: "inline-block", animation: "pulse 2s ease-in-out infinite" }} />
            <span style={{ fontSize: "0.58rem", letterSpacing: "0.2em", color: "#00c8ff", textTransform: "uppercase" }}>SOC AI Platform · Live</span>
          </div>

          {/* Title */}
          <h1 style={{
            fontFamily: "'Syne', sans-serif",
            fontSize: "clamp(3.2rem, 5.5vw, 4.8rem)",
            fontWeight: 800, lineHeight: 1.0, letterSpacing: "0.03em",
            color: "#fff", marginBottom: "18px",
          }}>
            SOC<span style={{ color: G, filter: "drop-shadow(0 0 18px rgba(127,216,50,0.35))" }}>ILIS</span>
          </h1>

          <p style={{
            fontSize: "0.7rem", letterSpacing: "0.2em",
            color: "rgba(255,255,255,0.3)", textTransform: "uppercase",
            marginBottom: "14px",
          }}>
            Detect faster. Respond smarter.
          </p>

          <p style={{
            fontSize: "0.88rem", color: "rgba(255,255,255,0.35)",
            lineHeight: 1.85, maxWidth: "380px", marginBottom: "40px",
          }}>
            AI-powered threat intelligence platform for real-time IOC enrichment, automated analysis, and incident response.
          </p>

          <Stats />
        </div>

        {/* Right */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "28px", padding: "0 64px 0 20px" }}>
          <LogoOrb />
          <div style={{ display: "flex", flexDirection: "column", gap: "10px", width: "100%", maxWidth: "340px" }}>
            <NavButton label="Models"   onClick={() => onNavigate("models")}   />
            <NavButton label="Platform" onClick={() => onNavigate("platform")} />
            <NavButton label="Mission"  onClick={() => onNavigate("mission")}  />
          </div>
        </div>
      </div>

      {/* Footer */}
      <div style={{
        position: "relative", zIndex: 10,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "14px 48px",
        borderTop: "1px solid rgba(127,216,50,0.07)",
        background: "rgba(4,10,18,0.5)",
      }}>
        <img src={MOBILIS_LOGO_URL} alt="Mobilis" style={{ height: "26px", opacity: 0.5 }} />
        <span style={{ fontSize: "0.58rem", color: "rgba(255,255,255,0.15)", letterSpacing: "0.12em" }}>
          SOCILIS v2.4 · USTHB 2026
        </span>
      </div>

      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Mono:wght@400;500&display=swap');
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes ringRotate { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes corePulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.88;transform:scale(1.04)} }
        @keyframes blink { 0%,49%{opacity:1} 50%,100%{opacity:0} }
      `}</style>
    </div>
  );
}