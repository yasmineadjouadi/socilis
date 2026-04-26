import { LOGO_URL, MOBILIS_LOGO_URL, NAV_ITEMS } from "../constants";

// Vert exact du logo SOCILIS
const BRAND_GREEN = "#7FD832";

export default function Home({ onNavigate }) {
  const col1 = [NAV_ITEMS[0], NAV_ITEMS[1]];
  const col2 = [NAV_ITEMS[2], NAV_ITEMS[3]];

  return (
    <div className="relative min-h-screen flex flex-col overflow-hidden" style={{ background: "#020c18" }}>

      {/* Blob bleu foncé gauche */}
      <div className="absolute pointer-events-none" style={{ top:"0", left:"0", width:"55vw", height:"100vh", background:"radial-gradient(ellipse at 30% 50%, #0a1f3d 0%, #050e1f 50%, transparent 80%)", zIndex:0 }} />
      {/* Blob teal/cyan haut droite */}
      <div className="absolute pointer-events-none" style={{ top:"-10%", right:"-5%", width:"60vw", height:"80vh", background:"radial-gradient(ellipse at 60% 40%, rgba(20,180,160,0.35) 0%, rgba(10,100,120,0.20) 35%, transparent 65%)", filter:"blur(40px)", zIndex:0 }} />
      {/* Blob jaune-vert bas droite */}
      <div className="absolute pointer-events-none" style={{ bottom:"-10%", right:"5%", width:"50vw", height:"60vh", background:"radial-gradient(ellipse at 70% 70%, rgba(120,180,60,0.25) 0%, rgba(60,120,40,0.12) 40%, transparent 70%)", filter:"blur(50px)", zIndex:0 }} />
      {/* Blob bleu profond bas gauche */}
      <div className="absolute pointer-events-none" style={{ bottom:"0", left:"0", width:"45vw", height:"50vh", background:"radial-gradient(ellipse at 20% 80%, rgba(10,40,100,0.5) 0%, transparent 70%)", filter:"blur(30px)", zIndex:0 }} />

      {/* Grid fine */}
      <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage:"linear-gradient(rgba(0,212,255,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,212,255,0.03) 1px,transparent 1px)", backgroundSize:"50px 50px", zIndex:1 }} />

      {/* ── Navbar ── */}
      <nav className="relative flex items-center justify-between px-10 py-4 border-b border-[rgba(0,212,255,0.08)] bg-[rgba(2,11,24,0.40)] backdrop-blur-[14px]" style={{ zIndex:10 }}>
        <div className="flex items-center gap-3">
          <img
            src={LOGO_URL}
            alt="Socilis logo"
            className="h-14 w-auto"
            style={{ filter:"drop-shadow(0 0 16px rgba(127,216,50,0.45))" }}
          />
          <div>
            <div className="font-display font-black tracking-[0.18em]" style={{ fontSize:"clamp(1.1rem,2.2vw,1.4rem)", lineHeight:1 }}>
              <span className="text-white">SOC</span>
              <span style={{ color: BRAND_GREEN }}>ILIS</span>
            </div>
            <div style={{ fontSize:"0.58rem", marginTop:"3px", letterSpacing:"0.15em", color:"#7aa3c0", fontFamily:"'JetBrains Mono',monospace" }}>
              SECURE CHATBOT · BY MOBILIS
            </div>
          </div>
        </div>

        {/* LOGIN vert */}
        <button
          onClick={() => onNavigate("auth")}
          style={{
            display:"flex", alignItems:"center", gap:"8px",
            padding:"8px 22px",
            background:`rgba(127,216,50,0.08)`,
            border:`1.5px solid ${BRAND_GREEN}`,
            borderRadius:"999px",
            color: BRAND_GREEN,
            fontSize:"0.78rem", letterSpacing:"0.2em",
            fontFamily:"'JetBrains Mono',monospace",
            fontWeight:"700", cursor:"pointer",
            boxShadow:`0 0 16px rgba(127,216,50,0.22)`,
            transition:"all 0.2s",
          }}
          onMouseEnter={e => { e.currentTarget.style.background=`rgba(127,216,50,0.18)`; e.currentTarget.style.boxShadow=`0 0 28px rgba(127,216,50,0.40)`; }}
          onMouseLeave={e => { e.currentTarget.style.background=`rgba(127,216,50,0.08)`; e.currentTarget.style.boxShadow=`0 0 16px rgba(127,216,50,0.22)`; }}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={BRAND_GREEN} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
          </svg>
          LOG IN
        </button>
      </nav>

      {/* ── Hero ── */}
      <div className="relative flex-1 flex items-center px-10 py-8" style={{ zIndex:5 }}>
        <div style={{ maxWidth:"620px" }}>

          {/* Titre */}
          <h1 className="font-display font-black tracking-[0.06em] leading-none mb-3"
            style={{ fontSize:"clamp(3rem,7vw,5.5rem)" }}>
            <span className="text-white">SOC</span>
            <span style={{ color: BRAND_GREEN, filter:`drop-shadow(0 0 22px rgba(127,216,50,0.55))` }}>ILIS</span>
          </h1>

          <p style={{ fontSize:"1.05rem", letterSpacing:"0.16em", color:"#7aa3c0", textTransform:"uppercase", fontWeight:300, marginBottom:"2.5rem", fontFamily:"'JetBrains Mono',monospace" }}>
            Detect faster. Respond smarter.
          </p>

          {/* 4 boutons verts */}
          <div className="grid grid-cols-2 gap-3" style={{ maxWidth:"560px" }}>
            {[col1, col2].map((col, ci) => (
              <div key={ci} className="flex flex-col gap-3">
                {col.map(item => (
                  <button
                    key={item.label}
                    onClick={() => {}}
                    style={{
                      display:"flex", alignItems:"center", justifyContent:"space-between",
                      padding:"11px 16px",
                      background:`rgba(127,216,50,0.05)`,
                      border:`1px solid rgba(127,216,50,0.35)`,
                      borderRadius:"4px",
                      color: BRAND_GREEN,
                      fontSize:"0.72rem", letterSpacing:"0.12em",
                      textTransform:"uppercase",
                      fontFamily:"'JetBrains Mono',monospace",
                      fontWeight:"700", cursor:"pointer",
                      transition:"all 0.18s",
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background=`rgba(127,216,50,0.12)`; e.currentTarget.style.borderColor=`rgba(127,216,50,0.7)`; e.currentTarget.style.boxShadow=`0 0 14px rgba(127,216,50,0.18)`; }}
                    onMouseLeave={e => { e.currentTarget.style.background=`rgba(127,216,50,0.05)`; e.currentTarget.style.borderColor=`rgba(127,216,50,0.35)`; e.currentTarget.style.boxShadow="none"; }}
                  >
                    {item.label}
                    <span style={{ fontSize:"12px", opacity:0.7 }}>›</span>
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Logo Mobilis bas gauche (fixe) ── */}
      <div style={{
        position:"fixed", bottom:"20px", left:"28px", zIndex:20,
        display:"flex", alignItems:"center",
      }}>
        <img
          src={MOBILIS_LOGO_URL}
          alt="Mobilis"
          style={{
            height:"32px", width:"auto", opacity:0.75,
            filter:"brightness(0) invert(1)",  // le rend blanc pour tenir sur fond sombre
            transition:"opacity 0.2s",
          }}
          onMouseEnter={e => e.currentTarget.style.opacity="1"}
          onMouseLeave={e => e.currentTarget.style.opacity="0.75"}
        />
      </div>

    </div>
  );
}