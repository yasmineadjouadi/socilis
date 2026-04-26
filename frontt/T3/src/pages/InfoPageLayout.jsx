import { LOGO_URL } from "../constants";

const GREEN = "#7FD832";
const BG    = "#020a14";

export default function InfoPageLayout({ onBack, badge, title, subtitle, children }) {
  return (
    <div style={{ position:"relative", minHeight:"100vh", display:"flex", flexDirection:"column", overflow:"hidden", background:BG, fontFamily:"'JetBrains Mono','Courier New',monospace" }}>

      {/* Fond */}
      <div style={{ position:"absolute", top:"-10%", right:"-5%", width:"70vw", height:"85vh", background:"radial-gradient(ellipse at 65% 28%, rgba(0,160,150,0.50) 0%, rgba(0,100,120,0.25) 35%, transparent 70%)", filter:"blur(30px)", zIndex:0, pointerEvents:"none" }} />
      <div style={{ position:"absolute", bottom:"-5%", right:"8%", width:"50vw", height:"55vh", background:"radial-gradient(ellipse at 65% 80%, rgba(0,80,40,0.40) 0%, rgba(0,50,20,0.18) 50%, transparent 70%)", filter:"blur(45px)", zIndex:0, pointerEvents:"none" }} />
      <div style={{ position:"absolute", top:0, left:0, width:"55%", height:"100%", background:"radial-gradient(ellipse at 15% 50%, #040e1c 0%, #020a14 60%, transparent 88%)", zIndex:0, pointerEvents:"none" }} />

      {/* Navbar */}
      <nav style={{ position:"relative", zIndex:10, display:"flex", alignItems:"center", justifyContent:"space-between", padding:"6px 32px", borderBottom:`1px solid rgba(0,255,136,0.12)`, background:"rgba(2,8,18,0.65)", backdropFilter:"blur(14px)" }}>
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          <img src={LOGO_URL} alt="Socilis" style={{ height:"52px", width:"auto", filter:"drop-shadow(0 0 10px rgba(0,255,136,0.40))" }} />
          <div>
            <div style={{ fontSize:"1.0rem", fontWeight:900, letterSpacing:"0.20em", lineHeight:1 }}>
              <span style={{ color:"#fff" }}>SOC</span><span style={{ color:GREEN }}>ILIS</span>
            </div>
            <div style={{ fontSize:"0.50rem", marginTop:3, letterSpacing:"0.14em", color:"#5a80a0" }}>SECURE CHATBOT · BY MOBILIS</div>
          </div>
        </div>

        <button
          onClick={onBack}
          style={{ display:"flex", alignItems:"center", gap:7, padding:"7px 20px", background:"transparent", border:`1.5px solid ${GREEN}`, borderRadius:"999px", color:GREEN, fontSize:"0.70rem", letterSpacing:"0.20em", fontWeight:700, cursor:"pointer", fontFamily:"'JetBrains Mono','Courier New',monospace", boxShadow:`0 0 10px rgba(0,255,136,0.20)` }}
          onMouseEnter={e => { e.currentTarget.style.background="rgba(0,255,136,0.10)"; e.currentTarget.style.boxShadow="0 0 20px rgba(0,255,136,0.35)"; }}
          onMouseLeave={e => { e.currentTarget.style.background="transparent"; e.currentTarget.style.boxShadow="0 0 10px rgba(0,255,136,0.20)"; }}
        >
          ← BACK
        </button>
      </nav>

      {/* Contenu */}
      <div style={{ position:"relative", zIndex:5, flex:1, display:"flex", justifyContent:"center", padding:"48px 32px" }}>
        <div style={{ maxWidth:780, width:"100%" }}>

          <div style={{ display:"inline-flex", alignItems:"center", gap:8, padding:"4px 14px", marginBottom:"1.4rem", border:`1px solid rgba(0,255,136,0.35)`, borderRadius:"999px", color:GREEN, fontSize:"0.65rem", letterSpacing:"0.2em", fontWeight:700, background:"rgba(0,255,136,0.06)" }}>
            <span style={{ width:6, height:6, borderRadius:"50%", background:GREEN, boxShadow:`0 0 6px ${GREEN}`, display:"inline-block" }} />
            {badge}
          </div>

          <h1 style={{ fontSize:"clamp(2rem,4.5vw,3.2rem)", color:"#fff", fontWeight:900, letterSpacing:"0.05em", lineHeight:1.1, margin:"0 0 8px 0" }}>
            {title}
          </h1>

          <p style={{ fontSize:"0.85rem", letterSpacing:"0.14em", color:"#5a80a0", textTransform:"uppercase", marginBottom:"2.5rem", fontWeight:300 }}>
            {subtitle}
          </p>

          <div style={{ height:1, background:`linear-gradient(90deg, ${GREEN}50, transparent)`, marginBottom:"2.5rem" }} />

          {children}
        </div>
      </div>
    </div>
  );
}