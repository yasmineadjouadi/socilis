import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

export default function SplashPage() {
  const [phase, setPhase] = useState("boot");
  const navigate = useNavigate();

  useEffect(() => {
    const t1 = setTimeout(() => setPhase("logo"), 300);
    const t2 = setTimeout(() => setPhase("text"), 1400);
    const t3 = setTimeout(() => setPhase("exit"), 3200);
    const t4 = setTimeout(() => navigate("/home"), 3900);
    return () => [t1, t2, t3, t4].forEach(clearTimeout);
  }, []);

  return (
    <div style={{
      position: "fixed", inset: 0, background: "#020d1a",
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      zIndex: 9999, fontFamily: "'Courier New', monospace",
      overflow: "hidden",
      opacity: phase === "exit" ? 0 : 1,
      transition: "opacity 0.7s ease",
    }}>
      {/* Grid background */}
      <div style={{
        position: "absolute", inset: 0,
        backgroundImage: `
          linear-gradient(rgba(0,200,255,0.03) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,200,255,0.03) 1px, transparent 1px)
        `,
        backgroundSize: "40px 40px",
      }} />

      {/* Radial glow */}
      <div style={{
        position: "absolute", width: "600px", height: "600px",
        borderRadius: "50%",
        background: "radial-gradient(circle, rgba(0,180,255,0.08) 0%, transparent 70%)",
        animation: "pulse 3s ease-in-out infinite",
      }} />

      {/* Logo */}
      <div style={{
        position: "relative",
        opacity: phase === "boot" ? 0 : 1,
        transform: phase === "boot" ? "scale(0.6)" : phase === "exit" ? "scale(1.1)" : "scale(1)",
        transition: "all 0.8s cubic-bezier(0.34, 1.56, 0.64, 1)",
        marginBottom: "32px",
      }}>
        <div style={{
          position: "absolute", inset: "-20px", borderRadius: "50%",
          border: "2px solid rgba(0,200,255,0.3)",
          animation: phase === "text" ? "spinRing 4s linear infinite" : "none",
        }} />
        <div style={{
          position: "absolute", inset: "-36px", borderRadius: "50%",
          border: "1px solid rgba(0,200,255,0.1)",
          animation: phase === "text" ? "spinRing 6s linear infinite reverse" : "none",
        }} />
        <img
          src="/logo socilis.webp"
          alt="SOCILIS"
          style={{
            width: "160px", height: "160px", objectFit: "contain",
            filter: "drop-shadow(0 0 30px rgba(0,200,255,0.6)) drop-shadow(0 0 60px rgba(0,200,255,0.3))",
            animation: phase === "logo" ? "bounce 0.6s ease" : "float 3s ease-in-out infinite",
          }}
        />
      </div>

      {/* Text */}
      <div style={{
        opacity: phase === "text" || phase === "exit" ? 1 : 0,
        transform: phase === "text" || phase === "exit" ? "translateY(0)" : "translateY(20px)",
        transition: "all 0.6s ease", textAlign: "center",
      }}>
        <div style={{
          fontSize: "42px", fontWeight: "900", letterSpacing: "12px", color: "#ffffff",
          textShadow: "0 0 20px rgba(0,200,255,0.5)",
        }}>
          <span style={{ color: "#fff" }}>SOC</span>
          <span style={{ color: "#7FD832" }}>ILIS</span>
        </div>
        <div style={{
          fontSize: "11px", letterSpacing: "6px", color: "#00c8ff", marginTop: "8px", opacity: 0.8,
        }}>
          // SECURE CHATBOT · BY MOBILIS
        </div>

        {/* Loading bar */}
        <div style={{
          marginTop: "32px", width: "240px", height: "2px",
          background: "rgba(255,255,255,0.1)", borderRadius: "2px", overflow: "hidden",
        }}>
          <div style={{
            height: "100%",
            background: "linear-gradient(90deg, #00c8ff, #00ff88)",
            borderRadius: "2px",
            animation: "loadBar 1.8s ease forwards",
            boxShadow: "0 0 8px #00c8ff",
          }} />
        </div>

        <div style={{
          marginTop: "12px", fontSize: "10px",
          color: "rgba(0,200,255,0.5)", letterSpacing: "3px",
          animation: "blink 1s step-end infinite",
        }}>
          INITIALIZING THREAT INTELLIGENCE...
        </div>
      </div>

      <style>{`
        @keyframes bounce {
          0%, 100% { transform: translateY(0) scale(1); }
          30% { transform: translateY(-30px) scale(1.05); }
          60% { transform: translateY(-10px) scale(0.98); }
        }
        @keyframes float {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-10px); }
        }
        @keyframes pulse {
          0%, 100% { transform: scale(1); opacity: 0.5; }
          50% { transform: scale(1.2); opacity: 1; }
        }
        @keyframes spinRing {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes loadBar {
          from { width: 0%; }
          to { width: 100%; }
        }
        @keyframes blink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
      `}</style>
    </div>
  );
}