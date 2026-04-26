// src/components/GlowingSphere.jsx
import { LOGO_URL, MOBILIS_LOGO_URL } from "../constants";

export default function GlowingSphere() {
  return (
    <div
      className="
        pointer-events-none absolute right-[-4vw] top-1/2 -translate-y-1/2
        w-[48vw] max-w-[620px] aspect-square z-[1]
      "
    >
      {/* Outer glow shell */}
      <div
        className="relative w-full h-full rounded-full animate-[spherePulse_6s_ease-in-out_infinite]"
        style={{
          background:
            "radial-gradient(circle at 35% 35%, rgba(0,180,255,0.18) 0%, rgba(0,80,150,0.12) 35%, rgba(0,212,255,0.06) 60%, transparent 75%)",
        }}
      >
        {/* Ring 1 — cyan */}
        <div className="absolute inset-[6%] rounded-full border border-[rgba(0,212,255,0.15)] animate-[ringRotate_20s_linear_infinite]" />
        {/* Ring 2 — green (Mobilis touch) */}
        <div className="absolute inset-[16%] rounded-full border border-[rgba(0,255,157,0.18)] animate-[ringRotate_14s_linear_infinite_reverse]" />
        {/* Ring 3 — cyan */}
        <div className="absolute inset-[27%] rounded-full border border-[rgba(0,212,255,0.22)] animate-[ringRotate_9s_linear_infinite]" />

        {/* Core glow */}
        <div
          className="absolute inset-[36%] rounded-full animate-[corePulse_3s_ease-in-out_infinite]"
          style={{
            background:
              "radial-gradient(circle, rgba(0,212,255,0.35), rgba(0,80,180,0.2), transparent)",
          }}
        />

        {/* ── Socilis logo in the center of the sphere ── */}
        <div className="absolute inset-0 flex items-center justify-center">
          <img
            src={LOGO_URL}
            alt="Socilis"
            className="w-[22%] h-auto drop-shadow-[0_0_24px_rgba(0,212,255,0.9)] animate-[corePulse_4s_ease-in-out_infinite]"
          />
        </div>

        {/* Orbiting dot — cyan */}
        <div className="absolute top-[12%] left-1/2 w-[6px] h-[6px] rounded-full bg-accent shadow-[0_0_8px_#00d4ff] animate-[dotOrbit_12s_linear_infinite]" />
        {/* Orbiting dot — green (Mobilis) */}
        <div className="absolute top-1/2 right-[8%] w-[5px] h-[5px] rounded-full bg-[#00ff9d] shadow-[0_0_10px_#00ff9d] animate-[dotOrbit_8s_linear_infinite] [animation-delay:-3s]" />
        {/* Orbiting dot — cyan */}
        <div className="absolute bottom-[15%] left-[30%] w-[5px] h-[5px] rounded-full bg-accent shadow-[0_0_8px_#00d4ff] animate-[dotOrbit_10s_linear_infinite] [animation-delay:-6s]" />

        {/* Mobilis logo — floating near sphere bottom-left */}
        <div
          className="absolute bottom-[14%] left-[8%] flex items-center gap-2 animate-[corePulse_5s_ease-in-out_infinite] [animation-delay:-2s]"
        >
          <img
            src={MOBILIS_LOGO_URL}
            alt="ATM Mobilis"
            className="h-[28px] w-auto opacity-70 drop-shadow-[0_0_8px_rgba(0,255,100,0.5)]"
            style={{ filter: "brightness(0) invert(1) sepia(1) saturate(3) hue-rotate(80deg) opacity(0.7)" }}
          />
        </div>
      </div>
    </div>
  );
}
