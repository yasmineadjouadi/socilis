// styles.js — primitives de style partagées entre les modals settings

export const overlay = {
  position: "fixed", inset: 0, background: "rgba(0,0,0,0.8)",
  zIndex: 1100, display: "flex", alignItems: "center", justifyContent: "center",
  backdropFilter: "blur(8px)",
};

export const card = (darkMode, accentColor = null) => ({
  background: darkMode ? "#060d16" : "#f0f6ff",
  border: `1px solid ${accentColor ?? "rgba(0,168,255,0.45)"}`,
  borderRadius: "10px", padding: "24px", width: "340px",
  fontFamily: "'JetBrains Mono',monospace",
  boxShadow: `0 0 40px ${accentColor ?? "rgba(0,168,255,0.15)"}, 0 24px 60px rgba(0,0,0,0.6)`,
  animation: "fadeInUp 0.2s ease",
});

export const modalHeader = (borderColor) => ({
  display: "flex", justifyContent: "space-between", alignItems: "center",
  marginBottom: "18px", paddingBottom: "12px",
  borderBottom: `1px solid ${borderColor}`,
});

export const closeBtn = {
  background: "transparent", border: "none",
  fontSize: "14px", cursor: "pointer", padding: "2px 6px", borderRadius: "4px",
};

export const fieldLabel = {
  display: "block", fontSize: "9px",
  letterSpacing: "2px", marginBottom: "4px",
};

export const inputField = (darkMode, hasError = false) => ({
  width: "100%", padding: "8px 10px", boxSizing: "border-box",
  background: darkMode ? "rgba(4,12,22,0.95)" : "rgba(255,255,255,0.9)",
  border: `1px solid ${hasError ? "rgba(239,68,68,0.5)" : "rgba(0,168,255,0.2)"}`,
  borderRadius: "6px", outline: "none",
  fontSize: "11px", letterSpacing: "0.5px",
  fontFamily: "'JetBrains Mono',monospace",
  transition: "border-color 0.2s",
});

export const btn = (bg, border, color) => ({
  flex: 1, padding: "9px", borderRadius: "6px",
  background: bg, border, color,
  fontSize: "10px", letterSpacing: "1.5px", cursor: "pointer",
  fontFamily: "'JetBrains Mono',monospace", transition: "all 0.2s",
});

export const errorText = {
  color: "#f87171", fontSize: "9px", marginTop: "3px", letterSpacing: "1px",
};

export const successMsg = {
  textAlign: "center", padding: "20px 0",
  color: "#34d399", fontSize: "12px", letterSpacing: "1.5px",
};