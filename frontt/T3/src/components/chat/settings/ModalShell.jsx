// ModalShell.jsx — enveloppe overlay + carte pour tous les sous-modals
import { overlay, card, modalHeader, closeBtn } from "./styles";

export default function ModalShell({ onClose, darkMode, accentColor, borderColor, titleIcon, title, children }) {
  return (
    <div style={overlay} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={card(darkMode, accentColor)}>

        <div style={modalHeader(borderColor ?? accentColor)}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px", color: accentColor, fontSize: "11px", letterSpacing: "2.5px", fontWeight: "700" }}>
            <span>{titleIcon}</span><span>{title}</span>
          </div>
          <button onClick={onClose} style={{ ...closeBtn, color: "rgba(160,210,255,0.28)" }}>✕</button>
        </div>

        {children}
      </div>
    </div>
  );
}