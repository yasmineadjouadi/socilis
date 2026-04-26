// DeleteUserModal.jsx
import { btn, inputField, fieldLabel, errorText, successMsg } from "./styles";
import ModalShell from "./ModalShell";
import { useDeleteForm } from "./useUserForm";

export default function DeleteUserModal({ darkMode, onClose }) {
  const { email, setEmail, confirm, setConfirm, step, error, setError, success, nextStep, back, submit } = useDeleteForm(onClose);

  const inp = { ...inputField(darkMode, !!error), color: darkMode ? "#e2f0ff" : "#0a1628" };

  return (
    <ModalShell
      onClose={onClose} darkMode={darkMode}
      accentColor="rgba(239,68,68,0.4)" titleIcon="⚠" title="SUPPRIMER UTILISATEUR"
    >
      {success ? (
        <div style={successMsg}>✓ Utilisateur supprimé</div>

      ) : step === 1 ? (
        <>
          <p style={{ color: "rgba(160,210,255,0.55)", fontSize: "10px", lineHeight: "1.6", marginBottom: "16px" }}>
            Entrez l'email de l'utilisateur à supprimer. Cette action est irréversible.
          </p>
          <div style={{ marginBottom: "12px" }}>
            <label style={fieldLabel}>EMAIL DE L'UTILISATEUR</label>
            <input style={inp} type="email" value={email} placeholder="utilisateur@mobilis.dz"
              onChange={e => { setEmail(e.target.value); setError(""); }} />
            {error && <div style={errorText}>{error}</div>}
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button onClick={onClose}  style={btn("transparent", "1px solid rgba(0,168,255,0.2)", "rgba(160,210,255,0.55)")}>ANNULER</button>
            <button onClick={nextStep} style={btn("rgba(239,68,68,0.1)", "1px solid rgba(239,68,68,0.35)", "#f87171")}>CONTINUER →</button>
          </div>
        </>

      ) : (
        <>
          <div style={{ background: "rgba(239,68,68,0.07)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "6px", padding: "10px 12px", marginBottom: "16px" }}>
            <div style={{ fontSize: "9px", color: "rgba(160,210,255,0.28)", letterSpacing: "2px", marginBottom: "4px" }}>COMPTE CIBLÉ</div>
            <div style={{ fontSize: "12px", color: "#f87171" }}>{email}</div>
          </div>
          <p style={{ color: "rgba(160,210,255,0.55)", fontSize: "10px", lineHeight: "1.6", marginBottom: "14px" }}>
            Pour confirmer, tapez <strong style={{ color: "#f87171" }}>SUPPRIMER</strong> ci-dessous :
          </p>
          <div style={{ marginBottom: "12px" }}>
            <input style={inp} value={confirm} placeholder="SUPPRIMER"
              onChange={e => { setConfirm(e.target.value); setError(""); }} />
            {error && <div style={errorText}>{error}</div>}
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button onClick={back}   style={btn("transparent", "1px solid rgba(0,168,255,0.2)", "rgba(160,210,255,0.55)")}>← RETOUR</button>
            <button onClick={submit} style={btn("rgba(239,68,68,0.15)", "1px solid rgba(239,68,68,0.45)", "#f87171")}>SUPPRIMER</button>
          </div>
        </>
      )}
    </ModalShell>
  );
}