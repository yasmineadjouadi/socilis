// CreateUserModal.jsx
import { btn, inputField, fieldLabel, successMsg, errorText } from "./styles";
import ModalShell from "./ModalShell";
import Field      from "./Field";
import { useCreateForm } from "./useUserForm";

export default function CreateUserModal({ darkMode, onClose }) {
  const { form, set, errors, success, submit } = useCreateForm(onClose);

  return (
    <ModalShell
      onClose={onClose} darkMode={darkMode}
      accentColor="rgba(0,200,80,0.35)" titleIcon="＋" title="CRÉER UTILISATEUR"
    >
      {success ? (
        <div style={successMsg}>✓ Utilisateur créé avec succès</div>
      ) : (
        <>
          <Field label="NOM COMPLET"   darkMode={darkMode} value={form.name}     onChange={set("name")}     placeholder="Ex: Ahmed Benali"    error={errors.name} />
          <Field label="PSEUDO"        darkMode={darkMode} value={form.pseudo}   onChange={set("pseudo")}   placeholder="Ex: a.benali"        error={errors.pseudo} />
          <Field label="EMAIL"         darkMode={darkMode} value={form.email}    onChange={set("email")}    placeholder="analyst@mobilis.dz"  error={errors.email} type="email" />
          <Field label="MOT DE PASSE"  darkMode={darkMode} value={form.password} onChange={set("password")} placeholder="••••••••"            error={errors.password} type="password" />

          <div style={{ marginBottom: "12px" }}>
            <label style={fieldLabel}>RÔLE</label>
            <select value={form.role} onChange={set("role")} style={{ ...inputField(darkMode), cursor: "pointer", color: darkMode ? "#e2f0ff" : "#0a1628" }}>
              <option value="1">Utilisateur standard</option>
              <option value="0">Administrateur</option>
            </select>
          </div>

          <div style={{ display: "flex", gap: "8px" }}>
            <button onClick={onClose} style={btn("transparent", "1px solid rgba(0,168,255,0.2)", "rgba(160,210,255,0.55)")}>ANNULER</button>
            <button onClick={submit}  style={btn("rgba(0,200,80,0.12)", "1px solid rgba(0,200,80,0.35)", "#34d399")}>CRÉER</button>
          </div>
        </>
      )}
    </ModalShell>
  );
}