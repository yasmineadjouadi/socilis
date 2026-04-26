// Field.jsx — input de formulaire réutilisable
import { fieldLabel, inputField, errorText } from "./styles";

export default function Field({ label, error, darkMode, ...inputProps }) {
  return (
    <div style={{ marginBottom: "12px" }}>
      {label && <label style={fieldLabel}>{label}</label>}
      <input style={inputField(darkMode, !!error)} {...inputProps} />
      {error && <div style={errorText}>{error}</div>}
    </div>
  );
}