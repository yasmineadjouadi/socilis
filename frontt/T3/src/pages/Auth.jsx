import { useState } from "react";
import Input  from "../components/input";
import { LOGO_URL } from "../constants";
import { useAuth } from "../context/AuthContext";
import { authApi } from "../services/api";

// ── Shared button style ──────────────────────────────────────────────────────
const BTN_STYLE = {
  display: "flex", alignItems: "center", justifyContent: "center", gap: "8px",
  width: "100%",
  padding: "10px 22px",
  background: "rgba(127,216,50,0.08)",
  border: "1.5px solid #7FD832",
  borderRadius: "999px",
  color: "#7FD832",
  fontSize: "0.78rem", letterSpacing: "0.2em",
  fontFamily: "'JetBrains Mono', monospace",
  fontWeight: "700",
  boxShadow: "0 0 16px rgba(127,216,50,0.22)",
  transition: "all 0.2s",
};

function useAuthForm(login, onNavigate) {
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [error,    setError]    = useState("");
  const [loading,  setLoading]  = useState(false);

  const validate = () => {
    if (!email || !/\S+@\S+\.\S+/.test(email)) return "Enter a valid email address.";
    if (!password || password.length < 6)       return "Password must be at least 6 characters.";
    return null;
  };

  const handleSubmit = async () => {
    const err = validate();
    if (err) { setError(err); return; }
    setError(""); setLoading(true);

    try {
      const data = await authApi.login({ email, password });
      login({ email, role: data.role === "superadmin" ? 0 : 1, name: email.split("@")[0] });
      onNavigate("chat");
    } catch (e) {
      setError(e.message || "Identifiants incorrects");
    } finally {
      setLoading(false);
    }
  };

  return { email, setEmail, password, setPassword, error, loading, handleSubmit };
}

// ── ForgotPasswordModal ──────────────────────────────────────────────────────
function ForgotPasswordModal({ onClose }) {
  const [resetEmail, setResetEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleReset = async () => {
    if (!resetEmail || !/\S+@\S+\.\S+/.test(resetEmail)) {
      setError("Email invalide.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      await authApi.forgotPassword(resetEmail);
      setSent(true);
    } catch (e) {
      setError(e.message || "Erreur lors de l'envoi.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        position: "fixed", inset: 0, zIndex: 50,
        display: "flex", alignItems: "center", justifyContent: "center",
        background: "rgba(2,11,24,0.80)", backdropFilter: "blur(8px)",
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: "100%", maxWidth: "380px", margin: "0 16px",
          background: "rgba(4,16,32,0.97)",
          border: "1px solid rgba(127,216,50,0.25)",
          padding: "36px 32px",
          boxShadow: "0 0 40px rgba(127,216,50,0.10)",
          position: "relative",
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Close */}
        <button
          onClick={onClose}
          style={{
            position: "absolute", top: 14, right: 16,
            background: "transparent", border: "none", cursor: "pointer",
            color: "rgba(127,216,50,0.5)", fontSize: "1.1rem", lineHeight: 1,
            fontFamily: "'JetBrains Mono', monospace",
            transition: "color 0.2s",
          }}
          onMouseEnter={e => e.currentTarget.style.color = "#7FD832"}
          onMouseLeave={e => e.currentTarget.style.color = "rgba(127,216,50,0.5)"}
        >
          ✕
        </button>

        {/* Header */}
        <div style={{ marginBottom: "20px" }}>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "0.65rem", letterSpacing: "0.2em",
            color: "#7FD832", marginBottom: "6px",
          }}>
            // RESET ACCESS
          </div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "1.1rem", fontWeight: 900, letterSpacing: "0.15em",
            color: "#ffffff",
          }}>
            MOT DE PASSE OUBLIÉ
          </div>
          <div style={{
            marginTop: "8px", fontSize: "0.75rem", letterSpacing: "0.06em",
            color: "#5a80a0", fontFamily: "'JetBrains Mono', monospace", lineHeight: 1.5,
          }}>
            {sent
              ? "Votre demande a été envoyée. L'administrateur vous enverra votre nouveau mot de passe."
              : "Entrez votre adresse email. L'administrateur vous enverra votre nouveau mot de passe."}
          </div>
        </div>

        {!sent ? (
          <>
            {/* Email field */}
            <div style={{ marginBottom: "20px" }}>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: "0.62rem", letterSpacing: "0.15em",
                color: "rgba(127,216,50,0.7)", marginBottom: "6px", textTransform: "uppercase",
              }}>
                Email Address
              </div>
              <input
                type="email"
                value={resetEmail}
                onChange={e => setResetEmail(e.target.value)}
                placeholder="analyst@example.com"
                style={{
                  width: "100%", boxSizing: "border-box",
                  padding: "9px 14px",
                  background: "rgba(0,212,255,0.04)",
                  border: "1px solid rgba(0,212,255,0.2)",
                  color: "#c8dff0",
                  fontSize: "0.83rem",
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: "0.06em",
                  outline: "none",
                  transition: "border-color 0.2s",
                }}
                onFocus={e => e.target.style.borderColor = "rgba(127,216,50,0.5)"}
                onBlur={e => e.target.style.borderColor = "rgba(0,212,255,0.2)"}
              />
            </div>

            {/* Submit */}
            <button
              onClick={handleReset}
              disabled={loading}
              style={{ ...BTN_STYLE, cursor: loading ? "not-allowed" : "pointer", opacity: loading ? 0.6 : 1 }}
              onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = "rgba(127,216,50,0.18)"; e.currentTarget.style.boxShadow = "0 0 28px rgba(127,216,50,0.40)"; } }}
              onMouseLeave={e => { e.currentTarget.style.background = "rgba(127,216,50,0.08)"; e.currentTarget.style.boxShadow = "0 0 16px rgba(127,216,50,0.22)"; }}
            >
              {loading ? "ENVOI..." : "ENVOYER LA DEMANDE"}
            </button>
            {error && (
              <div style={{ marginTop: "10px", color: "#ff8080", fontFamily: "'JetBrains Mono', monospace", fontSize: "0.72rem", letterSpacing: "0.06em" }}>
                ⚠ {error}
              </div>
            )}
          </>
        ) : (
          <>
            {/* Success state */}
            <div style={{
              display: "flex", alignItems: "center", gap: "10px",
              padding: "12px 16px", marginBottom: "20px",
              background: "rgba(127,216,50,0.07)",
              border: "1px solid rgba(127,216,50,0.25)",
            }}>
              <span style={{ color: "#7FD832", fontSize: "1.1rem" }}>✓</span>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: "0.75rem", letterSpacing: "0.08em", color: "#7FD832",
              }}>
                Email envoyé avec succès
              </span>
            </div>
            <button
              onClick={onClose}
              style={{ ...BTN_STYLE, cursor: "pointer" }}
              onMouseEnter={e => { e.currentTarget.style.background = "rgba(127,216,50,0.18)"; e.currentTarget.style.boxShadow = "0 0 28px rgba(127,216,50,0.40)"; }}
              onMouseLeave={e => { e.currentTarget.style.background = "rgba(127,216,50,0.08)"; e.currentTarget.style.boxShadow = "0 0 16px rgba(127,216,50,0.22)"; }}
            >
              FERMER
            </button>
          </>
        )}
      </div>
    </div>
  );
}

// ── Auth page ────────────────────────────────────────────────────────────────
export default function Auth({ onNavigate }) {
  const { login } = useAuth();
  const {
    email, setEmail, password, setPassword,
    error, loading, handleSubmit,
  } = useAuthForm(login, onNavigate);

  const [showForgot, setShowForgot] = useState(false);

  return (
    <div
      className="relative min-h-screen flex items-center justify-center p-8 overflow-hidden"
      style={{
        background: "radial-gradient(ellipse 60% 80% at 50% 50%, #041a30 0%, #020b18 70%)",
      }}
    >
      {/* Grid */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0,212,255,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,212,255,0.04) 1px, transparent 1px)
          `,
          backgroundSize: "40px 40px",
        }}
      />

      {/* Corner decorations */}
      <div className="absolute top-8 left-8 w-20 h-20 border-t border-l border-accent opacity-40 pointer-events-none" />
      <div className="absolute bottom-8 right-8 w-20 h-20 border-b border-r border-accent opacity-40 pointer-events-none" />

      {/* Card */}
      <div
        className="
          relative z-10 w-full max-w-[420px]
          bg-[rgba(4,16,32,0.9)] border border-[rgba(0,212,255,0.2)]
          p-10 backdrop-blur-[20px] clip-card
          shadow-card
        "
      >
        {/* Logo */}
        <div className="flex flex-col items-center mb-2">
          <img
            src={LOGO_URL}
            alt="Socialis"
            className="h-20 w-auto mb-2 drop-shadow-[0_0_16px_rgba(0,212,255,0.6)]"
          />
          <div
            className="font-display font-black tracking-[0.25em]"
            style={{ fontSize: "1.8rem", filter: "drop-shadow(0 0 20px rgba(127,216,50,0.4))" }}
          >
            <span style={{ color: "#ffffff" }}>SOC</span><span style={{ color: "#7FD832" }}>ILIS</span>
          </div>
        </div>

        <div className="text-center mb-8 text-[0.75rem] tracking-[0.25em] text-[#7aa3c0] uppercase font-body">
          // Secure Access Portal
        </div>

        {/* ── LOGIN button ── */}
        <button
          onClick={handleSubmit}
          disabled={loading}
          style={{
            ...BTN_STYLE,
            cursor: loading ? "not-allowed" : "pointer",
            opacity: loading ? 0.5 : 1,
            marginBottom: "24px",
          }}
          onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = "rgba(127,216,50,0.18)"; e.currentTarget.style.boxShadow = "0 0 28px rgba(127,216,50,0.40)"; } }}
          onMouseLeave={e => { e.currentTarget.style.background = "rgba(127,216,50,0.08)"; e.currentTarget.style.boxShadow = "0 0 16px rgba(127,216,50,0.22)"; }}
        >
          {loading ? "AUTHENTICATING..." : "LOGIN"}
        </button>

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2 bg-[rgba(255,60,60,0.08)] border border-[rgba(255,60,60,0.25)] text-[#ff8080] text-[0.82rem] px-4 py-[0.65rem] mb-5 tracking-[0.05em] font-body">
            <span className="w-[5px] h-[5px] rounded-full bg-[#ff4444] flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Fields */}
        <Input
          label="Email Address"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="analyst@example.com"
        />
        <Input
          label="Password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="••••••••"
        />

        {/* Forgot password link */}
        <div className="flex justify-end mb-4 -mt-2">
          <button
            onClick={() => setShowForgot(true)}
            style={{
              background: "transparent", border: "none", cursor: "pointer",
              color: "rgba(127,216,50,0.6)", fontSize: "0.72rem",
              letterSpacing: "0.08em", fontFamily: "'JetBrains Mono', monospace",
              transition: "color 0.2s", padding: 0,
              textDecoration: "underline", textUnderlineOffset: "3px",
            }}
            onMouseEnter={e => e.currentTarget.style.color = "#7FD832"}
            onMouseLeave={e => e.currentTarget.style.color = "rgba(127,216,50,0.6)"}
          >
            Mot de passe oublié ?
          </button>
        </div>

        {/* ── INITIATE SESSION button ── */}
        <button
          onClick={handleSubmit}
          disabled={loading}
          style={{
            ...BTN_STYLE,
            cursor: loading ? "not-allowed" : "pointer",
            opacity: loading ? 0.5 : 1,
            marginTop: "4px",
          }}
          onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = "rgba(127,216,50,0.18)"; e.currentTarget.style.boxShadow = "0 0 28px rgba(127,216,50,0.40)"; } }}
          onMouseLeave={e => { e.currentTarget.style.background = "rgba(127,216,50,0.08)"; e.currentTarget.style.boxShadow = "0 0 16px rgba(127,216,50,0.22)"; }}
        >
          {loading ? "AUTHENTICATING..." : "INITIATE SESSION"}
        </button>

        <button
          onClick={() => onNavigate("home")}
          className="block w-full text-center mt-4 text-[0.78rem] text-[#7aa3c0] tracking-[0.1em] bg-transparent border-none cursor-pointer transition-colors duration-200 hover:text-accent font-body"
        >
          ← Return to <span style={{ color: "#7FD832" }}>SOCILIS</span>
        </button>
      </div>

      {/* Forgot Password Modal */}
      {showForgot && <ForgotPasswordModal onClose={() => setShowForgot(false)} />}
    </div>
  );
}