// useUserForm.js — logique de formulaire et validation
import { useState } from "react";

const validateEmail = (email) => /\S+@\S+\.\S+/.test(email);

// ─── Hook : création d'utilisateur ──────────────────────────────────────────
export function useCreateForm(onDone) {
  const [form, setForm]     = useState({ name: "", email: "", password: "", role: "1" });
  const [errors, setErrors] = useState({});
  const [success, setSuccess] = useState(false);

  const set = (field) => (e) => setForm(f => ({ ...f, [field]: e.target.value }));

  const validate = () => {
    const e = {};
    if (!form.name.trim())              e.name     = "Nom requis";
    if (!validateEmail(form.email))     e.email    = "Email invalide";
    if (form.password.length < 6)       e.password = "6 caractères minimum";
    return e;
  };

  const submit = () => {
    const e = validate();
    if (Object.keys(e).length) { setErrors(e); return; }
    // TODO : appel API POST /api/users
    console.log("[ADMIN] Créer →", form);
    setSuccess(true);
    setTimeout(onDone, 1400);
  };

  return { form, set, errors, success, submit };
}

// ─── Hook : suppression d'utilisateur (2 étapes) ────────────────────────────
export function useDeleteForm(onDone) {
  const [email, setEmail]     = useState("");
  const [confirm, setConfirm] = useState("");
  const [step, setStep]       = useState(1);
  const [error, setError]     = useState("");
  const [success, setSuccess] = useState(false);

  const nextStep = () => {
    if (!validateEmail(email)) { setError("Email invalide"); return; }
    setError(""); setStep(2);
  };

  const back = () => { setStep(1); setConfirm(""); setError(""); };

  const submit = () => {
    if (confirm !== "SUPPRIMER") { setError('Tapez exactement "SUPPRIMER"'); return; }
    // TODO : appel API DELETE /api/users
    console.log("[ADMIN] Supprimer →", email);
    setSuccess(true);
    setTimeout(onDone, 1400);
  };

  return { email, setEmail, confirm, setConfirm, step, error, setError, success, nextStep, back, submit };
}