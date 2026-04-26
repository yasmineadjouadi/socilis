// useUserForm.js — logique de formulaire et validation
import { useState } from "react";
import { authApi } from "../../../services/api";

const validateEmail = (email) => /\S+@\S+\.\S+/.test(email);

// ─── Hook : création d'utilisateur ──────────────────────────────────────────
export function useCreateForm(onDone) {
  const [form, setForm]       = useState({ name: "", pseudo: "", email: "", password: "", role: "1" });
  const [errors, setErrors]   = useState({});
  const [success, setSuccess] = useState(false);

  const set = (field) => (e) => setForm(f => ({ ...f, [field]: e.target.value }));

  const validate = () => {
    const e = {};
    if (!form.name.trim())          e.name     = "Nom requis";
    if (!form.pseudo.trim())        e.pseudo   = "Pseudo requis";
    if (!validateEmail(form.email)) e.email    = "Email invalide";
    if (form.password.length < 6)   e.password = "6 caractères minimum";
    return e;
  };

  const submit = async () => {
    const e = validate();
    if (Object.keys(e).length) { setErrors(e); return; }

    try {
      await authApi.createUser(form.email, form.password);
      setSuccess(true);
      setTimeout(onDone, 1400);
    } catch (err) {
      setErrors({ email: err.message || "Erreur lors de la création" });
    }
  };

  return { form, set, errors, success, submit };
}

// ─── Hook : suppression d'utilisateur (2 étapes) ────────────────────────────
export function useDeleteForm(onDone) {
  const [email, setEmail]     = useState("");
  const [pseudo, setPseudo]   = useState("");
  const [confirm, setConfirm] = useState("");
  const [step, setStep]       = useState(1);
  const [error, setError]     = useState("");
  const [success, setSuccess] = useState(false);

  const nextStep = () => {
    if (!pseudo.trim())        { setError("Pseudo requis"); return; }
    if (!validateEmail(email)) { setError("Email invalide"); return; }
    setError(""); setStep(2);
  };

  const back = () => { setStep(1); setConfirm(""); setError(""); };

  const submit = async () => {
    if (confirm !== "SUPPRIMER") { setError('Tapez exactement "SUPPRIMER"'); return; }

    try {
      const users = await authApi.listUsers();
      const user  = users.find(u => u.email === email);

      if (!user) { setError("Utilisateur introuvable"); return; }
      if (user.role === "superadmin") { setError("Impossible de supprimer le superadmin"); return; }

      await authApi.deleteUser(user.id);
      setSuccess(true);
      setTimeout(onDone, 1400);
    } catch (err) {
      setError(err.message || "Erreur lors de la suppression");
    }
  };

  return { email, setEmail, pseudo, setPseudo, confirm, setConfirm, step, error, setError, success, nextStep, back, submit };
}