// src/context/AuthContext.jsx
// Centralise l'état d'authentification et le rôle utilisateur pour tout le frontend.
// Le backend est la source de vérité — ce contexte ne fait que refléter et persister
// côté client ce que le backend a déjà validé.

import { createContext, useContext, useState, useCallback } from "react";

// ─── Constantes de rôles ───────────────────────────────────────────────────
// Ajoutez ici de nouveaux rôles à mesure que le backend en introduit.
export const ROLES = Object.freeze({
  ADMIN:    0,
  USER:     1,
  // ANALYST: 2,  // exemple d'extension future
});

const STORAGE_KEY = "socilis_auth";

// ─── Helpers de persistance ───────────────────────────────────────────────
function loadSession() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveSession(data) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    // Si localStorage est indisponible (ex: mode privé strict), on continue sans persistance.
  }
}

function clearSession() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch { /* noop */ }
}

// ─── Context ──────────────────────────────────────────────────────────────
const AuthContext = createContext(null);

/**
 * AuthProvider  — à placer en haut de l'arbre (dans main.jsx, autour de <App />).
 *
 * Fournit :
 *   user        → objet utilisateur (tel que renvoyé par le backend) ou null
 *   role        → raccourci vers user.role (ou null)
 *   isAdmin     → booléen : role === ROLES.ADMIN
 *   isAuthenticated → booléen
 *   login(userFromBackend) → persiste la session
 *   logout()              → efface la session et redirige (via callback)
 */
export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => loadSession());

  const login = useCallback((userFromBackend) => {
    // Le backend renvoie un objet contenant au minimum : { role, email, ... }
    // On le stocke tel quel — sans transformation métier.
    setUser(userFromBackend);
    saveSession(userFromBackend);
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    clearSession();
  }, []);

  const value = {
    user,
    role:            user?.role ?? null,
    isAuthenticated: user !== null,
    isAdmin:         user?.role === ROLES.ADMIN,
    login,
    logout,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

/**
 * useAuth — hook principal pour consommer le contexte.
 * Lance une erreur explicite si utilisé hors du provider.
 */
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}