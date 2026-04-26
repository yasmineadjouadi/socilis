// src/hooks/useRole.js
// Hook utilitaire pour les vérifications de rôle côté composants.
// Factorise la logique de contrôle d'accès UI afin d'éviter toute duplication.

import { useAuth, ROLES } from "../context/AuthContext";

/**
 * useRole()
 *
 * @returns {object}
 *   hasRole(role)       → true si le rôle de l'utilisateur correspond exactement
 *   hasAnyRole([...])   → true si l'utilisateur possède l'un des rôles listés
 *   isAdmin             → raccourci booléen
 *   isUser              → raccourci booléen (role === ROLES.USER)
 *   canAccess(minRole)  → true si role <= minRole (logique de niveau d'accès)
 *
 * Exemple d'utilisation :
 *   const { isAdmin } = useRole();
 *   if (isAdmin) { ... }
 */
export function useRole() {
  const { role, isAuthenticated } = useAuth();

  const hasRole = (targetRole) => isAuthenticated && role === targetRole;

  const hasAnyRole = (roles = []) => isAuthenticated && roles.includes(role);

  // canAccess : utile si de nouveaux rôles intermédiaires sont ajoutés plus tard.
  // Convention : plus le chiffre est bas, plus le niveau de privilège est élevé.
  const canAccess = (requiredRole) => isAuthenticated && role <= requiredRole;

  return {
    hasRole,
    hasAnyRole,
    canAccess,
    isAdmin: hasRole(ROLES.ADMIN),
    isUser:  hasRole(ROLES.USER),
  };
}