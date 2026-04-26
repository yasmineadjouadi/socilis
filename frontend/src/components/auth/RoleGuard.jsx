// src/components/auth/RoleGuard.jsx
// Composant de rendu conditionnel basé sur le rôle.
// Garantit que les éléments restreints ne sont ni visibles ni présents dans le DOM.

import { useAuth, ROLES } from "../../context/AuthContext";

/**
 * RoleGuard
 *
 * Props :
 *   allowedRoles  — tableau de rôles autorisés (ex: [ROLES.ADMIN])
 *   fallback      — contenu à afficher si rôle insuffisant (défaut : null)
 *   children      — contenu à afficher si autorisé
 *
 * Exemples :
 *   // Visible uniquement par les admins :
 *   <RoleGuard allowedRoles={[ROLES.ADMIN]}>
 *     <button>Créer utilisateur</button>
 *   </RoleGuard>
 *
 *   // Avec fallback :
 *   <RoleGuard allowedRoles={[ROLES.ADMIN]} fallback={<span>Non autorisé</span>}>
 *     <AdminActions />
 *   </RoleGuard>
 */
export default function RoleGuard({ allowedRoles = [], fallback = null, children }) {
  const { role, isAuthenticated } = useAuth();

  if (!isAuthenticated) return fallback;
  if (!allowedRoles.includes(role)) return fallback;

  return children;
}

// ─── Export des ROLES pour usage pratique dans les consommateurs ──────────
export { ROLES };