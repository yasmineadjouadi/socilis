// src/components/auth/PrivateRoute.jsx
// Garde de route côté client (présentation uniquement).
// Si l'utilisateur n'est pas authentifié, ou n'a pas le rôle requis,
// il est redirigé vers une route sûre sans jamais voir le contenu protégé.

import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";

/**
 * PrivateRoute
 *
 * Props :
 *   children         — le composant à protéger
 *   requiredRole     — (optionnel) rôle exact exigé (ex : ROLES.ADMIN)
 *   redirectTo       — route de redirection si accès refusé (défaut : "/home")
 *   fallback         — composant alternatif à afficher si rôle insuffisant
 *                      (au lieu de rediriger)
 *
 * Exemples :
 *   <PrivateRoute>
 *     <ChatbotPage />
 *   </PrivateRoute>
 *
 *   <PrivateRoute requiredRole={ROLES.ADMIN} redirectTo="/home">
 *     <AdminPanel />
 *   </PrivateRoute>
 */
export default function PrivateRoute({
  children,
  requiredRole = null,
  redirectTo   = "/home",
  fallback     = null,
}) {
  const { isAuthenticated, role } = useAuth();
  const location = useLocation();

  // 1. Non authentifié → redirection vers auth avec mémorisation de la page demandée
  if (!isAuthenticated) {
    return <Navigate to="/auth" state={{ from: location }} replace />;
  }

  // 2. Rôle requis spécifié mais non satisfait
  if (requiredRole !== null && role !== requiredRole) {
    // Si un fallback est fourni (ex : message "Accès refusé"), on l'affiche.
    // Sinon on redirige vers la route sûre.
    if (fallback) return fallback;
    return <Navigate to={redirectTo} replace />;
  }

  return children;
}