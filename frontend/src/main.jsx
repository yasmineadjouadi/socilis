import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./app";
import { AuthProvider } from "./context/AuthContext";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    {/* AuthProvider doit envelopper toute l'application pour que
        useAuth() soit accessible partout, y compris dans les routes. */}
    <AuthProvider>
      <App />
    </AuthProvider>
  </StrictMode>
);