import { BrowserRouter, Routes, Route, useNavigate } from "react-router-dom";
import Splash       from "./pages/SplashPage";
import Home         from "./pages/Home";
import Auth         from "./pages/Auth";
import Chat         from "./pages/ChatbotPage";
import Dashboard    from "./pages/DashboardPage";
import PrivateRoute from "./components/auth/PrivateRoute";

function HomeWrapper() {
  const navigate = useNavigate();
  return <Home onNavigate={(page) => navigate(`/${page}`)} />;
}

function AuthWrapper() {
  const navigate = useNavigate();
  return <Auth onNavigate={(page) => navigate(`/${page}`)} />;
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"     element={<Splash />} />
        <Route path="/home" element={<HomeWrapper />} />
        <Route path="/auth" element={<AuthWrapper />} />
        <Route path="/chat" element={<PrivateRoute redirectTo="/auth"><Chat /></PrivateRoute>} />
        <Route path="/dashboard" element={<PrivateRoute redirectTo="/auth"><Dashboard /></PrivateRoute>} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;