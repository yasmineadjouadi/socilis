import { BrowserRouter, Routes, Route, useNavigate } from "react-router-dom";
import Splash        from "./pages/SplashPage";
import Home          from "./pages/Home";
import Auth          from "./pages/Auth";
import Chat          from "./pages/ChatbotPage";
import Dashboard     from "./pages/DashboardPage";
import MissionPage   from "./pages/MissionPage";
import ModelsPage    from "./pages/ModelsPage";
import PlatformOverviewPage from "./pages/PlatformOverviewPage";
import PrivateRoute  from "./components/auth/PrivateRoute";

function HomeWrapper() {
  const navigate = useNavigate();
  return <Home onNavigate={(page) => navigate(`/${page}`)} />;
}

function AuthWrapper() {
  const navigate = useNavigate();
  return <Auth onNavigate={(page) => navigate(`/${page}`)} />;
}

function MissionWrapper() {
  const navigate = useNavigate();
  return <MissionPage onNavigate={(page) => navigate(`/${page}`)} />;
}

function ModelsWrapper() {
  const navigate = useNavigate();
  return <ModelsPage onNavigate={(page) => navigate(`/${page}`)} />;
}

function PlatformWrapper() {
  const navigate = useNavigate();
  return <PlatformOverviewPage onNavigate={(page) => navigate(`/${page}`)} />;
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/"          element={<Splash />} />
        <Route path="/home"      element={<HomeWrapper />} />
        <Route path="/auth"      element={<AuthWrapper />} />
        <Route path="/mission"   element={<MissionWrapper />} />
        <Route path="/models"    element={<ModelsWrapper />} />
        <Route path="/platform"  element={<PlatformWrapper />} />
        <Route path="/chat"      element={<PrivateRoute redirectTo="/auth"><Chat /></PrivateRoute>} />
        <Route path="/dashboard" element={<PrivateRoute redirectTo="/auth"><Dashboard /></PrivateRoute>} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;