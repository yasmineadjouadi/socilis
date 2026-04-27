import { useState, useRef, useEffect } from "react";
import ChatSidebar     from "../components/chat/ChatSidebar";
import ChatTopBar      from "../components/chat/ChatTopBar";
import ChatInput       from "../components/chat/ChatInput";
import MessageBubble   from "../components/chat/MessageBubble";
import TypingIndicator from "../components/chat/TypingIndicator";
import SettingsModal   from "../components/chat/SettingsModal";
import CreateUserModal from "../components/chat/settings/CreateUserModal";
import DeleteUserModal from "../components/chat/settings/DeleteUserModal";
import { t }           from "../components/chat/chatTheme";
import { MODELS }      from "../components/chat/ModelSelector";
import { detectInputType, stripIOCPrefix, TYPE_LABELS } from "../utils/iocDetector";
import { chatbotApi }  from "../services/api";

function now() {
  return new Date().toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
}

function makeInitMsg() {
  return {
    id: 1, role: "bot",
    content: "Système SOCILIS initialisé. Soumettez un IOC (Hash, IP, URL, Domaine, Email ou CVE) pour analyse, ou posez une question en cybersécurité.",
    timestamp: now(),
  };
}

export default function ChatbotPage() {
  const [messages,      setMessages]      = useState([makeInitMsg()]);
  const [input,         setInput]         = useState("");
  const [loading,       setLoading]       = useState(false);
  const [sidebarOpen,   setSidebarOpen]   = useState(true);
  const [settingsOpen,  setSettingsOpen]  = useState(false);
  const [darkMode,      setDarkMode]      = useState(true);
  const [selectedChat,  setSelectedChat]  = useState(null);
  const [activeIOC,     setActiveIOC]     = useState(null);
  const [selectedModel, setSelectedModel] = useState(MODELS[0].id);
  const [adminModal,    setAdminModal]    = useState(null);
  const bottomRef = useRef();
  const th = t(darkMode);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSelectIOC = (type) => {
    setActiveIOC(type);
    if (type) setInput(prev => `[${type}] ${stripIOCPrefix(prev)}`);
    else      setInput(prev => stripIOCPrefix(prev));
  };

  const sendMessage = async (text) => {
    const raw = (text || input).trim();
    if (!raw || loading) return;
    setInput("");

    const userMsg = { id: Date.now(), role: "user", content: raw, timestamp: now() };
    setMessages(prev => [...prev, userMsg]);
    setLoading(true);

    const clean = stripIOCPrefix(raw);

    try {
      const data = await chatbotApi.message(clean, null, selectedModel);
      let botMsg;

      if (data.type && data.type !== "question") {
        botMsg = {
          id: Date.now() + 1, role: "bot",
          content: data.message || `Analyse terminée — ${data.type} : ${clean}`,
          timestamp: now(),
          report: {
            ioc:               clean,
            type:              data.type,
            verdict:           data.verdict?.threat_level || "unknown",
            threat_level:      data.verdict?.threat_level || "unknown",
            score:             data.verdict?.score        || 0,
            message:           data.message               || "",
            tags:              data.verdict?.tags         || [],
            isp:               data.ti_summary?.isp,
            asn:               data.ti_summary?.asn,
            country:           data.ti_summary?.country,
            vt_malicious:      data.ti_summary?.reputation?.virustotal?.malicious  ?? data.ti_summary?.detection?.virustotal?.malicious,
            vt_suspicious:     data.ti_summary?.reputation?.virustotal?.suspicious ?? data.ti_summary?.detection?.virustotal?.suspicious,
            abuseipdb:         data.ti_summary?.reputation?.abuseipdb?.score,
            otx_pulses:        data.ti_summary?.reputation?.otx?.pulses            ?? data.ti_summary?.detection?.otx?.pulses,
            associated_domains:data.ti_summary?.associated_domains || [],
            associated_files:  data.ti_summary?.associated_files   || [],
            file_type:         data.ti_summary?.file_type,
            first_seen:        data.ti_summary?.first_seen,
            vt_undetected:     data.ti_summary?.detection?.virustotal?.undetected,
            mitre_attack:      data.ti_summary?.mitre_attack || [],
            ip_domain:         data.ti_summary?.ip,
            registrar:         data.ti_summary?.registrar,
            created:           data.ti_summary?.created,
            subdomains_count:  data.ti_summary?.subdomains_count,
            global_risk_score: data.ti_summary?.global_risk_score,
            domain:            data.ti_summary?.domain,
            gsb_threats:       data.ti_summary?.detection?.google_safe_browsing?.threats || [],
            phishtank:         data.ti_summary?.detection?.phishtank?.verdict,
            mail_domain:       data.ti_summary?.domain,
            provider:          data.ti_summary?.provider,
            mx:                data.ti_summary?.security?.mx,
            spf:               data.ti_summary?.security?.spf,
            dmarc:             data.ti_summary?.security?.dmarc,
            alerts:            data.ti_summary?.alerts || [],
            severity:          data.ti_summary?.severity,
            cvss_score:        data.ti_summary?.cvss_score,
            cvss_vector:       data.ti_summary?.cvss_vector,
            cwe:               data.ti_summary?.cwe || [],
            published:         data.ti_summary?.published,
          },
        };
      } else {
        botMsg = {
          id: Date.now() + 1, role: "bot",
          content: data.message || "Pas de réponse.",
          timestamp: now(),
        };
      }

      setMessages(prev => [...prev, botMsg]);
    } catch (e) {
      setMessages(prev => [...prev, {
        id: Date.now() + 1, role: "bot",
        content: `Erreur : ${e.message}`,
        timestamp: now(),
      }]);
    } finally {
      setLoading(false);
      setActiveIOC(null);
    }
  };

  const handleNewChat = () => {
    setMessages([makeInitMsg()]);
    setSelectedChat(null);
    setInput("");
    setActiveIOC(null);
    setLoading(false);
  };

  return (
    <div style={{
      display: "flex", height: "100vh",
      background: th.bg,
      fontFamily: "'JetBrains Mono','Fira Code',monospace",
      fontSize: "14px", /* ← augmenté de ~11-12px à 14px */
      color: th.text,
      overflow: "hidden",
    }}>
      {/* Grid bg */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 0,
        backgroundImage: darkMode
          ? `linear-gradient(rgba(0,168,255,0.018) 1px,transparent 1px),linear-gradient(90deg,rgba(0,168,255,0.018) 1px,transparent 1px)`
          : "none",
        backgroundSize: "44px 44px",
      }} />

      {/* Modals */}
      {settingsOpen && (
        <SettingsModal
          onClose={() => setSettingsOpen(false)}
          darkMode={darkMode}
          setDarkMode={setDarkMode}
          onOpenAdminModal={(type) => { setSettingsOpen(false); setAdminModal(type); }}
        />
      )}
      {adminModal === "create" && <CreateUserModal darkMode={darkMode} onClose={() => setAdminModal(null)} />}
      {adminModal === "delete" && <DeleteUserModal darkMode={darkMode} onClose={() => setAdminModal(null)} />}

      {/* Sidebar */}
      <ChatSidebar
        open={sidebarOpen}
        darkMode={darkMode}
        selectedChat={selectedChat}
        onSelectChat={setSelectedChat}
        onNewChat={handleNewChat}
      />

      {/* Main */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", position: "relative", zIndex: 1 }}>
        <ChatTopBar
          darkMode={darkMode}
          sidebarOpen={sidebarOpen}
          onToggleSidebar={() => setSidebarOpen(v => !v)}
          onOpenSettings={() => setSettingsOpen(true)}
          activeIOC={activeIOC}
          onSelectIOC={handleSelectIOC}
        />

        {/* Messages */}
        <div style={{
          flex: 1, overflowY: "auto",
          padding: "24px 32px", /* ← padding légèrement augmenté */
          scrollbarWidth: "thin",
          scrollbarColor: `${th.scrollThumb} transparent`,
        }}>
          {messages.map(msg => (
            <MessageBubble key={msg.id} msg={msg} darkMode={darkMode} />
          ))}
          {loading && <TypingIndicator darkMode={darkMode} />}
          <div ref={bottomRef} />
        </div>

        <ChatInput
          darkMode={darkMode}
          input={input}
          loading={loading}
          selectedModel={selectedModel}
          onModelChange={setSelectedModel}
          onInputChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendMessage()}
          onSend={sendMessage}
        />
      </div>

      <style>{`
        @keyframes fadeInUp {
          from { opacity: 0; transform: translateY(8px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes typingDot {
          0%,100% { opacity: 0.3; transform: scale(0.8); }
          50%     { opacity: 1;   transform: scale(1.2); }
        }
        ::-webkit-scrollbar       { width: 3px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${th.scrollThumb}; border-radius: 2px; }

        /* ── Global font-size boost ── */
        .chat-message-content { font-size: 14px !important; line-height: 1.75 !important; }
        .chat-sidebar-item    { font-size: 13px !important; }
        .chat-topbar          { font-size: 13px !important; }
        .chat-input-area      { font-size: 14px !important; }
        .ioc-badge            { font-size: 11px !important; letter-spacing: 0.1em !important; }
      `}</style>
    </div>
  );
}