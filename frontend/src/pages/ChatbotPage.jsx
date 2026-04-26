import { useState, useRef, useEffect } from "react";
import ChatSidebar     from "../components/chat/ChatSidebar";
import ChatTopBar      from "../components/chat/ChatTopBar";
import ChatInput       from "../components/chat/ChatInput";
import MessageBubble   from "../components/chat/MessageBubble";
import TypingIndicator from "../components/chat/TypingIndicator";
import SettingsModal   from "../components/chat/SettingsModal";
import CreateUserModal from "../components/chat/settings/CreateUserModal";
import DeleteUserModal from "../components/chat/settings/DeleteUserModal";
import { t }           from "../components/chat/ChatTheme";
import { MODELS }      from "../components/chat/ModelSelector";
import { stripIOCPrefix } from "../utils/iocDetector";
import api             from "../api/api";

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

// ── Mapping ti_summary → champs attendus par ReportCard ──────
function buildReport(data) {
  const ti   = data.ti_summary || {};
  const type = data.type || "";

  const base = {
    ioc:          data.indicator,
    type,
    verdict:      data.verdict?.threat_level,
    threat_level: data.verdict?.threat_level,
    score:        data.verdict?.score,
    tags:         data.verdict?.tags || [],
  };

  if (type === "ip") {
    return {
      ...base,
      country:            ti.country,
      asn:                ti.asn,
      isp:                ti.isp,
      vt_malicious:       ti.reputation?.virustotal?.malicious  ?? 0,
      vt_suspicious:      ti.reputation?.virustotal?.suspicious ?? 0,
      abuseipdb:          ti.reputation?.abuseipdb?.score       ?? 0,
      otx_pulses:         ti.reputation?.otx?.pulses            ?? 0,
      associated_domains: ti.associated_domains || [],
      associated_files:   ti.associated_files   || [],
    };
  }

  if (type === "hash") {
    return {
      ...base,
      file_type:     ti.file_type,
      first_seen:    ti.first_seen,
      vt_malicious:  ti.detection?.virustotal?.malicious  ?? 0,
      vt_suspicious: ti.detection?.virustotal?.suspicious ?? 0,
      vt_undetected: ti.detection?.virustotal?.undetected ?? 0,
      otx_pulses:    ti.detection?.otx?.pulses            ?? 0,
      mitre_attack:  ti.mitre_attack || [],
    };
  }

  if (type === "domain") {
    return {
      ...base,
      ip_domain:        ti.ip        || "N/A",  // ✅ ip → ip_domain
      registrar:        ti.registrar || "N/A",
      created:          ti.created   || "N/A",
      subdomains_count: ti.subdomains_count ?? 0,
      // ✅ global_risk_score supprimé
      vt_malicious:     ti.detection?.virustotal?.malicious  ?? 0,
      vt_suspicious:    ti.detection?.virustotal?.suspicious ?? 0,
    };
  }

  if (type === "url") {
    return {
      ...base,
      domain:        ti.domain || "N/A",
      ip:            ti.ip     || "N/A",
      // ✅ global_risk_score supprimé
      vt_malicious:  ti.detection?.virustotal?.malicious  ?? 0,
      vt_suspicious: ti.detection?.virustotal?.suspicious ?? 0,
      // ✅ GSB threats toujours affiché même si vide
      gsb_threats:   ti.detection?.google_safe_browsing?.threats || [],
      phishtank:     ti.detection?.phishtank?.verdict || "N/A",
    };
  }

  if (type === "mail") {
    return {
      ...base,
      mail_domain: ti.domain   || "N/A",  // ✅ domain → mail_domain
      provider:    ti.provider || "N/A",
      mx:    ti.security?.mx    || "missing",  // ✅ depuis security object
      spf:   ti.security?.spf   || "missing",
      dmarc: ti.security?.dmarc || "missing",
      alerts: ti.alerts || [],
    };
  }

  if (type === "cve") {
    return {
      ...base,
      severity:    ti.severity,
      cvss_score:  ti.cvss_score,
      cvss_vector: ti.cvss_vector,
      cwe:         ti.cwe || [],
      published:   ti.published,
    };
  }

  return { ...base, ...ti };
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
    if (type) {
      setInput(prev => `[${type}] ${stripIOCPrefix(prev)}`);
    } else {
      setInput(prev => stripIOCPrefix(prev));
    }
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
      const { data } = await api.post("/chatbot/message", {
        message:    clean,
        model:      selectedModel,
        session_id: selectedChat || undefined,
      });

      let botMsg;

      if (data.indicator) {
        botMsg = {
          id:        Date.now() + 1,
          role:      "bot",
          content:   `Analyse terminée — ${data.type?.toUpperCase()} : ${data.indicator}`,
          timestamp: now(),
          report:    buildReport(data),
        };
      } else {
        botMsg = {
          id:        Date.now() + 1,
          role:      "bot",
          content:   data.message || "Pas de réponse.",
          timestamp: now(),
        };
      }

      setMessages(prev => [...prev, botMsg]);

    } catch (err) {
      const errMsg = err.response?.data?.detail || "Erreur de connexion au backend.";
      setMessages(prev => [...prev, {
        id:        Date.now() + 1,
        role:      "bot",
        content:   `⚠ Erreur : ${errMsg}`,
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
    <div style={{ display:"flex", height:"100vh", background:th.bg, fontFamily:"'JetBrains Mono','Fira Code',monospace", color:th.text, overflow:"hidden" }}>
      <div style={{ position:"fixed", inset:0, pointerEvents:"none", zIndex:0, backgroundImage:darkMode?`linear-gradient(rgba(0,168,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,168,255,0.025) 1px,transparent 1px)`:"none", backgroundSize:"40px 40px" }} />

      {settingsOpen          && <SettingsModal   onClose={()=>setSettingsOpen(false)} darkMode={darkMode} setDarkMode={setDarkMode} onOpenAdminModal={(type)=>{ setSettingsOpen(false); setAdminModal(type); }} />}
      {adminModal==="create" && <CreateUserModal darkMode={darkMode} onClose={()=>setAdminModal(null)} />}
      {adminModal==="delete" && <DeleteUserModal darkMode={darkMode} onClose={()=>setAdminModal(null)} />}

      <ChatSidebar open={sidebarOpen} darkMode={darkMode} selectedChat={selectedChat} onSelectChat={setSelectedChat} onNewChat={handleNewChat} />

      <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden", position:"relative", zIndex:1 }}>
        <ChatTopBar
          darkMode={darkMode} sidebarOpen={sidebarOpen}
          onToggleSidebar={()=>setSidebarOpen(v=>!v)}
          onOpenSettings={()=>setSettingsOpen(true)}
          activeIOC={activeIOC} onSelectIOC={handleSelectIOC}
        />

        <div style={{ flex:1, overflowY:"auto", padding:"20px 24px", scrollbarWidth:"thin", scrollbarColor:`${th.scrollThumb} transparent` }}>
          {messages.map(msg => (
            <MessageBubble key={msg.id} msg={msg} darkMode={darkMode} />
          ))}
          {loading && <TypingIndicator darkMode={darkMode} />}
          <div ref={bottomRef} />
        </div>

        <ChatInput
          darkMode={darkMode} input={input} loading={loading}
          selectedModel={selectedModel} onModelChange={setSelectedModel}
          onInputChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendMessage()}
          onSend={sendMessage}
        />
      </div>

      <style>{`
        @keyframes fadeInUp  { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:translateY(0)} }
        @keyframes typingDot { 0%,100%{opacity:0.3;transform:scale(0.8)} 50%{opacity:1;transform:scale(1.2)} }
        ::-webkit-scrollbar{width:4px}
        ::-webkit-scrollbar-track{background:transparent}
        ::-webkit-scrollbar-thumb{background:${th.scrollThumb};border-radius:2px}
      `}</style>
    </div>
  );
}
