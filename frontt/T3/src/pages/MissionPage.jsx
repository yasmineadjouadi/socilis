import InfoPageLayout from "./InfoPageLayout";

const BRAND_GREEN = "#7FD832";
const CYAN = "#00d4ff";

const prose = { color:"#a8c4d8", fontSize:"0.92rem", lineHeight:1.8, fontFamily:"'JetBrains Mono',monospace" };
const bullet = { display:"flex", alignItems:"flex-start", gap:"10px", marginBottom:"0.6rem" };

export default function MissionPage({ onNavigate }) {
  return (
    <InfoPageLayout
      onBack={() => onNavigate("home")}
      badge="PROJECT MISSION"
      title="Mission & Objectives"
      subtitle="AI-Powered SOC Assistance"
    >
      <p style={{ ...prose, marginBottom:"1.6rem" }}>
        The mission of this project is to simplify and accelerate cybersecurity analysis by providing an
        intelligent assistant dedicated to SOC analysts.
      </p>

      <p style={{ ...prose, marginBottom:"1.6rem" }}>
        In traditional workflows, analysts must manually investigate each Indicator of Compromise (IOC) by
        querying multiple platforms and interpreting scattered data. This process is time-consuming and can
        delay incident response.
      </p>

      <p style={{ ...prose, marginBottom:"1.6rem" }}>
        This platform addresses these challenges by centralizing analysis and integrating artificial
        intelligence into the workflow.
      </p>

      <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"0.75rem", letterSpacing:"0.2em", color:BRAND_GREEN, fontWeight:"700", marginBottom:"1rem" }}>
        MAIN OBJECTIVES:
      </div>
      {[
        "Automate the analysis of IOCs (IP, hash, domain, URL, email, CVE)",
        "Reduce investigation and response time",
        "Improve the accuracy and consistency of threat interpretation",
        "Assist analysts with clear, contextual, and actionable insights",
      ].map(t => (
        <div key={t} style={bullet}>
          <span style={{ color:BRAND_GREEN, fontWeight:"700", flexShrink:0 }}>-</span>
          <span style={prose}>{t}</span>
        </div>
      ))}

      <div style={{ height:"1px", background:`linear-gradient(90deg, ${CYAN}60, transparent)`, margin:"1.8rem 0" }} />

      <p style={{ ...prose, marginBottom:"1.6rem" }}>
        The system is designed not to replace analysts, but to enhance their capabilities by reducing
        repetitive tasks and providing faster access to relevant threat intelligence.
      </p>

      <p style={prose}>
        Ultimately, the goal is to create a smarter and more efficient SOC environment where decisions
        can be made quickly and confidently.
      </p>
    </InfoPageLayout>
  );
}
