import InfoPageLayout from "./InfoPageLayout";

const BRAND_GREEN = "#7FD832";
const CYAN = "#00d4ff";

const prose = { color:"#a8c4d8", fontSize:"0.92rem", lineHeight:1.8, fontFamily:"'JetBrains Mono',monospace" };
const bullet = { display:"flex", alignItems:"flex-start", gap:"10px", marginBottom:"0.6rem" };

export default function PlatformOverviewPage({ onNavigate }) {
  return (
    <InfoPageLayout
      onBack={() => onNavigate("home")}
      badge="PLATFORM ARCHITECTURE"
      title="Platform Overview"
      subtitle="Threat Intelligence Correlation Engine"
    >
      <p style={{ ...prose, marginBottom:"1.6rem" }}>
        The platform is built as a centralized Threat Intelligence engine powered by a FastAPI backend.
      </p>

      <p style={{ ...prose, marginBottom:"1.6rem" }}>
        When an IOC is submitted (such as an IP address, file hash, domain, or URL), the system automatically
        sends requests to multiple external threat intelligence sources simultaneously, including services like
        VirusTotal, Shodan, and URL scanning tools.
      </p>

      <p style={{ ...prose, marginBottom:"1.6rem" }}>
        Each source provides partial information about the IOC, such as reputation, known malicious activity,
        or related threats. The platform then aggregates and correlates all these results into a unified and
        structured response.
      </p>

      <div style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:"0.75rem", letterSpacing:"0.2em", color:BRAND_GREEN, fontWeight:"700", marginBottom:"1rem" }}>
        KEY FUNCTIONALITIES:
      </div>
      {[
        "Multi-source data collection in real time",
        "Parallel API requests for faster results",
        "Correlation and aggregation of threat data",
        "Structured JSON output for easy interpretation",
      ].map(t => (
        <div key={t} style={bullet}>
          <span style={{ color:BRAND_GREEN, fontWeight:"700", flexShrink:0 }}>-</span>
          <span style={prose}>{t}</span>
        </div>
      ))}

      <div style={{ height:"1px", background:`linear-gradient(90deg, ${CYAN}60, transparent)`, margin:"1.8rem 0" }} />

      <p style={{ ...prose, marginBottom:"1.2rem" }}>
        This approach eliminates the need for analysts to manually query multiple tools, significantly
        reducing investigation time.
      </p>

      <p style={{ ...prose, marginBottom:"1.2rem" }}>
        The platform is directly integrated with the chatbot:
      </p>

      {[
        "The chatbot sends IOC queries to the backend",
        "The backend returns enriched threat intelligence data",
        "The AI model interprets and explains the results in natural language",
      ].map(t => (
        <div key={t} style={bullet}>
          <span style={{ color:CYAN, fontWeight:"700", flexShrink:0 }}>-</span>
          <span style={prose}>{t}</span>
        </div>
      ))}

      <div style={{ height:"1px", background:`linear-gradient(90deg, rgba(127,216,50,0.4), transparent)`, margin:"1.8rem 0" }} />

      <p style={prose}>
        This combination of automation and AI provides a powerful tool for faster, clearer, and more reliable
        cybersecurity analysis.
      </p>
    </InfoPageLayout>
  );
}
