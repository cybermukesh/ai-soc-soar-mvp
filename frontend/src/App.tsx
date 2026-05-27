import React from "react";
import { Activity, Bot, Database, Server, ShieldAlert, Workflow } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles/app.css";

const alerts = [
  { id: "demo-001", severity: "high", score: 53, rule: "5710", description: "Multiple SSH authentication failures", asset: "prod-linux-01", ip: "10.10.1.25", source: "203.0.113.45", mitre: "T1110" },
  { id: "demo-002", severity: "critical", score: 80, rule: "554", description: "File added to malware quarantine path", asset: "finance-workstation-03", ip: "10.20.4.33", source: "10.20.4.33", mitre: "T1204" },
  { id: "demo-003", severity: "high", score: 67, rule: "80792", description: "Cloud console root login detected", asset: "aws-prod", ip: "52.95.10.1", source: "198.51.100.77", mitre: "T1078" },
  { id: "demo-004", severity: "medium", score: 40, rule: "31151", description: "Multiple denied connections from same source", asset: "edge-firewall", ip: "10.0.0.1", source: "203.0.113.99", mitre: "T1046" },
];

function App() {
  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">AI SOC</div>
        <button className="nav-item active"><Activity size={18} /> Overview</button>
        <button className="nav-item"><ShieldAlert size={18} /> Wazuh Alerts</button>
        <button className="nav-item"><Bot size={18} /> AI Triage</button>
        <button className="nav-item"><Workflow size={18} /> Automation</button>
      </aside>
      <section className="workspace">
        <header className="topbar"><div><p className="eyebrow">Day 3 complete - Day 4 next</p><h1>AI SOC SOAR Command Center</h1></div><span className="status-pill">Wazuh pipeline ready</span></header>
        <section className="metric-grid">
          <article className="metric"><span>Normalized alerts</span><strong>{alerts.length}</strong></article>
          <article className="metric"><span>High/Critical</span><strong>3</strong></article>
          <article className="metric"><span>Mapped MITRE</span><strong>4</strong></article>
          <article className="metric"><span>Next build</span><strong>AI triage</strong></article>
        </section>
        <section className="panel"><div className="panel-title"><Server size={18} /><h2>Wazuh Pipeline Proof</h2></div><div className="pipeline"><article><strong>Wazuh / OpenSearch</strong><span>sample fixtures ready; live endpoint gated by credentials</span></article><article><strong>FastAPI</strong><span>/alerts/sample, /alerts/normalized, /alerts/normalize</span></article><article><strong>Normalized schema</strong><span>alert, rule, asset, user, network, MITRE</span></article><article><strong>Dashboard</strong><span>rendering normalized alert shape</span></article><article><strong>Next</strong><span>Day 4 low-token AI triage verdicts</span></article></div></section>
        <section className="panel"><div className="panel-title"><Database size={18} /><h2>Normalized Wazuh Alerts</h2></div><div className="alert-table"><div className="table-head"><span>Severity</span><span>Rule</span><span>Asset</span><span>Source</span><span>MITRE</span></div>{alerts.map((alert) => (<article className="alert-row" key={alert.id}><span className={`severity ${alert.severity}`}>{alert.severity}</span><span><strong>{alert.rule}</strong>{alert.description}</span><span><strong>{alert.asset}</strong>{alert.ip}</span><span>{alert.source}</span><span>{alert.mitre}</span></article>))}</div></section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
