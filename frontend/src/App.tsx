import React from "react";
import { createRoot } from "react-dom/client";
import { Activity, ShieldAlert, Workflow } from "lucide-react";
import "./styles/app.css";

function App() {
  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">AI SOC</div>
        <button className="nav-item active"><Activity size={18} /> Overview</button>
        <button className="nav-item"><ShieldAlert size={18} /> Alerts</button>
        <button className="nav-item"><Workflow size={18} /> Automation</button>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <div>
            <p className="eyebrow">Wazuh-first MVP</p>
            <h1>AI SOC SOAR Command Center</h1>
          </div>
          <span className="status-pill">Base ready</span>
        </header>
        <section className="metric-grid">
          <article className="metric"><span>Total alerts</span><strong>128</strong></article>
          <article className="metric"><span>Noise reduced</span><strong>64%</strong></article>
          <article className="metric"><span>Open incidents</span><strong>7</strong></article>
          <article className="metric"><span>SOAR actions</span><strong>12</strong></article>
        </section>
        <section className="panel">
          <h2>Day 1 Foundation</h2>
          <p>
            Repository base, normalized alert model, Wazuh connector skeleton, project skills,
            and 7-day progress site are ready for implementation.
          </p>
        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
