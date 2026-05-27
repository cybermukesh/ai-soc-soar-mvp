import React from "react";
import { Activity, Bot, Database, Server, ShieldAlert, Workflow } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles/app.css";

type TriageDecision = {
  alert_id: string;
  verdict: "false_positive" | "low_priority" | "suspicious" | "true_positive" | "needs_review";
  confidence: number;
  risk_score: number;
  attack_summary: string;
  soar_recommendation: string;
  from_cache: boolean;
};

type BatchResponse = { decisions: TriageDecision[] };

const verdictClass: Record<TriageDecision["verdict"], string> = {
  false_positive: "sev-low",
  low_priority: "sev-medium",
  suspicious: "sev-high",
  true_positive: "sev-critical",
  needs_review: "sev-medium",
};

function App() {
  const [decisions, setDecisions] = React.useState<TriageDecision[]>([]);
  const [loading, setLoading] = React.useState(true);
  React.useEffect(() => {
    fetch("http://localhost:8000/triage/sample")
      .then((r) => r.json())
      .then((data: BatchResponse) => setDecisions(data.decisions || []))
      .finally(() => setLoading(false));
  }, []);
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
        <header className="topbar">
          <div>
            <p className="eyebrow">Day 4 complete - Day 5 next</p>
            <h1>AI SOC SOAR Command Center</h1>
          </div>
          <span className="status-pill">Low-token triage ready</span>
        </header>

        <section className="metric-grid">
          <article className="metric"><span>Triage decisions</span><strong>{decisions.length}</strong></article>
          <article className="metric"><span>Suspicious/TP</span><strong>{decisions.filter((d) => d.verdict === "suspicious" || d.verdict === "true_positive").length}</strong></article>
          <article className="metric"><span>Cache hits</span><strong>{decisions.filter((d) => d.from_cache).length}</strong></article>
          <article className="metric"><span>Next build</span><strong>Incidents</strong></article>
        </section>

        <section className="panel">
          <div className="panel-title">
            <Server size={18} />
            <h2>Day 4 Proof</h2>
          </div>
          <div className="pipeline">
            <article><strong>Structured JSON</strong><span>`/triage/alert` returns verdict, confidence, risk, evidence, and SOAR recommendation.</span></article>
            <article><strong>Batch Endpoint</strong><span>`/triage/sample` triages normalized Wazuh fixtures in one request.</span></article>
            <article><strong>Persistent backend</strong><span>SQLite runtime store keeps alerts and triage decisions across restarts.</span></article>
            <article><strong>Prompt-safe behavior</strong><span>Heuristic path treats log fields as untrusted input and stays approval-gated.</span></article>
            <article><strong>Next</strong><span>Day 5 incident grouping and noise reduction metrics.</span></article>
          </div>
        </section>

        <section className="panel">
          <div className="panel-title">
            <Database size={18} />
            <h2>Triage Decisions</h2>
          </div>
          <div className="alert-table">
            <div className="table-head">
              <span>Alert</span>
              <span>Verdict</span>
              <span>Confidence</span>
              <span>Risk</span>
              <span>SOAR</span>
            </div>
            {loading ? <article className="alert-row"><span>Loading triage decisions...</span><span>-</span><span>-</span><span>-</span><span>-</span></article> : decisions.map((decision) => (
              <article className="alert-row" key={decision.alert_id}>
                <span><strong>{decision.alert_id}</strong>{decision.attack_summary}</span>
                <span className={`severity ${verdictClass[decision.verdict]}`}>{decision.verdict}</span>
                <span>{decision.confidence}</span>
                <span>{decision.risk_score}</span>
                <span>{decision.soar_recommendation}{decision.from_cache ? " (cache)" : ""}</span>
              </article>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
