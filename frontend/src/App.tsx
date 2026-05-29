import React from "react";
import { Activity, BarChart3, Bot, ClipboardList, Plug, ShieldAlert, Users, Workflow } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles/app.css";

const API = "http://localhost:8000";

type User = { id: number; email: string; full_name: string; role: "admin" | "analyst" | "viewer"; is_active: boolean };
type AuditLog = { id: number; actor_user_id: number; action: string; target_type: string; target_id: string; detail: string; created_at: string };
type Connector = { id: number; name: string; connector_type: string; base_url: string; username: string; password_masked: string; enabled: boolean; last_status: string; last_error: string; last_latency_ms: number; last_checked_at: string };
type ConnectorHistory = { id: number; connector_id: number; ok: boolean; detail: string; latency_ms: number; checked_by_user_id: number; created_at: string };
type AlertRecord = {
  alert_id: string;
  timestamp: string;
  severity: string;
  severity_score: number;
  source_tool: string;
  rule: { id: string; name: string; description: string; groups: string[] };
  asset: { hostname: string; ip: string; criticality: string };
  user: { name: string; risk_level: string };
  network: { src_ip: string; dst_ip: string; src_port: number | null; dst_port: number | null };
  mitre: { tactics: string[]; techniques: string[] };
  raw_event: Record<string, unknown>;
};
type Incident = { id: number; title: string; severity: string; status: string; risk_score: number; source_tool: string; alert_id: string; ticket_ref: string; owner_name: string; phase: string; summary: string; created_by_user_id: number; created_at: string };
type IncidentEvent = { id: number; incident_id: number; event_type: string; detail: string; actor_user_id: number; created_at: string };
type TriageDecision = {
  alert_id: string;
  verdict: "false_positive" | "low_priority" | "suspicious" | "true_positive" | "needs_review";
  confidence: number;
  risk_score: number;
  attack_summary: string;
  evidence: string[];
  impacted_entities: string[];
  investigation_steps: string[];
  containment_steps: string[];
  resolution_criteria: string[];
  analyst_questions: string[];
  recommended_actions: string[];
  mitre: { tactics?: string[]; techniques?: string[] };
  soar_recommendation: string;
  from_cache: boolean;
};
type TriageHistory = { alert_id: string; decision: TriageDecision | null; disposition: string; note: string; updated_at: string };

const verdictClass: Record<TriageDecision["verdict"], string> = {
  false_positive: "sev-low",
  low_priority: "sev-medium",
  suspicious: "sev-high",
  true_positive: "sev-critical",
  needs_review: "sev-medium",
};

function App() {
  const [token, setToken] = React.useState<string>(localStorage.getItem("token") || "");
  const [user, setUser] = React.useState<User | null>(null);
  const [authMode, setAuthMode] = React.useState<"login" | "register">("login");
  const [email, setEmail] = React.useState("admin@aisocmvp.com");
  const [password, setPassword] = React.useState("admin123");
  const [fullName, setFullName] = React.useState("");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [tab, setTab] = React.useState<"overview" | "connectors" | "triage" | "incidents" | "automation" | "admin">("overview");
  const [decisions, setDecisions] = React.useState<TriageDecision[]>([]);
  const [triageHistory, setTriageHistory] = React.useState<TriageHistory[]>([]);
  const [triageFeedback, setTriageFeedback] = React.useState({ disposition: "needs_investigation", note: "" });
  const [alerts, setAlerts] = React.useState<AlertRecord[]>([]);
  const [selectedAlertId, setSelectedAlertId] = React.useState<string>("");

  const [newUser, setNewUser] = React.useState({ email: "", full_name: "", password: "", role: "analyst" });
  const [adminMsg, setAdminMsg] = React.useState("");
  const [users, setUsers] = React.useState<User[]>([]);
  const [auditLogs, setAuditLogs] = React.useState<AuditLog[]>([]);
  const [auditFilter, setAuditFilter] = React.useState({ action: "", actor_user_id: "", target_type: "" });
  const [connectors, setConnectors] = React.useState<Connector[]>([]);
  const [connectorHistory, setConnectorHistory] = React.useState<ConnectorHistory[]>([]);
  const [connectorMsg, setConnectorMsg] = React.useState("");
  const [connectorForm, setConnectorForm] = React.useState({ name: "wazuh", base_url: "", username: "", password: "", enabled: true });
  const [incidents, setIncidents] = React.useState<Incident[]>([]);
  const [incidentEvents, setIncidentEvents] = React.useState<IncidentEvent[]>([]);
  const [incidentSelectedId, setIncidentSelectedId] = React.useState<number | null>(null);
  const [incidentFilter, setIncidentFilter] = React.useState({ q: "", status: "", severity: "" });
  const [incidentForm, setIncidentForm] = React.useState({ title: "", severity: "medium", risk_score: 50, source_tool: "wazuh", alert_id: "", ticket_ref: "", owner_name: "", phase: "new", summary: "" });
  const [incidentEventForm, setIncidentEventForm] = React.useState({ event_type: "note", detail: "" });
  const [incidentMsg, setIncidentMsg] = React.useState("");
  const healthyConnectors = connectors.filter((c) => c.last_status === "ok").length;
  const openIncidents = incidents.filter((i) => i.status !== "resolved").length;
  const highRiskAlerts = alerts.filter((a) => a.severity === "high" || a.severity === "critical").length;
  const avgRisk = Math.round((decisions.reduce((sum, d) => sum + d.risk_score, 0) / Math.max(decisions.length, 1)) || 0);
  const severityCounts = ["critical", "high", "medium", "low"].map((severity) => ({
    severity,
    count: alerts.filter((alert) => alert.severity === severity).length,
  }));
  const incidentColumns = [
    { label: "New", phases: ["new"], tone: "neutral" },
    { label: "Triage", phases: ["triage"], tone: "warning" },
    { label: "Investigation", phases: ["investigation"], tone: "active" },
    { label: "Response", phases: ["containment", "eradication", "recovery"], tone: "danger" },
    { label: "Closed", phases: ["closed"], tone: "done" },
  ];

  React.useEffect(() => {
    if (!token) return;
    fetch(`${API}/api/v1/auth/me`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("Session expired"))))
      .then((data: User) => setUser(data))
      .catch(() => {
        localStorage.removeItem("token");
        setToken("");
        setUser(null);
      });
  }, [token]);

  React.useEffect(() => {
    if (!token) return;
    fetch(`${API}/triage/alerts/recent?limit=25`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setDecisions(data.decisions || []))
      .catch(() => setDecisions([]));
    fetch(`${API}/triage/history?limit=50`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setTriageHistory(Array.isArray(data) ? data : []))
      .catch(() => setTriageHistory([]));
  }, [token]);

  React.useEffect(() => {
    if (!token) return;
    fetch(`${API}/alerts/wazuh/recent?limit=25`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => (r.ok ? r.json() : fetch(`${API}/alerts/normalized`, { headers: { Authorization: `Bearer ${token}` } }).then((x) => x.json())))
      .then((data) => setAlerts(Array.isArray(data) ? data : data.alerts || []))
      .catch(() => setAlerts([]));
  }, [token, connectorMsg, incidentMsg]);

  React.useEffect(() => {
    if (!token || user?.role !== "admin") return;
    fetch(`${API}/api/v1/auth/users`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setUsers(Array.isArray(data) ? data : []));
    const params = new URLSearchParams();
    if (auditFilter.action) params.set("action", auditFilter.action);
    if (auditFilter.actor_user_id) params.set("actor_user_id", auditFilter.actor_user_id);
    if (auditFilter.target_type) params.set("target_type", auditFilter.target_type);
    fetch(`${API}/api/v1/auth/audit-logs?${params.toString()}`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setAuditLogs(Array.isArray(data) ? data : []));
  }, [token, user?.role, adminMsg, auditFilter.action, auditFilter.actor_user_id, auditFilter.target_type]);

  React.useEffect(() => {
    if (!token) return;
    fetch(`${API}/api/v1/connectors`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setConnectors(Array.isArray(data) ? data : []));
  }, [token, adminMsg]);

  React.useEffect(() => {
    if (!token) return;
    const params = new URLSearchParams();
    if (incidentFilter.q) params.set("q", incidentFilter.q);
    if (incidentFilter.status) params.set("status", incidentFilter.status);
    if (incidentFilter.severity) params.set("severity", incidentFilter.severity);
    fetch(`${API}/api/v1/incidents?${params.toString()}`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setIncidents(Array.isArray(data) ? data : []))
      .catch(() => setIncidents([]));
  }, [token, incidentMsg, incidentFilter.q, incidentFilter.status, incidentFilter.severity]);

  async function refreshConnectors() {
    if (!token) return;
    const res = await fetch(`${API}/api/v1/connectors`, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    setConnectors(Array.isArray(data) ? data : []);
  }

  async function checkConnectorHealth(name: string) {
    const res = await fetch(`${API}/api/v1/connectors/${name}/health`, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    setConnectorMsg(`${name}: ${data.detail}`);
    refreshConnectors();
    const historyRes = await fetch(`${API}/api/v1/connectors/${name}/history`, { headers: { Authorization: `Bearer ${token}` } });
    const historyData = await historyRes.json();
    setConnectorHistory(Array.isArray(historyData) ? historyData : []);
  }

  async function saveConnector() {
    const res = await fetch(`${API}/api/v1/connectors/${connectorForm.name}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ base_url: connectorForm.base_url, username: connectorForm.username, password: connectorForm.password, enabled: connectorForm.enabled }),
    });
    const data = await res.json();
    setConnectorMsg(res.ok ? `Saved ${data.name}` : `Failed: ${data.detail || "error"}`);
    refreshConnectors();
  }

  async function seedConnectorsFromEnv() {
    const res = await fetch(`${API}/api/v1/connectors/seed-defaults`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    setConnectorMsg(res.ok ? "Seeded connectors from env" : "Failed to seed from env");
    refreshConnectors();
  }

  async function createIncident() {
    if (!incidentForm.title.trim()) {
      setIncidentMsg("Title is required");
      return;
    }
    const res = await fetch(`${API}/api/v1/incidents`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(incidentForm),
    });
    const data = await res.json();
    setIncidentMsg(res.ok ? `Created incident #${data.id}` : `Failed: ${data.detail || "error"}`);
  }

  async function updateIncidentStatus(incidentId: number, status: string) {
    const res = await fetch(`${API}/api/v1/incidents/${incidentId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ status, note: `set via dashboard to ${status}`, owner_name: incidentForm.owner_name, ticket_ref: incidentForm.ticket_ref, phase: incidentForm.phase }),
    });
    setIncidentMsg(res.ok ? `Updated incident #${incidentId}` : "Failed to update incident");
  }

  async function loadIncidentEvents(incidentId: number) {
    const res = await fetch(`${API}/api/v1/incidents/${incidentId}/events`, { headers: { Authorization: `Bearer ${token}` } });
    const data = await res.json();
    setIncidentSelectedId(incidentId);
    setIncidentEvents(Array.isArray(data) ? data : []);
  }

  async function addIncidentEvent() {
    if (!incidentSelectedId || !incidentEventForm.detail.trim()) return;
    const res = await fetch(`${API}/api/v1/incidents/${incidentSelectedId}/events`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(incidentEventForm),
    });
    if (res.ok) {
      setIncidentEventForm({ event_type: "note", detail: "" });
      loadIncidentEvents(incidentSelectedId);
    }
  }

  function raiseTicketFromAlert(alertId: string) {
    const alert = alerts.find((item) => item.alert_id === alertId);
    const decision = decisions.find((item) => item.alert_id === alertId);
    if (!alert) return;
    setIncidentForm({
      title: `${alert.rule.name} on ${alert.asset.hostname || "unknown-host"}`,
      severity: alert.severity,
      risk_score: decision?.risk_score || alert.severity_score,
      source_tool: alert.source_tool,
      alert_id: alert.alert_id,
      ticket_ref: "",
      owner_name: user?.full_name || "",
      phase: "new",
      summary: decision?.attack_summary || alert.rule.description,
    });
    setTab("incidents");
    setIncidentMsg(`Prepared incident form from alert ${alert.alert_id}`);
  }

  async function saveTriageFeedback(alertId: string) {
    const res = await fetch(`${API}/triage/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ alert_id: alertId, disposition: triageFeedback.disposition, note: triageFeedback.note }),
    });
    if (res.ok) {
      const history = await fetch(`${API}/triage/history?limit=50`, { headers: { Authorization: `Bearer ${token}` } }).then((r) => r.json());
      setTriageHistory(Array.isArray(history) ? history : []);
      setTriageFeedback({ disposition: "needs_investigation", note: "" });
    }
  }

  async function login() {
    setLoading(true);
    setError("");
    const res = await fetch(`${API}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      setError(data.detail || "Login failed");
      setLoading(false);
      return;
    }
    localStorage.setItem("token", data.access_token);
    setToken(data.access_token);
    setLoading(false);
  }

  async function register() {
    setLoading(true);
    setError("");
    const res = await fetch(`${API}/api/v1/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, full_name: fullName, password }),
    });
    const data = await res.json();
    if (!res.ok) {
      setError(data.detail || "Registration failed");
      setLoading(false);
      return;
    }
    setError(data.message || "Registration submitted");
    setAuthMode("login");
    setLoading(false);
  }

  async function logout() {
    if (token) {
      await fetch(`${API}/api/v1/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => undefined);
    }
    localStorage.removeItem("token");
    setToken("");
    setUser(null);
  }

  async function createUser() {
    setAdminMsg("");
    const res = await fetch(`${API}/api/v1/auth/users`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(newUser),
    });
    const data = await res.json();
    if (!res.ok) {
      setAdminMsg(`Failed: ${data.detail || "error"}`);
      return;
    }
    setAdminMsg(`Created user: ${data.email} (${data.role})`);
    setNewUser({ email: "", full_name: "", password: "", role: "analyst" });
  }

  async function toggleActive(userId: number, isActive: boolean) {
    const res = await fetch(`${API}/api/v1/auth/users/${userId}/active`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ is_active: !isActive }),
    });
    if (res.ok) setAdminMsg(`Updated user ${userId}`);
  }

  if (!token || !user) {
    return (
      <main className="login-shell">
        <section className="login-card">
          <h1>{authMode === "login" ? "AI SOC SOAR Login" : "Register Access"}</h1>
          <p>{authMode === "login" ? "Phase-1 Auth + RBAC enabled" : "New accounts are created as viewer and require admin approval."}</p>
          {authMode === "register" ? <input value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Full name" /> : null}
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
          {error ? <span className="error">{error}</span> : null}
          <button onClick={authMode === "login" ? login : register} disabled={loading}>
            {loading ? "Working..." : authMode === "login" ? "Sign in" : "Register"}
          </button>
          <button className="secondary-button" onClick={() => { setError(""); setAuthMode(authMode === "login" ? "register" : "login"); }} disabled={loading}>
            {authMode === "login" ? "Need an account?" : "Back to login"}
          </button>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">AI SOC</div>
        <button className={`nav-item ${tab === "overview" ? "active" : ""}`} onClick={() => setTab("overview")}><BarChart3 size={18} /> Executive</button>
        <button className={`nav-item ${tab === "connectors" ? "active" : ""}`} onClick={() => setTab("connectors")}><Plug size={18} /> Connectors</button>
        <button className={`nav-item ${tab === "triage" ? "active" : ""}`} onClick={() => setTab("triage")}><ShieldAlert size={18} /> AI Triage</button>
        <button className={`nav-item ${tab === "incidents" ? "active" : ""}`} onClick={() => setTab("incidents")}><ClipboardList size={18} /> Cases</button>
        <button className={`nav-item ${tab === "automation" ? "active" : ""}`} onClick={() => setTab("automation")}><Workflow size={18} /> Automation</button>
        {user.role === "admin" ? <button className={`nav-item ${tab === "admin" ? "active" : ""}`} onClick={() => setTab("admin")}><Users size={18} /> Admin</button> : null}
        <button className="nav-item" onClick={logout}><Bot size={18} /> Logout</button>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <div><p className="eyebrow">Authenticated Session</p><h1>AI SOC SOAR Command Center</h1></div>
          <span className="status-pill">{user.full_name} - {user.role}</span>
        </header>

        {tab === "overview" ? (
          <>
            <section className="exec-hero">
              <div>
                <p className="eyebrow">Executive Summary</p>
                <h2>SOC posture from live Wazuh telemetry</h2>
                <p>{alerts.length} alerts are available for triage. {highRiskAlerts} are high-risk. Average AI risk is {avgRisk}. {openIncidents} cases remain active.</p>
              </div>
              <div className="exec-score">
                <span>Risk Index</span>
                <strong>{avgRisk}</strong>
              </div>
            </section>
            <section className="metric-grid">
              <article className="metric"><span>Connectors</span><strong>{connectors.length}</strong></article>
              <article className="metric"><span>Healthy Connectors</span><strong>{healthyConnectors}</strong></article>
              <article className="metric"><span>Open Incidents</span><strong>{openIncidents}</strong></article>
              <article className="metric"><span>Triage Decisions</span><strong>{decisions.length}</strong></article>
            </section>
            <section className="dashboard-grid">
              <article className="panel">
                <h2>Alert Severity Distribution</h2>
                <div className="bar-list">
                  {severityCounts.map((item) => (
                    <div className="bar-row" key={item.severity}>
                      <span>{item.severity}</span>
                      <div><i style={{ width: `${Math.max(8, (item.count / Math.max(alerts.length, 1)) * 100)}%` }} /></div>
                      <strong>{item.count}</strong>
                    </div>
                  ))}
                </div>
              </article>
              <article className="panel">
                <h2>Connector Status</h2>
                <div className="mini-list">
                  {connectors.map((c) => (
                    <span key={c.id}><b>{c.name}</b><em className={`state-pill state-${c.last_status || "unknown"}`}>{c.last_status || "unknown"}</em></span>
                  ))}
                </div>
              </article>
              <article className="panel wide-panel">
                <h2>Latest Live Alerts</h2>
                <div className="compact-feed">
                  {alerts.slice(0, 6).map((alert) => (
                    <button key={alert.alert_id} onClick={() => { setSelectedAlertId(alert.alert_id); setTab("triage"); }}>
                      <span>{alert.severity}</span>
                      <strong>{alert.rule.name}</strong>
                      <em>{alert.asset.hostname || "unknown"} | {alert.network.src_ip || "no source ip"}</em>
                    </button>
                  ))}
                </div>
              </article>
            </section>
          </>
        ) : null}
        {tab === "connectors" ? (
          <section className="panel">
            <div className="section-title">
              <div><h2>Connector Access Center</h2><p>Live health, credentials state, and audit-backed connectivity checks.</p></div>
              <span className="status-pill">{healthyConnectors}/{connectors.length} healthy</span>
            </div>
            {user.role === "admin" ? <div className="admin-form">
              <select value={connectorForm.name} onChange={(e) => setConnectorForm({ ...connectorForm, name: e.target.value })}><option value="wazuh">wazuh</option><option value="opensearch">opensearch</option></select>
              <input placeholder="Base URL" value={connectorForm.base_url} onChange={(e) => setConnectorForm({ ...connectorForm, base_url: e.target.value })} />
              <input placeholder="Username" value={connectorForm.username} onChange={(e) => setConnectorForm({ ...connectorForm, username: e.target.value })} />
              <input placeholder="Password" type="password" value={connectorForm.password} onChange={(e) => setConnectorForm({ ...connectorForm, password: e.target.value })} />
              <button onClick={saveConnector}>Save connector</button>
              <button onClick={seedConnectorsFromEnv}>Seed from env</button>
            </div> : null}
            {connectorMsg ? <p>{connectorMsg}</p> : null}
            <div className="connector-grid">
              {connectors.map((c) => (
                <article key={c.id} className="connector-card">
                  <span>
                    <strong>{c.name}</strong>
                    <span className={`state-pill state-${c.last_status || "unknown"}`}>{c.last_status || "unknown"}</span>
                    <span className="muted-line">{c.base_url || "base url not set"}</span>
                    <span className="muted-line">latency: {c.last_latency_ms}ms | checked: {c.last_checked_at || "-"}</span>
                    {c.last_error ? <span className="error-line">{c.last_error}</span> : null}
                  </span>
                  <button onClick={() => checkConnectorHealth(c.name)} disabled={user.role === "viewer"}>Check health</button>
                </article>
              ))}
            </div>
            <h3>Connector Access and Settings</h3>
            <div className="admin-list">
              {connectors.map((c) => (
                <article key={`${c.id}-settings`} className="admin-item">
                  <span>{c.name} | user={c.username || "-"} | access={c.enabled ? "enabled" : "disabled"} | secret={c.password_masked ? "configured" : "missing"}</span>
                </article>
              ))}
            </div>
            <h3>Recent Health Checks</h3>
            <div className="admin-list">
              {connectorHistory.slice(0, 10).map((h) => (
                <article key={h.id} className="admin-item">
                  <span>{h.created_at} | ok={String(h.ok)} | latency={h.latency_ms}ms | {h.detail}</span>
                </article>
              ))}
            </div>
          </section>
        ) : null}

        {tab === "triage" ? (
          <section className="panel">
            <div className="section-title">
              <div><h2>AI Triage Workbench</h2><p>Analyst view with evidence, MITRE context, raw event data, and case handoff.</p></div>
              <span className="status-pill">{decisions.length} decisions</span>
            </div>
            <div className="alert-table">
              <div className="table-head"><span>Alert</span><span>Verdict</span><span>Confidence</span><span>Risk</span><span>SOAR</span></div>
              {decisions.map((d) => (
                <article className="alert-row" key={d.alert_id} onClick={() => setSelectedAlertId(d.alert_id)}>
                  <span><strong>{d.alert_id}</strong>{d.attack_summary}</span>
                  <span className={`severity ${verdictClass[d.verdict]}`}>{d.verdict}</span>
                  <span>{d.confidence}</span>
                  <span>{d.risk_score}</span>
                  <span>{d.soar_recommendation}{d.from_cache ? " (cache)" : ""}</span>
                </article>
              ))}
            </div>
            {selectedAlertId ? (
              <section className="panel detail-panel">
                <h3>Alert Detail {selectedAlertId}</h3>
                {(() => {
                  const alert = alerts.find((item) => item.alert_id === selectedAlertId);
                  const decision = decisions.find((item) => item.alert_id === selectedAlertId);
                  const history = triageHistory.find((item) => item.alert_id === selectedAlertId);
                  if (!alert || !decision) return <p>Alert detail unavailable.</p>;
                  return (
                    <div className="detail-grid">
                      <article>
                        <strong>Investigation Context</strong>
                        <p>{decision.attack_summary}</p>
                        <p>Asset: {alert.asset.hostname || "-"} | User: {alert.user.name || "-"} | Source IP: {alert.network.src_ip || "-"}</p>
                        <p>MITRE: {(decision.mitre.techniques || alert.mitre.techniques).join(", ") || "-"}</p>
                        <p>Disposition: {history?.disposition || "not reviewed"} {history?.updated_at ? `| ${history.updated_at}` : ""}</p>
                      </article>
                      <article>
                        <strong>Evidence</strong>
                        <ul className="check-list">{decision.evidence.map((item) => <li key={item}>{item}</li>)}</ul>
                        <strong>Impacted Entities</strong>
                        <ul className="check-list">{decision.impacted_entities.map((item) => <li key={item}>{item}</li>)}</ul>
                      </article>
                      <article>
                        <strong>L2 Investigation Steps</strong>
                        <ol className="check-list">{decision.investigation_steps.map((item) => <li key={item}>{item}</li>)}</ol>
                        <strong>Recommended Actions</strong>
                        <ul className="check-list">{decision.recommended_actions.map((item) => <li key={item}>{item}</li>)}</ul>
                      </article>
                      <article>
                        <strong>Containment Steps</strong>
                        <ul className="check-list">{decision.containment_steps.map((item) => <li key={item}>{item}</li>)}</ul>
                        <strong>Resolution Criteria</strong>
                        <ul className="check-list">{decision.resolution_criteria.map((item) => <li key={item}>{item}</li>)}</ul>
                      </article>
                      <article>
                        <strong>Analyst Questions</strong>
                        <ul className="check-list">{decision.analyst_questions.map((item) => <li key={item}>{item}</li>)}</ul>
                        <div className="triage-feedback">
                          <select value={triageFeedback.disposition} onChange={(e) => setTriageFeedback({ ...triageFeedback, disposition: e.target.value })}>
                            <option value="needs_investigation">needs investigation</option>
                            <option value="true_positive">true positive</option>
                            <option value="false_positive">false positive</option>
                            <option value="duplicate">duplicate</option>
                            <option value="resolved">resolved</option>
                          </select>
                          <input placeholder="Analyst note / resolution summary" value={triageFeedback.note} onChange={(e) => setTriageFeedback({ ...triageFeedback, note: e.target.value })} />
                          <button onClick={() => saveTriageFeedback(alert.alert_id)}>Save review</button>
                        </div>
                        {history?.note ? <p>Last note: {history.note}</p> : null}
                      </article>
                      <article className="raw-event">
                        <strong>Raw Event Access</strong>
                        <pre>{JSON.stringify(alert.raw_event, null, 2)}</pre>
                      </article>
                      <article>
                        <button onClick={() => raiseTicketFromAlert(alert.alert_id)}>Raise ticket</button>
                      </article>
                    </div>
                  );
                })()}
              </section>
            ) : null}
            <section className="panel detail-panel">
              <h3>Triage Review History</h3>
              <div className="admin-list">
                {triageHistory.slice(0, 12).map((item) => (
                  <article className="admin-item" key={`${item.alert_id}-${item.updated_at}`}>
                    <span>{item.updated_at || "-"} | {item.alert_id} | {item.disposition || "pending"} | {item.note || "no note"}</span>
                  </article>
                ))}
              </div>
            </section>
          </section>
        ) : null}

        {tab === "incidents" ? (
          <section className="panel">
            <div className="section-title">
              <div><h2>Case Management Board</h2><p>Jira-style SOC lifecycle from new alert to closure, with owner, ticket, and timeline.</p></div>
              <span className="status-pill">{openIncidents} active</span>
            </div>
            {(user.role === "admin" || user.role === "analyst") ? (
              <div className="admin-form">
                <input placeholder="Title" value={incidentForm.title} onChange={(e) => setIncidentForm({ ...incidentForm, title: e.target.value })} />
                <select value={incidentForm.severity} onChange={(e) => setIncidentForm({ ...incidentForm, severity: e.target.value })}>
                  <option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
                </select>
                <input type="number" min={0} max={100} value={incidentForm.risk_score} onChange={(e) => setIncidentForm({ ...incidentForm, risk_score: Number(e.target.value) || 0 })} />
                <input placeholder="Source tool" value={incidentForm.source_tool} onChange={(e) => setIncidentForm({ ...incidentForm, source_tool: e.target.value })} />
                <input placeholder="Source alert id" value={incidentForm.alert_id} onChange={(e) => setIncidentForm({ ...incidentForm, alert_id: e.target.value })} />
                <input placeholder="Ticket ref" value={incidentForm.ticket_ref} onChange={(e) => setIncidentForm({ ...incidentForm, ticket_ref: e.target.value })} />
                <input placeholder="Owner" value={incidentForm.owner_name} onChange={(e) => setIncidentForm({ ...incidentForm, owner_name: e.target.value })} />
                <select value={incidentForm.phase} onChange={(e) => setIncidentForm({ ...incidentForm, phase: e.target.value })}>
                  <option value="new">new</option><option value="triage">triage</option><option value="investigation">investigation</option><option value="containment">containment</option><option value="eradication">eradication</option><option value="recovery">recovery</option><option value="closed">closed</option>
                </select>
                <input placeholder="Case summary" value={incidentForm.summary} onChange={(e) => setIncidentForm({ ...incidentForm, summary: e.target.value })} />
                <button onClick={createIncident}>Create incident</button>
              </div>
            ) : null}
            <div className="admin-form">
              <input placeholder="Search title" value={incidentFilter.q} onChange={(e) => setIncidentFilter({ ...incidentFilter, q: e.target.value })} />
              <select value={incidentFilter.status} onChange={(e) => setIncidentFilter({ ...incidentFilter, status: e.target.value })}>
                <option value="">all status</option><option value="open">open</option><option value="investigating">investigating</option><option value="resolved">resolved</option>
              </select>
              <select value={incidentFilter.severity} onChange={(e) => setIncidentFilter({ ...incidentFilter, severity: e.target.value })}>
                <option value="">all severity</option><option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
              </select>
            </div>
            {incidentMsg ? <p>{incidentMsg}</p> : null}
            <div className="case-board">
              {incidentColumns.map((column) => (
                <section className={`case-column column-${column.tone}`} key={column.label}>
                  <h3>{column.label}</h3>
                  {incidents.filter((i) => column.phases.includes(i.phase || "new")).map((i) => (
                    <article className="case-card" key={i.id}>
                      <div>
                        <strong>#{i.id} {i.title}</strong>
                        <span>{i.severity} | risk {i.risk_score} | {i.ticket_ref || "no ticket"}</span>
                        <p>{i.summary || "No summary captured yet."}</p>
                      </div>
                      <div className="incident-actions">
                        <button onClick={() => loadIncidentEvents(i.id)}>Timeline</button>
                        {(user.role === "admin" || user.role === "analyst") ? (
                          <>
                            <button onClick={() => updateIncidentStatus(i.id, "investigating")}>Investigate</button>
                            <button onClick={() => updateIncidentStatus(i.id, "resolved")}>Resolve</button>
                          </>
                        ) : null}
                      </div>
                    </article>
                  ))}
                </section>
              ))}
            </div>
            {incidentSelectedId ? (
              <>
                <h3>Incident Timeline #{incidentSelectedId}</h3>
                {(user.role === "admin" || user.role === "analyst") ? (
                  <div className="admin-form">
                    <select value={incidentEventForm.event_type} onChange={(e) => setIncidentEventForm({ ...incidentEventForm, event_type: e.target.value })}>
                      <option value="note">note</option><option value="ticket_raised">ticket_raised</option><option value="investigation">investigation</option><option value="containment">containment</option><option value="recovery">recovery</option>
                    </select>
                    <input placeholder="Investigation note / action detail" value={incidentEventForm.detail} onChange={(e) => setIncidentEventForm({ ...incidentEventForm, detail: e.target.value })} />
                    <button onClick={addIncidentEvent}>Add event</button>
                  </div>
                ) : null}
                <div className="admin-list">
                  {incidentEvents.map((e) => (
                    <article className="admin-item" key={e.id}>
                      <span>{e.event_type} - {e.detail} - user {e.actor_user_id} - {e.created_at}</span>
                    </article>
                  ))}
                </div>
              </>
            ) : null}
          </section>
        ) : null}

        {tab === "automation" ? <section className="panel"><h2>SOAR Hooks (Day 4 target)</h2><p>Approval-gated n8n/Shuffle execution panel will be enabled in Day 4 build.</p></section> : null}

        {tab === "admin" && user.role === "admin" ? (
          <section className="panel">
            <h2>Create User</h2>
            <div className="admin-form">
              <input placeholder="Email" value={newUser.email} onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} />
              <input placeholder="Full name" value={newUser.full_name} onChange={(e) => setNewUser({ ...newUser, full_name: e.target.value })} />
              <input type="password" placeholder="Password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} />
              <select value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
                <option value="admin">admin</option>
                <option value="analyst">analyst</option>
                <option value="viewer">viewer</option>
              </select>
              <button onClick={createUser}>Create user</button>
            </div>
            {adminMsg ? <p>{adminMsg}</p> : null}
            <h3>Users</h3>
            <div className="admin-list">
              {users.map((u) => (
                <article key={u.id} className="admin-item">
                  <span>{u.email} ({u.role})</span>
                  <button onClick={() => toggleActive(u.id, u.is_active)}>{u.is_active ? "Deactivate" : "Activate"}</button>
                </article>
              ))}
            </div>
            <h3>Audit Logs</h3>
            <div className="admin-form">
              <input placeholder="action (e.g. login_success)" value={auditFilter.action} onChange={(e) => setAuditFilter({ ...auditFilter, action: e.target.value })} />
              <input placeholder="actor_user_id" value={auditFilter.actor_user_id} onChange={(e) => setAuditFilter({ ...auditFilter, actor_user_id: e.target.value })} />
              <input placeholder="target_type (auth/user/connector)" value={auditFilter.target_type} onChange={(e) => setAuditFilter({ ...auditFilter, target_type: e.target.value })} />
            </div>
            <div className="admin-list">
              {auditLogs.slice(0, 20).map((log) => (
                <article key={log.id} className="admin-item">
                  <span>#{log.id} {log.action} {log.target_type}:{log.target_id} - {log.detail}</span>
                </article>
              ))}
            </div>
            <h3>Connector Health History</h3>
            <div className="admin-list">
              {connectorHistory.slice(0, 20).map((h) => (
                <article key={h.id} className="admin-item">
                  <span>#{h.id} connector={h.connector_id} ok={String(h.ok)} latency={h.latency_ms}ms user={h.checked_by_user_id} {h.detail}</span>
                </article>
              ))}
            </div>
          </section>
        ) : null}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
