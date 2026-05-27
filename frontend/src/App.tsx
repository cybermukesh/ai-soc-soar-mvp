import React from "react";
import { Activity, Bot, Plug, ShieldAlert, Users, Workflow } from "lucide-react";
import { createRoot } from "react-dom/client";
import "./styles/app.css";

const API = "http://localhost:8000";

type User = { id: number; email: string; full_name: string; role: "admin" | "analyst" | "viewer"; is_active: boolean };
type AuditLog = { id: number; actor_user_id: number; action: string; target_type: string; target_id: string; detail: string; created_at: string };
type Connector = { id: number; name: string; connector_type: string; base_url: string; username: string; password_masked: string; enabled: boolean; last_status: string; last_error: string; last_latency_ms: number; last_checked_at: string };
type ConnectorHistory = { id: number; connector_id: number; ok: boolean; detail: string; latency_ms: number; checked_by_user_id: number; created_at: string };
type Incident = { id: number; title: string; severity: string; status: string; risk_score: number; source_tool: string; created_by_user_id: number; created_at: string };
type TriageDecision = {
  alert_id: string;
  verdict: "false_positive" | "low_priority" | "suspicious" | "true_positive" | "needs_review";
  confidence: number;
  risk_score: number;
  attack_summary: string;
  soar_recommendation: string;
  from_cache: boolean;
};

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
  const [email, setEmail] = React.useState("admin@aisocmvp.com");
  const [password, setPassword] = React.useState("admin123");
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [tab, setTab] = React.useState<"overview" | "connectors" | "triage" | "incidents" | "automation" | "admin">("overview");
  const [decisions, setDecisions] = React.useState<TriageDecision[]>([]);

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
  const [incidentForm, setIncidentForm] = React.useState({ title: "", severity: "medium", risk_score: 50, source_tool: "wazuh" });
  const [incidentMsg, setIncidentMsg] = React.useState("");

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
    fetch(`${API}/triage/sample`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setDecisions(data.decisions || []))
      .catch(() => setDecisions([]));
  }, [token]);

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
    fetch(`${API}/api/v1/incidents`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setIncidents(Array.isArray(data) ? data : []))
      .catch(() => setIncidents([]));
  }, [token, incidentMsg]);

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
      body: JSON.stringify({ status, note: `set via dashboard to ${status}` }),
    });
    setIncidentMsg(res.ok ? `Updated incident #${incidentId}` : "Failed to update incident");
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
          <h1>AI SOC SOAR Login</h1>
          <p>Phase-1 Auth + RBAC enabled</p>
          <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Email" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" type="password" />
          {error ? <span className="error">{error}</span> : null}
          <button onClick={login} disabled={loading}>{loading ? "Signing in..." : "Sign in"}</button>
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">AI SOC</div>
        <button className={`nav-item ${tab === "overview" ? "active" : ""}`} onClick={() => setTab("overview")}><Activity size={18} /> Overview</button>
        <button className={`nav-item ${tab === "connectors" ? "active" : ""}`} onClick={() => setTab("connectors")}><Plug size={18} /> Connectors</button>
        <button className={`nav-item ${tab === "triage" ? "active" : ""}`} onClick={() => setTab("triage")}><ShieldAlert size={18} /> AI Triage</button>
        <button className={`nav-item ${tab === "incidents" ? "active" : ""}`} onClick={() => setTab("incidents")}><Activity size={18} /> Incidents</button>
        <button className={`nav-item ${tab === "automation" ? "active" : ""}`} onClick={() => setTab("automation")}><Workflow size={18} /> Automation</button>
        {user.role === "admin" ? <button className={`nav-item ${tab === "admin" ? "active" : ""}`} onClick={() => setTab("admin")}><Users size={18} /> Admin</button> : null}
        <button className="nav-item" onClick={() => { localStorage.removeItem("token"); setToken(""); setUser(null); }}><Bot size={18} /> Logout</button>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <div><p className="eyebrow">Authenticated Session</p><h1>AI SOC SOAR Command Center</h1></div>
          <span className="status-pill">{user.full_name} - {user.role}</span>
        </header>

        {tab === "overview" ? <section className="panel"><h2>Platform Status</h2><p>Backend API, JWT auth, RBAC roles, and triage endpoints are active.</p></section> : null}
        {tab === "connectors" ? (
          <section className="panel">
            <h2>Connector Health</h2>
            {user.role === "admin" ? <div className="admin-form">
              <select value={connectorForm.name} onChange={(e) => setConnectorForm({ ...connectorForm, name: e.target.value })}><option value="wazuh">wazuh</option><option value="opensearch">opensearch</option></select>
              <input placeholder="Base URL" value={connectorForm.base_url} onChange={(e) => setConnectorForm({ ...connectorForm, base_url: e.target.value })} />
              <input placeholder="Username" value={connectorForm.username} onChange={(e) => setConnectorForm({ ...connectorForm, username: e.target.value })} />
              <input placeholder="Password" type="password" value={connectorForm.password} onChange={(e) => setConnectorForm({ ...connectorForm, password: e.target.value })} />
              <button onClick={saveConnector}>Save connector</button>
              <button onClick={seedConnectorsFromEnv}>Seed from env</button>
            </div> : null}
            {connectorMsg ? <p>{connectorMsg}</p> : null}
            <div className="admin-list">
              {connectors.map((c) => (
                <article key={c.id} className="admin-item">
                  <span><strong>{c.name}</strong> {c.base_url || "not set"} | {c.last_status}{c.last_error ? ` (${c.last_error})` : ""} | latency: {c.last_latency_ms}ms | checked: {c.last_checked_at || "-"}</span>
              <button onClick={() => checkConnectorHealth(c.name)} disabled={user.role === "viewer"}>Check health</button>
                </article>
              ))}
            </div>
          </section>
        ) : null}

        {tab === "triage" ? (
          <section className="panel">
            <h2>Triage Decisions</h2>
            <div className="alert-table">
              <div className="table-head"><span>Alert</span><span>Verdict</span><span>Confidence</span><span>Risk</span><span>SOAR</span></div>
              {decisions.map((d) => (
                <article className="alert-row" key={d.alert_id}>
                  <span><strong>{d.alert_id}</strong>{d.attack_summary}</span>
                  <span className={`severity ${verdictClass[d.verdict]}`}>{d.verdict}</span>
                  <span>{d.confidence}</span>
                  <span>{d.risk_score}</span>
                  <span>{d.soar_recommendation}{d.from_cache ? " (cache)" : ""}</span>
                </article>
              ))}
            </div>
          </section>
        ) : null}

        {tab === "incidents" ? (
          <section className="panel">
            <h2>Incidents</h2>
            {(user.role === "admin" || user.role === "analyst") ? (
              <div className="admin-form">
                <input placeholder="Title" value={incidentForm.title} onChange={(e) => setIncidentForm({ ...incidentForm, title: e.target.value })} />
                <select value={incidentForm.severity} onChange={(e) => setIncidentForm({ ...incidentForm, severity: e.target.value })}>
                  <option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
                </select>
                <input type="number" min={0} max={100} value={incidentForm.risk_score} onChange={(e) => setIncidentForm({ ...incidentForm, risk_score: Number(e.target.value) || 0 })} />
                <input placeholder="Source tool" value={incidentForm.source_tool} onChange={(e) => setIncidentForm({ ...incidentForm, source_tool: e.target.value })} />
                <button onClick={createIncident}>Create incident</button>
              </div>
            ) : null}
            {incidentMsg ? <p>{incidentMsg}</p> : null}
            <div className="admin-list">
              {incidents.map((i) => (
                <article className="admin-item" key={i.id}>
                  <span><strong>#{i.id}</strong> {i.title} | sev={i.severity} | status={i.status} | risk={i.risk_score}</span>
                  {(user.role === "admin" || user.role === "analyst") ? (
                    <div className="incident-actions">
                      <button onClick={() => updateIncidentStatus(i.id, "investigating")}>Investigating</button>
                      <button onClick={() => updateIncidentStatus(i.id, "resolved")}>Resolved</button>
                    </div>
                  ) : null}
                </article>
              ))}
            </div>
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
