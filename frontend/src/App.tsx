import React from "react";
import { BarChart3, Bot, ClipboardList, LockKeyhole, Play, Plug, Search, Settings, ShieldAlert, Users, Workflow } from "lucide-react";
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
type Incident = { id: number; title: string; severity: string; status: string; risk_score: number; source_tool: string; alert_id: string; ticket_ref: string; owner_name: string; phase: string; summary: string; priority: string; sla_due_at: string; escalated: boolean; close_reason: string; resolution_summary: string; created_by_user_id: number; created_at: string };
type IncidentEvent = { id: number; incident_id: number; event_type: string; detail: string; actor_user_id: number; created_at: string };
type IngestionRun = { id: number; source: string; status: string; detail: string; fetched_count: number; stored_count: number; triaged_count: number; created_at: string };
type IngestionStatus = { stored_alerts: number; triage_history: number; last_run: IngestionRun | null; runs: IngestionRun[]; live_source: string };
type TriageDecision = {
  alert_id: string;
  verdict: "false_positive" | "low_priority" | "suspicious" | "true_positive" | "needs_review";
  confidence: number;
  risk_score: number;
  attack_summary: string;
  evidence: string[];
  analyst_priority: string;
  queue: string;
  noise_score: number;
  signal_score: number;
  suppression_decision: string;
  suppression_reason: string;
  correlation_key: string;
  correlation_count: number;
  related_alert_count: number;
  entity_frequency: Record<string, number>;
  escalation_reason: string;
  tuning_recommendation: string;
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
type NoiseSummary = { total_alerts: number; suppressed_noise: number; grouped_duplicates: number; escalated_signals: number; review_items: number; estimated_analyst_items: number; estimated_noise_reduction_percent: number; strategy: string };
type AiProvider = { id: number; provider: string; model: string; api_key_masked: string; base_url: string; enabled: boolean; cache_enabled: boolean; max_input_chars: number; max_output_tokens: number; min_severity: string; fallback_model: string; last_status: string; last_error: string; updated_at: string };
type ThreatIntelProvider = { id: number; provider: string; api_key_masked: string; base_url: string; enabled: boolean; daily_limit: number; cache_ttl_minutes: number; last_status: string; last_error: string; updated_at: string };
type AutomationConnector = { id: number; name: string; connector_type: string; enabled: boolean; webhook_url_masked: string; last_status: string; last_error: string; updated_at: string };
type WorkflowTemplate = { id: string; name: string; description: string; connector_name: string; action: string; enabled: boolean };
type WorkflowRun = { id: number; template_id: string; template_name: string; connector_name: string; status: string; incident_id: string; alert_id: string; request_summary: string; response_detail: string; triggered_by_user_id: number; created_at: string; completed_at: string };

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
  const [tab, setTab] = React.useState<"overview" | "connectors" | "triage" | "incidents" | "automation" | "settings" | "admin">("overview");
  const [decisions, setDecisions] = React.useState<TriageDecision[]>([]);
  const [noiseSummary, setNoiseSummary] = React.useState<NoiseSummary | null>(null);
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
  const [ingestionStatus, setIngestionStatus] = React.useState<IngestionStatus | null>(null);
  const [ingestionMsg, setIngestionMsg] = React.useState("");
  const [connectorForm, setConnectorForm] = React.useState({ name: "wazuh", base_url: "", username: "", password: "", enabled: true });
  const [incidents, setIncidents] = React.useState<Incident[]>([]);
  const [incidentEvents, setIncidentEvents] = React.useState<IncidentEvent[]>([]);
  const [incidentSelectedId, setIncidentSelectedId] = React.useState<number | null>(null);
  const [incidentFilter, setIncidentFilter] = React.useState({ q: "", status: "", severity: "" });
  const [incidentForm, setIncidentForm] = React.useState({ title: "", severity: "medium", risk_score: 50, source_tool: "wazuh", alert_id: "", ticket_ref: "", owner_name: "", phase: "new", summary: "", priority: "P3", sla_due_at: "", escalated: false, close_reason: "", resolution_summary: "" });
  const [incidentEventForm, setIncidentEventForm] = React.useState({ event_type: "note", detail: "" });
  const [incidentMsg, setIncidentMsg] = React.useState("");
  const [aiProviders, setAiProviders] = React.useState<AiProvider[]>([]);
  const [intelProviders, setIntelProviders] = React.useState<ThreatIntelProvider[]>([]);
  const [settingsMsg, setSettingsMsg] = React.useState("");
  const [settingsSection, setSettingsSection] = React.useState<"ai" | "intel" | "status">("ai");
  const [adminSection, setAdminSection] = React.useState<"users" | "approvals" | "audit" | "health">("users");
  const [triageSection, setTriageSection] = React.useState<"queue" | "detail" | "history">("queue");
  const [caseSection, setCaseSection] = React.useState<"board" | "intake" | "timeline" | "closure">("board");
  const [alertFilter, setAlertFilter] = React.useState({ q: "", severity: "", queue: "", verdict: "" });
  const [automationMsg, setAutomationMsg] = React.useState("");
  const [automationForm, setAutomationForm] = React.useState({ workflow: "notify", case_id: "", alert_id: "", approval_note: "" });
  const [automationConnectors, setAutomationConnectors] = React.useState<AutomationConnector[]>([]);
  const [workflowTemplates, setWorkflowTemplates] = React.useState<WorkflowTemplate[]>([]);
  const [workflowRuns, setWorkflowRuns] = React.useState<WorkflowRun[]>([]);
  const [aiForm, setAiForm] = React.useState({ provider: "openai", model: "gpt-4o-mini", api_key: "", base_url: "", enabled: true, cache_enabled: true, max_input_chars: 6000, max_output_tokens: 700, min_severity: "medium", fallback_model: "" });
  const [intelForm, setIntelForm] = React.useState({ provider: "virustotal", api_key: "", base_url: "", enabled: false, daily_limit: 500, cache_ttl_minutes: 1440 });
  const healthyConnectors = connectors.filter((c) => c.last_status === "ok").length;
  const openIncidents = incidents.filter((i) => i.status !== "resolved").length;
  const resolvedIncidents = incidents.filter((i) => i.status === "resolved" || i.phase === "closed").length;
  const unsolvedIncidents = incidents.length - resolvedIncidents;
  const activeAnalysts = users.filter((u) => u.is_active && (u.role === "admin" || u.role === "analyst")).length;
  const pendingUsers = users.filter((u) => !u.is_active).length;
  const highRiskAlerts = alerts.filter((a) => a.severity === "high" || a.severity === "critical").length;
  const visibleAlertCount = alerts.length || ingestionStatus?.stored_alerts || 0;
  const analystItems = noiseSummary?.estimated_analyst_items ?? decisions.length;
  const groupedDuplicates = noiseSummary?.grouped_duplicates ?? 0;
  const severityCounts = ["critical", "high", "medium", "low"].map((severity) => ({
    severity,
    count: alerts.filter((alert) => alert.severity === severity).length,
  }));
  const roleCopy = {
    admin: { label: "Admin", detail: "Full platform owner: users, secrets, settings, audit, case and automation approval." },
    analyst: { label: "Analyst", detail: "Operational user: sync, triage, feedback, cases, timeline notes, and approval-gated SOAR requests." },
    viewer: { label: "Viewer", detail: "Read-only user: dashboards, alerts, cases, connectors, and provider status without write actions." },
  }[user?.role || "viewer"];
  const alertById = React.useMemo(() => new Map(alerts.map((alert) => [alert.alert_id, alert])), [alerts]);
  const filteredDecisions = decisions.filter((decision) => {
    const alert = alertById.get(decision.alert_id);
    const haystack = [
      decision.alert_id,
      decision.attack_summary,
      decision.queue,
      decision.soar_recommendation,
      alert?.rule.name,
      alert?.asset.hostname,
      alert?.network.src_ip,
      alert?.user.name,
    ].join(" ").toLowerCase();
    if (alertFilter.q && !haystack.includes(alertFilter.q.toLowerCase())) return false;
    if (alertFilter.severity && alert?.severity !== alertFilter.severity) return false;
    if (alertFilter.queue && (decision.queue || decision.soar_recommendation || "review") !== alertFilter.queue) return false;
    if (alertFilter.verdict && decision.verdict !== alertFilter.verdict) return false;
    return true;
  });
  const alertQueues = Array.from(new Set(decisions.map((decision) => decision.queue || decision.soar_recommendation || "review"))).filter(Boolean);
  const selectedIncident = incidents.find((incident) => incident.id === incidentSelectedId) || null;
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
    fetch(`${API}/triage/noise-reduction?limit=100`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setNoiseSummary(data.summary || null))
      .catch(() => setNoiseSummary(null));
  }, [token]);

  React.useEffect(() => {
    if (!token) return;
    fetch(`${API}/alerts/wazuh/recent?limit=25`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => (r.ok ? r.json() : fetch(`${API}/alerts/normalized`, { headers: { Authorization: `Bearer ${token}` } }).then((x) => x.json())))
      .then((data) => setAlerts(Array.isArray(data) ? data : data.alerts || []))
      .catch(() => setAlerts([]));
  }, [token, connectorMsg, incidentMsg]);

  React.useEffect(() => {
    if (!token) return;
    fetch(`${API}/api/v1/ingestion/status`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setIngestionStatus(data))
      .catch(() => setIngestionStatus(null));
  }, [token, ingestionMsg, connectorMsg]);

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
    fetch(`${API}/api/v1/settings/ai-providers`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setAiProviders(Array.isArray(data) ? data : []))
      .catch(() => setAiProviders([]));
    fetch(`${API}/api/v1/settings/threat-intel`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setIntelProviders(Array.isArray(data) ? data : []))
      .catch(() => setIntelProviders([]));
  }, [token, settingsMsg]);

  React.useEffect(() => {
    if (!token) return;
    fetch(`${API}/api/v1/automation/connectors`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setAutomationConnectors(Array.isArray(data) ? data : []))
      .catch(() => setAutomationConnectors([]));
    fetch(`${API}/api/v1/automation/workflow-templates`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setWorkflowTemplates(Array.isArray(data) ? data : []))
      .catch(() => setWorkflowTemplates([]));
    fetch(`${API}/api/v1/automation/workflow-runs`, { headers: { Authorization: `Bearer ${token}` } })
      .then((r) => r.json())
      .then((data) => setWorkflowRuns(Array.isArray(data) ? data : []))
      .catch(() => setWorkflowRuns([]));
  }, [token, automationMsg]);

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

  async function saveAiProvider() {
    const res = await fetch(`${API}/api/v1/settings/ai-providers/${aiForm.provider}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(aiForm),
    });
    const data = await res.json();
    setSettingsMsg(res.ok ? `Saved AI provider ${data.provider}` : `Failed: ${data.detail || "error"}`);
    setAiForm({ ...aiForm, api_key: "" });
  }

  async function checkAiProvider(provider: string) {
    const res = await fetch(`${API}/api/v1/settings/ai-providers/${provider}/health`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    setSettingsMsg(`${provider}: ${data.detail || "health check failed"}`);
  }

  async function saveThreatIntelProvider() {
    const res = await fetch(`${API}/api/v1/settings/threat-intel/${intelForm.provider}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify(intelForm),
    });
    const data = await res.json();
    setSettingsMsg(res.ok ? `Saved threat intel provider ${data.provider}` : `Failed: ${data.detail || "error"}`);
    setIntelForm({ ...intelForm, api_key: "" });
  }

  async function checkThreatIntelProvider(provider: string) {
    const res = await fetch(`${API}/api/v1/settings/threat-intel/${provider}/health`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    setSettingsMsg(`${provider}: ${data.detail || "health check failed"}`);
  }

  async function syncWazuhNow() {
    setIngestionMsg("Syncing Wazuh alerts from OpenSearch...");
    const res = await fetch(`${API}/api/v1/ingestion/wazuh/sync?limit=100&triage=true`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
    });
    const data = await res.json();
    if (!res.ok) {
      setIngestionMsg(`Sync failed: ${data.detail?.message || data.detail || "error"}`);
      return;
    }
    setIngestionMsg(`Synced ${data.run?.stored_count || 0} alerts and triaged ${data.run?.triaged_count || 0}. Source: ${data.summary?.source || "opensearch"}`);
    setAlerts(data.alerts || []);
    setDecisions(data.decisions || []);
    setNoiseSummary(data.noise_reduction || null);
    const status = await fetch(`${API}/api/v1/ingestion/status`, { headers: { Authorization: `Bearer ${token}` } }).then((r) => r.json());
    setIngestionStatus(status);
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
      body: JSON.stringify({ status, note: `set via dashboard to ${status}`, owner_name: incidentForm.owner_name, ticket_ref: incidentForm.ticket_ref, phase: incidentForm.phase, priority: incidentForm.priority, sla_due_at: incidentForm.sla_due_at, escalated: incidentForm.escalated, close_reason: incidentForm.close_reason, resolution_summary: incidentForm.resolution_summary }),
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
      priority: alert.severity === "critical" ? "P1" : alert.severity === "high" ? "P2" : "P3",
      sla_due_at: "",
      escalated: alert.severity === "critical",
      close_reason: "",
      resolution_summary: "",
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

  async function requestAutomationRun() {
    setAutomationMsg("");
    if (user.role === "viewer") {
      setAutomationMsg("Viewer access is read-only. Ask an analyst or admin to request automation.");
      return;
    }
    if (!automationForm.case_id && !automationForm.alert_id) {
      setAutomationMsg("Select or enter a case id or alert id before requesting automation.");
      return;
    }
    const payload = {
      incident_id: automationForm.case_id,
      alert_id: automationForm.alert_id,
      dry_run: automationForm.workflow !== "containment_approval",
      payload: {
        requested_workflow: automationForm.workflow,
        approval_note: automationForm.approval_note,
        requested_by_role: user.role,
      },
    };
    try {
      const res = await fetch(`${API}/api/v1/automation/workflow-templates/n8n-test-webhook/trigger`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setAutomationMsg(`Automation request failed: ${data.detail || res.statusText || "backend rejected request"}`);
        return;
      }
      setAutomationMsg(`Automation run #${data.id} ${data.status}: ${data.response_detail || "submitted to n8n webhook"}`);
    } catch {
      setAutomationMsg("Automation backend is not reachable. Confirm the API service is running on port 8000.");
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
        <section className="login-visual">
          <div className="login-brandmark">AI SOC</div>
          <h1>Noise-aware SOC command center</h1>
          <p>Wazuh-first triage, case workflow, model controls, and SOAR handoff for lean security teams.</p>
          <div className="login-signal-grid">
            <span><b>62%</b><em>sample reduction</em></span>
            <span><b>RBAC</b><em>admin / analyst / viewer</em></span>
            <span><b>BYO</b><em>OpenAI / Ollama / intel</em></span>
          </div>
        </section>
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
        <button className={`nav-item ${tab === "settings" ? "active" : ""}`} onClick={() => setTab("settings")}><Settings size={18} /> AI & Intel</button>
        {user.role === "admin" ? <button className={`nav-item ${tab === "admin" ? "active" : ""}`} onClick={() => setTab("admin")}><Users size={18} /> Admin</button> : null}
        <button className="nav-item" onClick={logout}><Bot size={18} /> Logout</button>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <div><p className="eyebrow">Authenticated Session</p><h1>AI SOC SOAR Command Center</h1></div>
          <div className="identity-stack">
            <span className="status-pill">{user.full_name} - {roleCopy.label}</span>
            <span className="role-caption"><LockKeyhole size={13} /> {roleCopy.detail}</span>
          </div>
        </header>

        {tab === "overview" ? (
          <>
	            <section className="metric-grid">
	              <article className="metric"><span>Critical Alerts</span><strong>{severityCounts.find((s) => s.severity === "critical")?.count || 0}</strong></article>
	              <article className="metric"><span>High Alerts</span><strong>{severityCounts.find((s) => s.severity === "high")?.count || 0}</strong></article>
	              <article className="metric"><span>Medium Alerts</span><strong>{severityCounts.find((s) => s.severity === "medium")?.count || 0}</strong></article>
	              <article className="metric"><span>Low Alerts</span><strong>{severityCounts.find((s) => s.severity === "low")?.count || 0}</strong></article>
	              <article className="metric"><span>Solved Cases</span><strong>{resolvedIncidents}</strong></article>
	              <article className="metric"><span>Unsolved Cases</span><strong>{unsolvedIncidents}</strong></article>
	              <article className="metric"><span>Analyst Items</span><strong>{analystItems}</strong></article>
	              <article className="metric"><span>Grouped Duplicates</span><strong>{groupedDuplicates}</strong></article>
	            </section>
            <section className="dashboard-grid">
              <article className="panel">
                <div className="section-title">
                  <div>
                    <h2>Alert Severity Split</h2>
                    <p>Executive-safe distribution by severity, without panic scoring.</p>
                  </div>
                </div>
                <div className="chart-row">
                  <div
                    className="donut-chart severity-donut"
                    style={{
                      "--critical": `${((severityCounts.find((s) => s.severity === "critical")?.count || 0) / Math.max(alerts.length, 1)) * 100}%`,
                      "--high": `${(((severityCounts.find((s) => s.severity === "critical")?.count || 0) + (severityCounts.find((s) => s.severity === "high")?.count || 0)) / Math.max(alerts.length, 1)) * 100}%`,
                      "--medium": `${(((severityCounts.find((s) => s.severity === "critical")?.count || 0) + (severityCounts.find((s) => s.severity === "high")?.count || 0) + (severityCounts.find((s) => s.severity === "medium")?.count || 0)) / Math.max(alerts.length, 1)) * 100}%`,
                    } as React.CSSProperties}
                  >
                    <span>{visibleAlertCount}<em>alerts</em></span>
                  </div>
                  <div className="chart-legend">
                    {severityCounts.map((item) => <span key={item.severity} className={`legend-${item.severity}`}><i />{item.severity}: {item.count}</span>)}
                  </div>
                </div>
              </article>
              <article className="panel">
                <div className="section-title">
                  <div>
                    <h2>Case Outcome</h2>
                    <p>Solved versus unsolved work in the SOC queue.</p>
                  </div>
                </div>
                <div className="chart-row">
                  <div
                    className="donut-chart case-donut"
                    style={{ "--solved": `${(resolvedIncidents / Math.max(incidents.length, 1)) * 100}%` } as React.CSSProperties}
                  >
                    <span>{resolvedIncidents}<em>solved</em></span>
                  </div>
                  <div className="chart-legend">
                    <span className="legend-solved"><i />Solved: {resolvedIncidents}</span>
                    <span className="legend-unsolved"><i />Unsolved: {unsolvedIncidents}</span>
                    <span className="legend-review"><i />Open cases: {openIncidents}</span>
                  </div>
                </div>
              </article>
              <article className="panel wide-panel">
                <div className="section-title">
                  <div>
                    <h2>Noise Reduction Flow</h2>
                    <p>How raw Wazuh alerts become analyst work items after grouping and suppression.</p>
                  </div>
                  <span className="status-pill">{noiseSummary?.estimated_noise_reduction_percent ?? 0}% reduced</span>
                </div>
                <div className="flow-chart">
                  <span><b>{noiseSummary?.total_alerts || visibleAlertCount}</b><em>Raw alerts</em></span>
                  <span><b>{groupedDuplicates}</b><em>Grouped duplicates</em></span>
                  <span><b>{noiseSummary?.suppressed_noise || 0}</b><em>Suppressed noise</em></span>
                  <span><b>{analystItems}</b><em>Analyst items</em></span>
                </div>
              </article>
              <article className="panel wide-panel">
                <div className="section-title">
                  <div>
                    <h2>Live Wazuh Ingestion</h2>
                    <p>Pulls alerts from OpenSearch, normalizes them, stores them, and runs AI triage in one auditable operation.</p>
                  </div>
                  <button className="primary-action" onClick={syncWazuhNow} disabled={user.role === "viewer"}>Sync live Wazuh</button>
                </div>
                {ingestionMsg ? <p>{ingestionMsg}</p> : null}
                <div className="ingestion-strip">
                  <span><b>{ingestionStatus?.stored_alerts || 0}</b><em>stored alerts</em></span>
                  <span><b>{ingestionStatus?.triage_history || 0}</b><em>triage records</em></span>
                  <span><b>{ingestionStatus?.last_run?.status || "none"}</b><em>last sync</em></span>
                  <span><b>{ingestionStatus?.live_source || "unknown"}</b><em>source</em></span>
                </div>
              </article>
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
                <h2>Noise Reduction Engine</h2>
                <div className="triage-score-grid">
                  <span><b>{noiseSummary?.total_alerts || 0}</b><em>raw alerts</em></span>
                  <span><b>{noiseSummary?.estimated_analyst_items || 0}</b><em>analyst items</em></span>
                  <span><b>{noiseSummary?.suppressed_noise || 0}</b><em>suppressed</em></span>
                  <span><b>{noiseSummary?.escalated_signals || 0}</b><em>escalated</em></span>
                </div>
                <p>{noiseSummary?.strategy || "Batch-aware correlation will appear after triage runs."}</p>
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
                  {alerts.slice(0, 6).map((alert, index) => (
                    <button key={`${alert.alert_id}-${index}`} onClick={() => { setSelectedAlertId(alert.alert_id); setTab("triage"); }}>
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
            <section className="panel detail-panel">
              <div className="section-title">
                <div><h2>Ingestion Control</h2><p>Use this after Wazuh/OpenSearch is configured to fetch live alerts into the persistent store.</p></div>
                <button className="primary-action" onClick={syncWazuhNow} disabled={user.role === "viewer"}>Sync and triage now</button>
              </div>
              {ingestionMsg ? <p>{ingestionMsg}</p> : null}
              <div className="admin-list">
                {(ingestionStatus?.runs || []).slice(0, 6).map((run) => (
                  <article className="admin-item" key={run.id}>
                    <span>#{run.id} {run.created_at} | {run.status} | fetched={run.fetched_count} stored={run.stored_count} triaged={run.triaged_count} | {run.detail}</span>
                  </article>
                ))}
              </div>
            </section>
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
            <div className="subnav">
              <button className={triageSection === "queue" ? "active" : ""} onClick={() => setTriageSection("queue")}>Queue</button>
              <button className={triageSection === "detail" ? "active" : ""} onClick={() => setTriageSection("detail")} disabled={!selectedAlertId}>Investigation</button>
              <button className={triageSection === "history" ? "active" : ""} onClick={() => setTriageSection("history")}>Review History</button>
            </div>
            {triageSection === "queue" ? (
              <>
              <div className="filter-bar">
                <label><Search size={14} /><input placeholder="Search alert, host, IP, summary" value={alertFilter.q} onChange={(e) => setAlertFilter({ ...alertFilter, q: e.target.value })} /></label>
                <select value={alertFilter.severity} onChange={(e) => setAlertFilter({ ...alertFilter, severity: e.target.value })}>
                  <option value="">all severity</option>
                  <option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option>
                </select>
                <select value={alertFilter.verdict} onChange={(e) => setAlertFilter({ ...alertFilter, verdict: e.target.value })}>
                  <option value="">all verdicts</option>
                  <option value="true_positive">true positive</option><option value="suspicious">suspicious</option><option value="needs_review">needs review</option><option value="low_priority">low priority</option><option value="false_positive">false positive</option>
                </select>
                <select value={alertFilter.queue} onChange={(e) => setAlertFilter({ ...alertFilter, queue: e.target.value })}>
                  <option value="">all queues</option>
                  {alertQueues.map((queue) => <option value={queue} key={queue}>{queue}</option>)}
                </select>
                <button className="secondary-button" onClick={() => setAlertFilter({ q: "", severity: "", queue: "", verdict: "" })}>Clear</button>
                <span>{filteredDecisions.length}/{decisions.length} shown</span>
              </div>
	            <div className="alert-table">
	              <div className="table-head"><span>Alert</span><span>Verdict</span><span>Signal</span><span>Noise</span><span>Queue</span></div>
	              {filteredDecisions.map((d, index) => (
	                <article className="alert-row" key={`${d.alert_id}-${index}`} onClick={() => { setSelectedAlertId(d.alert_id); setTriageSection("detail"); }}>
	                  <span><strong>{d.alert_id}</strong>{d.attack_summary}</span>
	                  <span className={`severity ${verdictClass[d.verdict]}`}>{d.verdict}</span>
	                  <span>{d.signal_score || d.risk_score} / {d.analyst_priority || "P3"}</span>
	                  <span>{d.noise_score || 0} / {d.suppression_decision || "review"}</span>
	                  <span>{d.queue || d.soar_recommendation}{d.from_cache ? " (cache)" : ""}</span>
	                </article>
	              ))}
                {filteredDecisions.length === 0 ? <article className="empty-state">No alerts match the current filters.</article> : null}
	            </div>
              </>
            ) : null}
            {triageSection === "detail" && selectedAlertId ? (
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
	                        <p>Priority: {decision.analyst_priority || "P3"} | Queue: {decision.queue || "review"} | Signal: {decision.signal_score || decision.risk_score} | Noise: {decision.noise_score || 0}</p>
	                        <p>Suppression: {decision.suppression_decision || "review"} - {decision.suppression_reason || "requires analyst review"}</p>
	                        <p>Correlation: {decision.correlation_count || 1} matching alerts | Related entity max: {decision.related_alert_count || 1}</p>
	                        <p>Asset: {alert.asset.hostname || "-"} | User: {alert.user.name || "-"} | Source IP: {alert.network.src_ip || "-"}</p>
	                        <p>MITRE: {(decision.mitre.techniques || alert.mitre.techniques).join(", ") || "-"}</p>
	                        <p>Disposition: {history?.disposition || "not reviewed"} {history?.updated_at ? `| ${history.updated_at}` : ""}</p>
	                        {decision.escalation_reason ? <p>Escalation: {decision.escalation_reason}</p> : null}
	                        {decision.tuning_recommendation ? <p>Tuning: {decision.tuning_recommendation}</p> : null}
	                      </article>
                      <article>
                        <strong>Evidence</strong>
                        <ul className="check-list">{decision.evidence.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
                        <strong>Impacted Entities</strong>
                        <ul className="check-list">{decision.impacted_entities.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
                      </article>
                      <article>
                        <strong>L2 Investigation Steps</strong>
                        <ol className="check-list">{decision.investigation_steps.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol>
                        <strong>Recommended Actions</strong>
                        <ul className="check-list">{decision.recommended_actions.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
                      </article>
                      <article>
                        <strong>Containment Steps</strong>
                        <ul className="check-list">{decision.containment_steps.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
                        <strong>Resolution Criteria</strong>
                        <ul className="check-list">{decision.resolution_criteria.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
                      </article>
                      <article>
                        <strong>Analyst Questions</strong>
                        <ul className="check-list">{decision.analyst_questions.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
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
            {triageSection === "history" ? <section className="panel detail-panel">
              <h3>Triage Review History</h3>
              <div className="admin-list">
                {triageHistory.slice(0, 12).map((item, index) => (
                  <article className="admin-item" key={`${item.alert_id}-${item.updated_at}-${index}`}>
                    <span>{item.updated_at || "-"} | {item.alert_id} | {item.disposition || "pending"} | {item.note || "no note"}</span>
                  </article>
                ))}
              </div>
            </section> : null}
          </section>
        ) : null}

        {tab === "incidents" ? (
          <section className="panel">
            <div className="section-title">
              <div><h2>Case Management Board</h2><p>Jira-style SOC lifecycle from new alert to closure, with owner, ticket, and timeline.</p></div>
              <span className="status-pill">{openIncidents} active</span>
            </div>
            <div className="subnav">
              <button className={caseSection === "board" ? "active" : ""} onClick={() => setCaseSection("board")}>Lifecycle Board</button>
              <button className={caseSection === "intake" ? "active" : ""} onClick={() => setCaseSection("intake")}>Intake</button>
              <button className={caseSection === "timeline" ? "active" : ""} onClick={() => setCaseSection("timeline")}>Timeline</button>
              <button className={caseSection === "closure" ? "active" : ""} onClick={() => setCaseSection("closure")}>Closure</button>
            </div>
            {caseSection === "intake" && (user.role === "admin" || user.role === "analyst") ? (
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
                <select value={incidentForm.priority} onChange={(e) => setIncidentForm({ ...incidentForm, priority: e.target.value })}>
                  <option value="P1">P1 critical</option><option value="P2">P2 high</option><option value="P3">P3 normal</option><option value="P4">P4 low</option>
                </select>
                <input placeholder="SLA due time" value={incidentForm.sla_due_at} onChange={(e) => setIncidentForm({ ...incidentForm, sla_due_at: e.target.value })} />
                <select value={incidentForm.phase} onChange={(e) => setIncidentForm({ ...incidentForm, phase: e.target.value })}>
                  <option value="new">new</option><option value="triage">triage</option><option value="investigation">investigation</option><option value="containment">containment</option><option value="eradication">eradication</option><option value="recovery">recovery</option><option value="closed">closed</option>
                </select>
                <label className="checkbox-line"><input type="checkbox" checked={incidentForm.escalated} onChange={(e) => setIncidentForm({ ...incidentForm, escalated: e.target.checked })} /> Escalated</label>
                <input placeholder="Close reason" value={incidentForm.close_reason} onChange={(e) => setIncidentForm({ ...incidentForm, close_reason: e.target.value })} />
                <input placeholder="Case summary" value={incidentForm.summary} onChange={(e) => setIncidentForm({ ...incidentForm, summary: e.target.value })} />
                <input placeholder="Resolution summary" value={incidentForm.resolution_summary} onChange={(e) => setIncidentForm({ ...incidentForm, resolution_summary: e.target.value })} />
                <button onClick={createIncident}>Create incident</button>
              </div>
            ) : null}
            {caseSection === "intake" && user.role === "viewer" ? <article className="empty-state">Viewer role can inspect cases but cannot create or update them.</article> : null}
            {caseSection === "board" ? (
              <>
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
	                        <span>{i.priority || "P3"} | {i.severity} | risk {i.risk_score} | {i.ticket_ref || "no ticket"}</span>
	                        <span>owner: {i.owner_name || "unassigned"} | SLA: {i.sla_due_at || "not set"} {i.escalated ? "| escalated" : ""}</span>
	                        <p>{i.summary || "No summary captured yet."}</p>
	                        {i.resolution_summary ? <p>Resolution: {i.resolution_summary}</p> : null}
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
              </>
            ) : null}
            {caseSection === "timeline" ? (
              <>
                <div className="filter-bar compact-control">
                  <select value={incidentSelectedId || ""} onChange={(e) => e.target.value ? loadIncidentEvents(Number(e.target.value)) : setIncidentSelectedId(null)}>
                    <option value="">select case timeline</option>
                    {incidents.map((incident) => <option key={incident.id} value={incident.id}>#{incident.id} {incident.title}</option>)}
                  </select>
                  {selectedIncident ? <span>{selectedIncident.status} / {selectedIncident.phase || "new"}</span> : null}
                </div>
                <h3>Incident Timeline {incidentSelectedId ? `#${incidentSelectedId}` : ""}</h3>
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
            {caseSection === "closure" ? (
              <section className="panel detail-panel">
                <div className="section-title">
                  <div><h3>Closure Readiness</h3><p>Uses the current case records only: status, phase, close reason, resolution summary, and escalation state.</p></div>
                  <span className="status-pill">{resolvedIncidents} closed/resolved</span>
                </div>
                <div className="closure-grid">
                  {incidents.map((incident) => (
                    <article className="case-card" key={`closure-${incident.id}`}>
                      <strong>#{incident.id} {incident.title}</strong>
                      <span>{incident.status} | phase {incident.phase || "new"} | {incident.priority || "P3"} | {incident.escalated ? "escalated" : "not escalated"}</span>
                      <p>Close reason: {incident.close_reason || "not captured"}</p>
                      <p>Resolution: {incident.resolution_summary || "not captured"}</p>
                    </article>
                  ))}
                  {incidents.length === 0 ? <article className="empty-state">No cases available for closure review.</article> : null}
                </div>
              </section>
            ) : null}
          </section>
        ) : null}

        {tab === "automation" ? (
          <section className="panel">
            <div className="section-title">
              <div><h2>SOAR Automation</h2><p>Workflow handoff starts here. Shuffle is SOC-native; n8n can be used first when you want a quick self-hosted webhook workflow.</p></div>
              <span className="status-pill">RBAC controlled</span>
            </div>
            <section className="panel detail-panel soar-console">
              <div className="section-title">
                <div><h3>Automation Request Console</h3><p>Sends live case or alert identifiers to the configured n8n webhook template. High-impact approval gates are the next backend control.</p></div>
                <span className="state-pill state-configured">{roleCopy.label}: {user.role === "viewer" ? "read-only" : "can request"}</span>
              </div>
              <div className="automation-grid">
                <select value={automationForm.workflow} onChange={(e) => setAutomationForm({ ...automationForm, workflow: e.target.value })}>
                  <option value="notify">notify analyst channel</option>
                  <option value="create_ticket">create external ticket</option>
                  <option value="enrich_ioc">enrich IOC</option>
                  <option value="containment_approval">request containment approval</option>
                </select>
                <select value={automationForm.case_id} onChange={(e) => setAutomationForm({ ...automationForm, case_id: e.target.value })}>
                  <option value="">case id optional</option>
                  {incidents.map((incident) => <option key={incident.id} value={incident.id}>#{incident.id} {incident.title}</option>)}
                </select>
                <select value={automationForm.alert_id} onChange={(e) => setAutomationForm({ ...automationForm, alert_id: e.target.value })}>
                  <option value="">alert id optional</option>
                  {alerts.map((alert) => <option key={alert.alert_id} value={alert.alert_id}>{alert.alert_id} - {alert.rule.name}</option>)}
                </select>
                <input placeholder="Approval note" value={automationForm.approval_note} onChange={(e) => setAutomationForm({ ...automationForm, approval_note: e.target.value })} />
                <button className="primary-action" onClick={requestAutomationRun} disabled={user.role === "viewer"}><Play size={14} /> Request run</button>
              </div>
            {automationMsg ? <p>{automationMsg}</p> : null}
            </section>
            <div className="settings-grid">
              <article className="panel detail-panel">
                <h3>Connector Access</h3>
                <div className="permission-grid">
                  {automationConnectors.map((connector) => (
                    <span key={connector.id}>
                      <b>{connector.name}</b>
                      <em>{connector.enabled ? "enabled" : "not configured"} | {connector.webhook_url_masked || connector.last_error || "waiting for URL"}</em>
                    </span>
                  ))}
                  {automationConnectors.length === 0 ? <span><b>No connector rows</b><em>Backend has not returned automation connector state yet.</em></span> : null}
                </div>
              </article>
              <article className="panel detail-panel">
                <h3>Workflow Templates</h3>
                <div className="permission-grid">
                  {workflowTemplates.map((template) => (
                    <span key={template.id}>
                      <b>{template.name}</b>
                      <em>{template.enabled ? "ready" : "disabled until connector configured"} | {template.description}</em>
                    </span>
                  ))}
                  {workflowTemplates.length === 0 ? <span><b>No templates loaded</b><em>Check API health and authentication.</em></span> : null}
                </div>
              </article>
            </div>
            <section className="panel detail-panel">
              <h3>Workflow Run History</h3>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>ID</th><th>Template</th><th>Status</th><th>Case</th><th>Alert</th><th>Response</th><th>Completed</th></tr></thead>
                  <tbody>
                    {workflowRuns.slice(0, 8).map((run) => (
                      <tr key={run.id}>
                        <td>#{run.id}</td>
                        <td>{run.template_name}</td>
                        <td><span className={`sev ${run.status === "success" ? "sev-low" : run.status === "error" ? "sev-critical" : "sev-medium"}`}>{run.status}</span></td>
                        <td>{run.incident_id || "-"}</td>
                        <td>{run.alert_id || "-"}</td>
                        <td>{run.response_detail || run.request_summary}</td>
                        <td>{run.completed_at ? new Date(run.completed_at).toLocaleString() : "queued"}</td>
                      </tr>
                    ))}
                    {workflowRuns.length === 0 ? <tr><td colSpan={7}>No automation runs yet. Configure n8n and request a workflow run from a case or alert.</td></tr> : null}
                  </tbody>
                </table>
              </div>
            </section>
            <div className="settings-grid">
              <article className="panel detail-panel">
                <h3>n8n Setup on Wazuh Machine</h3>
                <ul className="check-list">
                  <li>Install Docker and Docker Compose plugin.</li>
                  <li>Run n8n on a non-conflicting port, recommended <code>5678</code>.</li>
                  <li>Create a webhook workflow that accepts incident JSON from this app.</li>
                  <li>Return a JSON response with status, ticket id, and workflow execution id.</li>
                  <li>Share the webhook URL so it can be saved as <code>N8N_WEBHOOK_URL</code> or later into the app settings.</li>
                </ul>
                <pre className="command-box">{`docker volume create n8n_data
docker run -d --name n8n --restart unless-stopped \\
  -p 5678:5678 \\
  -e N8N_HOST=0.0.0.0 \\
  -e N8N_PORT=5678 \\
  -e N8N_PROTOCOL=http \\
  -v n8n_data:/home/node/.n8n \\
  n8nio/n8n:latest`}</pre>
              </article>
              <article className="panel detail-panel">
                <h3>MVP Workflow Actions</h3>
                <div className="permission-grid">
                  <span><b>Notify</b><em>Analyst may request; viewer cannot run</em></span>
                  <span><b>Create Ticket</b><em>Analyst or admin handoff to external queue</em></span>
                  <span><b>Enrich IOC</b><em>Read-only enrichment before case action</em></span>
                  <span><b>Contain</b><em>Admin approval required before destructive action</em></span>
                </div>
              </article>
            </div>
            <section className="panel detail-panel">
              <h3>Automation Design Rules</h3>
              <ul className="check-list">
                <li>Read-only and notification actions can run from analyst approval.</li>
                <li>Destructive actions must require admin approval and write an audit event.</li>
                <li>Every workflow run must store request, response, actor, case id, and timestamp.</li>
                <li>Shuffle remains the target SOC-native orchestrator; n8n is acceptable for the first MVP webhook demo.</li>
              </ul>
            </section>
          </section>
        ) : null}

        {tab === "settings" ? (
          <section className="panel">
            <div className="section-title">
              <div>
                <h2>AI Model and Threat Intel Control Plane</h2>
                <p>Bring-your-own model and enrichment keys. Secrets are masked in the UI and write access is admin-only.</p>
              </div>
              <span className="status-pill">{aiProviders.filter((p) => p.enabled).length} AI active / {intelProviders.filter((p) => p.enabled).length} intel active</span>
            </div>
            {settingsMsg ? <p>{settingsMsg}</p> : null}
            <div className="subnav">
              <button className={settingsSection === "ai" ? "active" : ""} onClick={() => setSettingsSection("ai")}>AI Models</button>
              <button className={settingsSection === "intel" ? "active" : ""} onClick={() => setSettingsSection("intel")}>Threat Intel</button>
              <button className={settingsSection === "status" ? "active" : ""} onClick={() => setSettingsSection("status")}>Provider Status</button>
            </div>
            {user.role === "admin" && settingsSection !== "status" ? (
              <div className="settings-grid">
                {settingsSection === "ai" ? <article className="panel detail-panel">
                  <h3>AI Provider</h3>
                  <div className="admin-form">
                    <select value={aiForm.provider} onChange={(e) => setAiForm({ ...aiForm, provider: e.target.value })}>
                      <option value="openai">OpenAI</option>
                      <option value="anthropic">Anthropic</option>
                      <option value="ollama">Ollama local</option>
                      <option value="offline">Offline heuristic</option>
                    </select>
                    <input placeholder="Model" value={aiForm.model} onChange={(e) => setAiForm({ ...aiForm, model: e.target.value })} />
                    <input placeholder="API key / token" type="password" value={aiForm.api_key} onChange={(e) => setAiForm({ ...aiForm, api_key: e.target.value })} />
                    <input placeholder="Base URL" value={aiForm.base_url} onChange={(e) => setAiForm({ ...aiForm, base_url: e.target.value })} />
                    <input type="number" min={500} max={50000} value={aiForm.max_input_chars} onChange={(e) => setAiForm({ ...aiForm, max_input_chars: Number(e.target.value) || 6000 })} />
                    <input type="number" min={100} max={4000} value={aiForm.max_output_tokens} onChange={(e) => setAiForm({ ...aiForm, max_output_tokens: Number(e.target.value) || 700 })} />
                    <select value={aiForm.min_severity} onChange={(e) => setAiForm({ ...aiForm, min_severity: e.target.value })}>
                      <option value="low">low</option><option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
                    </select>
                    <input placeholder="Fallback model" value={aiForm.fallback_model} onChange={(e) => setAiForm({ ...aiForm, fallback_model: e.target.value })} />
                    <label className="checkbox-line"><input type="checkbox" checked={aiForm.enabled} onChange={(e) => setAiForm({ ...aiForm, enabled: e.target.checked })} /> Enabled</label>
                    <label className="checkbox-line"><input type="checkbox" checked={aiForm.cache_enabled} onChange={(e) => setAiForm({ ...aiForm, cache_enabled: e.target.checked })} /> Cache duplicate triage</label>
                    <button onClick={saveAiProvider}>Save AI provider</button>
                  </div>
                </article> : null}
                {settingsSection === "intel" ? <article className="panel detail-panel">
                  <h3>Threat Intel Provider</h3>
                  <div className="admin-form">
                    <select value={intelForm.provider} onChange={(e) => setIntelForm({ ...intelForm, provider: e.target.value })}>
                      <option value="virustotal">VirusTotal</option>
                      <option value="abuseipdb">AbuseIPDB</option>
                      <option value="otx">AlienVault OTX</option>
                      <option value="misp">MISP</option>
                      <option value="local_ioc">Local IOC</option>
                    </select>
                    <input placeholder="API key" type="password" value={intelForm.api_key} onChange={(e) => setIntelForm({ ...intelForm, api_key: e.target.value })} />
                    <input placeholder="Base URL" value={intelForm.base_url} onChange={(e) => setIntelForm({ ...intelForm, base_url: e.target.value })} />
                    <input type="number" min={1} max={100000} value={intelForm.daily_limit} onChange={(e) => setIntelForm({ ...intelForm, daily_limit: Number(e.target.value) || 500 })} />
                    <input type="number" min={5} max={43200} value={intelForm.cache_ttl_minutes} onChange={(e) => setIntelForm({ ...intelForm, cache_ttl_minutes: Number(e.target.value) || 1440 })} />
                    <label className="checkbox-line"><input type="checkbox" checked={intelForm.enabled} onChange={(e) => setIntelForm({ ...intelForm, enabled: e.target.checked })} /> Enabled</label>
                    <button onClick={saveThreatIntelProvider}>Save intel provider</button>
                  </div>
                </article> : null}
              </div>
            ) : null}
            {settingsSection === "status" || user.role !== "admin" ? <div className="settings-grid">
              <article className="panel detail-panel">
                <h3>Configured AI Providers</h3>
                <div className="admin-list">
                  {aiProviders.map((p) => (
                    <article className="admin-item" key={p.provider}>
                      <span>{p.provider} | model={p.model || "-"} | enabled={String(p.enabled)} | cache={String(p.cache_enabled)} | secret={p.api_key_masked || "not set"} | min={p.min_severity} | {p.last_status}</span>
                      <button onClick={() => checkAiProvider(p.provider)}>Check</button>
                    </article>
                  ))}
                </div>
              </article>
              <article className="panel detail-panel">
                <h3>Configured Threat Intel</h3>
                <div className="admin-list">
                  {intelProviders.map((p) => (
                    <article className="admin-item" key={p.provider}>
                      <span>{p.provider} | enabled={String(p.enabled)} | limit={p.daily_limit}/day | ttl={p.cache_ttl_minutes}m | secret={p.api_key_masked || "not set"} | {p.last_status}</span>
                      <button onClick={() => checkThreatIntelProvider(p.provider)}>Check</button>
                    </article>
                  ))}
                </div>
              </article>
            </div> : null}
          </section>
        ) : null}

        {tab === "admin" && user.role === "admin" ? (
          <section className="panel">
            <div className="section-title">
              <div><h2>Admin Portal</h2><p>User governance, access approval, audit trail, and platform health.</p></div>
              <span className="status-pill">{activeAnalysts} active analysts / {pendingUsers} pending</span>
            </div>
            <div className="subnav">
              <button className={adminSection === "users" ? "active" : ""} onClick={() => setAdminSection("users")}>Users</button>
              <button className={adminSection === "approvals" ? "active" : ""} onClick={() => setAdminSection("approvals")}>Approvals</button>
              <button className={adminSection === "audit" ? "active" : ""} onClick={() => setAdminSection("audit")}>Audit</button>
              <button className={adminSection === "health" ? "active" : ""} onClick={() => setAdminSection("health")}>Health</button>
            </div>
            {adminSection === "users" ? <>
              <h3>Create User</h3>
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
            </> : null}
            {adminSection === "approvals" ? <>
              <h3>Pending User Approval</h3>
              <div className="admin-list">
                {users.filter((u) => !u.is_active).map((u) => (
                  <article key={u.id} className="admin-item">
                    <span>{u.email} ({u.role}) waiting for activation</span>
                    <button onClick={() => toggleActive(u.id, u.is_active)}>Approve</button>
                  </article>
                ))}
                {users.filter((u) => !u.is_active).length === 0 ? <article className="admin-item"><span>No pending users.</span></article> : null}
              </div>
              <h3>Role Model</h3>
              <div className="permission-grid">
                <span><b>Admin</b><em>users, connectors, AI/intel keys, audit, all analyst actions</em></span>
                <span><b>Analyst</b><em>sync, triage, feedback, cases, timeline, SOAR request</em></span>
                <span><b>Viewer</b><em>read-only executive, alert, case, and connector visibility</em></span>
              </div>
            </> : null}
            {adminSection === "audit" ? <>
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
            </> : null}
            {adminSection === "health" ? <>
              <h3>Platform Health</h3>
              <div className="permission-grid">
                <span><b>{connectors.length}</b><em>connectors configured</em></span>
                <span><b>{healthyConnectors}</b><em>healthy connectors</em></span>
                <span><b>{ingestionStatus?.stored_alerts || 0}</b><em>persisted alerts</em></span>
                <span><b>{ingestionStatus?.triage_history || 0}</b><em>triage records</em></span>
              </div>
              <h3>Connector Health History</h3>
            <div className="admin-list">
              {connectorHistory.slice(0, 20).map((h) => (
                <article key={h.id} className="admin-item">
                  <span>#{h.id} connector={h.connector_id} ok={String(h.ok)} latency={h.latency_ms}ms user={h.checked_by_user_id} {h.detail}</span>
                </article>
              ))}
            </div>
            </> : null}
          </section>
        ) : null}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
