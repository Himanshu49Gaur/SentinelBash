/**
 * SentinelBash - Tactical Operations Web Console Controller
 * Implements real-time telemetry streaming, SSE gateways, REST API sync, and reactive UI state.
 */

// Application State Store
const STATE = {
  activeView: 'dashboard',
  apiKey: 'snt_live_bootstrap_master_admin_key_2026',
  isStreamPaused: false,
  logFilter: '',
  selectedIncidentId: null,
  activeBans: [],
  incidents: [],
  rules: [],
  whitelist: [],
  logEventSource: null,
  alertEventSource: null,
};

// ==============================================================================
// Initialization & Lifecycle
// ==============================================================================

document.addEventListener('DOMContentLoaded', () => {
  initClock();
  initNavigation();
  initModals();
  initShortcuts();
  initSSEStreams();
  refreshAllData();

  // Polling loop for metrics and health every 8s
  setInterval(() => {
    fetchHealth();
    fetchMetrics();
    if (STATE.activeView === 'containment') fetchBans();
    if (STATE.activeView === 'incidents') fetchIncidents();
  }, 8000);
});

// Live UTC Digital Clock
function initClock() {
  const clockEl = document.getElementById('live-utc-clock');
  function update() {
    const now = new Date();
    clockEl.textContent = now.toUTCString().split(' ')[4] + ' UTC';
  }
  update();
  setInterval(update, 1000);
}

// Navigation & Tab Switching
function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  const titleEl = document.getElementById('page-title-heading');

  const titles = {
    dashboard: 'Operations Dashboard',
    triage: 'Real-Time Log Triage',
    incidents: 'Incidents Hub & Forensics',
    containment: 'Active Netfilter Containment',
    rules: 'Detection Rules & Whitelist',
  };

  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      const view = item.getAttribute('data-view');
      switchView(view);
    });
  });
}

function switchView(viewName) {
  STATE.activeView = viewName;

  // Toggle active nav class
  document.querySelectorAll('.nav-item').forEach((el) => {
    el.classList.toggle('active', el.getAttribute('data-view') === viewName);
  });

  // Toggle visible view panel
  document.querySelectorAll('.view-panel').forEach((panel) => {
    panel.classList.toggle('active', panel.id === `view-${viewName}`);
  });

  const titles = {
    dashboard: 'Operations Dashboard',
    triage: 'Real-Time Log Triage',
    incidents: 'Incidents Hub & Forensics',
    containment: 'Active Netfilter Containment',
    rules: 'Detection Rules & Whitelist',
  };
  document.getElementById('page-title-heading').textContent = titles[viewName] || 'Operations';

  // Load view-specific data
  if (viewName === 'dashboard') { fetchMetrics(); fetchRecentContainments(); }
  if (viewName === 'incidents') fetchIncidents();
  if (viewName === 'containment') fetchBans();
  if (viewName === 'rules') { fetchRules(); fetchWhitelist(); }
}

// Global Keyboard Shortcuts
function initShortcuts() {
  window.addEventListener('keydown', (e) => {
    // Ctrl+B opens quarantine modal
    if (e.ctrlKey && (e.key === 'b' || e.key === 'B')) {
      e.preventDefault();
      openModal('quarantine-modal');
      document.getElementById('quarantine-ip').focus();
    }
    // Escape closes modals and drawer
    if (e.key === 'Escape') {
      closeAllModals();
      closeDrawer();
    }
  });
}

// ==============================================================================
// Real-Time Server-Sent Events (SSE) Gateway Integration
// ==============================================================================

function initSSEStreams() {
  // 1. Live Log Telemetry Stream
  const logContainer = document.getElementById('terminal-stream-container');
  const streamBadge = document.getElementById('sse-stream-badge');

  if (window.EventSource) {
    STATE.logEventSource = new EventSource('/api/v1/stream/logs');

    STATE.logEventSource.addEventListener('log_event', (e) => {
      if (STATE.isStreamPaused) return;

      try {
        const item = JSON.parse(e.data);
        renderTerminalLine(item);
      } catch (err) {
        console.error('Error parsing SSE log event:', err);
      }
    });

    STATE.logEventSource.addEventListener('handshake', () => {
      streamBadge.textContent = 'STREAM CONNECTED';
      streamBadge.className = 'badge badge-safe';
    });

    STATE.logEventSource.onerror = () => {
      streamBadge.textContent = 'RECONNECTING...';
      streamBadge.className = 'badge badge-high';
    };

    // 2. Live Alerts Stream
    STATE.alertEventSource = new EventSource('/api/v1/stream/alerts');
    STATE.alertEventSource.addEventListener('alert_event', (e) => {
      try {
        const alert = JSON.parse(e.data);
        showToast(`🚨 THREAT DETECTED: ${alert.event_type || 'ALERT'}`, `Attacker IP ${alert.ip || ''} contained.`, 'critical');
        fetchMetrics();
        fetchBans();
        fetchIncidents();
      } catch (err) {
        console.error('Error parsing SSE alert event:', err);
      }
    });
  }

  // Stream Toolbar Controls
  const btnToggleStream = document.getElementById('btn-toggle-stream');
  btnToggleStream.addEventListener('click', () => {
    STATE.isStreamPaused = !STATE.isStreamPaused;
    document.getElementById('btn-stream-text').textContent = STATE.isStreamPaused ? 'Resume Feed' : 'Pause Feed';
    btnToggleStream.classList.toggle('active', STATE.isStreamPaused);
    if (STATE.isStreamPaused) {
      streamBadge.textContent = 'STREAM PAUSED';
      streamBadge.className = 'badge badge-medium';
    } else {
      streamBadge.textContent = 'STREAM ACTIVE';
      streamBadge.className = 'badge badge-safe';
    }
  });

  document.getElementById('btn-clear-terminal').addEventListener('click', () => {
    logContainer.innerHTML = '<div class="log-line" style="color: var(--text-muted);"><span>Buffer cleared by analyst.</span></div>';
  });

  const filterInput = document.getElementById('terminal-filter-input');
  filterInput.addEventListener('input', (e) => {
    STATE.logFilter = e.target.value.toLowerCase();
  });
}

function renderTerminalLine(item) {
  const container = document.getElementById('terminal-stream-container');
  const lineText = `${item.service || ''} ${item.ip || ''} ${item.event_type || ''} ${item.details || ''}`.toLowerCase();

  if (STATE.logFilter && !lineText.includes(STATE.logFilter)) {
    return;
  }

  const lineEl = document.createElement('div');
  lineEl.className = 'log-line';

  const dateStr = item.epoch ? new Date(item.epoch * 1000).toTimeString().split(' ')[0] : new Date().toTimeString().split(' ')[0];

  lineEl.innerHTML = `
    <span class="log-time">${dateStr}</span>
    <span class="log-service">${item.service || 'sys'}</span>
    <span class="log-ip">${item.ip || '-'}</span>
    <span class="log-type ${item.event_type || ''}">${item.event_type || 'EVENT'}</span>
    <span class="log-msg">${escapeHtml(item.details || item.raw || '')}</span>
  `;

  container.appendChild(lineEl);

  // Buffer capping to 400 entries
  if (container.children.length > 400) {
    container.removeChild(container.firstChild);
  }

  // Auto-scroll
  container.scrollTop = container.scrollHeight;
}

// ==============================================================================
// REST API Data Fetching & State Synchronization
// ==============================================================================

async function apiFetch(endpoint, options = {}) {
  const headers = options.headers || {};
  headers['X-API-Key'] = STATE.apiKey;
  headers['Content-Type'] = 'application/json';

  try {
    const res = await fetch(endpoint, { ...options, headers });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || 'API request failed');
    }
    return await res.json();
  } catch (err) {
    console.error(`API Error on ${endpoint}:`, err);
    throw err;
  }
}

async function refreshAllData() {
  await Promise.allSettled([
    fetchHealth(),
    fetchMetrics(),
    fetchIncidents(),
    fetchBans(),
    fetchRules(),
    fetchWhitelist(),
    fetchRecentContainments(),
  ]);
}

async function fetchHealth() {
  try {
    const data = await apiFetch('/api/v1/health');
    const statusText = document.getElementById('engine-status-text');
    if (data.status === 'OPERATIONAL') {
      statusText.textContent = 'Engine: OPERATIONAL';
      statusText.style.color = 'var(--text-secondary)';
    } else {
      statusText.textContent = `Engine: ${data.status}`;
      statusText.style.color = 'var(--status-critical)';
    }
  } catch (err) {
    document.getElementById('engine-status-text').textContent = 'Engine: OFFLINE';
  }
}

async function fetchMetrics() {
  try {
    const data = await apiFetch('/api/v1/metrics');
    document.getElementById('kpi-total-incidents').textContent = data.total_incidents || 0;
    document.getElementById('kpi-active-bans').textContent = data.active_bans_count || 0;
    document.getElementById('kpi-mttd').textContent = (data.mttd_seconds || 1.2) + 's';
    document.getElementById('kpi-mttr').textContent = (data.mttr_seconds || 0.8) + 's';

    // Threat Breakdown
    const ssh = data.threat_breakdown.SSH_BRUTE_FORCE || 0;
    const web = data.threat_breakdown.WEB_EXPLOIT_SCAN || 0;
    const sudo = data.threat_breakdown.PRIV_ESC_ANOMALY || 0;
    const total = (ssh + web + sudo) || 1;

    document.getElementById('threat-ssh-count').textContent = ssh;
    document.getElementById('threat-web-count').textContent = web;
    document.getElementById('threat-sudo-count').textContent = sudo;

    document.getElementById('threat-ssh-bar').style.width = Math.min(100, Math.round((ssh / total) * 100)) + '%';
    document.getElementById('threat-web-bar').style.width = Math.min(100, Math.round((web / total) * 100)) + '%';
    document.getElementById('threat-sudo-bar').style.width = Math.min(100, Math.round((sudo / total) * 100)) + '%';
  } catch (err) {}
}

async function fetchRecentContainments() {
  const container = document.getElementById('dashboard-recent-containments');
  try {
    const bans = await apiFetch('/api/v1/containment/bans');
    if (!bans || bans.length === 0) {
      container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 30px;">Zero active containment rules. System clean.</div>';
      return;
    }

    let html = '<div style="display: flex; flex-direction: column; gap: 8px;">';
    bans.slice(0, 5).forEach((b) => {
      html += `
        <div style="display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--bg-surface-2); border-radius: 8px; border: 1px solid var(--border-subtle);">
          <div style="display: flex; align-items: center; gap: 10px;">
            <span class="badge badge-critical">DROP</span>
            <span class="ip-pill">${b.ip_address}</span>
            <span style="font-size: 11px; color: var(--text-muted);">${b.rule_comment_tag}</span>
          </div>
          <button class="btn-action btn-danger" onclick="handleUnbanIP('${b.ip_address}')" style="padding: 3px 8px; font-size: 11px;">Unban</button>
        </div>
      `;
    });
    html += '</div>';
    container.innerHTML = html;
  } catch (err) {}
}

async function fetchIncidents() {
  const tbody = document.getElementById('incidents-table-body');
  const statusFilter = document.getElementById('incidents-status-filter').value;
  const search = document.getElementById('global-search-input').value;

  try {
    let url = `/api/v1/incidents?limit=50&status=${statusFilter}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;

    const incidents = await apiFetch(url);
    STATE.incidents = incidents;

    if (!incidents || incidents.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 30px;">No matching incidents recorded.</td></tr>';
      return;
    }

    let html = '';
    incidents.forEach((inc) => {
      const sevClass = inc.severity === 'CRITICAL' ? 'badge-critical' : inc.severity === 'HIGH' ? 'badge-high' : 'badge-medium';
      const statusClass = inc.status === 'CONTAINED' ? 'badge-critical' : 'badge-safe';

      html += `
        <tr>
          <td><span style="font-family: var(--font-mono); font-weight: 600;">${inc.id}</span></td>
          <td><span class="ip-pill">${inc.source_ip}</span></td>
          <td>${inc.threat_type}</td>
          <td><span class="badge ${sevClass}">${inc.severity}</span></td>
          <td><span style="font-family: var(--font-mono);">${inc.trigger_count}</span></td>
          <td><span class="badge ${statusClass}">${inc.status}</span></td>
          <td style="color: var(--text-muted); font-size: 12px;">${formatDate(inc.created_at)}</td>
          <td>
            <button class="btn-action" onclick="openForensicDrawer('${inc.id}')">Inspect</button>
          </td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  } catch (err) {}
}

async function fetchBans() {
  const tbody = document.getElementById('containment-table-body');
  try {
    const bans = await apiFetch('/api/v1/containment/bans');
    STATE.activeBans = bans;

    if (!bans || bans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 30px;">Zero active IP quarantines. System clean.</td></tr>';
      return;
    }

    let html = '';
    bans.forEach((b) => {
      html += `
        <tr>
          <td><span class="ip-pill">${b.ip_address}</span></td>
          <td style="font-family: var(--font-mono); font-size: 11px;">${b.rule_comment_tag}</td>
          <td><span style="font-family: var(--font-mono); font-weight: 600;">${b.chain}</span></td>
          <td><span class="badge badge-critical">${b.action}</span></td>
          <td style="color: var(--text-muted); font-size: 12px;">${formatDate(b.applied_at)}</td>
          <td><span class="badge badge-medium">${b.driver || 'netfilter'}</span></td>
          <td>
            <button class="btn-action btn-danger" onclick="handleUnbanIP('${b.ip_address}')">Lift Ban</button>
          </td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  } catch (err) {}
}

async function fetchRules() {
  const tbody = document.getElementById('rules-table-body');
  try {
    const rules = await apiFetch('/api/v1/rules');
    STATE.rules = rules;

    let html = '';
    rules.forEach((r) => {
      html += `
        <tr>
          <td><strong>${r.rule_name}</strong><br><span style="font-size: 11px; color: var(--text-muted); font-family: var(--font-mono);">${r.regex_pattern}</span></td>
          <td><span style="font-family: var(--font-mono);">${r.service_target}</span></td>
          <td><span style="font-family: var(--font-mono); font-weight: 600;">${r.threshold_count} attempts</span></td>
          <td><span style="font-family: var(--font-mono);">${r.window_seconds}s</span></td>
          <td><span class="badge badge-critical">${r.severity}</span></td>
          <td><span class="badge badge-safe">ACTIVE</span></td>
          <td>
            <button class="btn-action" onclick="promptTuneRule('${r.id}', ${r.threshold_count}, ${r.window_seconds})">Tune</button>
          </td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  } catch (err) {}
}

async function fetchWhitelist() {
  const tbody = document.getElementById('whitelist-table-body');
  try {
    const wl = await apiFetch('/api/v1/whitelist');
    STATE.whitelist = wl;

    let html = '';
    wl.forEach((w) => {
      html += `
        <tr>
          <td><span class="ip-pill" style="color: var(--status-safe);">${w.cidr_or_ip}</span></td>
          <td><strong>${w.label}</strong></td>
          <td><span class="badge badge-safe">IMMUNE</span></td>
          <td style="color: var(--text-muted); font-size: 12px;">${w.notes || '-'}</td>
          <td>
            <button class="btn-action btn-danger" onclick="handleDeleteWhitelist('${w.id}')" style="padding: 3px 8px; font-size: 11px;">Remove</button>
          </td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  } catch (err) {}
}

// ==============================================================================
// SOAR Operations & Action Handlers
// ==============================================================================

async function handleUnbanIP(ip) {
  if (!confirm(`Are you sure you want to lift Netfilter quarantine for IP: ${ip}?`)) return;

  try {
    await apiFetch('/api/v1/containment/unban', {
      method: 'POST',
      body: JSON.stringify({ ip, reason: 'Operator manual console unban' }),
    });
    showToast('CONTAINMENT REVOKED', `IP ${ip} was successfully unbanned.`, 'safe');
    fetchBans();
    fetchMetrics();
    fetchIncidents();
  } catch (err) {
    showToast('UNBAN FAILED', err.message, 'critical');
  }
}

async function promptTuneRule(ruleId, currentThreshold, currentWindow) {
  const newThresh = prompt(`Enter new trigger threshold for ${ruleId}:`, currentThreshold);
  if (!newThresh) return;
  const newWindow = prompt(`Enter new sliding evaluation window in seconds for ${ruleId}:`, currentWindow);
  if (!newWindow) return;

  try {
    await apiFetch(`/api/v1/rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify({
        threshold_count: parseInt(newThresh, 10),
        window_seconds: parseInt(newWindow, 10),
      }),
    });
    showToast('RULE UPDATED', `Detection rule ${ruleId} updated successfully.`, 'safe');
    fetchRules();
  } catch (err) {
    showToast('UPDATE FAILED', err.message, 'critical');
  }
}

async function handleDeleteWhitelist(id) {
  if (!confirm('Are you sure you want to remove this subnet from immunity?')) return;
  try {
    await apiFetch(`/api/v1/whitelist/${id}`, { method: 'DELETE' });
    showToast('WHITELIST UPDATED', 'Immunity rule removed.', 'safe');
    fetchWhitelist();
  } catch (err) {
    showToast('DELETE FAILED', err.message, 'critical');
  }
}

// ==============================================================================
// Forensic Drawer & Markdown Dossier
// ==============================================================================

async function openForensicDrawer(incidentId) {
  STATE.selectedIncidentId = incidentId;
  const drawer = document.getElementById('forensic-drawer');
  drawer.classList.add('open');

  document.getElementById('drawer-incident-id').textContent = incidentId;
  document.getElementById('drawer-markdown-content').textContent = 'Loading forensic dossier from disk...';
  const eventsList = document.getElementById('drawer-events-list');
  eventsList.innerHTML = '<span style="color: var(--text-muted); font-size: 12px;">Loading events...</span>';

  try {
    const data = await apiFetch(`/api/v1/incidents/${incidentId}`);
    document.getElementById('drawer-incident-meta').textContent = `${data.incident.threat_type} | ${data.incident.source_ip} | Status: ${data.incident.status}`;
    document.getElementById('drawer-markdown-content').textContent = data.markdown_report || 'No Markdown report compiled for this incident.';

    if (data.events && data.events.length > 0) {
      let eventsHtml = '';
      data.events.forEach((ev) => {
        eventsHtml += `
          <div style="background: var(--bg-surface-2); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-subtle); font-family: var(--font-mono); font-size: 11px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
              <span style="color: #818cf8;">${ev.service}</span>
              <span style="color: var(--text-muted);">${formatDate(ev.event_timestamp)}</span>
            </div>
            <div style="color: #d1d5db; word-break: break-all;">${escapeHtml(ev.raw_log)}</div>
          </div>
        `;
      });
      eventsList.innerHTML = eventsHtml;
    } else {
      eventsList.innerHTML = '<span style="color: var(--text-muted); font-size: 12px;">No historical log lines captured in incident window.</span>';
    }

    const releaseBtn = document.getElementById('drawer-btn-release');
    releaseBtn.style.display = data.incident.status === 'CONTAINED' ? 'block' : 'none';
    releaseBtn.onclick = async () => {
      try {
        await apiFetch(`/api/v1/incidents/${incidentId}/release`, {
          method: 'POST',
          body: JSON.stringify({ reason: 'Manual release from forensic drawer' }),
        });
        showToast('INCIDENT RESOLVED', `Quarantine lifted for ${data.incident.source_ip}.`, 'safe');
        openForensicDrawer(incidentId);
        fetchIncidents();
        fetchBans();
        fetchMetrics();
      } catch (err) {
        showToast('RELEASE FAILED', err.message, 'critical');
      }
    };
  } catch (err) {
    document.getElementById('drawer-markdown-content').textContent = `Failed to load details: ${err.message}`;
  }
}

function closeDrawer() {
  document.getElementById('forensic-drawer').classList.remove('open');
}

// ==============================================================================
// Modals & Forms
// ==============================================================================

function initModals() {
  // Drawer close button
  document.getElementById('btn-close-drawer').addEventListener('click', closeDrawer);

  // Quarantine Modal
  const quarantineModal = document.getElementById('quarantine-modal');
  document.getElementById('btn-open-quarantine-modal').addEventListener('click', () => openModal('quarantine-modal'));
  document.getElementById('btn-close-quarantine-modal').addEventListener('click', () => closeModal('quarantine-modal'));
  document.getElementById('btn-cancel-quarantine').addEventListener('click', () => closeModal('quarantine-modal'));

  document.getElementById('btn-confirm-quarantine').addEventListener('click', async () => {
    const ip = document.getElementById('quarantine-ip').value.trim();
    const vector = document.getElementById('quarantine-vector').value;
    const reason = document.getElementById('quarantine-reason').value.trim() || 'Manual analyst isolation';
    const duration = parseInt(document.getElementById('quarantine-duration').value, 10) || 3600;

    if (!ip) {
      alert('Please enter a target IPv4 address.');
      return;
    }

    try {
      await apiFetch('/api/v1/containment/block', {
        method: 'POST',
        body: JSON.stringify({ ip, vector, reason, duration_seconds: duration }),
      });
      showToast('QUARANTINE ENFORCED', `IP ${ip} isolated with Netfilter DROP rule.`, 'critical');
      closeModal('quarantine-modal');
      document.getElementById('quarantine-ip').value = '';
      fetchBans();
      fetchIncidents();
      fetchMetrics();
    } catch (err) {
      alert(`Quarantine failed: ${err.message}`);
    }
  });

  // Whitelist Modal
  document.getElementById('btn-open-add-whitelist').addEventListener('click', () => openModal('whitelist-modal'));
  document.getElementById('btn-close-whitelist-modal').addEventListener('click', () => closeModal('whitelist-modal'));
  document.getElementById('btn-cancel-whitelist').addEventListener('click', () => closeModal('whitelist-modal'));

  document.getElementById('btn-confirm-whitelist').addEventListener('click', async () => {
    const cidr = document.getElementById('wl-cidr-input').value.trim();
    const label = document.getElementById('wl-label-input').value.trim() || 'Custom Protected Subnet';
    const notes = document.getElementById('wl-notes-input').value.trim() || '';

    if (!cidr) {
      alert('Please enter an IP or CIDR block.');
      return;
    }

    try {
      await apiFetch('/api/v1/whitelist', {
        method: 'POST',
        body: JSON.stringify({ cidr_or_ip: cidr, label, notes }),
      });
      showToast('IMMUNITY GRANTED', `Subnet ${cidr} added to whitelist.`, 'safe');
      closeModal('whitelist-modal');
      document.getElementById('wl-cidr-input').value = '';
      fetchWhitelist();
    } catch (err) {
      alert(`Failed to add whitelist: ${err.message}`);
    }
  });

  // Emergency Flush All
  document.getElementById('btn-emergency-flush').addEventListener('click', async () => {
    if (!confirm('CRITICAL ACTION: Are you sure you want to flush ALL active containment drop rules?')) return;
    try {
      await apiFetch('/api/v1/containment/flush', { method: 'POST' });
      showToast('ALL RULES FLUSHED', 'Netfilter drop rules have been completely purged.', 'safe');
      fetchBans();
      fetchMetrics();
      fetchIncidents();
    } catch (err) {
      showToast('FLUSH FAILED', err.message, 'critical');
    }
  });

  // Export Incidents CSV
  document.getElementById('btn-export-incidents-csv').addEventListener('click', () => {
    if (!STATE.incidents || STATE.incidents.length === 0) {
      alert('No incidents to export.');
      return;
    }
    const headers = ['id', 'source_ip', 'threat_type', 'severity', 'trigger_count', 'status', 'created_at'];
    let csv = headers.join(',') + '\n';
    STATE.incidents.forEach((i) => {
      csv += `${i.id},"${i.source_ip}",${i.threat_type},${i.severity},${i.trigger_count},${i.status},"${i.created_at}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sentinel-incidents-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Search & Filter change events
  document.getElementById('incidents-status-filter').addEventListener('change', fetchIncidents);
  document.getElementById('global-search-input').addEventListener('keyup', (e) => {
    if (e.key === 'Enter') fetchIncidents();
  });
}

function openModal(modalId) {
  document.getElementById(modalId).classList.add('open');
}

function closeModal(modalId) {
  document.getElementById(modalId).classList.remove('open');
}

function closeAllModals() {
  document.querySelectorAll('.modal-overlay').forEach((m) => m.classList.remove('open'));
}

// Toast System
function showToast(title, message, type = 'high') {
  const stack = document.getElementById('toast-stack');
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  toast.innerHTML = `
    <div class="toast-header">
      <span>${escapeHtml(title)}</span>
      <span style="font-size: 10px; color: var(--text-muted); cursor: pointer;" onclick="this.parentElement.parentElement.remove()">&times;</span>
    </div>
    <div class="toast-msg">${escapeHtml(message)}</div>
  `;

  stack.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 300ms ease';
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

// Utility Helpers
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (m) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[m]));
}

function formatDate(isoStr) {
  if (!isoStr) return '-';
  try {
    const d = new Date(isoStr.replace(' ', 'T'));
    return d.toLocaleString();
  } catch (e) {
    return isoStr;
  }
}
