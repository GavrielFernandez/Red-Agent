/* ============================================================================
   RedAgent Dashboard - Unified JavaScript
   ============================================================================ */

const state = {
    currentTab: 'dashboard',
    toolsHealth: [],
    toolsFilter: 'all',
    toolChecks: {},
    health: {},
    dashboardUpdateInFlight: false,
    toolsHealthLoadedAt: 0,
    cyberRangeInventory: null,
    cyberRangeInventoryLoadedAt: 0,
    reportImportInFlight: false
};

const navItems = document.querySelectorAll('.nav-item[data-tab]');
const tabContents = document.querySelectorAll('.tab-content');
const assessmentForm = document.getElementById('assessment-form');
const pageTitle = document.getElementById('page-title');

navItems.forEach(item => {
    item.addEventListener('click', () => {
        const tabName = item.getAttribute('data-tab');
        switchTab(tabName);
    });
});

function switchTab(tabName) {
    navItems.forEach(item => item.classList.remove('active'));
    const selected = document.querySelector(`[data-tab="${tabName}"]`);
    if (selected) selected.classList.add('active');

    tabContents.forEach(content => content.classList.remove('active'));
    const tabContent = document.getElementById(tabName);
    if (tabContent) tabContent.classList.add('active');

    const titles = {
        dashboard: 'Dashboard',
        assessment: 'New Assessment',
        jobs: 'Job History',
        reports: 'Assessment Reports',
        tools: 'Tools',
        intelligence: 'OSINT Intelligence Hub',
        mitre: 'MITRE ATT&CK Mapping',
        agents: 'Multi-Agent Swarm'
    };
    pageTitle.textContent = titles[tabName] || 'Dashboard';

    if (tabName === 'jobs') loadJobHistory();
    if (tabName === 'reports') loadReports();
    if (tabName === 'tools') loadToolsTab();
    if (tabName === 'dashboard') updateDashboard();
    if (tabName === 'agents') refreshSwarmStatus();
    if (tabName === 'tools') {
        setTimeout(() => {
            document.getElementById('tool-run-url')?.focus();
        }, 50);
    }
    if (tabName === 'dashboard') {
        loadHealthOverview();
    }

    state.currentTab = tabName;
}

function normalizeAssessmentTargetInput(target, type) {
    const value = String(target || '').trim();
    if (!value) return '';
    if (type === 'url' && !/^https?:\/\//i.test(value)) {
        return `http://${value}`;
    }
    return value;
}

assessmentForm?.addEventListener('submit', async e => {
    e.preventDefault();

    const target = document.getElementById('target').value.trim();
    const type = document.getElementById('target-type').value;
    const mode = document.getElementById('execution-mode')?.value || 'classic';

    if (!target) {
        showNotification('Please enter a target', 'error');
        return;
    }

    const submitBtn = assessmentForm.querySelector('button[type="submit"]');
    const originalHtml = submitBtn.innerHTML;
    const normalizedTarget = normalizeAssessmentTargetInput(target, type);

    try {
        submitBtn.disabled = true;
        submitBtn.innerHTML = 'Starting...';

        const response = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: normalizedTarget, type, mode })
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to start assessment');
        }

        assessmentForm.reset();
        showNotification(`Assessment started in ${mode} mode: ${result.job_id}`, 'success');
        switchTab('dashboard');
        monitorJob(result.job_id);
    } catch (error) {
        showNotification(error.message, 'error');
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalHtml;
    }
});

function monitorJob(jobId) {
    let attempts = 0;
    const maxAttempts = 180;

    const interval = setInterval(async () => {
        try {
            const response = await fetch(`/api/assess/${jobId}`);
            if (!response.ok) {
                clearInterval(interval);
                return;
            }

            const job = await response.json();
            updateDashboard();

            if (job.mode === 'swarm' && state.currentTab === 'agents') {
                refreshSwarmStatus();
            }

            if (['completed', 'failed', 'cancelled'].includes(job.status)) {
                clearInterval(interval);
                if (job.status === 'completed') showNotification('Assessment completed', 'success');
                if (job.status === 'failed') showNotification(`Assessment failed: ${job.error || 'unknown error'}`, 'error');
                if (job.status === 'cancelled') showNotification('Assessment cancelled', 'info');
            }

            attempts += 1;
            if (attempts >= maxAttempts) clearInterval(interval);
        } catch {
            clearInterval(interval);
        }
    }, 1000);
}

async function updateDashboard() {
    if (state.dashboardUpdateInFlight) return;
    state.dashboardUpdateInFlight = true;
    try {
        const statusResponse = await fetch('/api/status');
        if (!statusResponse.ok) throw new Error('Failed to fetch status');
        const status = await statusResponse.json();

        document.getElementById('total-jobs').textContent = status.jobs.total;
        document.getElementById('running-jobs').textContent = status.jobs.running;
        document.getElementById('completed-jobs').textContent = status.jobs.completed;
        document.getElementById('failed-jobs').textContent = status.jobs.failed;

        state.health = status;
        updateStatusChips(status);

        const jobsResponse = await fetch('/api/jobs');
        if (!jobsResponse.ok) throw new Error('Failed to fetch jobs');
        const jobsData = await jobsResponse.json();

        displayActiveJobs(jobsData.jobs || []);
        displayBusinessLogicInsights(jobsData.jobs || []);
        displayValidationInsights(jobsData.jobs || []);
        displayAttackAnalytics(jobsData.jobs || []);
        if (Date.now() - Number(state.toolsHealthLoadedAt || 0) > 30000) {
            await loadToolsHealth();
        }
        if (Date.now() - Number(state.cyberRangeInventoryLoadedAt || 0) > 30000) {
            await loadCyberRangeInventory();
        }
    } catch (error) {
        console.error('Dashboard update error:', error);
    } finally {
        state.dashboardUpdateInFlight = false;
    }
}

async function loadHealthOverview() {
    try {
        const response = await fetch('/api/health');
        if (!response.ok) throw new Error('Failed to load health');
        const health = await response.json();
        state.health = health;
        updateStatusChips(health);
    } catch (error) {
        console.error('Health overview error:', error);
    }
}

async function loadCyberRangeInventory() {
    const container = document.getElementById('cyber-range-container');
    const servicesEl = document.getElementById('cyber-range-services');
    const scenariosEl = document.getElementById('cyber-range-scenarios');
    const composeEl = document.getElementById('cyber-range-compose');
    const dockerfilesEl = document.getElementById('cyber-range-dockerfiles');
    const badgeEl = document.getElementById('cyber-range-badge');

    if (!container || !servicesEl || !scenariosEl || !composeEl || !dockerfilesEl || !badgeEl) return;

    try {
        const response = await fetch('/api/cyber-range/inventory?range_path=cyber_range');
        if (!response.ok) throw new Error('Failed to load cyber range inventory');

        const data = await response.json();
        const metadata = data.metadata || {};
        const summary = metadata.summary || {};
        const services = Array.isArray(metadata.services) ? metadata.services : [];
        const scenarios = Array.isArray(metadata.scenarios) ? metadata.scenarios : [];

        state.cyberRangeInventory = data;
        state.cyberRangeInventoryLoadedAt = Date.now();

        servicesEl.textContent = String(summary.services ?? services.length ?? 0);
        scenariosEl.textContent = String(summary.scenarios ?? scenarios.length ?? 0);
        composeEl.textContent = String(summary.compose_files ?? 0);
        dockerfilesEl.textContent = String(summary.dockerfiles ?? 0);
        badgeEl.textContent = `${String(summary.scenarios ?? scenarios.length ?? 0)} scenarios`;

        if (!services.length && !scenarios.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>No range content found</p>
                    <small>Add compose files and scenario manifests under cyber_range/.</small>
                </div>
            `;
            return;
        }

        const scenarioCards = scenarios.map(scenario => {
            const name = scenario.name || 'unnamed-scenario';
            const version = scenario.version || 'n/a';
            const objective = scenario.objective || 'No objective recorded';
            const path = scenario.path || '';
            return `
                <div class="job-card">
                    <div class="job-header">
                        <div class="job-title">${escapeHtml(name)}</div>
                        <span class="job-status status-completed">v${escapeHtml(version)}</span>
                    </div>
                    <div style="margin-top:0.35rem;color:var(--text-muted);font-size:0.9rem;">${escapeHtml(objective)}</div>
                    <div style="margin-top:0.5rem;color:var(--text-secondary);font-size:0.82rem;">${escapeHtml(path)}</div>
                </div>
            `;
        }).join('');

        const serviceText = services.map(service => `<li>${escapeHtml(service)}</li>`).join('');
        container.innerHTML = `
            <div class="job-card">
                <div class="job-header">
                    <div class="job-title">Local sandbox inventory</div>
                    <span class="job-status status-running">Ready</span>
                </div>
                <div style="margin-top:0.5rem;color:var(--text-muted);font-size:0.9rem;">The range is isolated and intended for local training only.</div>
                <div style="margin-top:0.75rem;">
                    <strong>Services</strong>
                    <ul style="margin:0.4rem 0 0 1.2rem;color:var(--text-secondary);">${serviceText}</ul>
                </div>
            </div>
            ${scenarioCards}
        `;
    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                <p>Unable to load cyber range</p>
                <small>${escapeHtml(error.message)}</small>
            </div>
        `;
    }
}

function updateStatusChips(payload) {
    const health = payload || {};
    const infra = health.infrastructure || health.checks || {};
    const reports = health.reports || {};
    const jobs = health.jobs || {};

    const ollamaEl = document.getElementById('status-ollama');
    const dashboardEl = document.getElementById('status-dashboard');
    const validationEl = document.getElementById('status-validation');
    const reportsEl = document.getElementById('status-reports');
    const heroSystemEl = document.getElementById('hero-system-status');
    const heroReportsEl = document.getElementById('hero-reports-count');
    const heroValidationEl = document.getElementById('hero-validation-count');

    const ollamaStatus = String(infra.ollama || infra.ollama_status || 'unknown');
    const validationStatus = String(infra.validation || health.validation || 'ready');
    const reportCount = Number(reports.total || health.reports_generated || 0);
    const validationCount = Number(jobs.completed || 0);

    if (ollamaEl) ollamaEl.textContent = ollamaStatus;
    if (dashboardEl) dashboardEl.textContent = 'Ready';
    if (validationEl) validationEl.textContent = validationStatus;
    if (reportsEl) reportsEl.textContent = String(reportCount);
    if (heroSystemEl) heroSystemEl.textContent = `${String(health.status || 'ok').toUpperCase()}`;
    if (heroReportsEl) heroReportsEl.textContent = String(reportCount);
    if (heroValidationEl) heroValidationEl.textContent = String(validationCount);
}

async function loadToolsHealth() {
    const container = document.getElementById('tools-health-container');
    const totalEl = document.getElementById('tools-total');
    const readyEl = document.getElementById('tools-ready');
    const degradedEl = document.getElementById('tools-degraded');
    const unavailableEl = document.getElementById('tools-unavailable');
    const readyCountBadge = document.getElementById('tools-ready-count');

    if (!container || !totalEl || !readyEl || !degradedEl || !unavailableEl || !readyCountBadge) {
        return;
    }

    try {
        const response = await fetch('/api/tools');
        if (!response.ok) throw new Error('Failed to load tools status');

        const data = await response.json();
        const summary = data.summary || {};
        const tools = Array.isArray(data.tools) ? data.tools : [];
        state.toolsHealth = tools;
        state.toolsHealthLoadedAt = Date.now();

        totalEl.textContent = String(summary.total || tools.length || 0);
        readyEl.textContent = String(summary.ready || 0);
        degradedEl.textContent = String(summary.degraded || 0);
        unavailableEl.textContent = String(summary.unavailable || 0);
        readyCountBadge.textContent = `${summary.ready || 0}/${summary.total || tools.length || 0} ready`;

        if (!tools.length) {
            container.innerHTML = `
                <div class="empty-state">
                    <p>No tools loaded</p>
                    <small>Check plugin directories and runtime logs.</small>
                </div>
            `;
            return;
        }

        container.innerHTML = tools.map(tool => {
            const status = String(tool.status || 'unknown').toLowerCase();
            const statusColor = status === 'ready'
                ? '#10b981'
                : status === 'degraded'
                    ? '#f59e0b'
                    : '#ef4444';

            return `
                <div class="job-card">
                    <div class="job-header">
                        <div class="job-title">${escapeHtml(tool.name || 'unknown')}</div>
                        <span class="job-status" style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}66;">${escapeHtml(status.toUpperCase())}</span>
                    </div>
                    <div style="margin-top:0.35rem;color:var(--text-muted);font-size:0.9rem;">${escapeHtml(tool.description || '')}</div>
                    <div style="margin-top:0.5rem;color:var(--text-secondary);font-size:0.82rem;">${escapeHtml(tool.reason || 'No diagnostics')}</div>
                </div>
            `;
        }).join('');

        renderToolsTab(tools, summary);
    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                <p>Unable to load tool health</p>
                <small>${escapeHtml(error.message)}</small>
            </div>
        `;
    }
}

function renderToolsTab(tools, summary = {}) {
    const container = document.getElementById('tools-tab-container');
    const totalEl = document.getElementById('tools-tab-total');
    const readyEl = document.getElementById('tools-tab-ready');
    const degradedEl = document.getElementById('tools-tab-degraded');
    const unavailableEl = document.getElementById('tools-tab-unavailable');

    if (!container || !totalEl || !readyEl || !degradedEl || !unavailableEl) return;

    totalEl.textContent = String(summary.total ?? tools.length ?? 0);
    readyEl.textContent = String(summary.ready ?? tools.filter(t => t.status === 'ready').length);
    degradedEl.textContent = String(summary.degraded ?? tools.filter(t => t.status === 'degraded').length);
    unavailableEl.textContent = String(summary.unavailable ?? tools.filter(t => t.status === 'unavailable').length);

    const filtered = state.toolsFilter === 'all'
        ? tools
        : tools.filter(t => String(t.status || '').toLowerCase() === state.toolsFilter);

    if (!filtered.length) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No tools match this filter</p>
                <small>Try a different status filter.</small>
            </div>
        `;
        return;
    }

    container.innerHTML = filtered.map(tool => {
        const status = String(tool.status || 'unknown').toLowerCase();
        const statusColor = status === 'ready' ? '#10b981' : status === 'degraded' ? '#f59e0b' : '#ef4444';
        const hint = String(tool.install_hint || '').trim();
        const check = state.toolChecks[tool.name] || null;
        const checkText = check
            ? `<div style="margin-top:0.45rem;color:var(--text-muted);font-size:0.82rem;">Check: ${escapeHtml(check.ok ? 'PASS' : 'FAIL')} | ${escapeHtml(check.message || '')} ${check.duration_ms ? `(${check.duration_ms}ms)` : ''}</div>`
            : '';
        return `
            <div class="job-card">
                <div class="job-header">
                    <div class="job-title">${escapeHtml(tool.name || 'unknown')}</div>
                    <span class="job-status" style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}66;">${escapeHtml(status.toUpperCase())}</span>
                </div>
                <div style="margin-top:0.35rem;color:var(--text-muted);font-size:0.9rem;">${escapeHtml(tool.description || '')}</div>
                <div style="margin-top:0.5rem;color:var(--text-secondary);font-size:0.82rem;">${escapeHtml(tool.reason || 'No diagnostics')}</div>
                ${checkText}
                ${hint ? `
                    <div class="job-actions" style="margin-top:0.6rem;">
                        <button class="btn btn-primary btn-small" onclick="runToolCheck('${escapeHtml(tool.name)}')">Run Check</button>
                        <button class="btn btn-secondary btn-small" onclick="copyToolInstallHint('${escapeHtml(tool.name)}')">Copy Install Hint</button>
                    </div>
                ` : `
                    <div class="job-actions" style="margin-top:0.6rem;">
                        <button class="btn btn-primary btn-small" onclick="runToolCheck('${escapeHtml(tool.name)}')">Run Check</button>
                    </div>
                `}
            </div>
        `;
    }).join('');
}

async function loadToolsTab() {
    try {
        const response = await fetch('/api/tools');
        if (!response.ok) throw new Error('Failed to load tools status');
        const data = await response.json();
        state.toolsHealth = Array.isArray(data.tools) ? data.tools : [];
        renderToolsTab(state.toolsHealth, data.summary || {});
        await loadCyberRangeInventory();
        setTimeout(() => {
            document.getElementById('tool-run-url')?.focus();
        }, 50);
    } catch (error) {
        const container = document.getElementById('tools-tab-container');
        if (container) {
            container.innerHTML = `<div class="empty-state"><p>Unable to load tools</p><small>${escapeHtml(error.message)}</small></div>`;
        }
    }
}

async function copyToolInstallHint(toolName) {
    const tool = state.toolsHealth.find(t => t.name === toolName);
    const hint = tool?.install_hint || '';
    if (!hint) {
        showNotification('No install hint available for this tool', 'info');
        return;
    }
    try {
        await navigator.clipboard.writeText(hint);
        showNotification(`Install hint copied for ${toolName}`, 'success');
    } catch {
        showNotification('Unable to copy install hint', 'error');
    }
}

async function runToolCheck(toolName) {
    try {
        const response = await fetch(`/api/tools/${encodeURIComponent(toolName)}/check`, { method: 'POST' });
        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to run tool check');
        }
        state.toolChecks[toolName] = result;
        renderToolsTab(state.toolsHealth || []);
        showNotification(`Tool check ${result.ok ? 'passed' : 'failed'} for ${toolName}`, result.ok ? 'success' : 'error');
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function runUrlTool() {
    const urlInput = document.getElementById('tool-run-url');
    const toolSelect = document.getElementById('tool-run-name');
    const resultBox = document.getElementById('tool-run-result');

    if (!urlInput || !toolSelect || !resultBox) return;

    const url = urlInput.value.trim();
    const tool = toolSelect.value;
    if (!url) {
        showNotification('Enter a target value first', 'error');
        return;
    }

    resultBox.style.display = 'block';
    resultBox.innerHTML = '<div class="job-header"><div class="job-title">Running...</div></div><div style="color:var(--text-muted);margin-top:0.5rem;">Executing the selected tool with safe parameters.</div>';

    try {
        const urlTools = new Set(['curl', 'nuclei']);
        const endpoint = urlTools.has(tool) ? '/api/tools/run-url' : '/api/tools/execute';
        const payload = urlTools.has(tool)
            ? { tool, url }
            : { tool, params: buildSafeToolParams(tool, url) };

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to run tool');
        }

        const status = result.ok ? 'success' : 'error';
        showNotification(`${tool} finished for ${url}`, status);
        resultBox.innerHTML = `
            <div class="job-header">
                <div class="job-title">${escapeHtml(tool)} on ${escapeHtml(url)}</div>
                <span class="job-status status-${result.ok ? 'completed' : 'failed'}">${escapeHtml((result.status || 'unknown').toUpperCase())}</span>
            </div>
            <div class="job-meta" style="margin-top:0.75rem;">
                <div class="job-meta-item"><span>Return Code:</span><strong>${result.return_code}</strong></div>
                <div class="job-meta-item"><span>Execution Time:</span><strong>${Number(result.execution_time || 0).toFixed(2)}s</strong></div>
            </div>
            ${result.stdout ? `<div style="margin-top:0.75rem;"><strong>Output</strong><pre style="white-space:pre-wrap;background:rgba(0,0,0,0.25);padding:12px;border-radius:8px;overflow:auto;max-height:260px;">${escapeHtml(result.stdout)}</pre></div>` : ''}
            ${result.stderr ? `<div style="margin-top:0.75rem;"><strong>Diagnostics</strong><pre style="white-space:pre-wrap;background:rgba(0,0,0,0.25);padding:12px;border-radius:8px;overflow:auto;max-height:220px;">${escapeHtml(result.stderr)}</pre></div>` : ''}
        `;
    } catch (error) {
        resultBox.style.display = 'block';
        resultBox.innerHTML = `<div class="job-header"><div class="job-title">Run failed</div></div><div style="color:var(--text-muted);margin-top:0.5rem;">${escapeHtml(error.message)}</div>`;
        showNotification(error.message, 'error');
    }
}

function buildSafeToolParams(tool, value) {
    const target = String(value || '').trim();
    switch (tool) {
        case 'fuzzing_harness':
            return {
                target,
                seed: 'redagent',
                iterations: 25,
                payload_mode: 'balanced'
            };
        case 'cloud_posture':
            return {
                target,
                profile: target || 'default'
            };
        case 'cyber_range':
            return {
                target,
                range_path: target || 'cyber_range'
            };
        default:
            return { target };
    }
}

function inferOsintTargetType(target) {
    const value = String(target || '').trim();
    if (!value) return 'domain';
    if (/^https?:\/\//i.test(value)) return 'url';
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return 'ip';
    return 'domain';
}

function setOsintSourceBadges(apiKeysStatus = {}) {
    const badgeMap = {
        shodan: document.getElementById('shodan-status'),
        virustotal: document.getElementById('vt-status'),
        censys: document.getElementById('censys-status'),
        securitytrails: document.getElementById('st-status')
    };

    Object.entries(badgeMap).forEach(([source, el]) => {
        if (!el) return;
        const configured = Boolean(apiKeysStatus[source]);
        el.textContent = configured ? 'Configured' : 'Configure API Key';
        el.style.background = configured ? 'rgba(16,185,129,0.2)' : 'rgba(245,158,11,0.2)';
        el.style.color = configured ? '#10b981' : '#f59e0b';
        el.style.border = configured ? '1px solid rgba(16,185,129,0.45)' : '1px solid rgba(245,158,11,0.45)';
        el.style.padding = '2px 8px';
        el.style.borderRadius = '999px';
    });
}

function renderOsintResult(data) {
    const container = document.getElementById('osint-results');
    if (!container) return;

    const summary = data.intelligence?.summary || {};
    const risks = Array.isArray(data.intelligence?.risk_indicators) ? data.intelligence.risk_indicators : [];
    const correlations = Array.isArray(data.intelligence?.correlations) ? data.intelligence.correlations : [];

    const summaryHtml = data.intelligence ? `
        <div class="stats-grid" style="margin-top: 14px;">
            <div class="stat-box"><div class="stat-content"><div class="stat-number">${Number(summary.total_sources_queried || 0)}</div><div class="stat-label">Sources Queried</div></div></div>
            <div class="stat-box"><div class="stat-content"><div class="stat-number">${Number(summary.successful_queries || 0)}</div><div class="stat-label">Successful</div></div></div>
            <div class="stat-box"><div class="stat-content"><div class="stat-number">${Number(summary.total_ips_found || 0)}</div><div class="stat-label">IPs</div></div></div>
            <div class="stat-box"><div class="stat-content"><div class="stat-number">${Number(summary.total_ports_found || 0)}</div><div class="stat-label">Open Ports</div></div></div>
        </div>
    ` : '';

    const riskHtml = risks.length ? `
        <div style="margin-top:14px;display:grid;gap:8px;">
            ${risks.map(risk => `<div class="job-card"><strong>${escapeHtml(String(risk.severity || 'info').toUpperCase())}</strong> - ${escapeHtml(risk.description || 'Risk indicator')}</div>`).join('')}
        </div>
    ` : '';

    const correlationHtml = correlations.length ? `
        <div style="margin-top:14px;display:grid;gap:8px;">
            ${correlations.map(item => `<div class="job-card"><strong>${escapeHtml(item.type || 'correlation')}</strong><div style="margin-top:6px;color:var(--text-muted);">${escapeHtml(item.description || '')}</div></div>`).join('')}
        </div>
    ` : '';

    container.innerHTML = `
        <div class="job-card" style="margin-top: 12px;">
            <div class="job-header">
                <div class="job-title">OSINT Result: ${escapeHtml(data.target || '-')}</div>
                <span class="job-status status-completed">${escapeHtml(String(data.status || 'ready').toUpperCase())}</span>
            </div>
            <div style="margin-top:8px;color:var(--text-muted);">${escapeHtml(data.message || 'OSINT check completed')}</div>
            <div style="margin-top:8px;color:var(--text-secondary);font-size:0.85rem;">Configured Sources: ${Number(data.configured_count || 0)}/${Number(data.total_count || 0)}</div>
            ${summaryHtml}
            ${riskHtml}
            ${correlationHtml}
        </div>
    `;
}

async function gatherOSINT() {
    const targetInput = document.getElementById('osint-target');
    const target = targetInput ? targetInput.value.trim() : '';
    const results = document.getElementById('osint-results');

    if (!target) {
        showNotification('Please provide a domain, URL, or IP target', 'error');
        return;
    }

    if (results) {
        results.innerHTML = '<div class="empty-state"><p>Gathering intelligence...</p><small>Querying configured OSINT sources.</small></div>';
    }

    try {
        const response = await fetch('/api/osint/gather', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, target_type: inferOsintTargetType(target) })
        });

        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || 'Failed to gather OSINT intelligence');
        }

        setOsintSourceBadges(payload.api_keys_status || {});
        renderOsintResult(payload);
        showNotification('OSINT intelligence updated', 'success');
    } catch (error) {
        if (results) {
            results.innerHTML = `<div class="empty-state"><p>OSINT request failed</p><small>${escapeHtml(error.message)}</small></div>`;
        }
        showNotification(error.message, 'error');
    }
}

function displayAttackAnalytics(jobs) {
    const modeEl = document.getElementById('attack-analytics-mode');
    const attemptsEl = document.getElementById('attack-attempts');
    const successRateEl = document.getElementById('attack-success-rate');
    const detectionRateEl = document.getElementById('attack-detection-rate');
    const fallbackEl = document.getElementById('attack-fallback-used');
    const avgDurationEl = document.getElementById('attack-avg-exploit-duration');
    const contextEl = document.getElementById('attack-analytics-context');

    if (!modeEl || !attemptsEl || !successRateEl || !detectionRateEl || !fallbackEl || !avgDurationEl || !contextEl) return;

    const latestSwarm = [...jobs]
        .filter(job => job.mode === 'swarm' && job.swarm)
        .sort((a, b) => new Date(b.completed_at || b.created_at || 0) - new Date(a.completed_at || a.created_at || 0))[0];

    if (!latestSwarm) {
        modeEl.textContent = 'n/a';
        attemptsEl.textContent = '0';
        successRateEl.textContent = '0%';
        detectionRateEl.textContent = '0%';
        fallbackEl.textContent = 'No';
        avgDurationEl.textContent = '0.00s';
        contextEl.textContent = 'Waiting for completed swarm assessment telemetry.';
        return;
    }

    const metrics = latestSwarm.swarm.attack_metrics || {};
    const timings = latestSwarm.swarm.agent_timings || {};

    const attempts = Number(metrics.attempted || 0);
    const successRate = Number(metrics.success_rate || 0);
    const detectionRate = Number(metrics.detection_rate || 0);
    const fallbackUsed = Boolean(metrics.fallback_attacks_used);
    const exploitTotal = Number(timings.exploit_execution || 0) + Number(timings.fallback_focused_attack || 0);
    const avgExploitDuration = attempts > 0 ? (exploitTotal / attempts) : 0;

    modeEl.textContent = fallbackUsed ? 'focused_fallback' : 'priority_exploit';
    attemptsEl.textContent = String(attempts);
    successRateEl.textContent = `${successRate}%`;
    detectionRateEl.textContent = `${detectionRate}%`;
    fallbackEl.textContent = fallbackUsed ? 'Yes' : 'No';
    avgDurationEl.textContent = `${avgExploitDuration.toFixed(2)}s`;
    contextEl.textContent = `Latest swarm mission: ${latestSwarm.swarm.mission_id || latestSwarm.id} | status: ${latestSwarm.status}`;
}

function displayBusinessLogicInsights(jobs) {
    const container = document.getElementById('business-logic-container');
    const badge = document.getElementById('business-logic-count');
    if (!container || !badge) return;

    const rows = [];
    jobs.forEach(job => {
        const findings = Array.isArray(job.findings) ? job.findings : [];
        findings
            .filter(isBusinessLogicFinding)
            .forEach(finding => rows.push({ job, finding }));
    });

    badge.textContent = rows.length;
    if (!rows.length) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No business-logic findings yet</p>
                <small>Run assessments to populate workflow and access-control insights</small>
            </div>
        `;
        return;
    }

    const topRows = rows.slice(0, 12);
    container.innerHTML = topRows.map(({ job, finding }) => {
        const severity = String(finding.severity || 'medium').toLowerCase();
        const confidence = deriveFindingConfidence(finding);
        return `
            <div class="job-card">
                <div class="job-header">
                    <div class="job-title">${escapeHtml(job.target || job.id)}</div>
                    <span class="job-status status-${escapeHtml(severity)}">${escapeHtml(severity.toUpperCase())}</span>
                </div>
                <div class="job-meta">
                    <div class="job-meta-item"><span>Variant:</span><strong>${escapeHtml(finding.attack_variant || finding.type || 'Business Logic')}</strong></div>
                    <div class="job-meta-item"><span>Confidence:</span><strong>${confidence}%</strong></div>
                    <div class="job-meta-item"><span>Evidence:</span><strong>${escapeHtml(finding.evidence_strength || 'moderate')}</strong></div>
                </div>
                <div style="margin-top:0.75rem;color:var(--text-muted);font-size:0.9rem;">
                    ${escapeHtml(finding.description || 'Business-logic condition detected')}
                </div>
                <div class="job-actions" style="margin-top:0.75rem;">
                    <button class="btn btn-secondary btn-small" onclick="viewJobDetails('${escapeHtml(job.id)}')">View Job</button>
                </div>
            </div>
        `;
    }).join('');
}

function displayValidationInsights(jobs) {
    const container = document.getElementById('remediation-container');
    const badge = document.getElementById('remediation-count');
    if (!container || !badge) return;

    const rows = [];
    jobs.forEach(job => {
        const findings = Array.isArray(job.findings) ? job.findings : [];
        const validation = job.validation || {};
        const verification = job.remediation_verification || {};

        findings.forEach(finding => {
            rows.push({ job, finding, validation, verification });
        });
    });

    badge.textContent = String(rows.length);
    if (!rows.length) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No remediation data yet</p>
                <small>Complete an assessment to see verification status and next-step guidance.</small>
            </div>
        `;
        return;
    }

    container.innerHTML = rows.slice(0, 12).map(({ job, finding, validation, verification }) => {
        const severity = String(finding.severity || 'medium').toLowerCase();
        const confirmed = Boolean(finding.validation?.confirmed || validation.confirmed);
        const verificationCount = Number(verification?.validation?.total_validations || validation.total_validations || 0);
        return `
            <div class="job-card">
                <div class="job-header">
                    <div class="job-title">${escapeHtml(finding.attack_variant || finding.type || 'Remediation item')}</div>
                    <span class="job-status status-${escapeHtml(severity)}">${escapeHtml(severity.toUpperCase())}</span>
                </div>
                <div class="job-meta">
                    <div class="job-meta-item"><span>Target:</span><strong>${escapeHtml(job.target || 'unknown')}</strong></div>
                    <div class="job-meta-item"><span>Verification:</span><strong>${confirmed ? 'Confirmed' : 'Pending'}</strong></div>
                    <div class="job-meta-item"><span>Checks:</span><strong>${verificationCount}</strong></div>
                </div>
                <div style="margin-top:0.5rem;color:var(--text-muted);font-size:0.9rem;">${escapeHtml(finding.remediation || 'Address this vulnerability per security best practices')}</div>
                <div class="job-actions" style="margin-top:0.75rem;">
                    <button class="btn btn-primary btn-small" onclick="verifyRemediation('${escapeHtml(job.id)}')">Verify Remediation</button>
                    <button class="btn btn-secondary btn-small" onclick="viewJobDetails('${escapeHtml(job.id)}')">Open Job</button>
                </div>
            </div>
        `;
    }).join('');
}

function displayActiveJobs(jobs) {
    const container = document.getElementById('active-jobs-container');
    const activeJobs = jobs.filter(job => job.status === 'running' || job.status === 'completed').slice(0, 10);
    const activeCount = jobs.filter(job => job.status === 'running').length;

    const badge = document.getElementById('active-count');
    if (badge) badge.textContent = activeCount;

    if (!activeJobs.length) {
        container.innerHTML = `
            <div class="empty-state">
                <p>No active assessments</p>
                <small>Start a new assessment to see it here</small>
            </div>
        `;
        return;
    }

    container.innerHTML = activeJobs.map(createJobCard).join('');
}

function createJobCard(job) {
    const findingsCount = Array.isArray(job.findings) ? job.findings.length : 0;
    const businessLogicCount = Array.isArray(job.findings)
        ? job.findings.filter(isBusinessLogicFinding).length
        : 0;
    const progress = job.progress || 0;
    const mode = (job.mode || 'classic').toUpperCase();
    const label = job.target_label || job.target;
    const remediationCount = job.validation ? Number(job.validation.total_validations || 0) : 0;

    return `
        <div class="job-card" data-job-id="${escapeHtml(job.id)}">
            <div class="job-header">
                <div class="job-title">${escapeHtml(label)}</div>
                <span class="job-status status-${escapeHtml(job.status)}">${escapeHtml(job.status.toUpperCase())}</span>
            </div>

            <div class="job-meta">
                <div class="job-meta-item"><span>Phase:</span><strong>${escapeHtml(job.phase || 'Initializing')}</strong></div>
                <div class="job-meta-item"><span>Progress:</span><strong>${progress}%</strong></div>
                <div class="job-meta-item"><span>Mode:</span><strong>${mode}</strong></div>
                <div class="job-meta-item"><span>Validation:</span><strong>${remediationCount}</strong></div>
            </div>

            <div class="progress-bar"><div class="progress-fill" style="width:${progress}%"></div></div>

            ${findingsCount > 0 ? `<div class="job-findings"><strong>Vulnerabilities Found: ${findingsCount}</strong></div>` : ''}
            ${businessLogicCount > 0 ? `<div class="job-findings" style="margin-top:0.35rem;"><strong>Business Logic Findings: ${businessLogicCount}</strong></div>` : ''}

            <div class="job-actions">
                <button class="btn btn-secondary btn-small" onclick="viewJobDetails('${escapeHtml(job.id)}')">Details</button>
                ${job.status === 'running' ? `<button class="btn btn-danger btn-small" onclick="cancelJob('${escapeHtml(job.id)}')">Cancel</button>` : ''}
                ${job.report ? `<button class="btn btn-primary btn-small" onclick="downloadReport('${escapeHtml(job.id)}')">JSON</button>` : ''}
                ${job.report ? `<button class="btn btn-secondary btn-small" onclick="downloadHtmlReport('${escapeHtml(job.id)}')">HTML</button>` : ''}
            </div>
        </div>
    `;
}

async function loadJobHistory() {
    try {
        const response = await fetch('/api/jobs');
        if (!response.ok) throw new Error('Failed to load history');
        const data = await response.json();

        const container = document.getElementById('history-container');
        if (!data.jobs?.length) {
            container.innerHTML = '<div class="empty-state"><p>No assessment history</p></div>';
            return;
        }

        const sorted = data.jobs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        container.innerHTML = sorted.map(createJobCard).join('');
    } catch (error) {
        document.getElementById('history-container').innerHTML = `<div class="empty-state"><p>Error loading history</p><small>${escapeHtml(error.message)}</small></div>`;
    }
}

async function loadReports() {
    try {
        const response = await fetch('/api/reports');
        if (!response.ok) throw new Error('Failed to load reports');
        const data = await response.json();

        const container = document.getElementById('reports-container');
        if (!data.reports?.length) {
            container.innerHTML = '<div class="empty-state"><p>No reports yet</p></div>';
            return;
        }

        container.innerHTML = data.reports.map(createReportCard).join('');
    } catch (error) {
        document.getElementById('reports-container').innerHTML = `<div class="empty-state"><p>Error loading reports</p><small>${escapeHtml(error.message)}</small></div>`;
    }
}

function createReportCard(report) {
    const timestamp = new Date(report.timestamp || '');
    const formattedDate = Number.isNaN(timestamp.getTime())
        ? 'Unknown'
        : timestamp.toLocaleDateString() + ' ' + timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const validationCount = Number(report.validation?.total_validations || 0);

    return `
        <div class="report-card">
            <div class="job-header">
                <div>
                    <div class="job-title" style="margin-bottom:0.25rem;">Assessment Report</div>
                    <small style="color: var(--text-muted);">${escapeHtml(report.target)}</small>
                </div>
                <span class="job-status status-${escapeHtml(String(report.risk_level || 'medium').toLowerCase())}">${escapeHtml(String(report.risk_level || 'MEDIUM').toUpperCase())}</span>
            </div>
            <div class="job-meta">
                <div class="job-meta-item"><span>Date:</span><strong>${formattedDate}</strong></div>
                <div class="job-meta-item"><span>Model:</span><strong>${escapeHtml(report.model || 'Unknown')}</strong></div>
                <div class="job-meta-item"><span>Validation:</span><strong>${validationCount}</strong></div>
                <div class="job-meta-item"><span>Remediations:</span><strong>${Number(report.remediation_total || 0)}</strong></div>
            </div>
            <div class="job-actions">
                <button class="btn btn-primary btn-small" onclick="viewReport('${escapeHtml(report.filename)}')">View</button>
                <button class="btn btn-secondary btn-small" onclick="downloadReportFile('${escapeHtml(report.filename)}')">Download</button>
            </div>
        </div>
    `;
}

function triggerReportImport() {
    if (state.reportImportInFlight) return;
    const input = document.getElementById('report-import-input');
    if (!input) {
        showNotification('Report import input not available', 'error');
        return;
    }
    input.value = '';
    input.click();
}

async function importReportFile(file) {
    if (!file) return;
    if (state.reportImportInFlight) return;

    const formData = new FormData();
    formData.append('file', file);
    state.reportImportInFlight = true;

    try {
        const response = await fetch('/api/reports/import', {
            method: 'POST',
            body: formData,
        });
        const payload = await response.json();
        if (!response.ok) {
            throw new Error(payload.error || 'Failed to import report');
        }

        showNotification(`Imported report: ${payload.filename}`, 'success');
        await loadReports();
        switchTab('reports');
    } catch (error) {
        showNotification(error.message, 'error');
    } finally {
        state.reportImportInFlight = false;
    }
}

function viewReport(reportName) {
    window.open(`/report?report=${encodeURIComponent(reportName)}`, '_blank', 'width=1400,height=900');
}

function downloadReportFile(reportName) {
    window.location.href = `/api/reports/${encodeURIComponent(reportName)}/download`;
}

function downloadReport(jobId) {
    window.location.href = `/api/assessments/${encodeURIComponent(jobId)}/download/json`;
}

function downloadHtmlReport(jobId) {
    window.location.href = `/api/assessments/${encodeURIComponent(jobId)}/download/html`;
}

async function viewJobDetails(jobId) {
    try {
        const response = await fetch(`/api/assess/${encodeURIComponent(jobId)}`);
        if (!response.ok) throw new Error('Job not found');
        const job = await response.json();

        const modal = document.getElementById('job-modal');
        const modalBody = document.getElementById('modal-body');
        const findings = Array.isArray(job.findings) ? job.findings : [];
        const businessLogicFindings = findings.filter(isBusinessLogicFinding);
        const validation = job.validation || {};
        const remediationVerification = job.remediation_verification || {};
        const swarm = (job.mode === 'swarm' && job.swarm && typeof job.swarm === 'object') ? job.swarm : {};
        const validationMarkup = validation.total_validations
            ? `
                <div>
                    <strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Validation Summary</strong>
                    <div style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0.65rem;margin-top:0.5rem;">
                        <div style="padding:0.65rem;border:1px solid var(--border-color);border-radius:8px;background:rgba(255,255,255,0.02);">
                            <div style="font-size:0.82rem;color:var(--text-muted);">Checks</div>
                            <div style="font-size:1.15rem;font-weight:700;">${Number(validation.total_validations || 0)}</div>
                        </div>
                        <div style="padding:0.65rem;border:1px solid var(--border-color);border-radius:8px;background:rgba(255,255,255,0.02);">
                            <div style="font-size:0.82rem;color:var(--text-muted);">Confirmed</div>
                            <div style="font-size:1.15rem;font-weight:700;color:#f87171;">${Number(validation.confirmed || 0)}</div>
                        </div>
                        <div style="padding:0.65rem;border:1px solid var(--border-color);border-radius:8px;background:rgba(255,255,255,0.02);">
                            <div style="font-size:0.82rem;color:var(--text-muted);">Not Confirmed</div>
                            <div style="font-size:1.15rem;font-weight:700;">${Number(validation.not_confirmed || 0)}</div>
                        </div>
                        <div style="padding:0.65rem;border:1px solid var(--border-color);border-radius:8px;background:rgba(255,255,255,0.02);">
                            <div style="font-size:0.82rem;color:var(--text-muted);">Errors</div>
                            <div style="font-size:1.15rem;font-weight:700;">${Number(validation.errors || 0)}</div>
                        </div>
                    </div>
                </div>
            `
            : '';
        const remediationMarkup = remediationVerification.validation
            ? `
                <div>
                    <strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Remediation Verification</strong>
                    <div style="margin-top:0.5rem;padding:0.75rem;border:1px solid var(--border-color);border-radius:8px;background:rgba(255,255,255,0.02);">
                        <div style="display:flex;justify-content:space-between;gap:0.75rem;flex-wrap:wrap;">
                            <span>Confirmed: ${Number(remediationVerification.validation.confirmed || 0)}</span>
                            <span>Checks: ${Number(remediationVerification.validation.total_validations || 0)}</span>
                            <span>Errors: ${Number(remediationVerification.validation.errors || 0)}</span>
                        </div>
                    </div>
                </div>
            `
            : '';
        const findingsMarkup = businessLogicFindings.length
            ? `
                <div>
                    <strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Business Logic Findings</strong>
                    <div style="display:grid;gap:0.65rem;margin-top:0.5rem;">
                        ${businessLogicFindings.slice(0, 8).map(f => `
                            <div style="padding:0.65rem;border:1px solid var(--border-color);border-radius:8px;background:rgba(255,255,255,0.02);">
                                <div style="display:flex;justify-content:space-between;gap:0.75rem;align-items:center;">
                                    <strong>${escapeHtml(f.attack_variant || f.type || 'Business Logic')}</strong>
                                    <span class="job-status status-${escapeHtml(String(f.severity || 'medium').toLowerCase())}">${escapeHtml(String(f.severity || 'medium').toUpperCase())}</span>
                                </div>
                                <div style="margin-top:0.4rem;color:var(--text-muted);font-size:0.9rem;">${escapeHtml(f.description || '')}</div>
                                <div style="display:flex;gap:0.75rem;margin-top:0.5rem;font-size:0.85rem;color:var(--text-muted);">
                                    <span>Family: ${escapeHtml(f.attack_family || 'Business Logic')}</span>
                                    <span>Confidence: ${deriveFindingConfidence(f)}%</span>
                                    <span>Evidence: ${escapeHtml(f.evidence_strength || 'moderate')}</span>
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `
            : '';

        const swarmControlMarkup = job.mode === 'swarm'
            ? `
                <div style="display:grid;gap:0.75rem;">
                    <div>
                        <strong style="color:var(--text-muted);display:block;font-size:0.85rem;">What-If Branch Control</strong>
                        ${renderSwarmBranchControls({
                            job_id: job.id,
                            what_if_branches: Array.isArray(swarm.what_if_branches) ? swarm.what_if_branches : [],
                            selected_branch: swarm.selected_branch || null,
                        })}
                    </div>
                    <div>
                        <strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Command Recommendations</strong>
                        ${renderSwarmRecommendations({
                            command_recommendations: Array.isArray(swarm.command_recommendations) ? swarm.command_recommendations : [],
                        })}
                    </div>
                    <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
                        <button class="btn btn-secondary btn-small" onclick="refreshSwarmRecommendations('${encodeURIComponent(String(job.id || ''))}')">Refresh Recommendations</button>
                        <button class="btn btn-secondary btn-small" onclick="refreshSwarmStatus()">Refresh Swarm Status</button>
                    </div>
                </div>
            `
            : '';

        modalBody.innerHTML = `
            <div style="display:grid;gap:1rem;">
                <div><strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Target</strong><div>${escapeHtml(job.target)}</div></div>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;">
                    <div><strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Status</strong><span class="job-status status-${escapeHtml(job.status)}">${escapeHtml(job.status.toUpperCase())}</span></div>
                    <div><strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Progress</strong><div>${job.progress || 0}%</div></div>
                </div>
                <div><strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Mode</strong><div>${escapeHtml((job.mode || 'classic').toUpperCase())}</div></div>
                <div><strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Current Phase</strong><div>${escapeHtml(job.phase || 'Initializing')}</div></div>
                <div><strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Findings Summary</strong><div>Total: ${findings.length} | Business Logic: ${businessLogicFindings.length}</div></div>
                ${validationMarkup}
                ${remediationMarkup}
                ${job.mode === 'swarm' ? `<div><strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Swarm Mission</strong><div>${escapeHtml(job.swarm?.mission_id || 'pending')} | replans: ${job.swarm?.replans || 0}</div></div>` : ''}
                ${swarmControlMarkup}
                ${findingsMarkup}
                <div style="padding-top:1rem;border-top:1px solid var(--border-color);display:flex;gap:0.5rem;flex-wrap:wrap;">
                    ${job.status === 'completed' && job.report ? `<button class="btn btn-primary btn-small" onclick="openJobReport('${escapeHtml(job.id)}')">View Report</button>` : ''}
                    ${job.status === 'completed' ? `<button class="btn btn-secondary btn-small" onclick="verifyRemediation('${escapeHtml(job.id)}')">Verify Remediation</button>` : ''}
                    ${job.status === 'completed' && job.report ? `<button class="btn btn-secondary btn-small" onclick="downloadHtmlReport('${escapeHtml(job.id)}')">Download HTML</button>` : ''}
                    <button class="btn btn-secondary btn-small" onclick="closeJobModal()">Close</button>
                </div>
            </div>
        `;

        modal.classList.add('active');
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

function closeJobModal() {
    document.getElementById('job-modal')?.classList.remove('active');
}

function openJobReport(jobId) {
    window.open(`/report?job=${encodeURIComponent(jobId)}`, '_blank', 'width=1400,height=900');
    closeJobModal();
}

async function cancelJob(jobId) {
    if (!confirm('Are you sure you want to cancel this assessment?')) return;

    try {
        const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' });
        if (!response.ok) throw new Error('Failed to cancel job');
        showNotification('Job cancelled', 'success');
        updateDashboard();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function verifyRemediation(jobId) {
    try {
        const response = await fetch(`/api/assess/${encodeURIComponent(jobId)}/verify-remediation`, { method: 'POST' });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'Failed to verify remediation');

        showNotification('Remediation verification completed', 'success');
        await updateDashboard();
        if (document.getElementById('job-modal')?.classList.contains('active')) {
            await viewJobDetails(jobId);
        }
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

function renderSwarmBranchControls(job) {
    const branches = Array.isArray(job.what_if_branches) ? job.what_if_branches : [];
    if (!branches.length) {
        return '<div style="margin-top:0.6rem;color:var(--text-muted);font-size:0.85rem;">No what-if branches yet.</div>';
    }

    const selectedBranch = String(job.selected_branch || '').trim();
    return `
        <div style="margin-top:0.7rem;display:grid;gap:0.45rem;">
            ${branches.slice(0, 3).map(branch => {
                const branchId = String(branch.id || '').trim();
                const isSelected = selectedBranch && branchId === selectedBranch;
                const score = Number(branch.score || 0).toFixed(2);
                const success = Math.round(Number(branch.estimated_success || 0) * 100);
                const detect = Math.round(Number(branch.estimated_detection || 0) * 100);
                return `
                    <div style="padding:0.55rem;border:1px solid var(--border-color);border-radius:8px;background:rgba(255,255,255,0.02);">
                        <div style="display:flex;justify-content:space-between;gap:0.5rem;align-items:center;">
                            <strong style="font-size:0.9rem;">${escapeHtml(branch.name || branchId || 'Branch')}</strong>
                            <span style="font-size:0.78rem;color:var(--text-muted);">Score ${escapeHtml(score)}</span>
                        </div>
                        <div style="display:flex;gap:0.8rem;margin-top:0.3rem;font-size:0.78rem;color:var(--text-muted);">
                            <span>Success ${success}%</span>
                            <span>Detection ${detect}%</span>
                        </div>
                        <div style="margin-top:0.45rem;display:flex;gap:0.5rem;align-items:center;">
                            <button class="btn btn-secondary btn-small" onclick="selectSwarmBranch('${encodeURIComponent(String(job.job_id || ''))}', '${encodeURIComponent(branchId)}')" ${isSelected ? 'disabled' : ''}>${isSelected ? 'Selected' : 'Select Branch'}</button>
                            ${isSelected ? '<span style="font-size:0.75rem;color:#6f6;">active</span>' : ''}
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

function renderSwarmRecommendations(job) {
    const recommendations = Array.isArray(job.command_recommendations) ? job.command_recommendations : [];
    if (!recommendations.length) {
        return '<div style="margin-top:0.5rem;color:var(--text-muted);font-size:0.85rem;">No command recommendations yet.</div>';
    }

    return `
        <div style="margin-top:0.5rem;display:grid;gap:0.4rem;">
            ${recommendations.slice(0, 3).map(rec => `
                <div style="padding:0.5rem;border:1px solid var(--border-color);border-radius:8px;background:rgba(255,255,255,0.02);font-size:0.83rem;">
                    <div style="display:flex;justify-content:space-between;gap:0.4rem;align-items:center;">
                        <strong>${escapeHtml(String(rec.action || 'maintain_course'))}</strong>
                        <span class="job-status status-${escapeHtml(String(rec.priority || 'info').toLowerCase())}">${escapeHtml(String(rec.priority || 'info').toUpperCase())}</span>
                    </div>
                    <div style="margin-top:0.25rem;color:var(--text-muted);">${escapeHtml(String(rec.reason || ''))}</div>
                </div>
            `).join('')}
        </div>
    `;
}

async function selectSwarmBranch(jobIdEncoded, branchIdEncoded) {
    const jobId = decodeURIComponent(String(jobIdEncoded || ''));
    const branchId = decodeURIComponent(String(branchIdEncoded || ''));
    if (!jobId || !branchId) return;

    try {
        const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/branch/select`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ branch_id: branchId })
        });
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Failed to select branch');

        showNotification(`Branch selected: ${branchId}`, 'success');
        await refreshSwarmStatus();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function refreshSwarmRecommendations(jobIdEncoded) {
    const jobId = decodeURIComponent(String(jobIdEncoded || ''));
    if (!jobId) return;

    try {
        const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}/command-recommendations`);
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error || 'Failed to load recommendations');

        const count = Array.isArray(payload.recommendations) ? payload.recommendations.length : 0;
        showNotification(`Recommendations refreshed (${count})`, 'info');
        await refreshSwarmStatus();
    } catch (error) {
        showNotification(error.message, 'error');
    }
}

async function refreshSwarmStatus() {
    try {
        const response = await fetch('/api/agents/status');
        if (!response.ok) throw new Error('Unable to load agent swarm status');

        const data = await response.json();
        const availability = document.getElementById('swarm-availability');
        const jobsContainer = document.getElementById('swarm-jobs');

        if (availability) {
            const swarmAvailable = data.runtime?.swarm_available === true;
            availability.textContent = swarmAvailable ? 'Swarm runtime: available' : 'Swarm runtime: unavailable';
            availability.style.color = swarmAvailable ? '#6f6' : '#ff6b6b';
        }

        const jobs = data.active_swarm_jobs || [];
        if (!jobs.length) {
            jobsContainer.innerHTML = `
                <div class="empty-state">
                    <p>No swarm mission data yet</p>
                    <small>Start an assessment in swarm mode to populate this panel</small>
                </div>
            `;
            return;
        }

        jobsContainer.innerHTML = jobs.map(job => `
            <div class="job-card">
                <div class="job-header">
                    <div class="job-title">${escapeHtml(job.target || job.job_id)}</div>
                    <span class="job-status status-${escapeHtml(job.status || 'running')}">${escapeHtml((job.status || 'running').toUpperCase())}</span>
                </div>
                <div class="job-meta">
                    <div class="job-meta-item"><span>Mission:</span><strong>${escapeHtml(job.mission_id || 'pending')}</strong></div>
                    <div class="job-meta-item"><span>Phase:</span><strong>${escapeHtml(job.phase || 'initializing')}</strong></div>
                    <div class="job-meta-item"><span>Replans:</span><strong>${job.replans || 0}</strong></div>
                </div>
                <div class="job-meta" style="margin-top:0.5rem;">
                    <div class="job-meta-item"><span>Attack Attempts:</span><strong>${Number(job.attack_metrics?.attempted || 0)}</strong></div>
                    <div class="job-meta-item"><span>Success Rate:</span><strong>${Number(job.attack_metrics?.success_rate || 0)}%</strong></div>
                    <div class="job-meta-item"><span>Stall Warnings:</span><strong>${Number(job.stall_warnings || 0)}</strong></div>
                </div>
                <div class="job-meta" style="margin-top:0.5rem;">
                    <div class="job-meta-item"><span>Threat Profile:</span><strong>${escapeHtml(job.threat_profile || job.policy?.threat_profile || 'adaptive_baseline')}</strong></div>
                    <div class="job-meta-item"><span>Detection Budget:</span><strong>${Number(job.policy?.max_detection_rate || 0)}%</strong></div>
                    <div class="job-meta-item"><span>Attempt Budget:</span><strong>${Number(job.policy?.max_attack_attempts || 0)}</strong></div>
                </div>
                <div style="margin-top:0.65rem;">
                    <strong style="font-size:0.84rem;color:var(--text-muted);display:block;">What-If Branch Control</strong>
                    ${renderSwarmBranchControls(job)}
                </div>
                <div style="margin-top:0.7rem;">
                    <strong style="font-size:0.84rem;color:var(--text-muted);display:block;">Command Recommendations</strong>
                    ${renderSwarmRecommendations(job)}
                </div>
                <div class="job-actions" style="margin-top:0.65rem;">
                    <button class="btn btn-secondary btn-small" onclick="refreshSwarmRecommendations('${encodeURIComponent(String(job.job_id || ''))}')">Refresh Recommendations</button>
                    <button class="btn btn-secondary btn-small" onclick="viewJobDetails('${escapeHtml(job.job_id || '')}')">Open Job</button>
                </div>
                ${job.stalled ? `<div class="job-findings" style="margin-top:0.5rem;"><strong>Phase appears stalled - runtime monitor raised warning.</strong></div>` : ''}
            </div>
        `).join('');
    } catch (error) {
        const jobsContainer = document.getElementById('swarm-jobs');
        if (jobsContainer) {
            jobsContainer.innerHTML = `<div class="empty-state"><p>Error loading swarm status</p><small>${escapeHtml(error.message)}</small></div>`;
        }
    }
}

function showNotification(message, type = 'info') {
    const el = document.getElementById('notification');
    if (!el) return;

    el.textContent = message;
    el.className = `notification ${type}`;

    setTimeout(() => {
        el.className = 'notification';
        el.textContent = '';
    }, 5000);
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

function isBusinessLogicFinding(finding) {
    if (!finding || typeof finding !== 'object') return false;
    const family = String(finding.attack_family || finding.family || '').toLowerCase();
    const type = String(finding.type || '').toLowerCase();
    const description = String(finding.description || '').toLowerCase();
    const evidence = String(finding.evidence || '').toLowerCase();

    return family === 'business logic'
        || type.startsWith('business_logic_')
        || /workflow|approval|privilege|access control|authorization|role|idor|coupon|checkout|tenant/.test(description)
        || /workflow|approval|privilege|access control|authorization|role|idor|coupon|checkout|tenant/.test(evidence);
}

function deriveFindingConfidence(finding) {
    const explicit = Number(finding?.confidence_score ?? finding?.confidence ?? finding?.confidence_percent);
    if (Number.isFinite(explicit) && explicit > 0) {
        return Math.max(0, Math.min(100, Math.round(explicit)));
    }

    const validation = finding?.validation || {};
    if (validation?.confirmed === true) return 95;
    if (String(validation?.status || '').toLowerCase() === 'bypass_confirmed') return 92;
    if (Number.isFinite(Number(validation?.confidence))) {
        return Math.max(0, Math.min(100, Math.round(Number(validation.confidence) * 100)));
    }

    const status = String(finding?.exploitation_status || finding?.status || '').toLowerCase();
    const severity = String(finding?.severity || 'medium').toLowerCase();

    if (status === 'confirmed') return 95;
    if (status === 'potential') return 65;
    if (severity === 'critical') return 85;
    if (severity === 'high') return 75;
    if (severity === 'medium') return 55;
    if (severity === 'low') return 35;
    return 25;
}

document.addEventListener('DOMContentLoaded', () => {
    updateDashboard();

    const importInput = document.getElementById('report-import-input');
    importInput?.addEventListener('change', async event => {
        const file = event?.target?.files?.[0];
        if (!file) return;
        await importReportFile(file);
    });

    document.querySelectorAll('.tool-filter').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tool-filter').forEach(item => item.classList.remove('active'));
            btn.classList.add('active');
            state.toolsFilter = btn.getAttribute('data-tool-filter') || 'all';
            renderToolsTab(state.toolsHealth || []);
        });
    });

    setInterval(() => {
        if (state.currentTab === 'dashboard') updateDashboard();
        if (state.currentTab === 'agents') refreshSwarmStatus();
        if (state.currentTab === 'tools') loadToolsTab();
    }, 9000);
});

document.getElementById('job-modal')?.addEventListener('click', e => {
    if (e.target.id === 'job-modal') closeJobModal();
});

window.loadJobHistory = loadJobHistory;
window.loadReports = loadReports;
window.viewJobDetails = viewJobDetails;
window.cancelJob = cancelJob;
window.downloadReport = downloadReport;
window.viewReport = viewReport;
window.gatherOSINT = gatherOSINT;
window.downloadReportFile = downloadReportFile;
window.downloadHtmlReport = downloadHtmlReport;
window.openJobReport = openJobReport;
window.closeJobModal = closeJobModal;
window.refreshSwarmStatus = refreshSwarmStatus;
window.selectSwarmBranch = selectSwarmBranch;
window.refreshSwarmRecommendations = refreshSwarmRecommendations;
window.loadToolsTab = loadToolsTab;
window.copyToolInstallHint = copyToolInstallHint;
window.runToolCheck = runToolCheck;
window.runUrlTool = runUrlTool;
window.verifyRemediation = verifyRemediation;
window.loadHealthOverview = loadHealthOverview;
window.triggerReportImport = triggerReportImport;
