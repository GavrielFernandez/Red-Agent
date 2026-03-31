/* ============================================================================
   RedAgent Dashboard - Unified JavaScript
   ============================================================================ */

const state = {
    currentTab: 'dashboard'
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
        intelligence: 'OSINT Intelligence Hub',
        mitre: 'MITRE ATT&CK Mapping',
        agents: 'Multi-Agent Swarm'
    };
    pageTitle.textContent = titles[tabName] || 'Dashboard';

    if (tabName === 'jobs') loadJobHistory();
    if (tabName === 'reports') loadReports();
    if (tabName === 'dashboard') updateDashboard();
    if (tabName === 'agents') refreshSwarmStatus();

    state.currentTab = tabName;
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

    try {
        submitBtn.disabled = true;
        submitBtn.innerHTML = 'Starting...';

        const response = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, type, mode })
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
    try {
        const statusResponse = await fetch('/api/status');
        if (!statusResponse.ok) throw new Error('Failed to fetch status');
        const status = await statusResponse.json();

        document.getElementById('total-jobs').textContent = status.jobs.total;
        document.getElementById('running-jobs').textContent = status.jobs.running;
        document.getElementById('completed-jobs').textContent = status.jobs.completed;
        document.getElementById('failed-jobs').textContent = status.jobs.failed;

        const jobsResponse = await fetch('/api/jobs');
        if (!jobsResponse.ok) throw new Error('Failed to fetch jobs');
        const jobsData = await jobsResponse.json();

        displayActiveJobs(jobsData.jobs || []);
        displayBusinessLogicInsights(jobsData.jobs || []);
        displayAttackAnalytics(jobsData.jobs || []);
    } catch (error) {
        console.error('Dashboard update error:', error);
    }
}

function displayAttackAnalytics(jobs) {
    const modeEl = document.getElementById('attack-analytics-mode');
    const attemptsEl = document.getElementById('attack-attempts');
    const successRateEl = document.getElementById('attack-success-rate');
    const fallbackEl = document.getElementById('attack-fallback-used');
    const avgDurationEl = document.getElementById('attack-avg-exploit-duration');
    const contextEl = document.getElementById('attack-analytics-context');

    if (!modeEl || !attemptsEl || !successRateEl || !fallbackEl || !avgDurationEl || !contextEl) return;

    const latestSwarm = [...jobs]
        .filter(job => job.mode === 'swarm' && job.swarm)
        .sort((a, b) => new Date(b.completed_at || b.created_at || 0) - new Date(a.completed_at || a.created_at || 0))[0];

    if (!latestSwarm) {
        modeEl.textContent = 'n/a';
        attemptsEl.textContent = '0';
        successRateEl.textContent = '0%';
        fallbackEl.textContent = 'No';
        avgDurationEl.textContent = '0.00s';
        contextEl.textContent = 'Waiting for completed swarm assessment telemetry.';
        return;
    }

    const metrics = latestSwarm.swarm.attack_metrics || {};
    const timings = latestSwarm.swarm.agent_timings || {};

    const attempts = Number(metrics.attempted || 0);
    const successRate = Number(metrics.success_rate || 0);
    const fallbackUsed = Boolean(metrics.fallback_attacks_used);
    const exploitTotal = Number(timings.exploit_execution || 0) + Number(timings.fallback_focused_attack || 0);
    const avgExploitDuration = attempts > 0 ? (exploitTotal / attempts) : 0;

    modeEl.textContent = fallbackUsed ? 'focused_fallback' : 'priority_exploit';
    attemptsEl.textContent = String(attempts);
    successRateEl.textContent = `${successRate}%`;
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
        return `
            <div class="job-card">
                <div class="job-header">
                    <div class="job-title">${escapeHtml(job.target || job.id)}</div>
                    <span class="job-status status-${escapeHtml(severity)}">${escapeHtml(severity.toUpperCase())}</span>
                </div>
                <div class="job-meta">
                    <div class="job-meta-item"><span>Variant:</span><strong>${escapeHtml(finding.attack_variant || finding.type || 'Business Logic')}</strong></div>
                    <div class="job-meta-item"><span>Confidence:</span><strong>${Number(finding.confidence_score || 0)}%</strong></div>
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

    return `
        <div class="job-card" data-job-id="${escapeHtml(job.id)}">
            <div class="job-header">
                <div class="job-title">${escapeHtml(job.target)}</div>
                <span class="job-status status-${escapeHtml(job.status)}">${escapeHtml(job.status.toUpperCase())}</span>
            </div>

            <div class="job-meta">
                <div class="job-meta-item"><span>Phase:</span><strong>${escapeHtml(job.phase || 'Initializing')}</strong></div>
                <div class="job-meta-item"><span>Progress:</span><strong>${progress}%</strong></div>
                <div class="job-meta-item"><span>Mode:</span><strong>${mode}</strong></div>
            </div>

            <div class="progress-bar"><div class="progress-fill" style="width:${progress}%"></div></div>

            ${findingsCount > 0 ? `<div class="job-findings"><strong>Vulnerabilities Found: ${findingsCount}</strong></div>` : ''}
            ${businessLogicCount > 0 ? `<div class="job-findings" style="margin-top:0.35rem;"><strong>Business Logic Findings: ${businessLogicCount}</strong></div>` : ''}

            <div class="job-actions">
                <button class="btn btn-secondary btn-small" onclick="viewJobDetails('${escapeHtml(job.id)}')">Details</button>
                ${job.status === 'running' ? `<button class="btn btn-danger btn-small" onclick="cancelJob('${escapeHtml(job.id)}')">Cancel</button>` : ''}
                ${job.report ? `<button class="btn btn-primary btn-small" onclick="downloadReport('${escapeHtml(job.id)}')">Report</button>` : ''}
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
    const timestamp = new Date(report.timestamp);
    const formattedDate = timestamp.toLocaleDateString() + ' ' + timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    return `
        <div class="report-card">
            <div class="job-header">
                <div>
                    <div class="job-title" style="margin-bottom:0.25rem;">Assessment Report</div>
                    <small style="color: var(--text-muted);">${escapeHtml(report.target)}</small>
                </div>
            </div>
            <div class="job-meta">
                <div class="job-meta-item"><span>Date:</span><strong>${formattedDate}</strong></div>
                <div class="job-meta-item"><span>Model:</span><strong>${escapeHtml(report.model || 'Unknown')}</strong></div>
            </div>
            <div class="job-actions">
                <button class="btn btn-primary btn-small" onclick="viewReport('${escapeHtml(report.filename)}')">View</button>
                <button class="btn btn-secondary btn-small" onclick="downloadReportFile('${escapeHtml(report.filename)}')">Download</button>
            </div>
        </div>
    `;
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

async function viewJobDetails(jobId) {
    try {
        const response = await fetch(`/api/assess/${encodeURIComponent(jobId)}`);
        if (!response.ok) throw new Error('Job not found');
        const job = await response.json();

        const modal = document.getElementById('job-modal');
        const modalBody = document.getElementById('modal-body');
        const findings = Array.isArray(job.findings) ? job.findings : [];
        const businessLogicFindings = findings.filter(isBusinessLogicFinding);
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
                                    <span>Confidence: ${Number(f.confidence_score || 0)}%</span>
                                    <span>Evidence: ${escapeHtml(f.evidence_strength || 'moderate')}</span>
                                </div>
                            </div>
                        `).join('')}
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
                ${job.mode === 'swarm' ? `<div><strong style="color:var(--text-muted);display:block;font-size:0.85rem;">Swarm Mission</strong><div>${escapeHtml(job.swarm?.mission_id || 'pending')} | replans: ${job.swarm?.replans || 0}</div></div>` : ''}
                ${findingsMarkup}
                <div style="padding-top:1rem;border-top:1px solid var(--border-color);display:flex;gap:0.5rem;">
                    ${job.status === 'completed' && job.report ? `<button class="btn btn-primary btn-small" onclick="openJobReport('${escapeHtml(job.id)}')">View Report</button>` : ''}
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
    const family = String(finding.attack_family || '').toLowerCase();
    const type = String(finding.type || '').toLowerCase();
    return family === 'business logic' || type.startsWith('business_logic_');
}

document.addEventListener('DOMContentLoaded', () => {
    updateDashboard();

    setInterval(() => {
        if (state.currentTab === 'dashboard') updateDashboard();
        if (state.currentTab === 'agents') refreshSwarmStatus();
    }, 5000);
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
window.downloadReportFile = downloadReportFile;
window.openJobReport = openJobReport;
window.closeJobModal = closeJobModal;
window.refreshSwarmStatus = refreshSwarmStatus;
