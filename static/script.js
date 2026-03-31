/* ============================================================================
   RedAgent Dashboard - Modern JavaScript
   ============================================================================ */

// State Management
const state = {
    jobs: {},
    reports: [],
    currentTab: 'dashboard',
    searchQuery: ''
};

// DOM References
const navItems = document.querySelectorAll('.nav-item');
const tabContents = document.querySelectorAll('.tab-content');
const assessmentForm = document.getElementById('assessment-form');
const notificationEl = document.getElementById('notification');
const pageTitle = document.getElementById('page-title');

// ============================================================================
// Navigation
// ============================================================================

navItems.forEach(item => {
    item.addEventListener('click', () => {
        const tabName = item.getAttribute('data-tab');
        switchTab(tabName);
    });
});

function switchTab(tabName) {
    // Update nav items
    navItems.forEach(item => item.classList.remove('active'));
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

    // Update tab content
    tabContents.forEach(content => content.classList.remove('active'));
    const tabContent = document.getElementById(tabName);
    if (tabContent) {
        tabContent.classList.add('active');
    }

    // Update page title
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

    // Load data for specific tabs
    if (tabName === 'jobs') {
        loadJobHistory();
    } else if (tabName === 'reports') {
        loadReports();
    } else if (tabName === 'dashboard') {
        updateDashboard();
    }

    state.currentTab = tabName;
}

// ============================================================================
// Assessment Form
// ============================================================================

assessmentForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const target = document.getElementById('target').value.trim();
    const type = document.getElementById('target-type').value;

    if (!target) {
        showNotification('Please enter a target', 'error');
        return;
    }

    try {
        const submitBtn = assessmentForm.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="9"></circle></svg>Starting...';

        const response = await fetch('/api/assess', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, type })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to start assessment');
        }

        const result = await response.json();
        const jobId = result.job_id;

        assessmentForm.reset();
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M5 12h14M12 5l7 7-7 7"></path></svg>Launch Assessment';

        showNotification(`✅ Assessment started! Job ID: ${jobId}`, 'success');
        switchTab('dashboard');
        monitorJob(jobId);

    } catch (error) {
        showNotification(`❌ ${error.message}`, 'error');
        const submitBtn = assessmentForm.querySelector('button[type="submit"]');
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M5 12h14M12 5l7 7-7 7"></path></svg>Launch Assessment';
    }
});

// ============================================================================
// Job Monitoring
// ============================================================================

function monitorJob(jobId) {
    const maxAttempts = 120;
    let attempts = 0;

    const interval = setInterval(async () => {
        try {
            const response = await fetch(`/api/assess/${jobId}`);
            if (!response.ok) {
                clearInterval(interval);
                return;
            }

            const job = await response.json();
            updateDashboard();

            if (['completed', 'failed', 'cancelled'].includes(job.status)) {
                clearInterval(interval);
                if (job.status === 'completed') {
                    showNotification('✅ Assessment completed successfully!', 'success');
                } else if (job.status === 'failed') {
                    showNotification(`❌ Assessment failed: ${job.error}`, 'error');
                }
            }

            attempts++;
            if (attempts >= maxAttempts) clearInterval(interval);

        } catch (error) {
            clearInterval(interval);
        }
    }, 1000);
}

// ============================================================================
// Dashboard
// ============================================================================

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

        displayActiveJobs(jobsData.jobs);

    } catch (error) {
        console.error('Error updating dashboard:', error);
    }
}

function displayActiveJobs(jobs) {
    const container = document.getElementById('active-jobs-container');
    const activeJobs = jobs
        .filter(job => job.status === 'running' || job.status === 'completed')
        .slice(0, 10);

    const activeCount = jobs.filter(j => j.status === 'running').length;
    const badge = document.getElementById('active-count');
    if (badge) {
        badge.textContent = activeCount;
    }

    if (activeJobs.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                    <circle cx="12" cy="12" r="9"></circle>
                    <path d="M9 9h6v6H9z"></path>
                </svg>
                <p>No active assessments</p>
                <small>Start a new assessment to see it here</small>
            </div>
        `;
        return;
    }

    container.innerHTML = activeJobs.map(job => createJobCard(job)).join('');
}

function createJobCard(job) {
    const vulnerabilityCount = job.findings ? job.findings.length : 0;
    const phase = job.phase || 'Initializing';
    const progress = job.progress || 0;

    return `
        <div class="job-card" data-job-id="${job.id}">
            <div class="job-header">
                <div>
                    <div class="job-title">${escapeHtml(job.target)}</div>
                </div>
                <span class="job-status status-${job.status}">${job.status.toUpperCase()}</span>
            </div>

            <div class="job-meta">
                <div class="job-meta-item">
                    <span>Phase:</span>
                    <strong>${escapeHtml(phase)}</strong>
                </div>
                <div class="job-meta-item">
                    <span>Progress:</span>
                    <strong>${progress}%</strong>
                </div>
                <div class="job-meta-item">
                    <span>Type:</span>
                    <strong>${job.type || 'url'}</strong>
                </div>
            </div>

            <div class="progress-bar">
                <div class="progress-fill" style="width: ${progress}%"></div>
            </div>

            ${job.findings && job.findings.length > 0 ? `
                <div class="job-findings">
                    <strong>Vulnerabilities Found: ${vulnerabilityCount}</strong>
                    ${job.findings.slice(0, 3).map(finding => 
                        `<div class="finding-badge">${escapeHtml(finding.attack || 'Unknown')}</div>`
                    ).join('')}
                </div>
            ` : ''}

            <div class="job-actions">
                <button class="btn btn-secondary btn-small" onclick="viewJobDetails('${job.id}')">
                    Details
                </button>
                ${job.status === 'running' ? `
                    <button class="btn btn-danger btn-small" onclick="cancelJob('${job.id}')">
                        Cancel
                    </button>
                ` : ''}
                ${job.report ? `
                    <button class="btn btn-primary btn-small" onclick="downloadReport('${job.id}')">
                        Report
                    </button>
                ` : ''}
            </div>
        </div>
    `;
}

// ============================================================================
// Job History
// ============================================================================

async function loadJobHistory() {
    try {
        const response = await fetch('/api/jobs');
        if (!response.ok) throw new Error('Failed to load history');
        const data = await response.json();

        const container = document.getElementById('history-container');
        if (data.jobs.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <circle cx="12" cy="12" r="9"></circle>
                        <path d="M12 6v6l4 2"></path>
                    </svg>
                    <p>No assessment history</p>
                </div>
            `;
            return;
        }

        const sortedJobs = data.jobs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        container.innerHTML = sortedJobs.map(job => createJobCard(job)).join('');

    } catch (error) {
        document.getElementById('history-container').innerHTML = `
            <div class="empty-state">
                <p>❌ Error loading history</p>
                <small>${error.message}</small>
            </div>
        `;
    }
}

// ============================================================================
// Reports
// ============================================================================

async function loadReports() {
    try {
        const response = await fetch('/api/reports');
        if (!response.ok) throw new Error('Failed to load reports');
        const data = await response.json();

        const container = document.getElementById('reports-container');
        if (data.reports.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                        <polyline points="13 2 13 9 20 9"></polyline>
                    </svg>
                    <p>No reports yet</p>
                    <small>Complete an assessment to generate reports</small>
                </div>
            `;
            return;
        }

        container.innerHTML = data.reports.map(report => createReportCard(report)).join('');

    } catch (error) {
        document.getElementById('reports-container').innerHTML = `
            <div class="empty-state">
                <p>❌ Error loading reports</p>
                <small>${error.message}</small>
            </div>
        `;
    }
}

function createReportCard(report) {
    const timestamp = new Date(report.timestamp);
    const formattedDate = timestamp.toLocaleDateString() + ' ' + timestamp.toLocaleTimeString([], { 
        hour: '2-digit', 
        minute: '2-digit' 
    });

    return `
        <div class="report-card">
            <div class="job-header">
                <div>
                    <div class="job-title" style="margin-bottom: 0.25rem;">Assessment Report</div>
                    <small style="color: var(--text-muted);">${escapeHtml(report.target)}</small>
                </div>
            </div>

            <div class="job-meta">
                <div class="job-meta-item">
                    <span>Date:</span>
                    <strong>${formattedDate}</strong>
                </div>
                <div class="job-meta-item">
                    <span>Model:</span>
                    <strong>${report.model || 'Unknown'}</strong>
                </div>
            </div>

            <div class="job-actions">
                <button class="btn btn-primary btn-small" onclick="viewReport('${escapeHtml(report.filename)}')">
                    View
                </button>
                <button class="btn btn-secondary btn-small" onclick="downloadReportFile('${escapeHtml(report.filename)}')">
                    Download
                </button>
            </div>
        </div>
    `;
}

async function viewReport(reportName) {
    try {
        // Open report in a new window with the report viewer
        window.open(`/report?report=${encodeURIComponent(reportName)}`, '_blank', 'width=1400,height=900');
    } catch (error) {
        showNotification(`❌ Error: ${error.message}`, 'error');
    }
}

function downloadReportFile(reportName) {
    window.location.href = `/api/reports/${escapeHtml(reportName)}`;
}

function downloadReport(jobId) {
    window.location.href = `/api/assess/${jobId}/download/json`;
}

// ============================================================================
// Job Actions
// ============================================================================

async function viewJobDetails(jobId) {
    try {
        const response = await fetch(`/api/assess/${jobId}`);
        if (!response.ok) throw new Error('Job not found');
        const job = await response.json();

        const modal = document.getElementById('job-modal');
        const modalBody = document.getElementById('modal-body');

        modalBody.innerHTML = `
            <div style="display: grid; gap: 1rem;">
                <div>
                    <strong style="color: var(--text-muted); display: block; font-size: 0.85rem; margin-bottom: 0.25rem;">Target</strong>
                    <div>${escapeHtml(job.target)}</div>
                </div>

                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
                    <div>
                        <strong style="color: var(--text-muted); display: block; font-size: 0.85rem; margin-bottom: 0.25rem;">Status</strong>
                        <span class="job-status status-${job.status}">${job.status.toUpperCase()}</span>
                    </div>
                    <div>
                        <strong style="color: var(--text-muted); display: block; font-size: 0.85rem; margin-bottom: 0.25rem;">Progress</strong>
                        <div>${job.progress || 0}%</div>
                    </div>
                </div>

                <div>
                    <strong style="color: var(--text-muted); display: block; font-size: 0.85rem; margin-bottom: 0.25rem;">Current Phase</strong>
                    <div>${escapeHtml(job.phase || 'Initializing')}</div>
                </div>

                ${job.findings && job.findings.length > 0 ? `
                    <div>
                        <strong style="color: var(--text-primary); display: block; margin-bottom: 0.5rem;">Vulnerabilities (${job.findings.length})</strong>
                        <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                            ${job.findings.map(f => `<div class="finding-badge">${escapeHtml(f.attack || 'Unknown')}</div>`).join('')}
                        </div>
                    </div>
                ` : ''}

                <div style="padding-top: 1rem; border-top: 1px solid var(--border-color); display: flex; gap: 0.5rem;">
                    ${job.status === 'completed' && job.report ? `
                        <button class="btn btn-primary btn-small" onclick="openJobReport('${escapeHtml(job.id)}')">📊 View Report</button>
                    ` : ''}
                    <button class="btn btn-secondary btn-small" onclick="closeJobModal()">Close</button>
                </div>
            </div>
        `;

        modal.classList.add('active');

    } catch (error) {
        showNotification(`❌ Error: ${error.message}`, 'error');
    }
}

function closeJobModal() {
    document.getElementById('job-modal').classList.remove('active');
}

function openJobReport(jobId) {
    try {
        window.open(`/report?job=${encodeURIComponent(jobId)}`, '_blank', 'width=1400,height=900');
        closeJobModal();
    } catch (error) {
        showNotification(`❌ Error opening report: ${error.message}`, 'error');
    }
}

async function cancelJob(jobId) {
    if (!confirm('Are you sure you want to cancel this assessment?')) return;

    try {
        const response = await fetch(`/api/jobs/${jobId}/cancel`, { method: 'POST' });
        if (!response.ok) throw new Error('Failed to cancel job');

        showNotification('✅ Job cancelled', 'success');
        updateDashboard();

    } catch (error) {
        showNotification(`❌ Error: ${error.message}`, 'error');
    }
}

// ============================================================================
// Utilities
// ============================================================================

function showNotification(message, type = 'info') {
    const el = document.getElementById('notification');
    el.textContent = message;
    el.className = `notification ${type}`;

    setTimeout(() => {
        el.className = 'notification';
        el.textContent = '';
    }, 5000);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    updateDashboard();

    // Auto-refresh dashboard every 5 seconds
    setInterval(() => {
        if (state.currentTab === 'dashboard') {
            updateDashboard();
        }
    }, 5000);

    console.log('🔴 RedAgent Dashboard initialized');
});

// Close modal on outside click
document.getElementById('job-modal')?.addEventListener('click', (e) => {
    if (e.target.id === 'job-modal') {
        closeJobModal();
    }
});

// ============================================================================
// Assessment Form Submission
// ============================================================================

assessmentForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const target = document.getElementById('target').value;
    const type = document.getElementById('target-type').value;
    
    if (!target.trim()) {
        showNotification('Please enter a target', 'error');
        return;
    }
    
    try {
        // Disable submit button
        const submitBtn = assessmentForm.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Starting Assessment...';
        
        // Create assessment
        const response = await fetch('/api/assess', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                target: target,
                type: type
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create assessment');
        }
        
        const result = await response.json();
        const jobId = result.job_id;
        
        // Reset form
        assessmentForm.reset();
        submitBtn.disabled = false;
        submitBtn.textContent = 'Start Assessment';
        
        // Show success notification
        showNotification(`✅ Assessment started! Job ID: ${jobId}`, 'success');
        
        // Switch to dashboard tab
        document.querySelector('[data-tab="dashboard"]').click();
        
        // Monitor job progress
        monitorJob(jobId);
        
    } catch (error) {
        showNotification(`❌ Error: ${error.message}`, 'error');
        const submitBtn = assessmentForm.querySelector('button[type="submit"]');
        submitBtn.disabled = false;
        submitBtn.textContent = 'Start Assessment';
    }
});

// ============================================================================
// Job Monitoring
// ============================================================================

async function monitorJob(jobId) {
    const maxAttempts = 120; // 2 minutes max
    let attempts = 0;
    
    const interval = setInterval(async () => {
        try {
            const response = await fetch(`/api/assess/${jobId}`);
            
            if (!response.ok) {
                clearInterval(interval);
                showNotification('Job not found', 'error');
                return;
            }
            
            const job = await response.json();
            state.currentJob = job;
            
            // Update UI
            updateDashboard();
            updateJobCard(job);
            
            // Check if job is complete
            if (job.status === 'completed' || job.status === 'failed' || job.status === 'cancelled') {
                clearInterval(interval);
                
                if (job.status === 'completed') {
                    showNotification('✅ Assessment completed!', 'success');
                } else if (job.status === 'failed') {
                    showNotification(`❌ Assessment failed: ${job.error}`, 'error');
                } else {
                    showNotification('⚠️ Assessment cancelled', 'info');
                }
            }
            
            attempts++;
            if (attempts >= maxAttempts) {
                clearInterval(interval);
            }
            
        } catch (error) {
            console.error('Error monitoring job:', error);
            clearInterval(interval);
        }
    }, 1000); // Update every second
}

// ============================================================================
// Dashboard Updates
// ============================================================================

async function updateDashboard() {
    try {
        console.log('[*] Fetching /api/status...');
        const response = await fetch('/api/status');
        console.log('[✓] /api/status response status:', response.status);
        
        if (!response.ok) {
            throw new Error(`API returned ${response.status}`);
        }
        
        const status = await response.json();
        console.log('[✓] Status data:', status);
        
        // Update stats
        document.getElementById('total-jobs').textContent = status.jobs.total;
        document.getElementById('running-jobs').textContent = status.jobs.running;
        document.getElementById('completed-jobs').textContent = status.jobs.completed;
        document.getElementById('failed-jobs').textContent = status.jobs.failed;
        
        // Load and display active jobs
        console.log('[*] Fetching /api/jobs...');
        const jobsResponse = await fetch('/api/jobs');
        console.log('[✓] /api/jobs response status:', jobsResponse.status);
        
        const jobsData = await jobsResponse.json();
        console.log('[✓] Jobs data:', jobsData);
        displayActiveJobs(jobsData.jobs);
        
    } catch (error) {
        console.error('[✗] Error updating dashboard:', error);
        showNotification(`Dashboard Error: ${error.message}`, 'error');
    }
}

function displayActiveJobs(jobs) {
    const container = document.getElementById('active-jobs-container');
    
    const activeJobs = jobs.filter(job => job.status === 'running' || job.status === 'completed').slice(0, 3);
    
    if (activeJobs.length === 0) {
        container.innerHTML = '<p class="empty-state">No active jobs. Start a new assessment to begin.</p>';
        return;
    }
    
    container.innerHTML = activeJobs.map(job => createJobCard(job)).join('');
}

function createJobCard(job) {
    const vulnerabilityCount = job.findings ? job.findings.length : 0;
    const statusClass = `status-${job.status}`;
    
    return `
        <div class="job-card">
            <div class="job-header">
                <div class="job-title">${escapeHtml(job.target)}</div>
                <span class="job-status ${statusClass}">${job.status.toUpperCase()}</span>
            </div>
            
            <div class="job-meta">
                <div class="job-meta-item">
                    <span>Phase:</span>
                    <strong>${job.phase}</strong>
                </div>
                <div class="job-meta-item">
                    <span>Progress:</span>
                    <strong>${job.progress}%</strong>
                </div>
                <div class="job-meta-item">
                    <span>Type:</span>
                    <strong>${job.type}</strong>
                </div>
            </div>
            
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${job.progress}%"></div>
            </div>
            
            ${job.findings && job.findings.length > 0 ? `
                <div class="job-findings">
                    <strong>Vulnerabilities: ${vulnerabilityCount}</strong>
                    ${job.findings.slice(0, 3).map(finding => 
                        `<div class="finding-badge">${escapeHtml(finding.attack)}</div>`
                    ).join('')}
                </div>
            ` : ''}
            
            <div style="display: flex; gap: 0.5rem; margin-top: 1rem;">
                <button class="btn btn-secondary btn-small" onclick="viewJobDetails('${job.id}')">
                    Details
                </button>
                ${job.status === 'running' ? `
                    <button class="btn btn-danger btn-small" onclick="cancelJob('${job.id}')">
                        Cancel
                    </button>
                ` : ''}
                ${job.report ? `
                    <button class="btn btn-primary btn-small" onclick="downloadReport('${job.id}')">
                        Report
                    </button>
                ` : ''}
            </div>
        </div>
    `;
}

function updateJobCard(job) {
    const card = document.querySelector(`[data-job-id="${job.id}"]`);
    if (card) {
        card.outerHTML = createJobCard(job);
    }
}

// ============================================================================
// Job History
// ============================================================================

async function loadJobHistory() {
    try {
        const response = await fetch('/api/jobs');
        const data = await response.json();
        
        const container = document.getElementById('history-container');
        
        if (data.jobs.length === 0) {
            container.innerHTML = '<p class="empty-state">No jobs yet. Create an assessment to see history.</p>';
            return;
        }
        
        // Sort by creation date, newest first
        const sortedJobs = data.jobs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
        
        container.innerHTML = sortedJobs.map(job => createJobCard(job)).join('');
        
    } catch (error) {
        console.error('Error loading job history:', error);
        document.getElementById('history-container').innerHTML = 
            `<p class="empty-state">❌ Error loading history: ${error.message}</p>`;
    }
}

// ============================================================================
// Reports
// ============================================================================

async function loadReports() {
    try {
        const response = await fetch('/api/reports');
        const data = await response.json();
        
        const container = document.getElementById('reports-container');
        
        if (data.reports.length === 0) {
            container.innerHTML = '<p class="empty-state">No reports yet. Complete an assessment to generate reports.</p>';
            return;
        }
        
        container.innerHTML = data.reports.map(report => createReportCard(report)).join('');
        
    } catch (error) {
        console.error('Error loading reports:', error);
        document.getElementById('reports-container').innerHTML = 
            `<p class="empty-state">❌ Error loading reports: ${error.message}</p>`;
    }
}

function createReportCard(report) {
    const timestamp = new Date(report.timestamp);
    const formattedDate = timestamp.toLocaleDateString() + ' ' + timestamp.toLocaleTimeString();
    
    return `
        <div class="report-card">
            <h4>Assessment Report</h4>
            <div class="job-meta">
                <div class="job-meta-item">
                    <span>Target:</span>
                    <strong>${escapeHtml(report.target)}</strong>
                </div>
                <div class="job-meta-item">
                    <span>Date:</span>
                    <strong>${formattedDate}</strong>
                </div>
                <div class="job-meta-item">
                    <span>Model:</span>
                    <strong>${report.model}</strong>
                </div>
            </div>
            
            <div style="display: flex; gap: 0.5rem; margin-top: 1rem;">
                <button class="btn btn-primary btn-small" onclick="viewReport('${report.filename}')">
                    View
                </button>
                <button class="btn btn-secondary btn-small" onclick="downloadReportFile('${report.filename}')">
                    Download
                </button>
            </div>
        </div>
    `;
}

async function viewReport(reportName) {
    try {
        const response = await fetch(`/api/reports/${reportName}`);
        const report = await response.json();
        
        // Display report in new tab or modal
        console.log('Report:', report);
        showNotification(`📊 Report loaded: ${reportName}`, 'info');
        
        // For now, just log it - you could create a modal to display it
        alert('Report data loaded. Check browser console for details.');
        
    } catch (error) {
        showNotification(`❌ Error loading report: ${error.message}`, 'error');
    }
}

function downloadReportFile(reportName) {
    // In a real app, you'd serve the file for download
    window.location.href = `/api/reports/${reportName}`;
}

function downloadReport(jobId) {
    // Download job report
    window.location.href = `/api/assess/${jobId}/report`;
}

// ============================================================================
// Job Actions
// ============================================================================

async function viewJobDetails(jobId) {
    try {
        const response = await fetch(`/api/assess/${jobId}`);
        const job = await response.json();
        
        console.log('Job details:', job);
        showNotification(`📋 Job ID: ${jobId} - Status: ${job.status}`, 'info');
        
    } catch (error) {
        showNotification(`❌ Error loading job details: ${error.message}`, 'error');
    }
}

async function cancelJob(jobId) {
    if (!confirm('Are you sure you want to cancel this assessment?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/jobs/${jobId}/cancel`, {
            method: 'POST'
        });
        
        if (!response.ok) {
            throw new Error('Failed to cancel job');
        }
        
        showNotification('✅ Job cancelled', 'success');
        updateDashboard();
        
    } catch (error) {
        showNotification(`❌ Error cancelling job: ${error.message}`, 'error');
    }
}

// ============================================================================
// Utilities
// ============================================================================

function showNotification(message, type = 'info') {
    const el = document.getElementById('notification');
    el.textContent = message;
    el.className = `notification ${type}`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        el.className = 'notification';
        el.textContent = '';
    }, 5000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    // Load initial dashboard
    updateDashboard();
    
    // Check enterprise features
    checkEnterpriseFeatures();
    
    // Refresh dashboard every 5 seconds
    setInterval(() => {
        if (document.getElementById('dashboard').classList.contains('active')) {
            updateDashboard();
        }
    }, 5000);
    
    console.log('🔴 RedAgent Dashboard initialized');
});

// ============================================================================
// Enterprise Features
// ============================================================================

async function checkEnterpriseFeatures() {
    try {
        const response = await fetch('/api/enterprise/status');
        const data = await response.json();
        console.log('Enterprise features:', data);
    } catch (error) {
        console.log('Enterprise features check:', error.message);
    }
}

async function gatherOSINT() {
    const target = document.getElementById('osint-target').value.trim();
    if (!target) {
        showNotification('Please enter a target domain or IP', 'error');
        return;
    }
    
    const resultsDiv = document.getElementById('osint-results');
    resultsDiv.innerHTML = '<div style="text-align: center; padding: 20px;"><span style="color: #888;">Gathering intelligence...</span></div>';
    
    try {
        const response = await fetch('/api/osint/gather', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            const status = data.api_keys_status || {};
            const getStatusIcon = (configured) => configured 
                ? '<span style="color: #6f6;">✓</span>' 
                : '<span style="color: #f66;">✗</span>';
            
            resultsDiv.innerHTML = `
                <div style="background: rgba(30,30,45,0.5); border-radius: 10px; padding: 20px; margin-top: 10px;">
                    <h4 style="color: #6f6; margin-bottom: 10px;">✓ OSINT Hub Ready</h4>
                    <p style="color: #888;">Target: <strong style="color: #fff;">${escapeHtml(target)}</strong></p>
                    <p style="color: #888; margin-top: 10px;">API Keys Status: <strong style="color: ${data.configured_count === data.total_count ? '#6f6' : '#ff6'};">${data.configured_count}/${data.total_count} configured</strong></p>
                    <ul style="color: #aaa; margin-left: 20px; margin-top: 10px; list-style: none;">
                        <li>${getStatusIcon(status.shodan)} SHODAN_API_KEY</li>
                        <li>${getStatusIcon(status.virustotal)} VIRUSTOTAL_API_KEY</li>
                        <li>${getStatusIcon(status.censys)} CENSYS_API_ID + CENSYS_API_SECRET</li>
                        <li>${getStatusIcon(status.securitytrails)} SECURITYTRAILS_API_KEY</li>
                        <li>${getStatusIcon(status.hunter)} HUNTER_API_KEY</li>
                    </ul>
                </div>
            `;
            showNotification(`OSINT Hub: ${data.configured_count}/${data.total_count} sources ready`, 'success');
        } else {
            resultsDiv.innerHTML = `<div style="color: #f66;">Error: ${escapeHtml(data.error || 'Unknown error')}</div>`;
        }
    } catch (error) {
        resultsDiv.innerHTML = `<div style="color: #f66;">Error: ${escapeHtml(error.message)}</div>`;
        showNotification('Failed to connect to OSINT Hub', 'error');
    }
}

async function loadMitreInfo() {
    try {
        const response = await fetch('/api/mitre/map', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ findings: [] })
        });
        
        const data = await response.json();
        if (data.techniques_loaded) {
            document.getElementById('mitre-techniques-count').textContent = data.techniques_loaded + '+';
        }
    } catch (error) {
        console.log('MITRE info load:', error.message);
    }
}

async function loadAgentsStatus() {
    try {
        const response = await fetch('/api/agents/status');
        const data = await response.json();
        console.log('Agents status:', data);
    } catch (error) {
        console.log('Agents status:', error.message);
    }
}
