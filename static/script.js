/* ============================================================================
   RedAgent Web Dashboard - Frontend Logic
   ============================================================================ */

// Global state
const state = {
    jobs: {},
    reports: [],
    currentJob: null
};

// DOM Elements
const assessmentForm = document.getElementById('assessment-form');
const tabButtons = document.querySelectorAll('.tab-button');
const tabContents = document.querySelectorAll('.tab-content');
const notificationEl = document.getElementById('notification');

// ============================================================================
// Tab Navigation
// ============================================================================

tabButtons.forEach(button => {
    button.addEventListener('click', () => {
        const tabName = button.getAttribute('data-tab');
        
        // Remove active class from all buttons and contents
        tabButtons.forEach(btn => btn.classList.remove('active'));
        tabContents.forEach(content => content.classList.remove('active'));
        
        // Add active class to clicked button and corresponding content
        button.classList.add('active');
        document.getElementById(tabName).classList.add('active');
        
        // Load data for specific tabs
        if (tabName === 'history') {
            loadJobHistory();
        } else if (tabName === 'reports') {
            loadReports();
        }
    });
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
        const response = await fetch('/api/status');
        const status = await response.json();
        
        // Update stats
        document.getElementById('total-jobs').textContent = status.jobs.total;
        document.getElementById('running-jobs').textContent = status.jobs.running;
        document.getElementById('completed-jobs').textContent = status.jobs.completed;
        document.getElementById('failed-jobs').textContent = status.jobs.failed;
        
        // Load and display active jobs
        const jobsResponse = await fetch('/api/jobs');
        const jobsData = await jobsResponse.json();
        displayActiveJobs(jobsData.jobs);
        
    } catch (error) {
        console.error('Error updating dashboard:', error);
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
    
    // Refresh dashboard every 5 seconds
    setInterval(() => {
        if (document.getElementById('dashboard').classList.contains('active')) {
            updateDashboard();
        }
    }, 5000);
    
    console.log('🔴 RedAgent Dashboard initialized');
});
