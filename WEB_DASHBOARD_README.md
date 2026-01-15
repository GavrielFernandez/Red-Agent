# RedAgent Web Dashboard

A professional web-based interface for the RedAgent autonomous penetration testing framework.

## Features

✅ **Real-time Dashboard**
- Live job monitoring
- Progress tracking
- System status
- Job statistics

✅ **Assessment Management**
- Start new assessments
- Monitor execution in real-time
- View job history
- Track vulnerabilities found

✅ **Report Visualization**
- Generate detailed reports
- View assessment history
- Download reports
- Export findings

✅ **Professional UI**
- Dark theme (cybersecurity aesthetic)
- Responsive design (mobile, tablet, desktop)
- Real-time updates
- Intuitive navigation

## Installation

### Prerequisites
- Python 3.8+
- Ollama (with Phi model)
- Docker (optional, for vulnerable test service)

### Setup

1. **Install dependencies**
```bash
pip install flask flask-cors
```

2. **Start the dashboard**
```bash
python app.py
```

3. **Access the interface**
```
http://localhost:5000
```

## Usage

### Starting an Assessment

1. Click the **"New Assessment"** tab
2. Enter target URL or IP address
3. Select target type (URL or IP)
4. Click **"Start Assessment"**
5. Watch real-time progress on the dashboard

### Monitoring Jobs

The **Dashboard** tab shows:
- Total jobs created
- Currently running assessments
- Completed assessments
- Failed assessments

### Viewing Reports

1. Click the **"Reports"** tab
2. View all generated reports
3. Click **"View"** to inspect findings
4. Click **"Download"** to save the report

### Job History

The **"Job History"** tab shows:
- All past assessments
- Current status
- Vulnerabilities found
- Job statistics

## API Documentation

### REST API Endpoints

#### System Status
```
GET /api/status
```
Returns: System status, job statistics, infrastructure health

#### Create Assessment
```
POST /api/assess
Content-Type: application/json

{
  "target": "http://localhost:8080",
  "type": "url"
}
```
Returns: Job ID and creation status

#### Get Job Status
```
GET /api/assess/{job_id}
```
Returns: Job details, progress, phase, findings

#### Get Job Report
```
GET /api/assess/{job_id}/report
```
Returns: Full assessment report in JSON format

#### List All Reports
```
GET /api/reports
```
Returns: List of all generated reports

#### Get Specific Report
```
GET /api/reports/{report_name}
```
Returns: Full report contents

#### List All Jobs
```
GET /api/jobs
```
Returns: All assessment jobs with details

#### Cancel Job
```
POST /api/jobs/{job_id}/cancel
```
Returns: Cancellation confirmation

## Architecture

### Backend (Flask)
- **app.py** - Main Flask application
- REST API endpoints
- Job management
- Report generation
- Background task execution

### Frontend
- **templates/index.html** - Dashboard HTML
- **static/style.css** - Professional styling
- **static/script.js** - Real-time UI updates

### File Structure
```
red_agent/
├── app.py                  # Flask backend
├── run.py                  # RedAgent core
├── tools/
│   └── tool_factory.py     # Security tools
├── static/
│   ├── style.css           # Styling
│   └── script.js           # Frontend logic
├── templates/
│   └── index.html          # Dashboard page
├── logs/
│   └── report_*.json       # Generated reports
└── requirements.txt        # Dependencies
```

## Dashboard Sections

### 1. Dashboard Tab
- **Statistics Cards** - Job counts and status overview
- **Active Jobs** - Real-time monitoring of running assessments
- **Progress Bars** - Visual progress tracking
- **Vulnerabilities** - Quick view of findings

### 2. New Assessment Tab
- **Target Input** - Enter URL or IP address
- **Target Type Selection** - Choose between URL and IP
- **Phase Information** - View all 5 assessment phases
- **Legal Notice** - Important authorization reminder

### 3. Job History Tab
- **Complete Job List** - All past assessments
- **Detailed Metrics** - Per-job statistics
- **Status Indicators** - Running/completed/failed/cancelled
- **Action Buttons** - View details, download reports

### 4. Reports Tab
- **Report List** - All generated reports
- **Metadata** - Target, date, LLM model used
- **View/Download** - Access report data
- **Filtering** - Sort by date

## Real-time Updates

The dashboard automatically:
- **Refreshes every 1 second** - While job is running
- **Refreshes every 5 seconds** - Dashboard tab
- **Shows phase progression** - Real-time phase updates
- **Displays findings** - As vulnerabilities are found

## Assessment Phases

The web interface displays progress through all 5 phases:

1. **Reconnaissance** (Phase 1)
   - Network scanning
   - Information gathering
   - Target analysis

2. **Vulnerability Analysis** (Phase 2)
   - Security header checking
   - SQL injection testing
   - CVE identification

3. **Exploitation Planning** (Phase 3)
   - Tool selection
   - Attack prioritization
   - Strategy development

4. **Attack Execution** (Phase 4)
   - 8 attack vectors tested
   - Real-time vulnerability discovery
   - Impact analysis

5. **Impact Assessment** (Phase 5)
   - Risk scoring
   - Remediation recommendations
   - Business impact analysis

## Vulnerability Indicators

The dashboard uses color-coded badges:

- 🔴 **CRITICAL** - Command injection, RCE, etc.
- 🟠 **HIGH** - Weak authentication, XXE, etc.
- 🟡 **MEDIUM** - Missing headers, path traversal, etc.
- 🟢 **LOW** - Informational findings

## Job Status

- **Running** - Assessment in progress (🟡 Yellow)
- **Completed** - Assessment finished successfully (🟢 Green)
- **Failed** - Assessment encountered an error (🔴 Red)
- **Cancelled** - User cancelled the assessment (⚫ Gray)

## Error Handling

The dashboard gracefully handles:
- Network timeouts
- Tool failures (Nmap, SQLmap not installed)
- LLM unavailability (fallback to demo responses)
- Missing reports
- Job not found errors

## Performance

- **Light Weight** - Minimal dependencies
- **Responsive** - Under 1 second updates
- **Scalable** - Handles multiple concurrent jobs
- **Resource Efficient** - Low memory footprint

## Security Considerations

⚠️ **IMPORTANT**

The dashboard is designed for:
- **Local testing** - Testing on your own systems
- **Authorized assessments** - With explicit permission
- **Learning purposes** - Educational use

⚠️ **Do NOT use for:**
- Unauthorized penetration testing
- Testing systems you don't own
- Malicious purposes

Unauthorized access to computer systems is **illegal** in most jurisdictions.

## Customization

### Change Port
Edit `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=8000)  # Change 5000 to 8000
```

### Change Theme Colors
Edit `static/style.css`:
```css
--primary-color: #dc143c;  /* Red */
--secondary-color: #1a1a1a;  /* Dark */
```

### Add Custom Branding
Edit `templates/index.html`:
```html
<h1>Your Company RedAgent</h1>
<p class="subtitle">Custom Assessment Platform</p>
```

## Troubleshooting

### Dashboard won't load
```bash
# Check if Flask is running
netstat -an | grep 5000

# Check logs
python app.py  # View console output
```

### Assessments not starting
```bash
# Verify Ollama is running
ollama list

# Check RedAgent core
python run.py "http://localhost:8080"
```

### Reports not appearing
```bash
# Check logs directory
ls -la logs/

# Check file permissions
chmod 755 logs/
```

## Development

### Project Structure
- Flask backend handles API requests
- Frontend uses vanilla JavaScript (no dependencies)
- Jobs run in background threads
- Reports stored as JSON files

### Adding New Endpoints

```python
@app.route('/api/new-feature', methods=['GET'])
def new_feature():
    """API endpoint documentation"""
    try:
        # Implementation
        return jsonify({"result": "data"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

### Updating Frontend

Edit `static/script.js` to add new functionality:
```javascript
async function newFeature() {
    const response = await fetch('/api/new-feature');
    const data = await response.json();
    // Handle data
}
```

## Future Enhancements

Planned features:
- [ ] User authentication/login
- [ ] Multi-user collaboration
- [ ] Report templates
- [ ] Scheduled assessments
- [ ] Email notifications
- [ ] Team management
- [ ] API key support
- [ ] Advanced filtering/search

## Support

For issues or questions:
1. Check [PROJECT_DEEP_DIVE.md](PROJECT_DEEP_DIVE.md)
2. Review error messages in console
3. Check Ollama/Docker status
4. Review RedAgent logs

## License

This project is provided as-is for educational purposes. Use responsibly and legally.

---

**Version:** 1.0  
**Last Updated:** January 15, 2026  
**Status:** Production Ready  
