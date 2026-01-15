# 🚀 RedAgent Web Dashboard - Quick Start

## Start Everything in 3 Steps

### Step 1: Start Ollama (Terminal 1)
```powershell
ollama serve
```
Wait for: `Ollama is running`

### Step 2: Start Docker Container (Terminal 2)
```powershell
docker run -p 8080:80 kennethreitz/httpbin
```
Wait for: `Running on http://`

### Step 3: Start Web Dashboard (Terminal 3)
```powershell
cd "c:\Users\User\Desktop\python\Exp\red_agent"
python app.py
```
Wait for: `Ollama is running on http://localhost:5000`

---

## Access the Dashboard

📊 **Open your browser:**
```
http://localhost:5000
```

---

## Test It!

1. **Click "New Assessment"** tab
2. **Enter target:** `http://localhost:8080`
3. **Select type:** URL
4. **Click "Start Assessment"**
5. **Watch it run** on the Dashboard tab!

---

## What You'll See

✅ **Real-time monitoring:**
- Phase progression (Reconnaissance → Attack Execution)
- Progress bar (0% to 100%)
- Vulnerabilities found in real-time

✅ **Final report with:**
- All 8 attack results
- Vulnerabilities discovered
- Impact assessment

---

## Dashboard Features

| Tab | Function |
|-----|----------|
| 📊 **Dashboard** | Live job monitoring, statistics |
| ➕ **New Assessment** | Start new penetration test |
| 📋 **Job History** | View all past assessments |
| 📄 **Reports** | Access generated reports |

---

## Stop Everything

**Press CTRL+C in each terminal:**
1. Ollama terminal
2. Docker terminal  
3. Dashboard terminal

---

## Troubleshooting

**Dashboard won't load?**
```powershell
# Check if port 5000 is in use
netstat -ano | findstr :5000

# Try different port in app.py line:
# app.run(port=5001)
```

**Ollama timeout?**
```powershell
# Restart Ollama
ollama serve

# Check status
ollama list
```

**Assessment not starting?**
```powershell
# Verify Docker is running
docker ps

# Check logs in Flask terminal
```

---

## Advanced

### Change Port
Edit `app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=8000)  # Change 5000 → 8000
```

### Change LLM Model
Edit `run.py` line ~150:
```python
self.llm_model = "llama2"  # Change from "phi"
```

### Custom Report Template
Edit `WEB_DASHBOARD_README.md` for customization guide

---

## API Usage (For Developers)

**Start assessment via curl:**
```bash
curl -X POST http://localhost:5000/api/assess \
  -H "Content-Type: application/json" \
  -d '{"target":"http://localhost:8080","type":"url"}'
```

**Get job status:**
```bash
curl http://localhost:5000/api/assess/job_1_120000
```

**Get system status:**
```bash
curl http://localhost:5000/api/status
```

---

## Performance

**Expected times:**
- Start to first results: 30 seconds
- Full assessment: 2 minutes
- Report generation: 1-2 minutes

---

## Next Steps

1. ✅ Test with local httpbin
2. ✅ View generated reports
3. ✅ Review vulnerabilities found
4. ✅ Read PROJECT_DEEP_DIVE.md for details
5. ✅ Customize for your needs

---

**Status:** Ready to Launch! 🔴
