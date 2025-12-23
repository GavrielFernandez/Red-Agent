# Red Agent - Git Workflow & Branch Strategy

## Branch Structure

### Main Branches

| Branch | Purpose | Notes |
|--------|---------|-------|
| `master` | Production-ready code | Stable releases only |
| `dev` | Development integration | Base for feature branches |

### Feature Branches

| Branch | Purpose | Status |
|--------|---------|--------|
| `feature/timeout-optimization` | Minimize Llama2 response timeouts | In Planning |
| `feature/tool-integration` | Add security tools (Nmap, SQLmap) | Backlog |
| `feature/rag-improvements` | Enhance ChromaDB memory system | Backlog |

## Current Tasks

### 🔴 Priority 1: Timeout Optimization
**Branch:** `feature/timeout-optimization`

Goals:
- Reduce Llama2 query response time (current: 2-3 min → target: 30-60 sec)
- Implement prompt caching
- Add streaming response support
- Optimize prompt engineering for faster inference

Tasks:
- [ ] Profile current response times
- [ ] Test different prompt structures for speed
- [ ] Implement streaming response handling
- [ ] Add response caching mechanism
- [ ] Test against multiple targets
- [ ] Performance benchmarks

### 🟡 Priority 2: Tool Integration
**Branch:** `feature/tool-integration`

Goals:
- Integrate Nmap for network scanning
- Integrate SQLmap for SQL injection testing
- Add Hydra for password testing
- Integrate Curl for HTTP testing

### 🟡 Priority 3: RAG Improvements
**Branch:** `feature/rag-improvements`

Goals:
- Enhance vector store queries
- Implement semantic search
- Add knowledge base for common vulnerabilities
- Improve memory retention

## Workflow

### Starting a feature branch

```bash
# Switch to dev branch
git checkout dev

# Create and switch to feature branch
git checkout -b feature/your-feature

# Make changes...
git add .
git commit -m "Description of changes"

# Push to remote
git push origin feature/your-feature
```

### Merging back to dev

```bash
# Switch to dev
git checkout dev

# Pull latest
git pull origin dev

# Merge feature
git merge feature/your-feature

# Push
git push origin dev
```

### Releasing to master

```bash
# Switch to master
git checkout master

# Merge dev
git merge dev

# Tag release
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin --tags
```

## Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `perf`: Performance improvement
- `refactor`: Code refactoring
- `test`: Adding tests
- `docs`: Documentation
- `chore`: Build/dependency changes

Example:
```
perf(llm): reduce timeout in query_llm function

- Implement response streaming for faster token output
- Add response caching for repeated queries
- Optimize prompt structure for Llama2

Closes #12
```

## Current Status

- ✅ Repository initialized
- ✅ Initial commit to master
- ✅ Development branches created
- ⏳ Ready to start feature development
- ⏳ Remote repository setup needed

## Next Steps

1. **Set up remote repository** (GitHub/GitLab)
   ```bash
   git remote add origin https://github.com/user/red-agent.git
   git push -u origin master
   git push -u origin dev
   git push -u origin feature/*
   ```

2. **Switch to `dev` branch for development**
   ```bash
   git checkout dev
   ```

3. **Start with timeout optimization feature**
   ```bash
   git checkout feature/timeout-optimization
   ```

