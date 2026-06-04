# V-Scan — Web Vulnerability Scanner

V-Scan is a full-stack security scanner that finds vulnerabilities in websites and repositories.
Point it at any URL and it checks for security issues — missing headers, SQL injection, open redirects, exposed files, and more.
It also uses a local AI model to explain findings and prioritize what to fix first, in plain language.

**[Live Demo →](https://alexonplus.github.io/V-Scan/)**

![.NET](https://img.shields.io/badge/.NET_8-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![React](https://img.shields.io/badge/React_19-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)

![CI](https://github.com/alexonplus/V-Scan/actions/workflows/ci.yml/badge.svg?branch=develop)
![Tests](https://img.shields.io/badge/tests-46%20passing-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/license-Polyform--NC-orange?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=flat-square)

---

<img width="1017" height="902" alt="1" src="https://github.com/user-attachments/assets/82580cca-be17-4a75-b84a-76d193da1479" />
<img width="1062" height="882" alt="2" src="https://github.com/user-attachments/assets/5fcbb539-8e0c-4b06-89cc-e6ed3f8481c7" />
<img width="1020" height="896" alt="3" src="https://github.com/user-attachments/assets/15747f35-138d-45f0-8cdb-439a3421a198" />

---

## Features

### Scan Modes
| Mode | Time | What runs |
|---|---|---|
| ⚡ **Quick** | ~30s | 7 HTTP analyzers |
| 🔍 **Standard** | ~1-2 min | HTTP + httpx + feroxbuster |
| 🔬 **Deep** | ~15 min | Everything + Nuclei (9000+ templates) |

### HTTP Analyzers (black-box — live site)
- 🛡️ **Security Headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- 💉 **SQL Injection** — payload testing on URL parameters
- ⚡ **Cross-Site Scripting (XSS)** — reflected XSS detection
- 🔀 **Open Redirect** — detects unvalidated redirects (CWE-601)
- 🌐 **CORS Misconfiguration** — wildcard and null origin checks
- 🔒 **CSRF** — POST forms without anti-forgery tokens
- 🔐 **SSL/TLS** — certificate expiry, HTTPS enforcement

### Repo Scanner — analyze before you clone
Paste any GitHub repository URL and V-Scan analyzes it for malicious patterns **without cloning** — via GitHub API only.

Detects **15 attack vectors** including:
- 🎯 MCP server auto-connect attacks (`.cursor/mcp.json`)
- 📦 Malicious `postinstall`/`preinstall` npm scripts
- 🖥️ VS Code tasks that auto-run on folder open
- 🐍 Python data exfiltration patterns
- 🪝 Git hooks (post-checkout, pre-commit)
- 🔑 Hardcoded tokens (AWS, GitHub, OpenAI)
- 🧬 Base64 obfuscated payloads

### External Tools (auto-downloaded)
- 🚀 **httpx** (Go) — fast tech fingerprinting: server version, frameworks, React/WordPress/etc.
- 🦀 **feroxbuster** (Rust) — hidden path discovery: `/.env`, `/.git`, `/admin`, `/backup.zip`
- ☢️ **Nuclei** (Go) — 9000+ CVE and misconfiguration templates *(Deep mode only)*
- 🐍 **semgrep** (Python) — 5000+ static analysis rules for C#, JS, TypeScript, React

### Static Code Analysis (white-box — source code)
- C# via Roslyn AST — SQL injection, hardcoded secrets, BinaryFormatter, MD5/SHA1
- React/TypeScript — `dangerouslySetInnerHTML`, `eval()`, localStorage tokens, HTTP calls
- semgrep OWASP Top 10 + CWE-25 rule packs *(when source path provided)*

### AI Analysis (local & private)
- 🤖 Powered by **Ollama** — runs entirely on your machine, no data sent to internet
- **On-demand** — click "Analyze with AI" after scan, your CPU stays quiet until you ask
- **AI Security Report** — overall risk assessment + top 3 priorities to fix
- **Per-vulnerability explanations** — plain language analysis on each High/Critical finding
- Model: **phi3:mini** (2.3GB, optimized for CPU)

### Scan History
- Every scan saved to database automatically
- Browse past scans, compare results, delete old entries
- Built with **Entity Framework Core + SQL Server**

### GitHub Action
Use V-Scan as a reusable GitHub Action in any repository — analyzes changed files on every PR and posts findings as a comment:

```yaml
- uses: alexonplus/V-Scan@main
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    fail-on-severity: High
```

### Real-time Progress Pipeline
```
🌐 Crawling          ████████████ 100% ✓
🛡️ HTTP Analyzers    ████████████ 100% ✓
📡 Nuclei Scanner    (Deep only)
🤖 AI Enrichment     on demand
```

---

## Architecture

Clean Architecture with 4 layers:

```
V-Scan/
├── Protector.Domain/         ← Entities, interfaces (zero dependencies)
├── Protector.Application/    ← Use cases, scan orchestration
├── Protector.Infrastructure/ ← All analyzers, tools, persistence
│   ├── Analyzers/Http/       ← SQLi, XSS, CORS, CSRF, SSL, Headers, OpenRedirect
│   ├── Analyzers/Static/     ← Roslyn (C#), React regex
│   ├── Analyzers/Httpx/      ← httpx wrapper
│   ├── Analyzers/Feroxbuster/← feroxbuster wrapper
│   ├── Analyzers/Nuclei/     ← Nuclei wrapper
│   ├── Analyzers/Semgrep/    ← semgrep wrapper
│   ├── Crawler/              ← BFS web crawler
│   ├── Enrichers/            ← Ollama AI enrichment
│   ├── Persistence/          ← EF Core + SQL Server (scan history)
│   └── Services/             ← ScanHistoryService, RepoScanService
├── Protector.API/            ← ASP.NET Core Web API + SignalR
├── Protector.CLI/            ← Command line interface + CI mode
├── Protector.Tests/          ← 46 tests (unit + integration + E2E)
└── protector-web/            ← React + TypeScript frontend
```

### Test Pyramid
| Level | Count | Speed | When |
|---|---|---|---|
| **Unit** | 28 | < 1s | Every CI push |
| **Integration** | 5 | ~2s | Manual |
| **E2E** | 5 | ~5s | Manual |

---

## Tech Stack

### Backend (.NET 8)
| Technology | Purpose |
|---|---|
| **ASP.NET Core** | Web API |
| **SignalR** | Real-time scan progress to frontend |
| **Entity Framework Core 8** | Scan history persistence |
| **SQL Server / InMemory** | Database (SQL Server in prod, InMemory in dev) |
| **Microsoft.CodeAnalysis (Roslyn)** | C# source code AST analysis |
| **HtmlAgilityPack** | HTML parsing for CSRF/XSS checks |
| **xUnit + FluentAssertions + NSubstitute** | 46 tests across 3 pyramid levels |
| **Spectre.Console** | Rich CLI output |

### Frontend
| Technology | Purpose |
|---|---|
| **React 19 + TypeScript** | UI framework |
| **Vite** | Build tool |
| **Tailwind CSS v4** | Styling |
| **Framer Motion** | Animations |
| **Lucide React** | Icons |
| **@microsoft/signalr** | Real-time connection to API |

### External Security Tools
| Tool | Language | Install size | Purpose |
|---|---|---|---|
| **httpx** | Go | ~15 MB | Technology fingerprinting |
| **feroxbuster** | Rust | ~8 MB | Directory & path enumeration |
| **Nuclei** | Go | ~45 MB | CVE scanning (9000+ templates) |
| **semgrep** | Python | via pip | Static code analysis (5000+ rules) |
| **Ollama + phi3:mini** | Go + GGUF | ~2.3 GB | Local AI analysis |

---

## Installation

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- [Node.js 18+](https://nodejs.org)
- [Git](https://git-scm.com)

### Clone & Setup
```bash
git clone https://github.com/alexonplus/V-Scan.git
cd V-Scan
dotnet restore
cd protector-web && npm install && cd ..
```

### Install External Tools (optional but recommended)
```bash
# httpx — fast technology fingerprinting
dotnet run --project Protector.CLI -- --install-httpx

# feroxbuster — hidden path discovery (Rust)
dotnet run --project Protector.CLI -- --install-feroxbuster

# Nuclei — 9000+ CVE templates (Deep mode only)
dotnet run --project Protector.CLI -- --install-nuclei

# semgrep — static code analysis (requires Python 3.8+)
pip install semgrep
```

### AI Setup (optional)
```bash
# 1. Download Ollama from https://ollama.ai
# 2. Pull the model (~2.3 GB)
ollama pull phi3:mini
# 3. Ollama runs automatically in background
```

### Database Setup (optional — for scan history)
```bash
# Set connection string via User Secrets (never committed to git)
dotnet user-secrets set "ConnectionStrings:DefaultConnection" \
  "Server=(localdb)\mssqllocaldb;Database=VScan;Trusted_Connection=True;" \
  --project Protector.API

# Without connection string → uses InMemory database (history lost on restart)
```

---

## Running

### Web UI
```bash
# Terminal 1 — Start the API
dotnet run --project Protector.API --launch-profile http

# Terminal 2 — Start the frontend
cd protector-web
npm run dev

# Open http://localhost:5173
```

### CLI
```bash
# Basic HTTP scan
dotnet run --project Protector.CLI -- --url https://example.com

# With source code analysis
dotnet run --project Protector.CLI -- --url https://example.com --source ./path/to/code

# Deep scan (includes Nuclei)
dotnet run --project Protector.CLI -- --url https://example.com --mode Deep

# CI mode — analyze changed files only (used by GitHub Action)
dotnet run --project Protector.CLI -- --source . --changed-files "src/Controllers/Auth.cs" --output-file results.json
```

### Tests
```bash
# Unit tests only (fast — used in CI)
dotnet test --filter "Category!=Integration&Category!=E2E"

# Integration tests
dotnet test --filter "Category=Integration"

# E2E tests
dotnet test --filter "Category=E2E"

# All tests
dotnet test
```

---

## Branch Strategy

This project uses **GitFlow**:

```
main        ← stable releases, auto-deploys to GitHub Pages
develop     ← integration branch
feature/*   ← individual features, merged via PR
fix/*       ← bug fixes
```

All PRs require CI to pass (build + unit tests) before merging.

---

## License

Polyform Non-Commercial — free for personal and educational use.
