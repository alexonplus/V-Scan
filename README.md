# V-Scan — Web Vulnerability Scanner

> A professional-grade web vulnerability scanner combining custom security analyzers,
> industry-leading open-source tools, and local AI analysis — all in one interface.

<!-- SCREENSHOT: Main UI screenshot here -->
<!-- ![V-Scan UI](docs/screenshots/main.png) -->

### Built with

![.NET](https://img.shields.io/badge/.NET_8-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![React](https://img.shields.io/badge/React_19-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)

### CI Status

![CI](https://github.com/alexonplus/V-Scan/actions/workflows/ci.yml/badge.svg?branch=develop)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=flat-square)

---

## Features

### Scan Modes
| Mode | Time | What runs |
|---|---|---|
| ⚡ **Quick** | ~30s | Our 6 HTTP analyzers |
| 🔍 **Standard** | ~1-2 min | HTTP + httpx + feroxbuster |
| 🔬 **Deep** | ~15 min | Everything + Nuclei (9000+ templates) |

### Security Checks
<!-- SCREENSHOT: Scan results page -->
<!-- ![Scan Results](docs/screenshots/results.png) -->

**HTTP Analyzers (black-box — live site)**
- 🛡️ Security Headers — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- 💉 SQL Injection — payload testing on URL parameters
- ⚡ Cross-Site Scripting (XSS) — reflected XSS detection
- 🌐 CORS Misconfiguration — wildcard and null origin checks
- 🔒 CSRF — POST forms without anti-forgery tokens
- 🔐 SSL/TLS — certificate expiry, HTTPS enforcement

**External Tools (auto-downloaded)**
- 🚀 **httpx** (Go) — fast tech fingerprinting: server version, frameworks, React/WordPress/etc.
- 🦀 **feroxbuster** (Rust) — hidden path discovery: `/.env`, `/.git`, `/admin`, `/backup.zip`
- ☢️ **Nuclei** (Go) — 9000+ CVE and misconfiguration templates *(Deep mode only)*
- 🐍 **semgrep** (Python) — 5000+ static analysis rules for C#, JS, TypeScript, React

**Static Code Analysis (white-box — source code)**
- C# via Roslyn AST — SQL injection, hardcoded secrets, BinaryFormatter, MD5/SHA1
- React/TypeScript — `dangerouslySetInnerHTML`, `eval()`, localStorage tokens, HTTP calls
- semgrep OWASP Top 10 + CWE-25 rule packs *(when source path provided)*

### AI Analysis (local & private)
<!-- SCREENSHOT: AI Security Report block -->
<!-- ![AI Report](docs/screenshots/ai-report.png) -->

- 🤖 Powered by **Ollama** — runs entirely on your machine, no data sent to internet
- **AI Security Report** — overall assessment + top 3 priorities to fix
- **Per-vulnerability explanations** — plain language analysis on each High/Critical finding
- Model: **phi3:mini** (2.3GB, optimized for CPU)

### Real-time Progress Pipeline
<!-- SCREENSHOT: Scanning progress pipeline -->
<!-- ![Pipeline](docs/screenshots/pipeline.png) -->

Each scan stage shows live progress:
```
🌐 Crawling          ████████████ 100% ✓
🛡️ HTTP Analyzers    ████████████ 100% ✓
📡 Nuclei Scanner    (Deep only)
🤖 AI Enrichment     ████████░░░░  67%  1/2
```

---

## Architecture

Clean Architecture with 4 layers:

```
V-Scan/
├── Protector.Domain/         ← Entities, interfaces (zero dependencies)
├── Protector.Application/    ← Use cases, scan orchestration
├── Protector.Infrastructure/ ← All analyzers and external tools
│   ├── Analyzers/Http/       ← SQLi, XSS, CORS, CSRF, SSL, Headers
│   ├── Analyzers/Static/     ← Roslyn (C#), React regex
│   ├── Analyzers/Httpx/      ← httpx wrapper
│   ├── Analyzers/Feroxbuster/← feroxbuster wrapper
│   ├── Analyzers/Nuclei/     ← Nuclei wrapper
│   ├── Analyzers/Semgrep/    ← semgrep wrapper
│   ├── Crawler/              ← BFS web crawler
│   └── Enrichers/            ← Ollama AI enrichment
├── Protector.API/            ← ASP.NET Core Web API + SignalR
├── Protector.CLI/            ← Command line interface
├── Protector.Tests/          ← 21 unit tests
└── protector-web/            ← React + TypeScript frontend
```

---

## Tech Stack

### Backend (.NET 8)
| Technology | Purpose |
|---|---|
| **ASP.NET Core** | Web API |
| **SignalR** | Real-time scan progress to frontend |
| **Microsoft.CodeAnalysis (Roslyn)** | C# source code AST analysis |
| **HtmlAgilityPack** | HTML parsing for CSRF/XSS checks |
| **xUnit + FluentAssertions + NSubstitute** | Unit testing |
| **Spectre.Console** | Rich CLI output |
| **Microsoft.Extensions.DependencyInjection** | Dependency injection |

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

---

## Running the Web UI

```bash
# Terminal 1 — Start the API
dotnet run --project Protector.API --launch-profile http

# Terminal 2 — Start the frontend
cd protector-web
npm run dev

# Open in browser
# http://localhost:5173
```

## Running the CLI

```bash
# Basic HTTP scan
dotnet run --project Protector.CLI -- --url https://example.com

# With source code analysis
dotnet run --project Protector.CLI -- --url https://example.com --source ./path/to/code

# Deep scan (includes Nuclei)
dotnet run --project Protector.CLI -- --url https://example.com --mode Deep

# Save HTML report
dotnet run --project Protector.CLI -- --url https://example.com --report html --output ./reports
```

## Running Tests

```bash
dotnet test
```

---

## Branch Strategy

This project uses **GitFlow**:

```
main        ← stable releases only
develop     ← integration branch
feature/*   ← individual features, merged via PR
```

All PRs require CI to pass (build + 21 tests) before merging.

---

## License

MIT — free for personal and commercial use.
