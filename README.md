# V-Scan — Web Vulnerability Scanner

A professional-grade tool for analyzing security vulnerabilities in web applications.
Combines our custom analyzers with industry-leading open source security tools.

## Features

### Scan Modes
| Mode | Speed | What runs |
|---|---|---|
| **Quick** | ~30s | HTTP analyzers only |
| **Standard** | ~1-2min | HTTP + httpx + feroxbuster |
| **Deep** | ~15min | Everything + Nuclei (9000+ templates) |

### HTTP Analyzers (black-box)
| Analyzer | What it finds |
|---|---|
| Security Headers | Missing CSP, HSTS, X-Frame-Options etc. |
| SQL Injection | SQLi payloads in URL parameters |
| XSS | Reflected XSS via unencoded input |
| CORS | Misconfigured cross-origin policies |
| CSRF | POST forms without anti-forgery tokens |
| SSL/TLS | Certificate issues, missing HTTPS redirect |

### External Tools (auto-downloaded)
| Tool | Language | Purpose |
|---|---|---|
| **httpx** | Go | Fast technology fingerprinting |
| **feroxbuster** | Rust | Hidden path discovery (/.env, /admin, /.git) |
| **Nuclei** | Go | 9000+ CVE and misconfiguration templates |
| **semgrep** | Python | Professional static code analysis |

### AI Analysis (local, private)
- Powered by **Ollama** running locally — no data sent to internet
- Model: **phi3:mini** (2.3GB, optimized for CPU)
- Per-vulnerability explanations in plain language
- AI Security Report with top 3 priorities to fix

## Architecture

```
V-Scan/
├── Protector.Domain/         ← Entities, interfaces (no dependencies)
├── Protector.Application/    ← Use cases, scan orchestration
├── Protector.Infrastructure/ ← Analyzers, tools, enrichers
├── Protector.API/            ← ASP.NET Core + SignalR
├── Protector.CLI/            ← Command line interface
├── Protector.Tests/          ← Unit tests (21 tests)
└── protector-web/            ← React + TypeScript frontend
```

## Web UI

```bash
# Terminal 1 — API
dotnet run --project Protector.API --launch-profile http

# Terminal 2 — Frontend
cd protector-web && npm run dev

# Open browser
http://localhost:5173
```

## CLI Usage

```bash
# Basic scan
dotnet run --project Protector.CLI -- --url https://example.com

# With source code analysis
dotnet run --project Protector.CLI -- --url https://example.com --source ./src

# Deep scan (includes Nuclei)
dotnet run --project Protector.CLI -- --url https://example.com --mode Deep
```

## Install External Tools

```bash
# httpx — technology fingerprinting
dotnet run --project Protector.CLI -- --install-httpx

# feroxbuster — hidden path discovery
dotnet run --project Protector.CLI -- --install-feroxbuster

# Nuclei — CVE scanner
dotnet run --project Protector.CLI -- --install-nuclei

# semgrep — static analysis (requires Python)
pip install semgrep
```

## AI Setup (optional)

```bash
# 1. Download Ollama from ollama.ai
# 2. Pull the model
ollama pull phi3:mini

# 3. Restart the API — AI Connected indicator appears automatically
```

## Running Tests

```bash
dotnet test
```

## Tech Stack

- **.NET 8** — runtime
- **ASP.NET Core + SignalR** — real-time API
- **React 19 + TypeScript + Tailwind CSS** — frontend
- **Roslyn** — C# static analysis
- **xUnit + FluentAssertions + NSubstitute** — testing
- **Ollama (phi3:mini)** — local AI
- **httpx, feroxbuster, Nuclei, semgrep** — external security tools
