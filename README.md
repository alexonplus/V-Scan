> A web vulnerability scanner with a local AI security analyst built in.
> Point it at any URL — it crawls the site, runs a dozen security analyzers,
> and a locally-running LLM explains what was found and what to fix first.
> No data ever leaves your machine.
 
![.NET](https://img.shields.io/badge/.NET_8-512BD4?style=for-the-badge&logo=dotnet&logoColor=white)
![React](https://img.shields.io/badge/React_19-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)
![SQL Server](https://img.shields.io/badge/SQL_Server-CC2927?style=for-the-badge&logo=microsoftsqlserver&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)
 
![CI](https://github.com/alexonplus/V-Scan/actions/workflows/ci.yml/badge.svg?branch=develop)
![License](https://img.shields.io/badge/license-Polyform--NC-orange?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-blue?style=flat-square)
 
<img width="1017" height="902" alt="V-Scan UI" src="https://github.com/user-attachments/assets/82580cca-be17-4a75-b84a-76d193da1479" />
---
 
## Why this exists
 
Most vulnerability scanners give you a wall of cryptic findings and let you
figure it out. V-Scan flips that: it combines a polished real-time UI, a
multi-tool scanning engine, and a local AI analyst that reads your findings
and tells you, in plain language, **what's actually dangerous and how to fix
it** — without sending anything to a cloud provider.
 
It's three products in one repo:
 
- A **web app** for interactive scanning with live progress streaming
- A **CLI** for terminal-driven scans and report generation
- A **GitHub Action** that scans pull requests and posts inline review comments
## Highlights
 
🤖 **Local AI security analyst** — Ollama + phi3:mini runs on your machine.
The model explains every High/Critical finding in plain language, generates
a prioritized fix list, and never sends your data anywhere.
 
⚡ **Real-time pipeline** — SignalR streams stage-by-stage progress to the
React frontend: crawl → HTTP analyzers → Nuclei → static analysis → AI
enrichment. You watch it work, not a spinner.
 
🛡️ **13 security analyzers, three modes** — From a 30-second header check to
a 15-minute deep scan with 9 000+ Nuclei CVE templates. Each analyzer is
single-responsibility and plugged in via DI.
 
🌐 **White-box + black-box** — Point it at a live URL *and* at the source
folder. Roslyn parses C# into an AST; semgrep runs 5 000+ OWASP rules across
TypeScript and React.
 
🐙 **Repo Scanner** — Paste a GitHub URL and V-Scan inspects it for malicious
postinstall scripts, hardcoded secrets, suspicious `.cursor/mcp.json` configs,
reverse-shell patterns, and base64-obfuscated payloads — **before you clone**.
 
📊 **History + CRUD** — Every scan is persisted to SQL Server through a
generic repository. Browse, annotate, and delete past scans from the UI.
 
🚦 **GitHub Action for PRs** — Drop the action into any repo; it runs static
analysis on changed files only and comments findings directly on the PR.
 
## Scan modes
 
| Mode | Time | Engine |
|---|---|---|
| ⚡ **Quick** | ~30s | 6 HTTP analyzers |
| 🔍 **Standard** | ~1–2 min | + httpx, feroxbuster |
| 🔬 **Deep** | ~15 min | + Nuclei (9 000+ templates) |
 
## What it checks
 
**Live site (black-box)** — security headers (CSP, HSTS, X-Frame-Options),
SQL injection, reflected XSS, CORS misconfiguration, CSRF, SSL/TLS, open
redirects.
 
**External tools** (auto-downloaded on first use) — `httpx` for tech
fingerprinting, `feroxbuster` for directory discovery (`/.env`, `/.git`,
`/admin`, `/backup.zip`), `Nuclei` for CVE templates, `semgrep` for OWASP
Top 10 rules.
 
**Source code (white-box)** — Roslyn AST detection of SQL injection via
string concat, hardcoded secrets, `BinaryFormatter`, weak crypto (MD5,
SHA1, DES). React/TS regex rules for `dangerouslySetInnerHTML`, `eval`,
tokens in localStorage, HTTP API calls.
 
<img width="1062" height="882" alt="Scan progress" src="https://github.com/user-attachments/assets/5fcbb539-8e0c-4b06-89cc-e6ed3f8481c7" />
<img width="1020" height="896" alt="AI report" src="https://github.com/user-attachments/assets/15747f35-138d-45f0-8cdb-439a3421a198" />
---
 
## Tech stack
 
**Backend (.NET 8)** — ASP.NET Core Web API · SignalR · EF Core 8 (SQL
Server) · Microsoft.CodeAnalysis (Roslyn) · HtmlAgilityPack ·
Microsoft.Extensions.DependencyInjection · xUnit · FluentAssertions ·
NSubstitute · Spectre.Console
 
**Frontend** — React 19 · TypeScript · Vite · Tailwind CSS v4 · Framer
Motion · Lucide React · @microsoft/signalr
 
**External security tools** — httpx (Go) · feroxbuster (Rust) · Nuclei (Go)
· semgrep (Python) · Ollama + phi3:mini (~2.3 GB, local CPU inference)
 
---
 
## Getting started
 
### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- [Node.js 18+](https://nodejs.org)
- SQL Server LocalDB (bundled with Visual Studio) **or** any SQL Server instance
### 1. Clone and restore
```bash
git clone https://github.com/alexonplus/V-Scan.git
cd V-Scan
dotnet restore
cd protector-web && npm install && cd ..
```
 
### 2. Create the database
The API auto-applies EF Core migrations on startup, but you can also create
the schema manually:
```bash
dotnet ef database update --project Protector.Infrastructure --startup-project Protector.API
```
The connection string lives in `Protector.API/appsettings.Development.json`
(LocalDB, database `VScan`). Adjust if you use a different SQL Server
instance.
 
### 3. Run
```bash
# Terminal 1 — API on http://localhost:5153
dotnet run --project Protector.API --launch-profile http
 
# Terminal 2 — frontend on the URL Vite prints (usually http://localhost:5173)
cd protector-web && npm run dev
```
 
Or use the shortcut script that starts both:▶️
```powershell
.\run.ps1
```
 
### 4. (Optional) Install external scanners
```bash
dotnet run --project Protector.CLI -- --install-httpx
dotnet run --project Protector.CLI -- --install-feroxbuster
dotnet run --project Protector.CLI -- --install-nuclei
pip install semgrep
```
 
### 5. (Optional) Enable the local AI analyst
Install [Ollama](https://ollama.ai), then:
```bash
ollama pull phi3:mini
```
Ollama runs in the background; V-Scan auto-detects it and the AI panel
lights up in the UI.
 
### CLI usage
```bash
# Basic HTTP scan
dotnet run --project Protector.CLI -- --url https://example.com
 
# With source code analysis
dotnet run --project Protector.CLI -- --url https://example.com --source ./src
 
# Deep scan with HTML report
dotnet run --project Protector.CLI -- --url https://example.com --mode Deep --report html
```
 
### Tests
```bash
dotnet test
```
 
---
 
## Project structure
 
```
V-Scan/
├── Protector.Domain/         Entities, enums, interfaces — no dependencies
├── Protector.Application/    Use cases, DTOs, orchestration
├── Protector.Infrastructure/ EF Core, analyzers, external tool wrappers
│   ├── Analyzers/Http/         HTTP analyzers (SQLi, XSS, CORS, CSRF, SSL, Headers)
│   ├── Analyzers/Static/       Roslyn (C#) + regex (React)
│   ├── Analyzers/{Httpx,Feroxbuster,Nuclei,Semgrep}/  External tool wrappers
│   ├── Crawler/                BFS web crawler
│   ├── Enrichers/              Ollama AI client
│   ├── Persistence/            DbContext, entities, migrations, repositories
│   └── Services/               RepoScanService, ScanHistoryService
├── Protector.API/            ASP.NET Core Web API + SignalR hub
├── Protector.CLI/            Command-line interface (Spectre.Console)
├── Protector.Tests/          63 tests — unit, integration, E2E
├── protector-web/            React 19 + TypeScript + Vite frontend
└── action.yml                GitHub Action for PR-time security scanning
```
 
### Dependency rule
 
Dependencies point inward — outer layers depend on inner, never the reverse:
 
```
API / CLI  ──→  Application  ──→  Domain
                     ↑
              Infrastructure

main      ← stable releases only, protected
develop   ← integration branch
feature/* ← merged via PR after CI passes
```
 

 

 
## License
 
[Polyform Noncommercial](LICENSE) — free for personal, educational, and
research use.
 
