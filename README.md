# Protector — Web Vulnerability Scanner

A tool for analyzing vulnerabilities in web applications (React + C# backend).
Supports two modes: **black-box** (HTTP requests to a live site) and **white-box** (static source code analysis).

## Architecture

```
Protector.Domain/         <- Entities, interfaces (no external dependencies)
Protector.Application/    <- Use cases, scan orchestration
Protector.Infrastructure/ <- Implementations: HTTP, Roslyn, file system
Protector.CLI/            <- Entry point, DI setup, console UI
Protector.Tests/          <- Unit tests (xUnit + FluentAssertions)
```

## What It Checks

### HTTP Analyzers (black-box)
| Check | Description |
|---|---|
| Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| SQL Injection | Parameter testing with SQLi payloads |
| XSS | Reflected XSS via forms and URL parameters |
| CORS | Misconfigured Cross-Origin policies |
| CSRF | Missing anti-forgery tokens |
| SSL/TLS | Weak ciphers, outdated protocols |
| Open Redirect | Unprotected redirects |
| Info Disclosure | Version leaks, stack traces in responses |

### Static Code Analysis (white-box)
| Check | Language |
|---|---|
| SQL via string concatenation | C# |
| Unsafe deserialization (`BinaryFormatter`) | C# |
| Hardcoded credentials / API keys | C# / React |
| `dangerouslySetInnerHTML` | React |
| `eval()` and `Function()` | React/JS |
| HTTP instead of HTTPS | React |

## Usage

```bash
# HTTP scan only
dotnet run --project Protector.CLI -- --url https://example.com

# HTTP + source code analysis
dotnet run --project Protector.CLI -- --url https://example.com --source ./path/to/project

# Save HTML report
dotnet run --project Protector.CLI -- --url https://example.com --report html --output ./reports
```

## Running Tests

```bash
dotnet test
```

## Branch Strategy

| Branch | Status | Description |
|---|---|---|
| `main` | stable | Production-ready code |
| `develop` | active | Feature integration |
| `feature/domain` | done | Domain layer |
| `feature/infrastructure-http` | planned | HTTP analyzers |
| `feature/infrastructure-static` | planned | Static code analysis |
| `feature/application` | planned | Use cases |
| `feature/cli` | planned | CLI interface |
| `feature/tests` | planned | Unit tests |

## Tech Stack

- **.NET 8** — runtime
- **Roslyn (Microsoft.CodeAnalysis.CSharp)** — C# source code analysis
- **HtmlAgilityPack** — HTML parsing
- **Spectre.Console** — rich CLI output
- **xUnit + FluentAssertions + NSubstitute** — testing
- **Microsoft.Extensions.DependencyInjection** — DI container
