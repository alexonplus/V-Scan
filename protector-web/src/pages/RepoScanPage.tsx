import { useState } from 'react'
import { Search, ShieldAlert, ShieldCheck, AlertTriangle, Info, GitBranch } from 'lucide-react'

interface RepoFinding {
  filePath: string
  ruleId: string
  title: string
  description: string
  severity: 'Info' | 'Warning' | 'Danger'
  lineNumber: number | null
  evidence: string | null
}

interface RepoScanResult {
  repoUrl: string
  owner: string
  repoName: string
  scannedAt: string
  findings: RepoFinding[]
}

const API = 'http://localhost:5153'

const severityConfig = {
  Danger:  { color: 'text-red-400',    bg: 'bg-red-900/30',    border: 'border-red-500/40',    icon: ShieldAlert,     label: 'DANGER' },
  Warning: { color: 'text-yellow-400', bg: 'bg-yellow-900/30', border: 'border-yellow-500/40', icon: AlertTriangle,   label: 'WARNING' },
  Info:    { color: 'text-blue-400',   bg: 'bg-blue-900/30',   border: 'border-blue-500/40',   icon: Info,            label: 'INFO' },
}

export function RepoScanPage() {
  const [repoUrl, setRepoUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<RepoScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!repoUrl.trim()) return

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await fetch(`${API}/api/reposcan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrl: repoUrl.trim() })
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error ?? 'Scan failed')
      }

      setResult(await res.json())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not connect to API')
    } finally {
      setLoading(false)
    }
  }

  const dangerCount = result?.findings.filter(f => f.severity === 'Danger').length ?? 0
  const warningCount = result?.findings.filter(f => f.severity === 'Warning').length ?? 0

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <GitBranch className="w-7 h-7 text-purple-400" />
          <h1 className="text-2xl font-bold text-white">Repo Scanner</h1>
        </div>
        <p className="text-white/50 text-sm">
          Analyze a GitHub repository for malicious scripts, hardcoded secrets, and suspicious patterns — before you clone it.
        </p>
      </div>

      <form onSubmit={handleScan} className="mb-8">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <GitBranch className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-white/30" />
            <input
              type="text"
              value={repoUrl}
              onChange={e => setRepoUrl(e.target.value)}
              placeholder="github.com/owner/repo or https://github.com/owner/repo"
              className="w-full bg-white/5 border border-white/10 rounded-xl py-4 pl-12 pr-4 text-white focus:outline-none focus:border-neon-primary/50 focus:bg-white/10 transition-all placeholder:text-white/20"
            />
          </div>
          <button
            type="submit"
            disabled={loading || !repoUrl.trim()}
            className="flex items-center gap-2 px-6 py-4 bg-neon-primary/10 border border-neon-primary/30 text-neon-primary rounded-xl font-semibold hover:bg-neon-primary/20 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Search className="w-4 h-4" />
            {loading ? 'Scanning...' : 'Scan'}
          </button>
        </div>
      </form>

      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-xl p-4 text-red-400 mb-6">
          {error}
        </div>
      )}

      {loading && (
        <div className="text-center py-16 text-white/40">
          <Search className="w-10 h-10 mx-auto mb-3 animate-pulse text-neon-primary" />
          <p>Fetching files from GitHub API...</p>
          <p className="text-xs mt-1">No code is downloaded to your machine</p>
        </div>
      )}

      {result && (
        <div>
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-white font-bold text-lg">{result.owner}/{result.repoName}</h2>
              <p className="text-white/40 text-xs">{new Date(result.scannedAt).toLocaleString()}</p>
            </div>
            <div className="flex gap-3">
              {dangerCount > 0
                ? <span className="flex items-center gap-1.5 px-3 py-1.5 bg-red-900/30 border border-red-500/30 rounded-lg text-red-400 text-sm font-bold">
                    <ShieldAlert className="w-4 h-4" /> {dangerCount} Danger
                  </span>
                : <span className="flex items-center gap-1.5 px-3 py-1.5 bg-green-900/30 border border-green-500/30 rounded-lg text-green-400 text-sm font-bold">
                    <ShieldCheck className="w-4 h-4" /> Safe
                  </span>
              }
              {warningCount > 0 &&
                <span className="flex items-center gap-1.5 px-3 py-1.5 bg-yellow-900/30 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm font-bold">
                  <AlertTriangle className="w-4 h-4" /> {warningCount} Warning
                </span>
              }
            </div>
          </div>

          {result.findings.length === 0 ? (
            <div className="text-center py-12 text-green-400">
              <ShieldCheck className="w-14 h-14 mx-auto mb-3 opacity-80" />
              <p className="text-lg font-semibold">No suspicious patterns found</p>
              <p className="text-white/40 text-sm mt-1">This repository appears safe to clone</p>
            </div>
          ) : (
            <div className="space-y-3">
              {result.findings.map((f, i) => {
                const cfg = severityConfig[f.severity]
                const Icon = cfg.icon
                return (
                  <div key={i} className={`${cfg.bg} border ${cfg.border} rounded-xl p-4`}>
                    <div className="flex items-start gap-3">
                      <Icon className={`w-5 h-5 ${cfg.color} flex-shrink-0 mt-0.5`} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-xs font-black uppercase tracking-wider ${cfg.color}`}>{cfg.label}</span>
                          <span className="text-white font-semibold">{f.title}</span>
                        </div>
                        <p className="text-white/60 text-sm mb-2">{f.description}</p>
                        <div className="flex items-center gap-2 text-xs text-white/40 font-mono">
                          <span>{f.filePath}</span>
                          {f.lineNumber && <span>line {f.lineNumber}</span>}
                        </div>
                        {f.evidence && (
                          <div className="mt-2 bg-black/30 rounded px-3 py-1.5 text-xs font-mono text-white/70 truncate">
                            {f.evidence}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
