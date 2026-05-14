import { useState } from 'react'
import { useScan } from './useScan'
import type { Vulnerability } from './types'

const SEVERITY_CONFIG = {
  Critical: { color: 'text-red-400',    bg: 'bg-red-900/30',    border: 'border-red-700',    dot: '✖' },
  High:     { color: 'text-orange-400', bg: 'bg-orange-900/30', border: 'border-orange-700', dot: '●' },
  Medium:   { color: 'text-yellow-400', bg: 'bg-yellow-900/30', border: 'border-yellow-700', dot: '◆' },
  Low:      { color: 'text-blue-400',   bg: 'bg-blue-900/30',   border: 'border-blue-700',   dot: '◇' },
  Info:     { color: 'text-gray-400',   bg: 'bg-gray-800/30',   border: 'border-gray-600',   dot: '○' },
}

export default function App() {
  const [url, setUrl] = useState('')
  const [sourcePath, setSourcePath] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const { status, progress, result, error, startScan, reset } = useScan()

  const handleScan = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    if (url.trim()) startScan(url.trim(), sourcePath.trim() || undefined)
  }

  return (
    <div className="min-h-screen bg-[#0d1117] text-[#e6edf3] p-6 max-w-4xl mx-auto">

      {/* Header */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold text-red-400 tracking-tight">V-Scan</h1>
        <p className="text-[#8b949e] mt-1">Web Vulnerability Scanner</p>
      </div>

      {/* Scan Form */}
      {status === 'idle' && (
        <form onSubmit={handleScan} className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">New Scan</h2>
          <div className="mb-4">
            <label className="block text-sm text-[#8b949e] mb-1">Target URL *</label>
            <input
              type="url"
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com"
              required
              className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-4 py-2.5
                         text-[#e6edf3] placeholder-[#484f58] focus:outline-none
                         focus:border-red-500 transition-colors"
            />
          </div>
          <div className="mb-6">
            <label className="block text-sm text-[#8b949e] mb-1">
              Source code path <span className="text-[#484f58]">(optional)</span>
            </label>
            <input
              type="text"
              value={sourcePath}
              onChange={e => setSourcePath(e.target.value)}
              placeholder="C:\path\to\your\project"
              className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg px-4 py-2.5
                         text-[#e6edf3] placeholder-[#484f58] focus:outline-none
                         focus:border-red-500 transition-colors"
            />
          </div>
          <button
            type="submit"
            className="w-full bg-red-600 hover:bg-red-500 text-white font-semibold py-2.5 rounded-lg transition-colors"
          >
            Start Scan
          </button>
        </form>
      )}

      {/* Progress */}
      {status === 'running' && (
        <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse" />
            <h2 className="text-lg font-semibold">Scanning {url}...</h2>
          </div>
          <div className="bg-[#0d1117] rounded-lg p-4 h-48 overflow-y-auto font-mono text-sm">
            {progress.length === 0
              ? <span className="text-[#484f58]">Starting...</span>
              : progress.map((msg, i) => (
                <div key={i} className="text-[#8b949e] py-0.5">
                  <span className="text-red-400">»</span> {msg}
                </div>
              ))
            }
          </div>
        </div>
      )}

      {/* Error */}
      {status === 'error' && (
        <div className="bg-red-900/20 border border-red-700 rounded-xl p-6 mb-6">
          <h2 className="text-red-400 font-semibold mb-2">Scan Failed</h2>
          <p className="text-[#8b949e] text-sm">{error}</p>
          <button onClick={reset} className="mt-4 px-4 py-2 bg-[#21262d] hover:bg-[#30363d] rounded-lg text-sm transition-colors">
            Try Again
          </button>
        </div>
      )}

      {/* Results */}
      {status === 'completed' && result && (
        <div>
          {/* Summary */}
          <div className="grid grid-cols-3 md:grid-cols-6 gap-3 mb-6">
            {(['Critical', 'High', 'Medium', 'Low', 'Info'] as const).map(sev => (
              <div key={sev} className={`${SEVERITY_CONFIG[sev].bg} border ${SEVERITY_CONFIG[sev].border} rounded-xl p-4 text-center`}>
                <div className={`text-2xl font-bold ${SEVERITY_CONFIG[sev].color}`}>
                  {result[sev.toLowerCase() as keyof typeof result] as number}
                </div>
                <div className="text-xs text-[#8b949e] mt-1">{sev}</div>
              </div>
            ))}
            <div className="bg-red-900/20 border border-red-700 rounded-xl p-4 text-center">
              <div className="text-2xl font-bold text-red-400">{result.riskScore}</div>
              <div className="text-xs text-[#8b949e] mt-1">Risk Score</div>
            </div>
          </div>

          <div className="bg-[#161b22] border border-[#30363d] rounded-xl p-4 mb-6 text-sm text-[#8b949e]">
            <span className="text-[#e6edf3] font-medium">{result.targetUrl}</span>
            <span className="mx-2">·</span>{result.scannedUrls.length} URLs
            <span className="mx-2">·</span>{result.totalVulnerabilities} vulnerabilities
          </div>

          {/* Vuln list */}
          {(['Critical', 'High', 'Medium', 'Low', 'Info'] as const).map(sev => {
            const vulns = result.vulnerabilities.filter(v => v.severity === sev)
            if (!vulns.length) return null
            const cfg = SEVERITY_CONFIG[sev]
            return (
              <div key={sev} className="mb-4">
                <h3 className={`${cfg.color} font-semibold mb-2`}>{cfg.dot} {sev} ({vulns.length})</h3>
                <div className="space-y-2">
                  {vulns.map(v => (
                    <VulnCard key={v.id} vuln={v} isOpen={expanded === v.id}
                      onToggle={() => setExpanded(expanded === v.id ? null : v.id)} />
                  ))}
                </div>
              </div>
            )
          })}

          <button onClick={reset} className="mt-6 w-full py-2.5 bg-[#21262d] hover:bg-[#30363d] rounded-lg text-sm transition-colors">
            New Scan
          </button>
        </div>
      )}
    </div>
  )
}

function VulnCard({ vuln, isOpen, onToggle }: { vuln: Vulnerability; isOpen: boolean; onToggle: () => void }) {
  const cfg = SEVERITY_CONFIG[vuln.severity]
  return (
    <div className={`bg-[#161b22] border ${cfg.border} rounded-lg overflow-hidden`}>
      <button onClick={onToggle}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-[#21262d] transition-colors">
        <div className="flex items-center gap-3">
          <span className={`text-xs font-bold px-2 py-0.5 rounded ${cfg.bg} ${cfg.color} border ${cfg.border}`}>
            {vuln.severity}
          </span>
          <span className="text-sm font-medium">{vuln.title}</span>
        </div>
        <span className="text-[#484f58] text-xs">{isOpen ? '▲' : '▼'}</span>
      </button>
      {isOpen && (
        <div className="px-4 pb-4 text-sm space-y-3 border-t border-[#30363d] pt-3">
          <p className="text-[#8b949e]">{vuln.description}</p>
          {vuln.url && <div><span className="text-[#484f58]">URL: </span><span className="font-mono text-xs text-blue-400">{vuln.url}</span></div>}
          {vuln.filePath && <div><span className="text-[#484f58]">File: </span><span className="font-mono text-xs">{vuln.filePath}{vuln.lineNumber ? `:${vuln.lineNumber}` : ''}</span></div>}
          {vuln.evidence && <div className="bg-[#0d1117] rounded-lg p-3 font-mono text-xs text-[#8b949e] break-all">{vuln.evidence}</div>}
          <div className="flex gap-4 text-xs text-[#484f58]">
            {vuln.cweId && <span>{vuln.cweId}</span>}
            {vuln.owaspCategory && <span>{vuln.owaspCategory}</span>}
          </div>
          <div className="bg-green-900/20 border border-green-700/50 rounded-lg p-3 text-xs text-green-400">
            <span className="font-semibold">Fix: </span>{vuln.remediation}
          </div>
        </div>
      )}
    </div>
  )
}
