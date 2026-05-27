import { useEffect, useState } from 'react'
import { Clock, Trash2, ExternalLink, Shield, ChevronDown, ChevronUp } from 'lucide-react'

interface HistorySession {
  id: string
  targetUrl: string
  mode: string
  startedAt: string
  completedAt: string | null
  totalVulnerabilities: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  riskScore: number
}

const API = 'http://localhost:5285'

const severityColor = (count: number, type: 'critical' | 'high' | 'medium' | 'low') => {
  if (count === 0) return 'text-gray-500'
  if (type === 'critical') return 'text-red-400 font-bold'
  if (type === 'high') return 'text-orange-400 font-bold'
  if (type === 'medium') return 'text-yellow-400'
  return 'text-blue-400'
}

const riskColor = (score: number) => {
  if (score >= 30) return 'text-red-400'
  if (score >= 15) return 'text-orange-400'
  if (score >= 5) return 'text-yellow-400'
  return 'text-green-400'
}

export function HistoryPage() {
  const [sessions, setSessions] = useState<HistorySession[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(`${API}/api/history`)
      if (!res.ok) throw new Error('Failed to load history')
      setSessions(await res.json())
    } catch {
      setError('Could not load scan history. Make sure the API is running.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const handleDelete = async (id: string) => {
    setDeleting(id)
    try {
      await fetch(`${API}/api/history/${id}`, { method: 'DELETE' })
      setSessions(prev => prev.filter(s => s.id !== id))
    } finally {
      setDeleting(null)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-400">
        <Clock className="animate-spin mr-2 w-5 h-5" />
        Loading history...
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-16 text-red-400">
        <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
        <p>{error}</p>
        <button onClick={load} className="mt-4 px-4 py-2 bg-gray-700 rounded-lg hover:bg-gray-600 text-white text-sm">
          Retry
        </button>
      </div>
    )
  }

  if (sessions.length === 0) {
    return (
      <div className="text-center py-16 text-gray-500">
        <Clock className="w-12 h-12 mx-auto mb-3 opacity-30" />
        <p className="text-lg">No scans yet</p>
        <p className="text-sm mt-1">Run your first scan and it will appear here</p>
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto px-4 py-8">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <Clock className="w-6 h-6 text-indigo-400" />
          Scan History
        </h1>
        <span className="text-gray-400 text-sm">{sessions.length} scans</span>
      </div>

      <div className="space-y-3">
        {sessions.map(s => (
          <div key={s.id} className="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
            <div className="flex items-center gap-4 p-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-white font-medium truncate">{s.targetUrl}</span>
                  <a href={s.targetUrl} target="_blank" rel="noopener noreferrer" className="text-gray-500 hover:text-indigo-400 flex-shrink-0">
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
                <div className="flex items-center gap-3 text-xs text-gray-400">
                  <span className="bg-gray-700 px-2 py-0.5 rounded">{s.mode}</span>
                  <span>{new Date(s.startedAt).toLocaleString()}</span>
                  <span className={`font-semibold ${riskColor(s.riskScore)}`}>
                    Risk: {s.riskScore}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-3 text-sm flex-shrink-0">
                <span className={severityColor(s.critical, 'critical')}>{s.critical}C</span>
                <span className={severityColor(s.high, 'high')}>{s.high}H</span>
                <span className={severityColor(s.medium, 'medium')}>{s.medium}M</span>
                <span className={severityColor(s.low, 'low')}>{s.low}L</span>
              </div>

              <div className="flex items-center gap-1 flex-shrink-0">
                <button
                  onClick={() => setExpanded(expanded === s.id ? null : s.id)}
                  className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-700"
                >
                  {expanded === s.id
                    ? <ChevronUp className="w-4 h-4" />
                    : <ChevronDown className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => handleDelete(s.id)}
                  disabled={deleting === s.id}
                  className="p-2 text-gray-500 hover:text-red-400 rounded-lg hover:bg-gray-700 disabled:opacity-40"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>

            {expanded === s.id && (
              <ScanDetail id={s.id} />
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function ScanDetail({ id }: { id: string }) {
  const [data, setData] = useState<any>(null)

  useEffect(() => {
    fetch(`${API}/api/history/${id}`)
      .then(r => r.json())
      .then(setData)
  }, [id])

  if (!data) return (
    <div className="px-4 pb-4 text-gray-500 text-sm">Loading details...</div>
  )

  const findings = data.findings ?? []

  if (findings.length === 0) return (
    <div className="px-4 pb-4 text-green-400 text-sm">No vulnerabilities found</div>
  )

  return (
    <div className="border-t border-gray-700 px-4 pb-4">
      <div className="mt-3 space-y-2 max-h-64 overflow-y-auto">
        {findings.map((f: any) => (
          <div key={f.id} className="flex items-start gap-3 text-sm py-2 border-b border-gray-700 last:border-0">
            <span className={`px-2 py-0.5 rounded text-xs font-semibold flex-shrink-0 ${
              f.severity === 'Critical' ? 'bg-red-900 text-red-300' :
              f.severity === 'High' ? 'bg-orange-900 text-orange-300' :
              f.severity === 'Medium' ? 'bg-yellow-900 text-yellow-300' :
              'bg-blue-900 text-blue-300'
            }`}>{f.severity}</span>
            <div className="min-w-0">
              <div className="text-gray-200 font-medium">{f.title}</div>
              {f.url && <div className="text-gray-500 text-xs truncate">{f.url}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
