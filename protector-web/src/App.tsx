import { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'motion/react'
import {
  Shield, Terminal, Search, AlertTriangle, Info as InfoIcon,
  ChevronDown, RefreshCcw, Zap, Lock, Globe,
  Activity, Cpu, Radar, Clock, GitBranch
} from 'lucide-react'
import { useScan } from './services/scanService'
import type { Vulnerability, Severity, AiReport } from './types'
import { HistoryPage } from './pages/HistoryPage'
import { RepoScanPage } from './pages/RepoScanPage'

const SEVERITY_CONFIG: Record<Severity, { color: string; bg: string; border: string; glow: string; icon: React.ElementType }> = {
  Critical: { color: 'text-neon-accent',    bg: 'bg-neon-accent/10',    border: 'border-neon-accent/40',    glow: 'shadow-[0_0_15px_rgba(255,0,200,0.3)]',  icon: AlertTriangle },
  High:     { color: 'text-orange-400',     bg: 'bg-orange-500/10',     border: 'border-orange-500/40',     glow: 'shadow-[0_0_15px_rgba(251,146,60,0.3)]', icon: AlertTriangle },
  Medium:   { color: 'text-yellow-400',     bg: 'bg-yellow-500/10',     border: 'border-yellow-500/40',     glow: 'shadow-[0_0_15px_rgba(250,204,21,0.3)]', icon: AlertTriangle },
  Low:      { color: 'text-neon-primary',   bg: 'bg-neon-primary/10',   border: 'border-neon-primary/40',   glow: 'shadow-[0_0_15px_rgba(0,255,157,0.3)]',  icon: InfoIcon },
  Info:     { color: 'text-neon-secondary', bg: 'bg-neon-secondary/10', border: 'border-neon-secondary/40', glow: 'shadow-[0_0_15px_rgba(0,209,255,0.3)]',  icon: InfoIcon },
}

export default function App() {
  const [page, setPage] = useState<string>('scanner') // 'scanner' | 'history' | 'repo'
  const [url, setUrl] = useState('')
  const [sourcePath, setSourcePath] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [activeFilter, setActiveFilter] = useState<Severity | null>(null)
  const [scanMode, setScanMode] = useState<'Quick' | 'Standard' | 'Deep'>('Standard')
  const { status, progress, result, ollamaOnline, stages, startScan, reset } = useScan()
  const terminalEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [progress])

  const handleScan = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    setActiveFilter(null)
    if (url.trim()) startScan(url.trim(), sourcePath.trim() || undefined, scanMode)
  }

  if (page === 'history' || page === 'repo') {
    return (
      <div className="relative min-h-screen font-sans">
        <div className="max-w-5xl mx-auto px-6 py-12 md:px-12 relative z-10">
          <header className="mb-10 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="relative p-3 glass-card rounded-2xl border border-neon-primary/30">
                <Shield className="w-8 h-8 text-neon-primary neon-text-primary" />
              </div>
              <h1 className="text-4xl font-black tracking-tight text-white uppercase italic">
                V-SCAN<span className="text-neon-primary">_</span>
              </h1>
            </div>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage('scanner')} className="flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border border-white/10 text-white/40 hover:text-white/70 transition-colors">
                <Shield className="w-3.5 h-3.5" /> Scanner
              </button>
              <button onClick={() => setPage('history')} className="flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border bg-indigo-500/10 border-indigo-500/30 text-indigo-400">
                <Clock className="w-3.5 h-3.5" /> History
              </button>
              <button onClick={() => setPage('repo')} className="flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border bg-purple-500/10 border-purple-500/30 text-purple-400">
                <GitBranch className="w-3.5 h-3.5" /> Repo
              </button>
            </div>
          </header>
          {page === 'repo' ? <RepoScanPage /> : <HistoryPage />}
        </div>
      </div>
    )
  }

  return (
    <div className="relative min-h-screen font-sans">
      {status === 'running' && <div className="scanning-overlay" />}

      <div className="max-w-5xl mx-auto px-6 py-12 md:px-12 relative z-10">
        {/* Header */}
        <header className="mb-16 flex flex-col md:flex-row md:items-center justify-between gap-8">
          <motion.div initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} className="flex items-center gap-4">
            <div className="relative">
              <div className="absolute inset-0 bg-neon-primary blur-xl opacity-20 animate-pulse" />
              <div className="relative p-3 glass-card rounded-2xl border border-neon-primary/30">
                <Shield className="w-10 h-10 text-neon-primary neon-text-primary" />
              </div>
            </div>
            <div>
              <h1 className="text-5xl font-black tracking-[calc(-0.06em)] text-white uppercase italic leading-none">
                V-SCAN<span className="text-neon-primary neon-text-primary">_</span>
              </h1>
              <p className="text-white/40 text-xs font-mono uppercase tracking-[0.3em] mt-2 italic font-bold">Web Vulnerability Scanner</p>
            </div>
          </motion.div>
          <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} className="flex flex-col items-end gap-2">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage('scanner')}
                className={`flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border transition-colors ${
                  page === 'scanner'
                    ? 'bg-neon-primary/10 border-neon-primary/30 text-neon-primary'
                    : 'border-white/10 text-white/40 hover:text-white/70'
                }`}
              >
                <Shield className="w-3.5 h-3.5" /> Scanner
              </button>
              <button
                onClick={() => setPage('history')}
                className={`flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border transition-colors ${
                  page === 'history'
                    ? 'bg-indigo-500/10 border-indigo-500/30 text-indigo-400'
                    : 'border-white/10 text-white/40 hover:text-white/70'
                }`}
              >
                <Clock className="w-3.5 h-3.5" /> History
              </button>
              <button
                onClick={() => setPage('repo')}
                className={`flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-lg border transition-colors ${
                  page === 'repo'
                    ? 'bg-purple-500/10 border-purple-500/30 text-purple-400'
                    : 'border-white/10 text-white/40 hover:text-white/70'
                }`}
              >
                <GitBranch className="w-3.5 h-3.5" /> Repo
              </button>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-neon-secondary neon-text-secondary uppercase tracking-widest bg-neon-secondary/5 border border-neon-secondary/20 px-4 py-2 rounded-lg">
              <span className="w-2 h-2 rounded-full bg-neon-secondary animate-pulse shadow-[0_0_8px_var(--color-neon-secondary)]" />
              System Ready
            </div>
            <div className={`flex items-center gap-2 text-[10px] font-mono px-3 py-1.5 rounded-lg border ${
              ollamaOnline
                ? 'text-neon-primary border-neon-primary/20 bg-neon-primary/5'
                : 'text-white/20 border-white/10 bg-white/5'
            }`}>
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${ollamaOnline ? 'bg-neon-primary animate-pulse' : 'bg-white/20'}`} />
              {ollamaOnline
                ? <><span className="text-neon-primary font-black uppercase tracking-widest">AI Connected</span><span className="text-white/30 ml-1">· local</span></>
                : <span className="uppercase tracking-widest">AI · not running</span>
              }
            </div>
          </motion.div>
        </header>

        <AnimatePresence mode="wait">
          {/* IDLE — Scan Form */}
          {status === 'idle' && (
            <motion.div key="idle" initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 1.02, filter: 'blur(10px)' }}
              className="glass-card neon-border rounded-[2.5rem] p-10 md:p-16 relative shadow-2xl overflow-hidden">
              <div className="absolute top-0 right-0 w-64 h-64 bg-neon-primary/10 blur-[120px] pointer-events-none" />
              <div className="max-w-2xl mx-auto text-center mb-12">
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.2 }}
                  className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-white/5 border border-white/10 text-[10px] font-black uppercase tracking-[0.2em] text-white/60 mb-6">
                  <Radar className="w-3 h-3 text-neon-secondary" />
                  System Identification Ready
                </motion.div>
                <h2 className="text-4xl font-bold text-white mb-4 tracking-tight leading-tight">
                  Initiate Secure <br />
                  <span className="bg-gradient-to-r from-neon-primary to-neon-secondary bg-clip-text text-transparent italic">Cyber-Surface Assessment</span>
                </h2>
                <p className="text-white/50 text-lg leading-relaxed font-medium">
                  Scan for host integrity, architectural leaks, and algorithmic vulnerabilities.
                </p>
              </div>

              <form onSubmit={handleScan} className="max-w-3xl mx-auto space-y-8">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8 text-left">
                  <div className="space-y-3">
                    <label className="flex items-center gap-2 text-[11px] font-black text-white/40 uppercase tracking-[0.2em] ml-2">Target URL</label>
                    <div className="relative group">
                      <div className="absolute inset-x-0 bottom-0 h-[2px] bg-gradient-to-r from-neon-primary/0 via-neon-primary to-neon-primary/0 scale-x-0 group-focus-within:scale-x-100 transition-transform duration-500" />
                      <Globe className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5 text-white/20 group-focus-within:text-neon-primary transition-colors" />
                      <input type="url" value={url} onChange={e => setUrl(e.target.value)} placeholder="https://secure-target.io" required
                        className="w-full bg-white/5 border border-white/10 rounded-2xl py-5 pl-14 pr-6 text-white text-lg font-medium focus:outline-none focus:bg-white/10 transition-all placeholder:text-white/10 group-hover:border-white/20" />
                    </div>
                  </div>
                  <div className="space-y-3">
                    <label className="flex items-center gap-2 text-[11px] font-black text-white/40 uppercase tracking-[0.2em] ml-2">Source Code Path <span className="text-white/20 normal-case tracking-normal font-normal">(optional)</span></label>
                    <div className="relative group">
                      <div className="absolute inset-x-0 bottom-0 h-[2px] bg-gradient-to-r from-neon-secondary/0 via-neon-secondary to-neon-secondary/0 scale-x-0 group-focus-within:scale-x-100 transition-transform duration-500" />
                      <Cpu className="absolute left-5 top-1/2 -translate-y-1/2 w-5 h-5 text-white/20 group-focus-within:text-neon-secondary transition-colors" />
                      <input type="text" value={sourcePath} onChange={e => setSourcePath(e.target.value)} placeholder="C:\path\to\project"
                        className="w-full bg-white/5 border border-white/10 rounded-2xl py-5 pl-14 pr-6 text-white text-lg font-medium focus:outline-none focus:bg-white/10 transition-all placeholder:text-white/10 group-hover:border-white/20" />
                    </div>
                  </div>
                </div>
                {/* Scan Mode Selector */}
                <div className="space-y-3">
                  <label className="text-[11px] font-black text-white/40 uppercase tracking-[0.2em] ml-2 block">Scan Mode</label>
                  <div className="grid grid-cols-3 gap-3">
                    {([
                      { mode: 'Quick',    label: 'Quick',    desc: '~30s • HTTP analyzers',         color: 'neon-primary' },
                      { mode: 'Standard', label: 'Standard', desc: '~1min • HTTP analyzers',        color: 'neon-secondary' },
                      { mode: 'Deep',     label: 'Deep',     desc: '~15min • + Full Nuclei scan',   color: 'neon-accent' },
                    ] as const).map(({ mode, label, desc, color }) => (
                      <motion.button
                        key={mode}
                        type="button"
                        whileTap={{ scale: 0.97 }}
                        onClick={() => setScanMode(mode)}
                        className={`glass-card rounded-2xl p-4 border text-left transition-all ${
                          scanMode === mode
                            ? `border-${color}/60 bg-${color}/10 shadow-[0_0_20px_rgba(0,0,0,0.3)]`
                            : 'border-white/5 hover:border-white/20'
                        }`}
                      >
                        <div className={`text-sm font-black uppercase tracking-wider mb-1 ${scanMode === mode ? `text-${color}` : 'text-white/60'}`}>
                          {label}
                        </div>
                        <div className="text-[10px] text-white/30">{desc}</div>
                        {scanMode === mode && (
                          <div className={`mt-2 w-1.5 h-1.5 rounded-full bg-${color} animate-pulse`} />
                        )}
                      </motion.button>
                    ))}
                  </div>
                </div>

                <div className="flex flex-col items-center pt-4">
                  <motion.button whileHover={{ scale: 1.02, boxShadow: '0 0 35px rgba(0,255,157,0.4)' }} whileTap={{ scale: 0.98 }} type="submit"
                    className="group relative px-16 py-6 bg-neon-primary rounded-2xl text-[#020203] font-black uppercase tracking-[0.3em] overflow-hidden shadow-2xl shadow-neon-primary/20 btn-glow-primary">
                    <span className="absolute inset-0 bg-gradient-to-tr from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                    <span className="relative flex items-center gap-3 text-sm">
                      <Zap className="w-5 h-5 fill-current" />
                      Execute Scan
                    </span>
                  </motion.button>
                </div>
              </form>
            </motion.div>
          )}

          {/* RUNNING — Pipeline */}
          {status === 'running' && (
            <motion.div key="running" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-6">

              {/* Header */}
              <div className="glass-card rounded-3xl p-6 border border-neon-secondary/20 flex items-center justify-between">
                <div className="flex items-center gap-5">
                  <div className="relative">
                    <div className="absolute inset-0 bg-neon-secondary blur-xl opacity-30 animate-pulse" />
                    <div className="relative w-14 h-14 glass-card rounded-2xl flex items-center justify-center border border-neon-secondary/50">
                      <Activity className="w-7 h-7 text-neon-secondary animate-pulse" />
                    </div>
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-white mb-1">Engaging Analysis</h2>
                    <span className="font-mono text-xs text-neon-secondary/60 truncate max-w-[300px] block">{url}</span>
                  </div>
                </div>
                <div className="text-neon-primary font-black text-2xl italic neon-text-primary">SCANNING...</div>
              </div>

              {/* Stage Pipeline */}
              <div className="space-y-3">
                {([
                  { key: 'crawl',  label: 'Crawling',         icon: Globe,    color: 'neon-secondary' },
                  { key: 'http',   label: 'HTTP Analyzers',   icon: Shield,   color: 'neon-primary' },
                  { key: 'nuclei', label: 'Nuclei Scanner',   icon: Radar,    color: 'orange-400' },
                  { key: 'static', label: 'Static Analysis',  icon: Cpu,      color: 'yellow-400' },
                  { key: 'ai',     label: 'AI Enrichment',    icon: Activity, color: 'neon-accent' },
                ] as const)
                // Only show Nuclei if it actually received progress (Deep mode only)
                .filter(({ key }) => key !== 'nuclei' || !!stages['nuclei'])
                .map(({ key, label, icon: Icon, color }) => {
                  const stage = stages[key]
                  const pct = stage ? Math.round((stage.done / Math.max(stage.total, 1)) * 100) : 0
                  const isDone = pct === 100
                  const isActive = !!stage && !isDone

                  return (
                    <motion.div
                      key={key}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: stage ? 1 : 0.3, x: 0 }}
                      className={`glass-card rounded-2xl p-5 border transition-all ${
                        isDone ? 'border-white/20' : isActive ? `border-${color}/40` : 'border-white/5'
                      }`}
                    >
                      <div className="flex items-center gap-4 mb-3">
                        <div className={`p-2 rounded-xl ${isActive ? `bg-${color}/20` : 'bg-white/5'}`}>
                          <Icon className={`w-4 h-4 ${isActive ? `text-${color}` : isDone ? 'text-white/60' : 'text-white/20'}`} />
                        </div>
                        <span className={`text-sm font-bold uppercase tracking-wider ${
                          isDone ? 'text-white/60' : isActive ? `text-${color}` : 'text-white/20'
                        }`}>{label}</span>
                        <div className="ml-auto flex items-center gap-3">
                          {isDone && <span className="text-[10px] text-white/40 font-mono">✓ Done</span>}
                          {isActive && (
                            <span className={`text-[10px] font-mono text-${color}/70`}>
                              {stage.done}/{stage.total}
                            </span>
                          )}
                          <span className={`text-sm font-black ${isDone ? 'text-white/40' : `text-${color}`}`}>
                            {stage ? `${pct}%` : '—'}
                          </span>
                        </div>
                      </div>

                      {/* Progress bar */}
                      <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                        <motion.div
                          className={`h-full rounded-full ${isDone ? 'bg-white/30' : `bg-${color}`}`}
                          initial={{ width: 0 }}
                          animate={{ width: `${pct}%` }}
                          transition={{ duration: 0.3, ease: 'easeOut' }}
                        />
                      </div>

                      {/* Current message */}
                      {isActive && stage.message && (
                        <p className="text-[10px] text-white/30 font-mono mt-2 truncate">{stage.message}</p>
                      )}
                    </motion.div>
                  )
                })}
              </div>

              {/* Log */}
              {progress.length > 0 && (
                <div className="glass-card rounded-2xl overflow-hidden border border-white/5">
                  <div className="bg-white/5 px-5 py-3 flex items-center gap-3 border-b border-white/5">
                    <Terminal className="w-4 h-4 text-neon-secondary" />
                    <span className="text-[10px] font-black text-white/40 uppercase tracking-[0.3em]">Log</span>
                  </div>
                  <div className="p-5 h-40 overflow-y-auto font-mono text-xs bg-black/50" ref={terminalEndRef}>
                    {progress.slice(-20).map((msg, i) => (
                      <div key={i} className="text-white/40 py-0.5">
                        <span className="text-neon-secondary/30 mr-3">{String(i + 1).padStart(3, '0')}</span>{msg}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          )}

          {/* COMPLETED — Results */}
          {status === 'completed' && result && (
            <motion.div key="completed" initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }} className="space-y-10">
              {/* Score + Summary */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <div className="lg:col-span-4 glass-card rounded-[3rem] p-12 flex flex-col items-center justify-center border border-neon-accent/30 shadow-[0_0_60px_rgba(255,0,200,0.1)] relative overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-neon-accent/5 to-transparent pointer-events-none" />
                  <div className="text-[11px] font-black text-white/40 uppercase tracking-[0.5em] mb-8">Threat Matrix</div>
                  <div className="text-9xl font-black text-neon-accent neon-text-accent italic leading-none tracking-tighter">{result.riskScore}</div>
                  <div className="mt-6 text-[11px] font-black text-white/40 uppercase tracking-[0.2em]">Risk Score</div>
                </div>

                <div className="lg:col-span-8 glass-card rounded-[3rem] p-10 border border-white/10 relative">
                  <div className="flex items-center justify-between mb-8">
                    <h3 className="text-lg font-bold text-white uppercase tracking-[0.2em] flex items-center gap-3 italic">
                      <Activity className="w-5 h-5 text-neon-secondary" />Intelligence Segments
                    </h3>
                    <motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} onClick={reset}
                      className="text-[10px] font-black text-neon-secondary uppercase tracking-[0.3em] bg-neon-secondary/10 border border-neon-secondary/30 px-4 py-2 rounded-xl hover:bg-neon-secondary/20 transition-all flex items-center gap-2">
                      <RefreshCcw className="w-3 h-3" />New Scan
                    </motion.button>
                  </div>
                  <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                    {(['Critical', 'High', 'Medium', 'Low', 'Info'] as const).map(sev => {
                      const cfg = SEVERITY_CONFIG[sev]
                      const count = result[sev.toLowerCase() as keyof typeof result] as number
                      const isActive = activeFilter === sev
                      return (
                        <motion.button
                          key={sev}
                          whileHover={{ y: -4 }}
                          whileTap={{ scale: 0.95 }}
                          onClick={() => setActiveFilter(isActive ? null : sev)}
                          className={`glass-card rounded-[1.5rem] p-6 border flex flex-col items-center transition-all cursor-pointer ${
                            isActive
                              ? `${cfg.border} ${cfg.glow} ring-1 ring-inset ${cfg.border}`
                              : 'border-white/5 hover:border-white/20'
                          }`}
                        >
                          <div className={`text-3xl font-black ${cfg.color} mb-2`}>{count}</div>
                          <div className={`text-[10px] font-black uppercase tracking-[0.3em] ${isActive ? cfg.color : 'text-white/30'}`}>{sev}</div>
                          {isActive && <div className={`mt-2 w-1.5 h-1.5 rounded-full ${cfg.color} bg-current animate-pulse`} />}
                        </motion.button>
                      )
                    })}
                  </div>
                </div>
              </div>

              {/* AI Report — shown prominently when Ollama is available */}
              {result.aiReport && <AiReportBlock report={result.aiReport} />}

              {/* Meta */}
              <div className="flex flex-wrap gap-4">
                {[
                  { icon: Globe,  label: 'Target',        value: result.targetUrl,              color: 'text-neon-primary' },
                  { icon: Search, label: 'URLs Crawled',   value: result.scannedUrls.length,     color: 'text-neon-secondary' },
                  { icon: Lock,   label: 'Vulnerabilities',value: result.totalVulnerabilities,   color: 'text-neon-accent' },
                ].map((stat, i) => (
                  <div key={i} className="flex-1 min-w-[200px] glass-card rounded-2xl p-5 border border-white/5 flex items-center gap-4 hover:border-white/20 transition-colors">
                    <div className={`p-3 rounded-xl bg-white/5 ${stat.color}`}><stat.icon className="w-5 h-5" /></div>
                    <div>
                      <div className="text-[9px] font-bold text-white/30 uppercase tracking-widest">{stat.label}</div>
                      <div className="text-sm font-bold text-white/80 truncate max-w-[180px]">{stat.value}</div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Vulnerabilities */}
              {activeFilter && (
                <div className="flex items-center gap-3">
                  <span className="text-xs text-white/40">Filtered by:</span>
                  <span className={`text-xs font-bold px-3 py-1 rounded-full border ${SEVERITY_CONFIG[activeFilter].border} ${SEVERITY_CONFIG[activeFilter].color} ${SEVERITY_CONFIG[activeFilter].bg}`}>
                    {activeFilter}
                  </span>
                  <button onClick={() => setActiveFilter(null)} className="text-xs text-white/30 hover:text-white/60 transition-colors ml-1">
                    ✕ Clear
                  </button>
                </div>
              )}
              <div className="space-y-14 py-4">
                {(['Critical', 'High', 'Medium', 'Low', 'Info'] as const).map(sev => {
                  if (activeFilter && activeFilter !== sev) return null
                  const vulns = result.vulnerabilities.filter((v: Vulnerability) => v.severity === sev)
                  if (!vulns.length) return null
                  const cfg = SEVERITY_CONFIG[sev]
                  return (
                    <div key={sev}>
                      <div className="flex items-center gap-6 mb-8">
                        <div className={`w-2 h-2 rounded-full ${cfg.color} animate-pulse`} />
                        <h3 className={`${cfg.color} text-[11px] font-black uppercase tracking-[0.6em] whitespace-nowrap`}>
                          {sev} Cluster ({vulns.length})
                        </h3>
                        <div className="grow h-[1px] bg-white/5" />
                      </div>
                      <div className="space-y-4">
                        {vulns.map((vuln: Vulnerability) => (
                          <VulnerabilityCard key={vuln.id} vuln={vuln}
                            aiInsight={result.aiInsights?.[vuln.id]}
                            isExpanded={expanded === vuln.id}
                            onToggle={() => setExpanded(expanded === vuln.id ? null : vuln.id)} />
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            </motion.div>
          )}

          {/* ERROR */}
          {status === 'error' && (
            <motion.div key="error" initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="glass-card rounded-3xl p-10 border border-neon-accent/40 text-center">
              <AlertTriangle className="w-12 h-12 text-neon-accent mx-auto mb-4" />
              <h2 className="text-xl font-bold text-white mb-2">Scan Failed</h2>
              <p className="text-white/40 mb-6">Could not connect to API. Make sure <code className="text-neon-secondary">Protector.API</code> is running.</p>
              <motion.button whileHover={{ scale: 1.05 }} onClick={reset}
                className="px-8 py-3 bg-neon-accent/20 border border-neon-accent/40 text-neon-accent rounded-xl font-bold text-sm uppercase tracking-widest">
                Try Again
              </motion.button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  )
}

interface VulnCardProps {
  vuln: Vulnerability
  isExpanded: boolean
  onToggle: () => void
  aiInsight?: string
}

function AiReportBlock({ report }: { report: AiReport }) {
  const riskColor = {
    Critical: 'neon-accent', High: 'orange-400',
    Medium: 'yellow-400', Low: 'neon-primary'
  }[report.overallRisk] ?? 'neon-secondary'

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card rounded-[2rem] p-8 border border-neon-secondary/30 bg-neon-secondary/5 relative overflow-hidden"
    >
      <div className="absolute top-0 right-0 w-64 h-64 bg-neon-secondary/5 blur-[100px] pointer-events-none" />

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-neon-secondary/20">
            <Activity className="w-5 h-5 text-neon-secondary" />
          </div>
          <div>
            <h3 className="text-sm font-black text-neon-secondary uppercase tracking-[0.3em]">
              AI Security Report
            </h3>
            <p className="text-[10px] text-white/30 font-mono mt-0.5">Local AI · phi3:mini · private</p>
          </div>
        </div>
        <div className={`px-4 py-1.5 rounded-xl text-xs font-black uppercase tracking-widest bg-${riskColor}/20 text-${riskColor} border border-${riskColor}/30`}>
          {report.overallRisk} Risk
        </div>
      </div>

      {/* Summary */}
      <p className="text-white/70 leading-relaxed mb-6 pl-4 border-l-2 border-neon-secondary/30 italic">
        {report.summary}
      </p>

      {/* Top Priorities */}
      {report.topPriorities.length > 0 && (
        <div>
          <h4 className="text-[10px] font-black text-white/40 uppercase tracking-[0.4em] mb-4 flex items-center gap-2">
            <Zap className="w-3.5 h-3.5 text-neon-secondary" />
            Top Priorities to Fix
          </h4>
          <div className="space-y-2">
            {report.topPriorities.map((p, i) => (
              <div key={i} className="flex items-start gap-3 p-3 bg-white/5 rounded-xl border border-white/5">
                <span className="text-neon-secondary font-black text-sm shrink-0 w-5">{i + 1}.</span>
                <span className="text-white/70 text-sm">{p}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  )
}

function VulnerabilityCard({ vuln, isExpanded, onToggle, aiInsight }: VulnCardProps) {
  const cfg = SEVERITY_CONFIG[vuln.severity]
  const Icon = cfg.icon
  return (
    <motion.div layout className={`glass-card rounded-[1.5rem] overflow-hidden border transition-all duration-500 ${isExpanded ? `${cfg.border} ${cfg.glow}` : 'border-white/5 hover:border-white/20'}`}>
      <button onClick={onToggle} className="w-full flex items-center justify-between px-8 py-6 text-left group">
        <div className="flex items-center gap-6">
          <div className={`p-3 rounded-2xl ${cfg.bg} ${cfg.color} group-hover:scale-110 group-hover:rotate-6 transition-transform`}>
            <Icon className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-base font-bold text-white uppercase italic group-hover:translate-x-1 transition-transform">{vuln.title}</span>
              {/* AI badge — visible on collapsed card */}
              {aiInsight && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-lg bg-neon-secondary/20 border border-neon-secondary/30 text-[9px] font-black text-neon-secondary uppercase tracking-widest shrink-0">
                  <Activity className="w-2.5 h-2.5" />
                  AI
                </span>
              )}
            </div>
            <div className="flex items-center gap-4 mt-1 flex-wrap">
              <span className="text-[10px] font-black text-white/30 uppercase tracking-[0.2em]">{vuln.category}</span>
              {vuln.cweId && <span className="text-[11px] font-mono text-neon-secondary/40">{vuln.cweId}</span>}
              {vuln.foundBy && (
                <span className="text-[9px] font-mono text-white/20 bg-white/5 px-2 py-0.5 rounded-md">
                  🔍 {vuln.foundBy}
                </span>
              )}
            </div>
          </div>
        </div>
        <motion.div animate={{ rotate: isExpanded ? 180 : 0 }} className="w-10 h-10 glass-card rounded-xl flex items-center justify-center border border-white/10">
          <ChevronDown className="w-5 h-5 text-white/30" />
        </motion.div>
      </button>

      <AnimatePresence>
        {isExpanded && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}>
            <div className="px-8 pb-10 pt-4 space-y-8 border-t border-white/5 bg-white/[0.01]">
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-10">
                <div className="lg:col-span-8 space-y-6">

                  {/* AI Analysis — shown FIRST, most prominent */}
                  {aiInsight && (
                    <motion.div
                      initial={{ opacity: 0, y: 8 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="glass-card border border-neon-secondary/40 bg-neon-secondary/8 rounded-2xl p-6 relative overflow-hidden"
                    >
                      <div className="absolute top-0 right-0 w-32 h-32 bg-neon-secondary/10 blur-[60px] pointer-events-none" />
                      <div className="flex items-center gap-2 mb-3">
                        <div className="p-1.5 rounded-lg bg-neon-secondary/30">
                          <Activity className="w-3.5 h-3.5 text-neon-secondary" />
                        </div>
                        <span className="text-[10px] font-black text-neon-secondary uppercase tracking-[0.4em]">
                          AI Analysis
                        </span>
                        <span className="text-[9px] text-white/25 font-mono ml-1">local · phi3:mini</span>
                      </div>
                      <p className="text-neon-secondary/80 text-sm leading-relaxed font-medium">{aiInsight}</p>
                    </motion.div>
                  )}

                  <p className="text-base text-white/60 leading-relaxed font-medium pl-5 border-l border-white/10 italic">{vuln.description}</p>

                  <div className="glass-card border border-green-500/30 bg-green-500/5 rounded-2xl p-8">
                    <h4 className="text-[10px] font-black text-green-400 uppercase tracking-[0.5em] mb-3 flex items-center gap-2">
                      <Zap className="w-4 h-4 fill-current" />Remediation
                    </h4>
                    <p className="text-green-400 font-bold leading-snug">{vuln.remediation}</p>
                  </div>
                </div>
                <div className="lg:col-span-4 space-y-4 font-mono text-xs">
                  {vuln.url && (
                    <div className="p-4 bg-white/5 rounded-2xl border border-white/5">
                      <span className="text-[9px] text-white/20 uppercase block mb-2 font-bold">URL</span>
                      <span className="text-neon-secondary break-all">{vuln.url}</span>
                    </div>
                  )}
                  {vuln.owaspCategory && (
                    <div className="p-4 bg-white/5 rounded-2xl border border-white/5">
                      <span className="text-[9px] text-white/20 uppercase block mb-2 font-bold">OWASP</span>
                      <span className="text-white/50">{vuln.owaspCategory}</span>
                    </div>
                  )}
                  {vuln.evidence && (
                    <div className="p-4 bg-black/50 rounded-2xl border border-white/5">
                      <span className="text-[9px] text-white/20 uppercase block mb-2 font-bold">Evidence</span>
                      <span className="text-white/40 italic break-all">{vuln.evidence}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
