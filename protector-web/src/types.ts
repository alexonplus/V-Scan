export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'

export interface Vulnerability {
  id: string
  title: string
  description: string
  severity: Severity
  category: string
  url?: string
  filePath?: string
  lineNumber?: number
  evidence?: string
  cweId?: string
  owaspCategory?: string
  remediation: string
}

export interface ScanResult {
  scanId: string
  targetUrl: string
  startedAt: string
  completedAt?: string
  totalVulnerabilities: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  riskScore: number
  vulnerabilities: Vulnerability[]
  scannedUrls: string[]
  // vulnId → AI-generated insight from Ollama (present only if Ollama is running)
  aiInsights?: Record<string, string>
}

export type ScanStatus = 'idle' | 'running' | 'completed' | 'error'
