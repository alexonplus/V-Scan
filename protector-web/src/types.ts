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

export interface AiReport {
  summary: string
  topPriorities: string[]
  overallRisk: string
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
  aiInsights?: Record<string, string>
  aiReport?: AiReport
}

export type ScanStatus = 'idle' | 'running' | 'completed' | 'error'
