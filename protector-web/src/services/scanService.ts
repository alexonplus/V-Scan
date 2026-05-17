import { useState, useRef, useCallback, useEffect } from 'react'
import * as signalR from '@microsoft/signalr'
import type { ScanResult, ScanStatus } from '../types'

const API_URL = 'http://localhost:5153'

export interface StageInfo {
  done: number
  total: number
  message: string
}

export async function checkOllamaStatus(): Promise<boolean> {
  try {
    const res = await fetch('http://localhost:11434/api/tags', { signal: AbortSignal.timeout(2000) })
    return res.ok
  } catch { return false }
}

export function useScan() {
  const [status, setStatus] = useState<ScanStatus>('idle')
  const [progress, setProgress] = useState<string[]>([])
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [ollamaOnline, setOllamaOnline] = useState<boolean | null>(null)
  const [stages, setStages] = useState<Record<string, StageInfo>>({})
  const connectionRef = useRef<signalR.HubConnection | null>(null)

  useEffect(() => {
    checkOllamaStatus().then(setOllamaOnline)
  }, [])

  const startScan = useCallback(async (url: string, sourcePath?: string, mode: string = 'Standard') => {
    setStatus('running')
    setProgress([])
    setResult(null)
    setError(null)
    setStages({})

    try {
      const response = await fetch(`${API_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, sourceCodePath: sourcePath || null, mode, timeoutSeconds: 8 })
      })

      if (!response.ok) {
        const err = await response.json()
        throw new Error(err.error || 'Failed to start scan')
      }

      const { scanId } = await response.json()

      const connection = new signalR.HubConnectionBuilder()
        .withUrl(`${API_URL}/hubs/scan`)
        .withAutomaticReconnect()
        .build()

      connectionRef.current = connection

      connection.on('Progress', (msg: string) => {
        if (msg.startsWith('STAGE:')) {
          // Format: "STAGE:name:done:total:message"
          const parts = msg.split(':')
          const name = parts[1]
          const done = Number(parts[2])
          const total = Number(parts[3])
          const message = parts.slice(4).join(':')
          setStages(prev => ({ ...prev, [name]: { done, total, message } }))
        } else if (msg.startsWith('AI_PROGRESS:')) {
          // AI stage progress feeds into stages too
          const [, done, total, ...rest] = msg.split(':')
          setStages(prev => ({
            ...prev,
            ai: { done: Number(done), total: Number(total), message: rest.join(':') }
          }))
        } else {
          setProgress(prev => [...prev, msg])
        }
      })

      connection.on('Completed', (data: ScanResult) => {
        setResult(data)
        setStatus('completed')
        connection.stop()
      })

      connection.on('Error', (msg: string) => {
        setError(msg)
        setStatus('error')
        connection.stop()
      })

      await connection.start()
      await connection.invoke('JoinScan', scanId)

    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unknown error')
      setStatus('error')
    }
  }, [])

  const reset = useCallback(() => {
    connectionRef.current?.stop()
    setStatus('idle')
    setProgress([])
    setResult(null)
    setError(null)
    setStages({})
  }, [])

  return { status, progress, result, error, ollamaOnline, stages, startScan, reset }
}
