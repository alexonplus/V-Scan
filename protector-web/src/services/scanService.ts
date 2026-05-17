import { useState, useRef, useCallback, useEffect } from 'react'
import * as signalR from '@microsoft/signalr'
import type { ScanResult, ScanStatus } from '../types'

const API_URL = 'http://localhost:5153'

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
  const [aiProgress, setAiProgress] = useState<{ done: number; total: number; message: string } | null>(null)
  const connectionRef = useRef<signalR.HubConnection | null>(null)

  useEffect(() => {
    checkOllamaStatus().then(setOllamaOnline)
  }, [])

  const startScan = useCallback(async (url: string, sourcePath?: string, mode: string = 'Standard') => {
    setStatus('running')
    setProgress([])
    setResult(null)
    setError(null)

    try {
      // Step 1: POST to API — returns scanId immediately
      const response = await fetch(`${API_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url,
          sourceCodePath: sourcePath || null,
          mode,
          timeoutSeconds: 8
        })
      })

      if (!response.ok) {
        const err = await response.json()
        throw new Error(err.error || 'Failed to start scan')
      }

      const { scanId } = await response.json()

      // Step 2: connect to SignalR hub for real-time progress
      const connection = new signalR.HubConnectionBuilder()
        .withUrl(`${API_URL}/hubs/scan`)
        .withAutomaticReconnect()
        .build()

      connectionRef.current = connection

      connection.on('Progress', (msg: string) => {
        // Parse AI progress messages: "AI_PROGRESS:done:total:message"
        if (msg.startsWith('AI_PROGRESS:')) {
          const [, done, total, ...rest] = msg.split(':')
          setAiProgress({ done: Number(done), total: Number(total), message: rest.join(':') })
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
    setAiProgress(null)
  }, [])

  return { status, progress, result, error, ollamaOnline, aiProgress, startScan, reset }
}
