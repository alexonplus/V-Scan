import { useState, useRef, useCallback } from 'react'
import * as signalR from '@microsoft/signalr'
import type { ScanResult, ScanStatus } from './types'

const API_URL = 'http://localhost:5000'

export function useScan() {
  const [status, setStatus] = useState<ScanStatus>('idle')
  const [progress, setProgress] = useState<string[]>([])
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const connectionRef = useRef<signalR.HubConnection | null>(null)

  const startScan = useCallback(async (url: string, sourcePath?: string) => {
    setStatus('running')
    setProgress([])
    setResult(null)
    setError(null)

    try {
      // Step 1: start the scan — API returns scanId immediately
      const response = await fetch(`${API_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, sourceCodePath: sourcePath || null, maxDepth: 2 })
      })

      if (!response.ok) {
        const err = await response.json()
        throw new Error(err.error || 'Failed to start scan')
      }

      const { scanId } = await response.json()

      // Step 2: connect to SignalR hub to receive real-time progress
      const connection = new signalR.HubConnectionBuilder()
        .withUrl(`${API_URL}/hubs/scan`)
        .withAutomaticReconnect()
        .build()

      connectionRef.current = connection

      // Listen for progress messages from the server
      connection.on('Progress', (msg: string) => {
        setProgress(prev => [...prev, msg])
      })

      // Listen for scan completion
      connection.on('Completed', (data: ScanResult) => {
        setResult(data)
        setStatus('completed')
        connection.stop()
      })

      // Listen for errors
      connection.on('Error', (msg: string) => {
        setError(msg)
        setStatus('error')
        connection.stop()
      })

      await connection.start()

      // Join the group for this specific scan
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
  }, [])

  return { status, progress, result, error, startScan, reset }
}
