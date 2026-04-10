import { useState } from 'react'
import { Brain, RefreshCw, Check, X, AlertTriangle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { invoke } from '@tauri-apps/api/core'
import type { MemoryScanResult, MemoryAnomalyKind, NtdllHookResult, ByovdAlert } from '@/lib/types'

type Tab = 'injections' | 'ntdll' | 'byovd'

const ANOMALY_LABELS: Record<MemoryAnomalyKind, { label: string; color: string }> = {
  AnonymousExecutable: { label: 'RWX SHELLCODE', color: 'text-critical border-critical/30 bg-critical/10' },
  ProcessHollowing:    { label: 'HOLLOWED',      color: 'text-critical border-critical/30 bg-critical/10' },
  ExecutableHeap:      { label: 'EXEC HEAP',     color: 'text-high border-high/30 bg-high/10' },
}

export default function MemoryForensics() {
  const [tab, setTab]           = useState<Tab>('injections')
  const [loading, setLoading]   = useState(false)
  const [scans, setScans]       = useState<MemoryScanResult[]>([])
  const [hooks, setHooks]       = useState<NtdllHookResult[]>([])
  const [drivers, setDrivers]   = useState<ByovdAlert[]>([])
  const [scanned, setScanned]   = useState(false)

  const scan = async () => {
    setLoading(true)
    try {
      const [s, h, d] = await Promise.all([
        invoke<MemoryScanResult[]>('scan_memory'),
        invoke<NtdllHookResult[]>('check_ntdll'),
        invoke<ByovdAlert[]>('check_byovd'),
      ])
      setScans(s)
      setHooks(h)
      setDrivers(d)
      setScanned(true)
    } finally {
      setLoading(false)
    }
  }

  const tabs: { key: Tab; label: string }[] = [
    { key: 'injections', label: 'Injections' },
    { key: 'ntdll',      label: 'NTDLL Hooks' },
    { key: 'byovd',      label: 'BYOVD Drivers' },
  ]

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-3">
        <Brain className="size-3.5 text-accent" strokeWidth={1.5} />
        <h1 className="text-xs font-bold tracking-widest text-accent text-glow-accent">MEMORY FORENSICS</h1>
        <div className="flex-1" />
        <Button variant="ghost" size="sm" onClick={scan} disabled={loading}>
          <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
          {scanned ? 'Re-scan' : 'Scan'}
        </Button>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 px-6 py-2 border-b border-border bg-surface">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-3 py-1 rounded text-xs font-medium transition-all border ${
              tab === t.key
                ? 'border-accent/30 bg-accent/10 text-accent'
                : 'border-transparent text-text-muted hover:text-text hover:border-border'
            }`}
          >
            {t.label}
          </button>
        ))}
        <div className="flex-1" />
        <span className="text-[10px] text-text-dim flex items-center gap-1">
          <AlertTriangle className="size-3" />
          Memory scanning requires Administrator privileges
        </span>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto">
        {!scanned ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
            <Brain className="size-10 opacity-20" strokeWidth={1} />
            <p className="text-sm">Click Scan to analyze process memory</p>
            <p className="text-xs opacity-60">Checks for code injection, NTDLL hooks, and vulnerable drivers</p>
          </div>
        ) : tab === 'injections' ? (
          scans.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
              <Check className="size-10 opacity-20" strokeWidth={1} />
              <p className="text-sm">No memory anomalies detected</p>
            </div>
          ) : (
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 bg-surface z-10">
                <tr className="border-b border-border">
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium w-20">PID</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium">Image</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium w-20">Regions</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium">Anomalies</th>
                </tr>
              </thead>
              <tbody>
                {scans.map(s => (
                  <tr key={s.pid} className="border-b border-border/50 hover:bg-surface-elevated/40">
                    <td className="px-4 py-2.5 font-mono text-text">{s.pid}</td>
                    <td className="px-4 py-2.5 text-text truncate max-w-xs" title={s.image_path}>{s.image_path}</td>
                    <td className="px-4 py-2.5 text-text-muted">{s.total_regions}</td>
                    <td className="px-4 py-2.5 space-y-1">
                      {s.suspicious.map((a, i) => {
                        const info = ANOMALY_LABELS[a.kind]
                        return (
                          <div key={i} className="flex items-center gap-2">
                            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${info.color}`}>{info.label}</span>
                            <span className="font-mono text-text-muted text-[10px]">0x{a.base.toString(16)}</span>
                            <span className="text-text-dim text-[10px]">{a.size} bytes</span>
                          </div>
                        )
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : tab === 'ntdll' ? (
          hooks.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
              <Check className="size-10 opacity-20" strokeWidth={1} />
              <p className="text-sm">No NTDLL data available</p>
              <p className="text-xs opacity-60">Run a scan to check for hooks</p>
            </div>
          ) : (
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 bg-surface z-10">
                <tr className="border-b border-border">
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium">Function</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium w-32">Status</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium w-40">Hook Type</th>
                </tr>
              </thead>
              <tbody>
                {hooks.map(h => (
                  <tr key={h.function_name} className="border-b border-border/50 hover:bg-surface-elevated/40">
                    <td className="px-4 py-2.5 font-mono text-text">{h.function_name}</td>
                    <td className="px-4 py-2.5">
                      {h.is_hooked ? (
                        <span className="inline-flex items-center gap-1.5 text-critical">
                          <X className="size-3.5" /> Hooked
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-low">
                          <Check className="size-3.5" /> Clean
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      {h.hook_type ? (
                        <span className="px-1.5 py-0.5 rounded border text-[10px] font-medium text-critical border-critical/30 bg-critical/10">
                          {h.hook_type}
                        </span>
                      ) : (
                        <span className="text-text-dim">--</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        ) : (
          drivers.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
              <Check className="size-10 opacity-20" strokeWidth={1} />
              <p className="text-sm">No vulnerable drivers detected</p>
              <p className="text-xs opacity-60">System is clean</p>
            </div>
          ) : (
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 bg-surface z-10">
                <tr className="border-b border-border">
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium">Driver</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium">Path</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium w-36">SHA-256</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium">Vulnerability</th>
                  <th className="text-left px-4 py-2.5 text-text-muted font-medium w-28">CVE</th>
                </tr>
              </thead>
              <tbody>
                {drivers.map(d => (
                  <tr key={d.sha256} className="border-b border-border/50 hover:bg-surface-elevated/40">
                    <td className="px-4 py-2.5 text-text font-medium">{d.driver_name}</td>
                    <td className="px-4 py-2.5 text-text-muted font-mono text-[10px] truncate max-w-xs" title={d.driver_path}>{d.driver_path}</td>
                    <td className="px-4 py-2.5 text-text-dim font-mono text-[10px]" title={d.sha256}>{d.sha256.slice(0, 16)}...</td>
                    <td className="px-4 py-2.5 text-high">{d.vuln_name}</td>
                    <td className="px-4 py-2.5">
                      {d.cve ? (
                        <span className="font-mono text-accent text-[10px]">{d.cve}</span>
                      ) : (
                        <span className="text-text-dim">--</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </div>
    </div>
  )
}
