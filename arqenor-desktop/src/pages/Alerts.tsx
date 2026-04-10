import { useEffect, useState } from 'react'
import { ShieldAlert, RefreshCw } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { invoke } from '@tauri-apps/api/core'
import type { Alert, Severity } from '@/lib/types'

const SEVERITY_ORDER: Record<Severity, number> = {
  Critical: 4, High: 3, Medium: 2, Low: 1, Info: 0,
}

const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: 'text-critical border-critical/30 bg-critical/10',
  High:     'text-high border-high/30 bg-high/10',
  Medium:   'text-medium border-medium/30 bg-medium/10',
  Low:      'text-low border-low/30 bg-low/10',
  Info:     'text-accent border-accent/30 bg-accent/10',
}

const SEVERITY_DOT: Record<Severity, string> = {
  Critical: 'bg-critical',
  High:     'bg-high',
  Medium:   'bg-medium',
  Low:      'bg-low',
  Info:     'bg-accent',
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState<Severity | 'All'>('All')

  const refresh = async () => {
    setLoading(true)
    try {
      const data = await invoke<Alert[]>('get_alerts')
      setAlerts(data.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])

  const filtered = filter === 'All' ? alerts : alerts.filter(a => a.severity === filter)

  const counts = alerts.reduce((acc, a) => {
    acc[a.severity] = (acc[a.severity] ?? 0) + 1
    return acc
  }, {} as Record<Severity, number>)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-3">
        <h1 className="text-xs font-bold tracking-widest text-accent text-glow-accent">
          ALERTS
        </h1>
        <span className="text-xs text-text-muted">{filtered.length} / {alerts.length}</span>
        <div className="flex-1" />
        <Button variant="ghost" size="sm" onClick={refresh} disabled={loading}>
          <RefreshCw className={`size-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Severity filter tabs */}
      <div className="flex items-center gap-1 px-6 py-2 border-b border-border bg-surface">
        {(['All', 'Critical', 'High', 'Medium', 'Low', 'Info'] as const).map(sev => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`px-3 py-1 rounded text-xs font-medium transition-all border ${
              filter === sev
                ? sev === 'All'
                  ? 'border-accent/30 bg-accent/10 text-accent'
                  : SEVERITY_COLORS[sev as Severity]
                : 'border-transparent text-text-muted hover:text-text hover:border-border'
            }`}
          >
            {sev}
            {sev !== 'All' && counts[sev as Severity] ? (
              <span className="ml-1.5 text-[10px] opacity-70">{counts[sev as Severity]}</span>
            ) : null}
          </button>
        ))}
      </div>

      {/* Alerts list */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
            <ShieldAlert className="size-10 opacity-20" strokeWidth={1} />
            <p className="text-sm">No alerts detected</p>
            <p className="text-xs opacity-60">Detection engines are running in the background</p>
          </div>
        ) : (
          <table className="w-full text-xs border-collapse">
            <thead className="sticky top-0 bg-surface z-10">
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-24">Severity</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-28">ATT&amp;CK</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium">Message</th>
                <th className="text-left px-4 py-2.5 text-text-muted font-medium w-32">Kind</th>
                <th className="text-right px-4 py-2.5 text-text-muted font-medium w-36">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(alert => (
                <tr key={alert.id} className="data-row border-b border-border/50 hover:bg-surface-elevated/40">
                  <td className="px-4 py-2.5">
                    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px] font-medium ${SEVERITY_COLORS[alert.severity]}`}>
                      <span className={`size-1.5 rounded-full ${SEVERITY_DOT[alert.severity]}`} />
                      {alert.severity}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    {alert.attack_id ? (
                      <span className="px-1.5 py-0.5 rounded bg-surface-elevated border border-border text-accent text-[10px] font-mono">
                        {alert.attack_id}
                      </span>
                    ) : (
                      <span className="text-text-dim">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-text max-w-sm">
                    <span className="block truncate" title={alert.message}>{alert.message}</span>
                  </td>
                  <td className="px-4 py-2.5 text-text-muted font-mono text-[10px]">{alert.kind}</td>
                  <td className="px-4 py-2.5 text-right text-text-dim font-mono text-[10px]">
                    {new Date(alert.occurred_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
