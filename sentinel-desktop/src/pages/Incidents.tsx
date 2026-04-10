import { useEffect, useState } from 'react'
import { Siren, RefreshCw, ChevronDown, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { invoke } from '@tauri-apps/api/core'
import type { Incident, Severity } from '@/lib/types'

const SEVERITY_COLORS: Record<Severity, string> = {
  Critical: 'text-critical border-critical/30 bg-critical/10',
  High:     'text-high border-high/30 bg-high/10',
  Medium:   'text-medium border-medium/30 bg-medium/10',
  Low:      'text-low border-low/30 bg-low/10',
  Info:     'text-accent border-accent/30 bg-accent/10',
}

const scoreColor = (score: number) =>
  score >= 100 ? 'text-critical bg-critical/10 border-critical/30' :
  score >= 60  ? 'text-high bg-high/10 border-high/30' :
  score >= 30  ? 'text-medium bg-medium/10 border-medium/30' :
                 'text-low bg-low/10 border-low/30'

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading]     = useState(true)
  const [filter, setFilter]       = useState<Severity | 'All'>('All')
  const [expanded, setExpanded]   = useState<Set<string>>(new Set())

  const refresh = async () => {
    setLoading(true)
    try {
      const data = await invoke<Incident[]>('get_incidents')
      setIncidents(data)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    refresh()
    const interval = setInterval(refresh, 10_000)
    return () => clearInterval(interval)
  }, [])

  const toggle = (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const filtered = filter === 'All' ? incidents : incidents.filter(i => i.severity === filter)

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-border px-6 py-3">
        <Siren className="size-3.5 text-accent" strokeWidth={1.5} />
        <h1 className="text-xs font-bold tracking-widest text-accent text-glow-accent">INCIDENTS</h1>
        <span className="text-xs text-text-muted">{filtered.length} incidents</span>
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
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {filtered.length === 0 && !loading ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-text-muted">
            <Siren className="size-10 opacity-20" strokeWidth={1} />
            <p className="text-sm">No incidents</p>
            <p className="text-xs opacity-60">Individual alerts may exist but haven't been correlated into attack chains</p>
          </div>
        ) : (
          filtered.map(inc => (
            <div
              key={inc.id}
              className={`rounded-lg border border-border bg-surface p-4 space-y-2.5 ${inc.is_closed ? 'opacity-50' : ''}`}
            >
              {/* Top row */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-medium ${SEVERITY_COLORS[inc.severity]}`}>
                  {inc.severity}
                </span>
                <span className={`inline-flex items-center px-2 py-0.5 rounded border text-[10px] font-bold font-mono ${scoreColor(inc.score)}`}>
                  {inc.score}
                </span>
                {inc.pid !== null && (
                  <span className="text-[10px] text-text-muted font-mono">PID {inc.pid}</span>
                )}
                {inc.is_closed && (
                  <span className="text-[10px] text-text-dim border border-border rounded px-1.5 py-0.5">CLOSED</span>
                )}
              </div>

              {/* Summary */}
              <p className="text-xs text-text leading-relaxed">{inc.summary}</p>

              {/* ATT&CK IDs */}
              {inc.attack_ids.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {inc.attack_ids.map(id => (
                    <span key={id} className="font-mono text-accent bg-surface-elevated border border-border rounded px-1.5 py-0.5 text-[10px]">
                      {id}
                    </span>
                  ))}
                </div>
              )}

              {/* Meta + expand */}
              <div className="flex items-center gap-3 text-[10px] text-text-muted">
                <span>{inc.alerts.length} alert{inc.alerts.length !== 1 ? 's' : ''}</span>
                <span className="font-mono">{new Date(inc.first_seen).toLocaleString()} — {new Date(inc.last_seen).toLocaleString()}</span>
                <div className="flex-1" />
                {inc.alerts.length > 0 && (
                  <button onClick={() => toggle(inc.id)} className="flex items-center gap-1 text-accent hover:text-text transition-colors">
                    {expanded.has(inc.id) ? <ChevronDown className="size-3" /> : <ChevronRight className="size-3" />}
                    {expanded.has(inc.id) ? 'Hide' : 'Show'} alerts
                  </button>
                )}
              </div>

              {/* Expanded alerts */}
              {expanded.has(inc.id) && inc.alerts.length > 0 && (
                <table className="w-full text-[10px] border-collapse mt-1">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left px-2 py-1 text-text-muted font-medium">Severity</th>
                      <th className="text-left px-2 py-1 text-text-muted font-medium">Message</th>
                      <th className="text-right px-2 py-1 text-text-muted font-medium">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {inc.alerts.map(a => (
                      <tr key={a.id} className="border-b border-border/30">
                        <td className="px-2 py-1">
                          <span className={`px-1.5 py-0.5 rounded border text-[10px] ${SEVERITY_COLORS[a.severity]}`}>{a.severity}</span>
                        </td>
                        <td className="px-2 py-1 text-text truncate max-w-xs">{a.message}</td>
                        <td className="px-2 py-1 text-right text-text-dim font-mono">{new Date(a.occurred_at).toLocaleTimeString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
